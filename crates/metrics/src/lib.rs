// Build-scoped FS-metrics daemon. A root LaunchDaemon owns kdebug only while a build
// window is open (opt-in via sandboxfs_metrics=1), so default builds take zero overhead.
// The daemon is the central SINK: producers push aggregates into it (the kdebug collector
// in-process now; an FSKit backend over XPC later), it RETAINS the per-workspace timeline
// + build spans, and the app TAILS it live over one XPC method:
//
//   feed(since=<cursor_ms>) -> JSON {now, workspaces:[…samples after cursor…], builds}
//
// since=0 backfills all retained history; tailing with the last cursor streams the live
// edge. The server keeps everything and decides nothing about the view — the client derives
// throughput, rates, fleet sums, the swimlane, and the build timeline. begin/end/report stay
// privileged side-effecting controls (arming root-only kdebug). All over the existing XPC
// plane (xpc.rs); JSON keys are camelCase so the Swift client decodes raw (no snake-case
// remap that would mangle the op map's `posix_spawn`).

#![allow(non_upper_case_globals)] // BSC_*/VFS_* mirror the kernel trace-code names

mod collect;
mod kdebug;
mod xpc;

use collect::{Bucket, Collector, Stats};
use kdebug::Session;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WINDOW_MS: u64 = 120_000; // a feed never sends more than this much trailing history (~2min)
const HISTORY_CAP: usize = 6000; // retained buckets per workspace (~10min @100ms, sparse)
const CREATES_CAP: usize = 6000; // retained create-rate samples per workspace
const SPANS_CAP: usize = 256; // retained build spans per workspace

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn cap<T>(v: &mut Vec<T>, n: usize) {
    if v.len() > n {
        v.drain(0..v.len() - n);
    }
}

/// The controller's latest cumulative backend report for a workspace (parsed from the
/// line-based text it pushes; see backend `stats::report_text`). Cumulative over the
/// controller's life — we diff successive reports into per-interval create samples.
#[derive(Default, Clone)]
struct Ctrl {
    backend: String,
    creates: u64,
    laydown_us: u64,
    files: u64,
    dirs: u64,
    mnemonics: Vec<(String, u64, u64, u64)>, // (name, creates, laydown_us, max_us)
}

impl Ctrl {
    fn parse(text: &str) -> Ctrl {
        let mut c = Ctrl::default();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("backend=") {
                c.backend = v.to_string();
            } else if let Some(v) = line.strip_prefix("creates=") {
                c.creates = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("laydown_us=") {
                c.laydown_us = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("files=") {
                c.files = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("dirs=") {
                c.dirs = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("m=") {
                // "<name>:<creates>:<laydown_us>:<max_us>" — mnemonic names carry no ':'.
                let mut it = v.rsplitn(4, ':');
                let max = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let laydown = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let creates = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                if let Some(name) = it.next().filter(|n| !n.is_empty()) {
                    c.mnemonics.push((name.to_string(), creates, laydown, max));
                }
            }
        }
        c
    }
}

/// One ~1s sample of sandbox creates: how many landed and the laydown µs they cost
/// (avg create time = laydownUs / n). Diffed from successive cumulative reports.
#[derive(Clone)]
struct CreateSample {
    t_ms: u64,
    n: u64,
    laydown_us: u64,
}

/// One build window as a span on the timeline. Open while the build runs (`end_ms` None),
/// closed with the window's own deltas (kdebug bytes/syscalls + report creates/files).
#[derive(Clone)]
struct BuildSpan {
    start_ms: u64,
    end_ms: Option<u64>,
    backend: String,
    base_creates: u64,
    base_files: u64,
    creates: u64,
    files: u64,
    bytes_read: u64,
    bytes_written: u64,
    syscalls: u64,
}

#[derive(Default)]
struct BuildMeta {
    start_ms: u64,
    end_ms: Option<u64>,
    ctrl: Option<Ctrl>, // latest cumulative report
}

static DAEMON: OnceLock<Mutex<Daemon>> = OnceLock::new();

fn daemon() -> &'static Mutex<Daemon> {
    DAEMON.get_or_init(|| Mutex::new(Daemon::default()))
}

/// kdebug is machine-global: one session + drain thread (refcounted by open windows) feeds
/// one Collector for every concurrent workspace. The daemon retains the per-workspace
/// timeline, create-rate samples, and build spans beyond the session's life so the app can
/// scroll back through finished builds.
#[derive(Default)]
struct Daemon {
    session: Option<SharedSession>,
    active: Vec<String>,                         // workspaces with an open window now
    totals: HashMap<String, Stats>,              // cumulative kdebug stats per workspace
    history: HashMap<String, Vec<Bucket>>,       // drained timeline lanes (finished windows)
    creates: HashMap<String, Vec<CreateSample>>, // report-diffed create-rate timeline
    spans: HashMap<String, Vec<BuildSpan>>,      // build windows
    meta: HashMap<String, BuildMeta>,            // window times + latest report
}

struct SharedSession {
    collector: Arc<Mutex<Collector>>,
    stop: Arc<AtomicBool>,
    drain: JoinHandle<()>,
}

impl Daemon {
    fn begin(&mut self, build_id: &str, clone_prefix: &str, owner_pid: i32) -> Result<(), String> {
        if self.active.iter().any(|b| b == build_id) {
            return Err(format!("window already active for {build_id:?}"));
        }
        if self.session.is_none() {
            self.session = Some(SharedSession::start().map_err(|e| e.to_string())?);
        }
        let s = self.session.as_ref().unwrap();
        s.collector.lock().unwrap().add_tenant(build_id, clone_prefix, owner_pid);
        self.active.push(build_id.to_string());

        let now = now_ms();
        let base = self.meta.get(build_id).and_then(|m| m.ctrl.as_ref());
        let span = BuildSpan {
            start_ms: now,
            end_ms: None,
            backend: base.map(|c| c.backend.clone()).unwrap_or_default(),
            base_creates: base.map_or(0, |c| c.creates),
            base_files: base.map_or(0, |c| c.files),
            creates: 0,
            files: 0,
            bytes_read: 0,
            bytes_written: 0,
            syscalls: 0,
        };
        let spans = self.spans.entry(build_id.to_string()).or_default();
        spans.push(span);
        cap(spans, SPANS_CAP);

        let m = self.meta.entry(build_id.to_string()).or_default();
        m.start_ms = now;
        m.end_ms = None;
        Ok(())
    }

    /// Store the controller's latest cumulative report and diff it into a create-rate
    /// sample (off the kdebug path). FSKit will later push the same shape over XPC.
    fn report(&mut self, build_id: &str, payload: &str) {
        let new = Ctrl::parse(payload);
        let prev = self.meta.get(build_id).and_then(|m| m.ctrl.as_ref());
        let (pn, pl) = prev.map_or((0, 0), |c| (c.creates, c.laydown_us));
        let (dn, dl) = (new.creates.saturating_sub(pn), new.laydown_us.saturating_sub(pl));
        if dn > 0 {
            let v = self.creates.entry(build_id.to_string()).or_default();
            v.push(CreateSample { t_ms: now_ms(), n: dn, laydown_us: dl });
            cap(v, CREATES_CAP);
        }
        self.meta.entry(build_id.to_string()).or_default().ctrl = Some(new);
    }

    /// Close a window. Returns the session to reap if this was the last one (the caller
    /// stops+joins the drain OUTSIDE the daemon lock so teardown can't stall other requests).
    fn end(&mut self, build_id: &str) -> Result<Option<SharedSession>, String> {
        let pos = self.active.iter().position(|b| b == build_id).ok_or("no active window for that build")?;
        let s = self.session.as_ref().ok_or("no session")?;
        let (delta, lane) = s.collector.lock().unwrap().remove_tenant(build_id);

        // close the open span with this window's own deltas
        let ctrl = self.meta.get(build_id).and_then(|m| m.ctrl.as_ref()).cloned().unwrap_or_default();
        let now = now_ms();
        if let Some(span) = self.spans.get_mut(build_id).and_then(|v| v.iter_mut().rev().find(|s| s.end_ms.is_none())) {
            span.end_ms = Some(now);
            span.backend = ctrl.backend.clone();
            span.creates = ctrl.creates.saturating_sub(span.base_creates);
            span.files = ctrl.files.saturating_sub(span.base_files);
            span.bytes_read = delta.bytes_read;
            span.bytes_written = delta.bytes_written;
            span.syscalls = delta.ops.values().sum();
        }

        let h = self.history.entry(build_id.to_string()).or_default();
        h.extend(lane);
        cap(h, HISTORY_CAP);
        self.totals.entry(build_id.to_string()).or_default().add(&delta);
        self.active.remove(pos);
        self.meta.entry(build_id.to_string()).or_default().end_ms = Some(now);

        if self.active.is_empty() {
            // last window: rescue the unattributed lane before the collector is dropped
            if let Some(sess) = &self.session {
                let u = sess.collector.lock().unwrap().take_lane("");
                let hu = self.history.entry(String::new()).or_default();
                hu.extend(u);
                cap(hu, HISTORY_CAP);
            }
            Ok(self.session.take())
        } else {
            Ok(None)
        }
    }

    /// Cumulative kdebug stats for a workspace: retained totals plus its in-progress window.
    /// A plain `lock()` — the drain chunks its batches (spawn_drain) so this waits at most
    /// one chunk; skipping the live read (try_lock) lost buckets and made the charts bursty.
    fn workspace_stats(&self, ws: &str) -> Stats {
        let mut s = self.totals.get(ws).cloned().unwrap_or_default();
        if self.active.iter().any(|b| b == ws) {
            if let Some(sess) = &self.session {
                s.add(&sess.collector.lock().unwrap().tenant_stats(ws));
            }
        }
        s
    }

    /// Timeline buckets for a workspace with t_ms > floor: retained history plus, for an
    /// active workspace, the live in-progress lane.
    fn samples(&self, ws: &str, floor: u64) -> Vec<Bucket> {
        let mut out: Vec<Bucket> =
            self.history.get(ws).map_or_else(Vec::new, |h| h.iter().filter(|b| b.t_ms > floor).cloned().collect());
        if self.active.iter().any(|b| b == ws) {
            if let Some(sess) = &self.session {
                out.extend(sess.collector.lock().unwrap().series_lane(ws, floor));
            }
        }
        out
    }

    fn clear(&mut self) {
        let live = self.active.clone();
        self.totals.retain(|ws, _| live.contains(ws));
        self.history.retain(|ws, _| live.contains(ws));
        self.creates.retain(|ws, _| live.contains(ws));
        self.spans.retain(|ws, _| live.contains(ws));
        self.meta.retain(|ws, _| live.contains(ws));
    }

    /// The whole feed: one record per workspace (cumulative totals + new timeline buckets +
    /// new create-rate samples since the cursor), plus all build spans. `since`=0 backfills.
    fn feed_json(&self, since: u64) -> String {
        let mut workspaces: Vec<&String> = self
            .totals
            .keys()
            .chain(self.active.iter())
            .chain(self.history.keys())
            .chain(self.creates.keys())
            .chain(self.meta.keys())
            .collect();
        workspaces.sort();
        workspaces.dedup();

        let recs = workspaces.iter().map(|ws| self.workspace_json(ws, since)).collect::<Vec<_>>().join(",");
        let builds = self
            .spans
            .iter()
            .flat_map(|(ws, v)| v.iter().map(move |s| span_json(ws, s)))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"now\":{},\"workspaces\":[{recs}],\"builds\":[{builds}]}}", now_ms())
    }

    fn workspace_json(&self, ws: &str, since: u64) -> String {
        let s = self.workspace_stats(ws);
        let ctrl = self.meta.get(ws).and_then(|m| m.ctrl.as_ref()).cloned().unwrap_or_default();
        let meta = self.meta.get(ws);
        let active = self.active.iter().any(|b| b == ws);
        let end = meta.and_then(|m| m.end_ms).map_or("null".into(), |e| e.to_string());

        // Never serialize more than WINDOW_MS of trailing history in one feed, even on a
        // since=0 backfill — bounds the payload, the daemon-lock hold, and the client merge.
        let floor = since.max(now_ms().saturating_sub(WINDOW_MS));
        let ops = s.ops.iter().map(|(k, v)| format!("{k:?}:{v}")).collect::<Vec<_>>().join(",");
        let samples = self
            .samples(ws, floor)
            .iter()
            .map(|b| {
                let o = b.ops.iter().map(|(k, v)| format!("{k:?}:{v}")).collect::<Vec<_>>().join(",");
                format!("{{\"t\":{},\"ops\":{{{o}}},\"readBytes\":{},\"writeBytes\":{}}}", b.t_ms, b.read_bytes, b.write_bytes)
            })
            .collect::<Vec<_>>()
            .join(",");
        let creates = self
            .creates
            .get(ws)
            .map(|v| {
                v.iter()
                    .filter(|c| c.t_ms > floor)
                    .map(|c| format!("{{\"t\":{},\"n\":{},\"laydownUs\":{}}}", c.t_ms, c.n, c.laydown_us))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();

        let mnem = ctrl
            .mnemonics
            .iter()
            .map(|(n, cr, lu, mx)| format!("{{\"name\":{n:?},\"creates\":{cr},\"laydownUs\":{lu},\"maxUs\":{mx}}}"))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                "{{\"workspace\":{:?},\"backend\":{:?},\"active\":{},\"startMs\":{},\"endMs\":{},",
                "\"totals\":{{\"creates\":{},\"files\":{},\"dirs\":{},\"laydownUs\":{},",
                "\"bytesRead\":{},\"bytesWritten\":{},\"procs\":{},\"ops\":{{{}}},",
                "\"diskioBytes\":{},\"dropped\":{},\"unattributedOps\":{},\"mnemonics\":[{}]}},",
                "\"samples\":[{}],\"creates\":[{}]}}"
            ),
            ws,
            ctrl.backend,
            active,
            meta.map_or(0, |m| m.start_ms),
            end,
            ctrl.creates,
            ctrl.files,
            ctrl.dirs,
            ctrl.laydown_us,
            s.bytes_read,
            s.bytes_written,
            s.procs,
            ops,
            s.diskio_bytes,
            s.dropped_events,
            s.unattributed_ops,
            mnem,
            samples,
            creates,
        )
    }
}

fn span_json(ws: &str, s: &BuildSpan) -> String {
    let end = s.end_ms.map_or("null".into(), |e| e.to_string());
    format!(
        concat!(
            "{{\"workspace\":{:?},\"backend\":{:?},\"startMs\":{},\"endMs\":{},",
            "\"creates\":{},\"files\":{},\"bytesRead\":{},\"bytesWritten\":{},\"syscalls\":{}}}"
        ),
        ws, s.backend, s.start_ms, end, s.creates, s.files, s.bytes_read, s.bytes_written, s.syscalls,
    )
}

impl SharedSession {
    fn start() -> std::io::Result<SharedSession> {
        let session = Session::start()?;
        let collector = Arc::new(Mutex::new(Collector::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let drain = spawn_drain(session, collector.clone(), stop.clone());
        Ok(SharedSession { collector, stop, drain })
    }
}

/// Drain kdebug into the shared collector until `stop`, then one final drain. Tight-loops
/// while events keep coming (buffer saturation), sleeps briefly when idle.
fn spawn_drain(mut session: Session, collector: Arc<Mutex<Collector>>, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    let feed = move |events: &[kdebug::KdBuf]| {
        // Feed in chunks, releasing the collector lock between them, so a concurrent feed
        // query (which also takes the collector) waits at most one chunk — bounds the
        // control-plane stall WITHOUT dropping the live lane the way try_lock did.
        for chunk in events.chunks(8192) {
            let mut c = collector.lock().unwrap();
            c.tick(now_ms()); // set the current 100ms bucket, then attribute
            c.feed(chunk);
        }
    };
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            match session.read() {
                Ok(events) if !events.is_empty() => {
                    feed(events);
                    thread::sleep(Duration::from_millis(2)); // yield the collector lock to feed readers
                }
                Ok(_) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if let Ok(events) = session.read() {
            feed(events);
        }
    })
}

/// Entry for `sandboxfs metricsd`: serve the XPC plane (feed + control) forever (root).
pub fn run_daemon() -> ! {
    daemon();
    xpc::serve()
}

/// Dispatch a validated control/query message. `peer_pid` is the calling controller's pid
/// (from the XPC connection), used to attribute its file ops to its workspace.
pub(crate) fn dispatch(method: &str, build_id: &str, clone_prefix: &str, payload: &str, peer_pid: i32) -> Result<Option<String>, String> {
    match method {
        // Read path: tail the feed. `payload` carries the cursor (since_ms; "" => 0).
        "feed" => Ok(Some(daemon().lock().unwrap().feed_json(payload.parse().unwrap_or(0)))),
        "begin" => daemon().lock().unwrap().begin(build_id, clone_prefix, peer_pid).map(|_| None),
        "end" => {
            let reap = daemon().lock().unwrap().end(build_id)?;
            if let Some(s) = reap {
                s.stop.store(true, Ordering::Release);
                let _ = s.drain.join();
            }
            Ok(None)
        }
        "report" => {
            daemon().lock().unwrap().report(build_id, payload);
            Ok(None)
        }
        "clear" => {
            daemon().lock().unwrap().clear();
            Ok(None)
        }
        other => Err(format!("unknown method {other:?}")),
    }
}

/// Client side, used by the `sandboxfs metrics …` subcommands and the controller gate.
pub fn client(method: &str, build_id: &str, clone_prefix: &str, payload: &str) -> Result<Option<String>, String> {
    xpc::call(method, build_id, clone_prefix, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_carries_totals_samples_creates_and_spans() {
        let mut d = Daemon::default();
        let now = now_ms(); // stamp data inside the WINDOW_MS feed horizon
        d.history.entry("/ws".into()).or_default().push(Bucket {
            t_ms: now - 5000,
            ops: [("openat", 3u64), ("read", 7)].into_iter().collect(),
            read_bytes: 4096,
            write_bytes: 0,
        });
        d.meta.entry("/ws".into()).or_default().start_ms = now - 6000;
        // m= line exercises the 4-field parse (name:creates:laydown_us:max_us)
        d.report("/ws", "backend=cfs\ncreates=5\nlaydown_us=2500\nfiles=40\ndirs=6\nm=CppCompile:5:2500:1800\n");
        d.creates.insert("/ws".into(), vec![CreateSample { t_ms: now - 4000, n: 5, laydown_us: 2500 }]);
        d.spans.insert(
            "/ws".into(),
            vec![BuildSpan { start_ms: now - 6000, end_ms: Some(now - 1000), backend: "cfs".into(), base_creates: 0, base_files: 0, creates: 5, files: 40, bytes_read: 4096, bytes_written: 0, syscalls: 10 }],
        );

        let all = d.feed_json(0);
        assert!(all.contains(r#""workspace":"/ws""#), "{all}");
        assert!(all.contains(r#""creates":5"#) && all.contains(r#""files":40"#), "{all}");
        assert!(all.contains(r#""ops":{"openat":3,"read":7},"readBytes":4096"#), "{all}");
        assert!(all.contains(r#""n":5,"laydownUs":2500"#), "{all}");
        assert!(all.contains(r#""mnemonics":[{"name":"CppCompile","creates":5,"laydownUs":2500,"maxUs":1800}]"#), "{all}");
        assert!(all.contains(r#""builds":[{"workspace":"/ws","backend":"cfs""#), "{all}");

        // a future cursor drops the timeline samples but keeps the cumulative totals
        let tail = d.feed_json(now + 10_000);
        assert!(tail.contains(r#""samples":[],"creates":[]"#), "{tail}");
        assert!(tail.contains(r#""creates":5"#), "totals survive the cursor {tail}");
    }

    #[test]
    fn feed_dispatch_returns_json() {
        let now = now_ms();
        {
            let mut d = daemon().lock().unwrap();
            d.history.entry("/ws-d".into()).or_default().push(Bucket {
                t_ms: now - 1000,
                ops: [("openat", 2u64)].into_iter().collect(),
                read_bytes: 0,
                write_bytes: 0,
            });
        }
        let out = dispatch("feed", "", "", "0", 0).unwrap().unwrap();
        assert!(out.contains(r#""workspace":"/ws-d""#), "{out}");
        assert!(out.contains(r#""ops":{"openat":2}"#), "{out}");
    }
}
