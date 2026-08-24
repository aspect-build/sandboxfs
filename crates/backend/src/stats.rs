// Daemon-level instrumentation: in-flight and live sandbox counts (the backends' reapers consult
// them so background work only runs while the daemon is idle) and per-request latency. Anything
// specific to how a backend lays a tree down lives in that backend's own crate. Relaxed adds only.


use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

pub static INFLIGHT: AtomicU64 = AtomicU64::new(0);

/// Live sandboxes: successful creates minus destroys. Stays positive for a whole
/// `bazel build` even across long request-silent gaps (an action's sandbox is live
/// from Create until Destroy while it runs), unlike INFLIGHT which falls to 0 between
/// request bursts. The metrics gate uses live>0 as "build running" and live==0 held
/// quiet as "build done" — the only signal available, since Bazel sends no boundaries
/// and keeps the controller alive across builds.
pub static LIVE: AtomicI64 = AtomicI64::new(0);

pub fn bump(c: &AtomicU64) {
    c.fetch_add(1, Relaxed);
}

/// Per-request-kind latency, server-side. `wait` is push→pop (queue/backpressure), `handle` is the
/// morph/collect/destroy itself, `write` is framing + the output-lock + pipe write. Their sum is the
/// daemon's whole view of the request; Bazel's profile span minus this sum is the wire trip.
pub struct Timing {
    pub count: AtomicU64,
    pub wait_ns: AtomicU64,
    pub handle_ns: AtomicU64,
    pub write_ns: AtomicU64,
    pub handle_max_ns: AtomicU64,
}
impl Timing {
    const fn new() -> Self {
        Timing {
            count: AtomicU64::new(0),
            wait_ns: AtomicU64::new(0),
            handle_ns: AtomicU64::new(0),
            write_ns: AtomicU64::new(0),
            handle_max_ns: AtomicU64::new(0),
        }
    }
    pub fn record(&self, wait_ns: u64, handle_ns: u64, write_ns: u64) {
        self.count.fetch_add(1, Relaxed);
        self.wait_ns.fetch_add(wait_ns, Relaxed);
        self.handle_ns.fetch_add(handle_ns, Relaxed);
        self.write_ns.fetch_add(write_ns, Relaxed);
        self.handle_max_ns.fetch_max(handle_ns, Relaxed);
    }
    fn line(&self, name: &str) -> String {
        let n = self.count.load(Relaxed).max(1);
        let us = |sum: &AtomicU64| sum.load(Relaxed) as f64 / 1000.0; // ns sum -> us
        format!(
            "{name}: n={} wait_total={:.1}ms handle_total={:.1}ms write_total={:.1}ms | avg wait={:.0}us handle={:.0}us write={:.0}us | handle_max={:.0}us\n",
            self.count.load(Relaxed),
            us(&self.wait_ns) / 1000.0,
            us(&self.handle_ns) / 1000.0,
            us(&self.write_ns) / 1000.0,
            us(&self.wait_ns) / n as f64,
            us(&self.handle_ns) / n as f64,
            us(&self.write_ns) / n as f64,
            self.handle_max_ns.load(Relaxed) as f64 / 1000.0,
        )
    }
}

pub static CREATE_T: Timing = Timing::new();
pub static COLLECT_T: Timing = Timing::new();
pub static DESTROY_T: Timing = Timing::new();

/// Sandbox creates grouped by Bazel action mnemonic: name -> (creates, laydown_ns sum,
/// laydown_ns max, laydown_ns min). The max surfaces the slow outlier the average hides; the
/// min shows the mnemonic's best case (a Merkle-skip or farm rename). Few distinct mnemonics
/// and one insert per create, so a Mutex<BTreeMap> is ample.
pub static MNEMONICS: Mutex<BTreeMap<String, (u64, u64, u64, u64)>> = Mutex::new(BTreeMap::new());

/// Record a finished sandbox create against its mnemonic (laydown = the create's
/// server-side handle time). `mnemonic` empty -> bucketed under "unknown".
pub fn record_create(mnemonic: &str, laydown_ns: u64) {
    let key = if mnemonic.is_empty() { "unknown" } else { mnemonic };
    let mut m = MNEMONICS.lock().unwrap();
    let e = m.entry(key.to_string()).or_insert((0, 0, 0, u64::MAX));
    e.0 += 1;
    e.1 += laydown_ns;
    e.2 = e.2.max(laydown_ns);
    e.3 = e.3.min(laydown_ns);
}

/// The three per-request timing lines, assembled. Backends append this to their own idle-edge dump.
pub fn timing_report() -> String {
    format!("{}{}{}", CREATE_T.line("create"), COLLECT_T.line("collect"), DESTROY_T.line("destroy"))
}

/// The generic half of the metrics report the daemon parses: create volume and the per-mnemonic
/// table. A backend adds its own lines by overriding `Backend::report_text`.
pub fn report_text(backend: &str) -> String {
    let mut s = format!(
        "backend={backend}\ncreates={}\nlaydown_us={}\n",
        CREATE_T.count.load(Relaxed),
        CREATE_T.handle_ns.load(Relaxed) / 1000,
    );
    // Snapshot under the lock, format outside it — workers' record_create never waits on
    // this gate-thread formatting. The m= wire keeps its 3-field shape (the dashboard's
    // parser is strict); min rides only in the backends' local dump tables.
    let snapshot: Vec<(String, (u64, u64, u64, u64))> =
        MNEMONICS.lock().unwrap().iter().map(|(k, v)| (k.clone(), *v)).collect();
    for (name, (creates, laydown_ns, max_ns, _)) in &snapshot {
        s.push_str(&format!("m={name}:{creates}:{}:{}\n", laydown_ns / 1000, max_ns / 1000));
    }
    s
}
