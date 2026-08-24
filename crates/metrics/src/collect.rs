// Turns the raw kdebug stream into per-workspace backend metrics with a full
// per-syscall breakdown. kdebug keys by thread/fd, never path, and Bazel runs actions
// with cwd=execroot so most opens are relative — so we identify a *process* as
// belonging to a workspace (it chdir'd into, or opened an absolute path under, that
// workspace's pool prefix) and then attribute ALL its file ops to that workspace. That
// rescues the relative-open reads that would otherwise be "unattributed".
//
// Attribution order for an op: tagged (pid,fd) -> looked-up path under a prefix ->
// the process's sticky workspace -> unattributed. diskio/unattributed are
// machine-level deltas.
//
// Besides cumulative `Stats`, the collector keeps a SPARSE per-workspace time-series
// (`MultiSeries`, 100ms buckets) — the live timeline the client tails. When a window
// ends its lane is drained out (`remove_tenant`) and retained by the daemon, so history
// survives the kdebug session being torn down between builds.

use crate::kdebug::*;
use std::collections::{BTreeMap, HashMap, VecDeque};

#[derive(Default, Clone)]
pub struct Stats {
    pub ops: BTreeMap<&'static str, u64>, // op name -> count (open, read, stat, …)
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub procs: u64, // processes attributed to this workspace
    // machine-level deltas, filled at window end (labeled; may include concurrent builds)
    pub diskio_bytes: u64,
    pub diskio_ops: u64,
    pub dropped_events: u64,
    pub unattributed_ops: u64,
    pub unattributed_bytes: u64,
}

#[derive(Clone, Copy, Default)]
struct Machine {
    diskio_bytes: u64,
    diskio_ops: u64,
    dropped: u64,
    unattr_ops: u64,
    unattr_bytes: u64,
}

struct Tenant {
    build_id: String,
    prefix: Vec<u8>,
    begin: Machine,
}

#[derive(Default)]
pub struct Collector {
    tenants: Vec<Tenant>,
    pid_tenant: HashMap<i32, String>,   // process identified as operating in a workspace
    tid_pid: HashMap<u64, i32>,
    lookup: HashMap<u64, Vec<u8>>,
    last_path: HashMap<u64, String>,
    clone_fds: HashMap<(i32, i32), String>,
    spawning: HashMap<u64, Spawn>, // spawning tid -> in-flight posix_spawn window
    stats: HashMap<String, Stats>,
    series: MultiSeries,
    machine: Machine,
}

// An in-flight posix_spawn observed on a thread: the new child pid (from the NEWTHREAD
// emitted during the call) and the workspace its SETCWD directory lands under (from the
// cwd VFS_LOOKUP during the call). At the spawn's exit, a child with both known is marked
// sticky to that workspace — the fix for Bazel's POSIX_SPAWN_SETCWD (no chdir syscall,
// relative opens) that otherwise leaves an action's reads unattributed.
#[derive(Default)]
struct Spawn {
    child_pid: Option<i32>,
    tenant: Option<String>,
}

// Syscall handling class. Phase: fd ops act at entry (args available); open, path ops
// and chdir act at exit (the lookup has set last_path by then).
enum Kind {
    Read,   // fd in arg1, nbyte in arg3 (entry)
    Write,  // fd in arg1, nbyte in arg3 (entry)
    FdMeta, // fd in arg1 (entry): close/lseek/fsync/getdirentries/getattrlistbulk/…
    Open,   // exit: errno arg1, fd arg2; attribute by path, tag the fd
    Path,   // exit: a pathname op (stat/access/mkdir/unlink/rename/…)
    Chdir,  // exit: marks the process's workspace
    Spawn,  // start/exit: posix_spawn window — used only to root the child by its SETCWD
}

fn classify(eventid: u32) -> Option<(&'static str, Kind)> {
    use Kind::*;
    Some(match eventid {
        BSC_read | BSC_read_nocancel => ("read", Read),
        BSC_pread | BSC_pread_nocancel => ("pread", Read),
        BSC_write | BSC_write_nocancel => ("write", Write),
        BSC_pwrite | BSC_pwrite_nocancel => ("pwrite", Write),
        BSC_close | BSC_close_nocancel => ("close", FdMeta),
        BSC_lseek => ("lseek", FdMeta),
        BSC_fsync => ("fsync", FdMeta),
        BSC_fdatasync => ("fdatasync", FdMeta),
        BSC_getdirentries | BSC_getdirentries64 => ("getdirentries", FdMeta),
        BSC_fgetattrlist => ("fgetattrlist", FdMeta),
        BSC_getattrlistbulk => ("getattrlistbulk", FdMeta),
        BSC_open | BSC_open_nocancel => ("open", Open),
        BSC_openat | BSC_openat_nocancel => ("openat", Open),
        BSC_stat | BSC_stat64 | BSC_stat_extended => ("stat", Path),
        BSC_lstat | BSC_lstat64 => ("lstat", Path),
        BSC_fstatat | BSC_fstatat64 => ("fstatat", Path),
        BSC_access | BSC_faccessat => ("access", Path),
        BSC_getattrlist => ("getattrlist", Path),
        BSC_getattrlistat => ("getattrlistat", Path),
        BSC_readlink | BSC_readlinkat => ("readlink", Path),
        BSC_mkdir | BSC_mkdirat => ("mkdir", Path),
        BSC_rmdir => ("rmdir", Path),
        BSC_unlink | BSC_unlinkat => ("unlink", Path),
        BSC_rename | BSC_renameat | BSC_renameatx_np => ("rename", Path),
        BSC_symlink | BSC_symlinkat => ("symlink", Path),
        BSC_link | BSC_linkat => ("link", Path),
        BSC_chdir => ("chdir", Chdir),
        BSC_posix_spawn => ("posix_spawn", Spawn),
        _ => return None,
    })
}

impl Collector {
    pub fn new() -> Collector {
        Collector::default()
    }

    pub fn add_tenant(&mut self, build_id: &str, prefix: &str, owner_pid: i32) {
        self.tenants.push(Tenant { build_id: build_id.into(), prefix: prefix.as_bytes().to_vec(), begin: self.machine });
        self.pid_tenant.insert(owner_pid, build_id.into());
        self.stats.entry(build_id.into()).or_default();
        self.series.ensure_lane(build_id);
    }

    /// Roll the shared per-bucket timeline clock to wall-clock ms `now`. The drain calls
    /// this once per batch (before `feed`) so bucketing costs no per-op locking.
    pub fn tick(&mut self, now_ms: u64) {
        self.series.advance(now_ms);
    }

    /// Clone an active workspace's in-progress series lane (buckets with t_ms > since).
    pub fn series_lane(&self, build_id: &str, since: u64) -> Vec<Bucket> {
        self.series.lane(build_id, since)
    }

    /// Remove and return a lane's buckets (e.g. the `""` unattributed lane at last close).
    pub fn take_lane(&mut self, build_id: &str) -> Vec<Bucket> {
        self.series.take_lane(build_id)
    }

    pub fn tenant_stats(&self, build_id: &str) -> Stats {
        let begin = self.tenants.iter().find(|t| t.build_id == build_id).map(|t| t.begin).unwrap_or(self.machine);
        let mut s = self.stats.get(build_id).cloned().unwrap_or_default();
        s.procs = self.pid_tenant.values().filter(|b| b.as_str() == build_id).count() as u64;
        s.diskio_bytes = self.machine.diskio_bytes - begin.diskio_bytes;
        s.diskio_ops = self.machine.diskio_ops - begin.diskio_ops;
        s.dropped_events = self.machine.dropped - begin.dropped;
        s.unattributed_ops = self.machine.unattr_ops - begin.unattr_ops;
        s.unattributed_bytes = self.machine.unattr_bytes - begin.unattr_bytes;
        s
    }

    /// Close a window: return its cumulative stats AND drain its series lane so the daemon
    /// can retain the timeline after the kdebug session is gone.
    pub fn remove_tenant(&mut self, build_id: &str) -> (Stats, Vec<Bucket>) {
        let s = self.tenant_stats(build_id);
        let lane = self.series.take_lane(build_id);
        self.tenants.retain(|t| t.build_id != build_id);
        self.stats.remove(build_id);
        self.clone_fds.retain(|_, b| b != build_id);
        self.pid_tenant.retain(|_, b| b != build_id);
        (s, lane)
    }

    pub fn feed(&mut self, events: &[KdBuf]) {
        for e in events {
            self.one(e);
        }
    }

    fn one(&mut self, e: &KdBuf) {
        let id = e.eventid();
        let tid = e.tid();
        match id {
            VFS_LOOKUP => return self.lookup_event(e),
            TRACE_DATA_NEWTHREAD => {
                let (new_tid, new_pid, emitter) = (e.arg1, e.arg2 as i32, tid);
                self.tid_pid.insert(new_tid, new_pid);
                // tie this new child to the emitter's in-flight posix_spawn (if any)
                if let Some(sp) = self.spawning.get_mut(&emitter) {
                    sp.child_pid = Some(new_pid);
                }
                // lineage: a forked/spawned process inherits its creator's workspace, so
                // an action's child tools (cc1, ld, …) attribute even without their own
                // SETCWD or absolute open under the prefix.
                if let Some(parent_pid) = self.tid_pid.get(&emitter).copied() {
                    if let Some(w) = self.pid_tenant.get(&parent_pid).cloned() {
                        self.pid_tenant.entry(new_pid).or_insert(w);
                    }
                }
                return;
            }
            TRACE_DATA_THREAD_TERMINATE => {
                self.tid_pid.remove(&e.arg1);
                return;
            }
            TRACE_LOST_EVENTS => {
                self.machine.dropped += 1;
                return;
            }
            _ => {}
        }
        let Some((name, kind)) = classify(id) else {
            if is_diskio_issue(id) {
                self.machine.diskio_ops += 1;
                self.machine.diskio_bytes += e.arg4;
            }
            return;
        };
        let f = e.func();
        match kind {
            Kind::Read if f == FUNC_START => self.record(tid, Some(e.arg1 as i32), false, name, e.arg3, 0),
            Kind::Write if f == FUNC_START => self.record(tid, Some(e.arg1 as i32), false, name, 0, e.arg3),
            Kind::FdMeta if f == FUNC_START => {
                let fd = e.arg1 as i32;
                self.record(tid, Some(fd), false, name, 0, 0);
                if name == "close" {
                    if let Some(pid) = self.tid_pid.get(&tid) {
                        self.clone_fds.remove(&(*pid, fd));
                    }
                }
            }
            Kind::Open if f == FUNC_END => self.open_done(tid, name, e.arg1 as i64, e.arg2 as i64),
            Kind::Path if f == FUNC_END => self.record(tid, None, true, name, 0, 0),
            Kind::Chdir if f == FUNC_END => {
                if e.arg1 == 0 {
                    // success: if the target is under a prefix, this process is now in
                    // that workspace's sandbox.
                    if let (Some(pid), Some(t)) = (self.tid_pid.get(&tid).copied(), self.path_tenant(tid)) {
                        self.pid_tenant.insert(pid, t.clone());
                    }
                }
                self.record(tid, None, true, name, 0, 0);
            }
            Kind::Spawn if f == FUNC_START => {
                self.spawning.insert(tid, Spawn::default());
            }
            Kind::Spawn if f == FUNC_END => {
                if let Some(Spawn { child_pid: Some(child), tenant: Some(w) }) = self.spawning.remove(&tid) {
                    // the spawned process ran with cwd under `w`'s prefix → its relative
                    // opens belong to that workspace.
                    self.pid_tenant.insert(child, w);
                }
            }
            _ => {}
        }
    }

    /// Resolve and record an op against the owning workspace, or count it unattributed.
    /// Every op lands in exactly one series lane (`""` = unattributed) at the current bucket.
    fn record(&mut self, tid: u64, fd: Option<i32>, path_based: bool, name: &'static str, rbytes: u64, wbytes: u64) {
        match self.tenant(tid, fd, path_based) {
            Some(b) => {
                self.series.bump(&b, name, rbytes, wbytes);
                let s = self.stats.entry(b).or_default();
                *s.ops.entry(name).or_insert(0) += 1;
                s.bytes_read += rbytes;
                s.bytes_written += wbytes;
            }
            None => {
                self.series.bump("", name, rbytes, wbytes);
                self.machine.unattr_ops += 1;
                self.machine.unattr_bytes += rbytes + wbytes;
            }
        }
    }

    fn open_done(&mut self, tid: u64, name: &'static str, errno: i64, fd: i64) {
        if errno != 0 || fd < 0 {
            return;
        }
        let Some(b) = self.tenant(tid, None, true) else {
            self.series.bump("", name, 0, 0);
            self.machine.unattr_ops += 1;
            return;
        };
        self.series.bump(&b, name, 0, 0);
        *self.stats.entry(b.clone()).or_default().ops.entry(name).or_insert(0) += 1;
        if let Some(pid) = self.tid_pid.get(&tid).copied() {
            self.clone_fds.insert((pid, fd as i32), b);
        }
    }

    /// Pick the workspace for an op: fd tag, then looked-up path under a prefix (which
    /// also marks the process sticky), then the process's sticky workspace.
    fn tenant(&mut self, tid: u64, fd: Option<i32>, path_based: bool) -> Option<String> {
        let pid = *self.tid_pid.get(&tid)?;
        if let Some(fd) = fd {
            if let Some(b) = self.clone_fds.get(&(pid, fd)) {
                return Some(b.clone());
            }
        }
        if path_based {
            if let Some(b) = self.path_tenant(tid) {
                self.pid_tenant.insert(pid, b.clone());
                return Some(b);
            }
        }
        self.pid_tenant.get(&pid).cloned()
    }

    /// The workspace whose prefix contains this thread's last looked-up path, if any.
    fn path_tenant(&self, tid: u64) -> Option<String> {
        let p = self.last_path.get(&tid)?;
        self.tenants.iter().find(|t| p.as_bytes().starts_with(&t.prefix)).map(|t| t.build_id.clone())
    }

    fn lookup_event(&mut self, e: &KdBuf) {
        let f = e.func();
        let (is_start, is_end) = (f & FUNC_START != 0, f & FUNC_END != 0);
        let buf = self.lookup.entry(e.tid()).or_default();
        if is_start {
            buf.clear();
            push_le(buf, &[e.arg2, e.arg3, e.arg4]);
        } else {
            push_le(buf, &[e.arg1, e.arg2, e.arg3, e.arg4]);
        }
        if is_end {
            let raw = self.lookup.remove(&e.tid()).unwrap_or_default();
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let path = String::from_utf8_lossy(&raw[..end]).into_owned();
            // during a posix_spawn, the SETCWD directory is looked up on the spawning
            // thread; if it's under a workspace prefix, the child belongs there. (The
            // spawn-cwd lookup can arrive without a leading slash, so match loosely.)
            if self.spawning.contains_key(&e.tid()) {
                if let Some(w) = self.tenants.iter().find(|t| under_prefix(&path, &t.prefix)).map(|t| t.build_id.clone()) {
                    if let Some(sp) = self.spawning.get_mut(&e.tid()) {
                        sp.tenant.get_or_insert(w);
                    }
                }
            }
            self.last_path.insert(e.tid(), path);
        }
    }
}

/// Prefix containment tolerant of a missing leading slash (the spawn-cwd VFS_LOOKUP can
/// drop it) — both sides are compared with leading slashes trimmed.
fn under_prefix(path: &str, prefix: &[u8]) -> bool {
    let p = path.as_bytes();
    let p = p.strip_prefix(b"/").unwrap_or(p);
    let pre = prefix.strip_prefix(b"/").unwrap_or(prefix);
    !pre.is_empty() && p.starts_with(pre)
}

fn push_le(buf: &mut Vec<u8>, words: &[u64]) {
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

impl Stats {
    pub fn add(&mut self, o: &Stats) {
        for (k, v) in &o.ops {
            *self.ops.entry(k).or_insert(0) += v;
        }
        self.bytes_read += o.bytes_read;
        self.bytes_written += o.bytes_written;
        self.procs += o.procs;
        self.diskio_bytes += o.diskio_bytes;
        self.diskio_ops += o.diskio_ops;
        self.dropped_events += o.dropped_events;
        self.unattributed_ops += o.unattributed_ops;
        self.unattributed_bytes += o.unattributed_bytes;
    }
}

// One SPARSE 100ms bucket of a workspace's syscall activity. RAW per-syscall counts (the
// client groups/rates as it likes) + read/write throughput. Public so the daemon can
// retain drained lanes and serialize the feed.
pub const BUCKET_MS: u64 = 100; // 10 Hz time resolution

#[derive(Clone, Default)]
pub struct Bucket {
    pub t_ms: u64, // bucket start, epoch ms (multiple of BUCKET_MS)
    pub ops: BTreeMap<&'static str, u64>,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

const SERIES_CAP: usize = 3000; // live buckets retained per lane before drain (~5min active)

#[derive(Default)]
struct MultiSeries {
    now_ms: u64,
    lanes: BTreeMap<String, VecDeque<Bucket>>,
}

impl MultiSeries {
    fn ensure_lane(&mut self, ws: &str) {
        self.lanes.entry(ws.to_string()).or_default();
    }

    fn advance(&mut self, now_ms: u64) {
        if now_ms != 0 {
            self.now_ms = now_ms - (now_ms % BUCKET_MS);
        }
    }

    fn bump(&mut self, ws: &str, name: &'static str, rbytes: u64, wbytes: u64) {
        let t = self.now_ms;
        let ring = self.lanes.entry(ws.to_string()).or_default();
        if ring.back().map_or(true, |b| b.t_ms != t) {
            ring.push_back(Bucket { t_ms: t, ..Default::default() });
            while ring.len() > SERIES_CAP {
                ring.pop_front();
            }
        }
        let b = ring.back_mut().unwrap();
        *b.ops.entry(name).or_insert(0) += 1;
        b.read_bytes += rbytes;
        b.write_bytes += wbytes;
    }

    /// Buckets of a live lane with t_ms > since (cloned).
    fn lane(&self, ws: &str, since: u64) -> Vec<Bucket> {
        self.lanes.get(ws).map_or_else(Vec::new, |r| r.iter().filter(|b| b.t_ms > since).cloned().collect())
    }

    /// Remove a lane and hand back all its buckets (window end → daemon retention).
    fn take_lane(&mut self, ws: &str) -> Vec<Bucket> {
        self.lanes.remove(ws).map_or_else(Vec::new, |r| r.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(eventid: u32, func: u32, tid: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> KdBuf {
        KdBuf { timestamp: 0, arg1: a1, arg2: a2, arg3: a3, arg4: a4, arg5: tid, debugid: eventid | func, cpuid: 0, unused: 0 }
    }
    fn lookup(tid: u64, path: &str) -> Vec<KdBuf> {
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        while bytes.len() % 8 != 0 {
            bytes.push(0);
        }
        let words: Vec<u64> = bytes.chunks(8).map(|c| { let mut b = [0u8; 8]; b[..c.len()].copy_from_slice(c); u64::from_le_bytes(b) }).collect();
        let mut out = vec![ev(VFS_LOOKUP, FUNC_START, tid, 0xdead, *words.first().unwrap_or(&0), *words.get(1).unwrap_or(&0), *words.get(2).unwrap_or(&0))];
        let mut i = 3;
        while i < words.len() {
            let last = i + 4 >= words.len();
            out.push(ev(VFS_LOOKUP, if last { FUNC_END } else { 0 }, tid, *words.get(i).unwrap_or(&0), *words.get(i + 1).unwrap_or(&0), *words.get(i + 2).unwrap_or(&0), *words.get(i + 3).unwrap_or(&0)));
            i += 4;
        }
        if words.len() <= 3 {
            out[0].debugid = VFS_LOOKUP | FUNC_START | FUNC_END;
        }
        out
    }

    #[test]
    fn relative_reads_attributed_via_sticky_process() {
        let mut c = Collector::new();
        c.add_tenant("/ws", "/pool/", 1);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 9, 9, 4242, 0, 0)]); // tid9 -> pid 4242
        c.feed(&lookup(9, "/pool/slot/root"));
        c.feed(&[ev(BSC_chdir, FUNC_END, 9, 0, 0, 0, 0)]);
        c.feed(&lookup(9, "src/main.c"));
        c.feed(&[ev(BSC_openat, FUNC_END, 9, 0, 7, 0, 0)]);
        c.feed(&[ev(BSC_read, FUNC_START, 9, 7, 0, 4096, 0)]);
        c.feed(&[ev(BSC_stat, FUNC_END, 9, 0, 0, 0, 0)]);
        let (s, _) = c.remove_tenant("/ws");
        assert_eq!(s.ops.get("openat"), Some(&1));
        assert_eq!(s.ops.get("read"), Some(&1), "relative read attributed via sticky pid");
        assert_eq!(s.ops.get("stat"), Some(&1));
        assert_eq!(s.bytes_read, 4096);
        assert_eq!(s.unattributed_ops, 0);
    }

    #[test]
    fn series_splits_lanes_and_drains_on_remove() {
        let mut c = Collector::new();
        c.add_tenant("/ws", "/pool/", 1);
        c.tick(100); // open the timeline at bucket 100ms
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 9, 9, 4242, 0, 0)]);
        c.feed(&lookup(9, "/pool/x"));
        c.feed(&[ev(BSC_openat, FUNC_END, 9, 0, 7, 0, 0)]); // open under prefix -> sticky
        c.feed(&[ev(BSC_read, FUNC_START, 9, 7, 0, 4096, 0)]);
        // unrelated process -> unattributed lane
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 8, 8, 5, 0, 0)]);
        c.feed(&[ev(BSC_read, FUNC_START, 8, 3, 0, 8192, 0)]);

        let unattr = c.series_lane("", 0);
        assert_eq!(unattr.len(), 1);
        assert_eq!(unattr[0].read_bytes, 8192);

        let (_, lane) = c.remove_tenant("/ws");
        assert_eq!(lane.len(), 1, "the /ws lane drains out on window end");
        assert_eq!(lane[0].t_ms, 100);
        assert_eq!(lane[0].ops.get("openat"), Some(&1));
        assert_eq!(lane[0].ops.get("read"), Some(&1));
        assert_eq!(lane[0].read_bytes, 4096);
        assert!(c.series_lane("/ws", 0).is_empty(), "drained lane is gone from the collector");
    }

    #[test]
    fn series_since_cursor_filters_old_buckets() {
        let mut c = Collector::new();
        c.add_tenant("/ws", "/pool/", 1);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 1, 1, 4242, 0, 0)]);
        c.feed(&lookup(1, "/pool/x"));
        c.feed(&[ev(BSC_openat, FUNC_END, 1, 0, 7, 0, 0)]); // open under prefix -> sticky pid
        c.tick(1000);
        c.feed(&[ev(BSC_read, FUNC_START, 1, 7, 0, 4096, 0)]);
        c.tick(1150); // -> bucket 1100ms
        c.feed(&[ev(BSC_read, FUNC_START, 1, 7, 0, 4096, 0)]);
        assert_eq!(c.series_lane("/ws", 0).len(), 2);
        let tail = c.series_lane("/ws", 1000); // strictly after 1000
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].t_ms, 1100);
    }

    #[test]
    fn spawn_setcwd_roots_child_and_lineage_covers_descendants() {
        let mut c = Collector::new();
        c.add_tenant("/ws", "/pool/", 1);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 10, 10, 500, 0, 0)]); // tid10 -> pid500 (parent)
        c.feed(&[ev(BSC_posix_spawn, FUNC_START, 10, 0, 0, 0, 0)]);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 10, 20, 200, 0, 0)]); // emitter tid10: child tid20 pid200
        c.feed(&lookup(10, "/pool/slot/execroot"));
        c.feed(&[ev(BSC_posix_spawn, FUNC_END, 10, 0, 0, 0, 0)]);
        c.feed(&lookup(20, "src/main.c"));
        c.feed(&[ev(BSC_openat, FUNC_END, 20, 0, 7, 0, 0)]);
        c.feed(&[ev(BSC_read, FUNC_START, 20, 7, 0, 4096, 0)]);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 20, 30, 300, 0, 0)]); // emitter tid20 (pid200 sticky)
        c.feed(&[ev(BSC_read, FUNC_START, 30, 3, 0, 8192, 0)]);

        let (s, _) = c.remove_tenant("/ws");
        assert_eq!(s.ops.get("openat"), Some(&1));
        assert_eq!(s.ops.get("read"), Some(&2), "child + grandchild relative reads attributed");
        assert_eq!(s.bytes_read, 4096 + 8192);
        assert_eq!(s.unattributed_ops, 0);
    }

    #[test]
    fn unrelated_process_is_unattributed() {
        let mut c = Collector::new();
        c.add_tenant("/ws", "/pool/", 1);
        c.feed(&[ev(TRACE_DATA_NEWTHREAD, 0, 9, 9, 5, 0, 0)]);
        c.feed(&[ev(BSC_read, FUNC_START, 9, 3, 0, 8192, 0)]); // never touched the prefix
        let (s, _) = c.remove_tenant("/ws");
        assert_eq!(s.ops.get("read"), None);
        assert_eq!(s.unattributed_ops, 1);
    }
}
