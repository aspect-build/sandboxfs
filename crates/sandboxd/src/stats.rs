// The daemon's own view of the work it dispatches: how many sandboxes are in flight and live, and
// what each request cost. A backend's own counters -- how many files it cloned, which placement
// path it took -- are its business and live in its crate. Relaxed adds only.


use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

pub static INFLIGHT: AtomicU64 = AtomicU64::new(0);

/// Creates minus destroys. Unlike INFLIGHT this stays positive across the request-silent gaps
/// while actions run, which is what lets the metrics gate infer build boundaries -- Bazel sends
/// none, and keeps the controller alive across builds.
pub static LIVE: AtomicI64 = AtomicI64::new(0);

/// Server-side latency: `wait` is queue time, `handle` the work itself, `write` framing and the
/// pipe. Bazel's profile span minus their sum is the wire trip.
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
}

pub static CREATE_T: Timing = Timing::new();
pub static COLLECT_T: Timing = Timing::new();
pub static DESTROY_T: Timing = Timing::new();

/// Creates by mnemonic: name -> (creates, sum, max, min). Max surfaces the outlier the average
/// hides, min the best case. Few mnemonics and one insert per create, so a Mutex is ample.
pub static MNEMONICS: Mutex<BTreeMap<String, (u64, u64, u64, u64)>> = Mutex::new(BTreeMap::new());

/// Record a finished create against its mnemonic; empty buckets under "unknown".
pub fn record_create(mnemonic: &str, laydown_ns: u64) {
    let key = if mnemonic.is_empty() { "unknown" } else { mnemonic };
    let mut m = MNEMONICS.lock().unwrap();
    let e = m.entry(key.to_string()).or_insert((0, 0, 0, u64::MAX));
    e.0 += 1;
    e.1 += laydown_ns;
    e.2 = e.2.max(laydown_ns);
    e.3 = e.3.min(laydown_ns);
}

/// The report the metrics daemon parses. Every line comes from counters here, so a backend
/// contributes by bumping them rather than by implementing anything.
pub fn report_text(backend: &str) -> String {
    let mut s = format!(
        "backend={backend}\ncreates={}\nlaydown_us={}\n",
        CREATE_T.count.load(Relaxed),
        CREATE_T.handle_ns.load(Relaxed) / 1000,
    );
    // Snapshot under the lock, format outside it, so a worker's record_create never waits on this.
    let snapshot: Vec<(String, (u64, u64, u64, u64))> =
        MNEMONICS.lock().unwrap().iter().map(|(k, v)| (k.clone(), *v)).collect();
    for (name, (creates, laydown_ns, max_ns, _)) in &snapshot {
        s.push_str(&format!("m={name}:{creates}:{}:{}\n", laydown_ns / 1000, max_ns / 1000));
    }
    s
}
