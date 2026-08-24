use backend::proto::{self, ContentSource, CreateReply, NegotiateReply, Reply, Request, Response, Status};
use backend::{stats, Backend, BlobStore, CreateOutcome};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;

/// Opens a projection backend rooted at a pool dir, for a workspace.
pub type Open = fn(&std::path::Path, &str) -> io::Result<Arc<dyn Backend>>;

/// The default backend ships in its own crate, which this one deliberately does not depend on --
/// a build here must never need to reach the private repo it lives in. The binary that links it
/// registers it before `run`; a build without it answers `--backend cfs` with a plain error.
static CFS: OnceLock<Open> = OnceLock::new();

pub fn register_cfs(open: Open) {
    let _ = CFS.set(open);
}

pub fn run() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("debugmanifest") => {
            let path = args.next().expect("usage: debugmanifest <manifest.pb>");
            let m = proto::decode_manifest(&std::fs::read(&path).unwrap()).expect("decode");
            fn walk(d: &proto::Dir, path: &str, n: &mut usize, s: &mut Vec<String>) {
                if !d.host_path.is_empty() {
                    *n += 1;
                    if s.len() < 8 {
                        s.push(format!("{path} -> {}", d.host_path));
                    }
                }
                for sub in &d.directories {
                    let p = if path.is_empty() { sub.name.clone() } else { format!("{path}/{}", sub.name) };
                    walk(sub, &p, n, s);
                }
            }
            let (mut n, mut s) = (0usize, Vec::new());
            if let Some(r) = &m.root {
                walk(r, "", &mut n, &mut s);
            }
            eprintln!("dirs with host_path: {n}");
            for x in &s {
                eprintln!("  {x}");
            }
        }
        // Dev helper: build a manifest.pb from a real directory tree, for manually
        // mounting the appex (`mount -F -t sandboxfs -o nobrowse <out.pb> <mnt>`).
        Some("mkmanifest") => {
            let src = args.next().expect("usage: mkmanifest <src_dir> <out.pb>");
            let out = args.next().expect("usage: mkmanifest <src_dir> <out.pb>");
            let m = proto::Manifest {
                mnemonic: Some("manual-test".into()),
                root: Some(build_dir_from_fs(std::path::Path::new(&src))),
                ..Default::default()
            };
            std::fs::write(&out, proto::encode(&m)).expect("write manifest");
            eprintln!("wrote {out}");
        }
        Some("serve") => {
            let rest: Vec<String> = args.collect();
            let workspace = flag(&rest, "--workspace")
                .or_else(|| std::env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()))
                .unwrap_or_else(|| ".".into());
            serve(&workspace, flag(&rest, "--backend").as_deref());
        }
        // The metrics daemon (root LaunchDaemon) and its client. The daemon owns
        // kdebug only between begin/end, so it is otherwise inert.
        Some("metricsd") => metrics::run_daemon(),
        Some("metrics") => {
            let method = args.next().unwrap_or_default();
            let build_id = args.next().unwrap_or_default();
            // Optional explicit prefix (for `begin`, mainly manual testing); the real
            // controller always supplies the backend's prefix via the gate.
            let prefix = args.next();
            let needs_id = matches!(method.as_str(), "begin" | "end");
            if !(needs_id || matches!(method.as_str(), "feed" | "clear")) || (needs_id && build_id.is_empty()) {
                eprintln!("usage: sandboxfs metrics <begin|end> <build_id> [prefix]");
                eprintln!("       sandboxfs metrics feed [since_ms]   (dump the JSON feed)");
                eprintln!("       sandboxfs metrics clear             (drop retained history)");
                std::process::exit(2);
            }
            // `feed` takes an optional since cursor in the build_id slot (manual debug).
            let payload = if method == "feed" { build_id.clone() } else { String::new() };
            let prefix = prefix.unwrap_or_else(|| backend::pool::pool_root().to_string_lossy().into_owned());
            match metrics::client(&method, &build_id, &prefix, &payload) {
                Ok(Some(json)) => println!("{json}"),
                Ok(None) => {}
                Err(e) => {
                    eprintln!("sandboxfs metrics: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: sandboxfs serve [--workspace <path>] [--backend cfs|lazyfs]");
            eprintln!("       sandboxfs metrics <begin|end> <build_id>   (read: sandboxfs metrics feed)");
            eprintln!("       backend also settable via env sandboxfs_backend (Bazel: --client_env=sandboxfs_backend=cfs)");
            std::process::exit(2);
        }
    }
}

/// Walk a real directory into a manifest tree, each file backed by its absolute
/// host path (dev helper for manual appex mounts).
fn build_dir_from_fs(dir: &std::path::Path) -> proto::Dir {
    let mut d = proto::Dir::default();
    let mut entries: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        match e.file_type() {
            Ok(ft) if ft.is_dir() => {
                let mut sub = build_dir_from_fs(&path);
                sub.name = name;
                d.directories.push(sub);
            }
            Ok(ft) if ft.is_symlink() => {
                let target = std::fs::read_link(&path).unwrap_or_default().to_string_lossy().into_owned();
                d.symlinks.push(proto::Symlink { name, target });
            }
            _ => {
                let body = std::fs::read(&path).unwrap_or_default();
                d.files.push(proto::File {
                    digest: proto::sha256_hex(&body),
                    host_path: path.to_string_lossy().into_owned(),
                    size: body.len() as u64,
                    name,
                    executable: false,
                });
            }
        }
    }
    d
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

enum Kind {
    Cfs,
    Lazy,
}

/// Resolve a backend name to a kind. `--backend` flag wins, else the env knob, else
/// the default (cfs). Case-insensitive.
fn resolve(flag: Option<&str>, env: Option<&str>) -> io::Result<Kind> {
    match flag.or(env).map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("cfs") => Ok(Kind::Cfs),
        Some("lazyfs") => Ok(Kind::Lazy),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown backend {other:?} (expected: cfs|lazyfs)"),
        )),
    }
}

/// Build the projection backend. The env knob is what Bazel sets via
/// `--client_env=sandboxfs_backend=…`. The backend label is folded into the pool key
/// (see `workspace_key`) so the same workspace built under two backends never shares
/// a subtree — their on-disk slot layouts are incompatible. `options` (from the Negotiate
/// handshake) may carry `--pool-root=<path>`: required when the default pool root (`$HOME` or
/// `SANDBOXFS_POOL`) isn't on the same volume as `workspace` — projection and rename are
/// same-device-only, so there's no safe default to guess; `check_same_device` fails fast with
/// the fix instead of letting it surface later as a cryptic EXDEV.
fn select(flag: Option<&str>, workspace: &str, options: &[String]) -> io::Result<Arc<dyn Backend>> {
    let explicit = options.iter().find_map(|o| o.strip_prefix("--pool-root="));
    let root = backend::pool::resolve_pool_root(explicit);
    backend::pool::check_same_device(&root, std::path::Path::new(workspace))?;
    let env = std::env::var("sandboxfs_backend").or_else(|_| std::env::var("SANDBOXFS_BACKEND")).ok();
    match resolve(flag, env.as_deref())? {
        Kind::Cfs => match CFS.get() {
            Some(open) => open(&root, workspace),
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this build carries no cfs backend; build the cfs-bin shim, or use --backend lazyfs",
            )),
        },
        Kind::Lazy => Ok(Arc::new(fskit_fs::Fskit::open(&root, "lazyfs", workspace)?)),
    }
}

/// Spawns the worker pool that drains `queue` and writes framed replies (rid echoed, so
/// out-of-order is fine). One worker per core is optimal: measured oversubscription (3x) added
/// concurrent-morph contention and was slightly slower, so creates aren't queue-bound.
/// CFS_WORKERS overrides for tuning.
fn spawn_workers(backend: Arc<dyn Backend>, queue: Arc<Queue>, out: Arc<Mutex<io::Stdout>>, store: Arc<BlobStore>) -> Vec<thread::JoinHandle<()>> {
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let n = std::env::var("CFS_WORKERS").ok().and_then(|s| s.parse().ok()).unwrap_or(cores);
    (0..n)
        .map(|_| {
            let (backend, queue, out, store) = (backend.clone(), queue.clone(), out.clone(), store.clone());
            thread::spawn(move || {
                while let Some((req, queued_at)) = queue.pop() {
                    let wait = queued_at.elapsed();
                    let (timing, kind) = match &req {
                        Request::Create { .. } => (&stats::CREATE_T, 1u8),
                        Request::Collect { .. } => (&stats::COLLECT_T, 0u8),
                        Request::Destroy { .. } => (&stats::DESTROY_T, 2u8),
                        Request::Negotiate { .. } => unreachable!("negotiate is answered inline in serve(), before queueing"),
                        Request::Push { .. } => unreachable!("push is applied inline in serve(), never queued"),
                    };
                    // The action mnemonic rides on the Create manifest (field 16); peek just
                    // that field (no tree, no maps) so grouping stays off the create hot path.
                    let mnemonic = match &req {
                        Request::Create { manifest_bytes, .. } => proto::peek_mnemonic(manifest_bytes),
                        _ => None,
                    };
                    stats::INFLIGHT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let t0 = std::time::Instant::now();
                    let resp = handle(backend.as_ref(), req, &store);
                    let handle = t0.elapsed();
                    stats::INFLIGHT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    // Track live sandboxes for build-window detection: a successful
                    // create adds one, a destroy removes one.
                    match kind {
                        1 if matches!(resp.reply, Reply::Create(CreateReply::Ok { .. })) => {
                            stats::LIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            stats::record_create(mnemonic.as_deref().unwrap_or(""), handle.as_nanos() as u64);
                        }
                        2 => {
                            stats::LIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    let frame = frame(&proto::encode_response(&resp));
                    let t1 = std::time::Instant::now();
                    let mut o = out.lock().unwrap();
                    let werr = o.write_all(&frame).is_err() || o.flush().is_err();
                    drop(o);
                    timing.record(wait.as_nanos() as u64, handle.as_nanos() as u64, t1.elapsed().as_nanos() as u64);
                    if werr {
                        break;
                    }
                }
            })
        })
        .collect()
}

/// The controller, spawned by Bazel. Speaks varint length-delimited proto on
/// stdin/stdout. A reader thread (this one) frames requests onto a queue; a pool
/// of workers projects sandboxes concurrently and writes framed replies.
///
/// The backend itself isn't built until the Negotiate handshake arrives: that's the only place
/// backend_arg options (`--metrics`, `--pool-root=<path>`) show up, and Bazel always sends it
/// once, immediately, before any sandbox is created — so deferring costs nothing. Requests that
/// somehow arrived first just sit on the queue until the workers spawn.
fn serve(workspace: &str, backend_name: Option<&str>) {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let queue = Arc::new(Queue::new());
    let out = Arc::new(Mutex::new(io::stdout()));
    // Session-scoped content store for pushed directory blobs. Shared with the workers; Pushes are
    // applied here in the reader thread (below) before the next frame is read, so any Create framed
    // after a Push is guaranteed to see its blobs — the ordering invariant the no-ack Push relies on.
    let store = Arc::new(BlobStore::new());
    let mut metrics = MetricsGate::off();
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut backend_ref: Option<Arc<dyn Backend>> = None;

    let stdin = io::stdin();
    let mut r = stdin.lock();
    while let Some(len) = read_len(&mut r) {
        let mut body = vec![0u8; len as usize];
        if r.read_exact(&mut body).is_err() {
            break;
        }
        match proto::decode_request(&body) {
            // The one-time handshake, sent before any sandbox is created: answer inline rather
            // than through the worker queue/timing stats, which model only Create/Collect/Destroy.
            Some(Request::Negotiate { rid, versions, options }) => {
                let backend = match select(backend_name, workspace, &options) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("sandboxfs: cannot open backend: {e}");
                        std::process::exit(1);
                    }
                };
                backend.start();
                let env = std::env::var("sandboxfs_backend").or_else(|_| std::env::var("SANDBOXFS_BACKEND")).ok();
                let backend_label = match resolve(backend_name, env.as_deref()) {
                    Ok(Kind::Lazy) => "lazyfs",
                    _ => "cfs",
                };
                metrics = MetricsGate::start(workspace, backend.clone(), backend_label, &options);
                backend_ref = Some(backend.clone());
                workers = spawn_workers(backend, queue.clone(), out.clone(), store.clone());
                let frame = frame(&proto::encode_response(&negotiate(rid, &versions)));
                let mut o = out.lock().unwrap();
                if o.write_all(&frame).is_err() || o.flush().is_err() {
                    break;
                }
            }
            // Fire-and-forget, no reply: apply to the store right here, before the next frame is
            // read, so a Create that references these blobs (and is framed after this Push) always
            // finds them once a worker picks it up.
            Some(Request::Push { blobs, content }) => {
                let hashes: Vec<String> = blobs.iter().map(|(h, _)| h.clone()).collect();
                store.insert_many(blobs);
                // Capture-on-receipt: a `Content{location}` path is live only NOW, so snapshot each
                // leaf into the backend's own store while processing this Push (never deferred to
                // Create). A relative location resolves against the session exec root first. The
                // captured host path is pinned in the store for the controller's lifetime.
                if let Some(b) = &backend_ref {
                    let er = store.exec_root();
                    for (digest, source) in content {
                        let source = match source {
                            ContentSource::Location(host) if !host.starts_with('/') => match &er {
                                Some(er) => ContentSource::Location(format!("{er}/{host}")),
                                None => ContentSource::Location(host),
                            },
                            other => other,
                        };
                        if let Some(path) = b.capture_content(&digest, source) {
                            store.insert_captured(digest, path);
                        }
                    }
                    // Advisory: lets the clone backend pre-stage subtrees during the push window.
                    b.blobs_pushed(&hashes);
                }
            }
            Some(req) => queue.push(req),
            None => {}
        }
    }
    queue.close();
    for w in workers {
        let _ = w.join();
    }
    metrics.finish();
}

/// Opt-in metrics, keyed by workspace. Bazel sends no build boundaries (only
/// Create/Collect/Destroy) and keeps this controller alive across builds, so we infer
/// each `bazel build` from live-sandbox edges: a build is running while `stats::LIVE`
/// (creates minus destroys) is > 0 — which holds even across long request-silent gaps
/// while actions run — and is done once LIVE has sat at 0 for IDLE_GRACE. The
/// controller drives begin/end itself (so the daemon learns its pid, for per-workspace
/// attribution); the daemon runs other workspaces' windows concurrently. Armed by either
/// `--client_env=sandboxfs_metrics=1` or a `--metrics` backend arg (relayed via the Negotiate
/// handshake's `options`, e.g. `--sandbox_backend_arg=<name>=--metrics`), and only when the
/// backend opts into kdebug attribution.
struct MetricsGate {
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    monitor: Option<thread::JoinHandle<()>>,
}

impl MetricsGate {
    const POLL: std::time::Duration = std::time::Duration::from_millis(250);

    fn off() -> MetricsGate {
        MetricsGate { stop: None, monitor: None }
    }

    fn start(workspace: &str, backend: Arc<dyn Backend>, label: &'static str, options: &[String]) -> MetricsGate {
        let env_enabled = std::env::var("sandboxfs_metrics").ok().as_deref() == Some("1");
        let opt_enabled = options.iter().any(|o| o == "--metrics");
        if !(env_enabled || opt_enabled) {
            return Self::off();
        }
        let Some(prefix) = backend.metrics_prefix() else {
            return Self::off(); // backend isn't observed via kdebug (e.g. lazyfs)
        };
        // How long LIVE must stay 0 before a build is called done. Bridges inter-wave
        // lulls; tunable via `--client_env=sandboxfs_idle_s=<seconds>` (default 4).
        let idle = std::env::var("sandboxfs_idle_s")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(4));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ws, st) = (workspace.to_string(), stop.clone());
        let monitor = thread::spawn(move || Self::watch(ws, prefix, backend, label, idle, st));
        MetricsGate { stop: Some(stop), monitor: Some(monitor) }
    }

    fn watch(
        workspace: String,
        prefix: String,
        backend: Arc<dyn Backend>,
        label: &'static str,
        idle: std::time::Duration,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        let report = |ws: &str| {
            let _ = metrics::client("report", ws, "", &backend.report_text(label));
        };
        let mut open = false;
        let mut idle_since: Option<std::time::Instant> = None;
        let mut ticks: u32 = 0;
        while !stop.load(Acquire) {
            thread::sleep(Self::POLL);
            ticks = ticks.wrapping_add(1);
            let live = stats::LIVE.load(Relaxed) > 0;
            if live {
                idle_since = None;
                if !open {
                    match metrics::client("begin", &workspace, &prefix, "") {
                        Ok(_) => {
                            open = true;
                            report(&workspace); // seed the daemon with the controller's counters
                        }
                        Err(e) => eprintln!("sandboxfs: metrics begin failed: {e}"),
                    }
                }
            } else if open {
                let since = *idle_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= idle {
                    report(&workspace); // final snapshot before the window closes
                    let _ = metrics::client("end", &workspace, "", "");
                    (open, idle_since) = (false, None);
                    continue;
                }
            }
            // refresh the daemon's view ~1s while a build runs (POLL is 250ms)
            if open && ticks % 4 == 0 {
                report(&workspace);
            }
        }
        if open {
            report(&workspace);
            let _ = metrics::client("end", &workspace, "", ""); // finalize in-flight build on shutdown
        }
    }

    fn finish(self) {
        if let Some(stop) = self.stop {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(m) = self.monitor {
            let _ = m.join();
        }
    }
}

fn handle(backend: &dyn Backend, req: Request, store: &BlobStore) -> Response {
    match req {
        Request::Create { rid, sandbox_id, manifest_bytes } => {
            let reply = match backend.create(&sandbox_id, &manifest_bytes, store) {
                // Ok reports `unconfined`: our projected filesystem view IS the confinement, so
                // Bazel applies no OS jail on top (a default Seatbelt jail would deny the action's
                // $TMPDIR writes). See CreateReply::Ok.
                Ok(CreateOutcome::Created(path)) => CreateReply::Ok { path },
                Ok(CreateOutcome::MissingContent(hashes)) => CreateReply::MissingContent(hashes),
                Err(e) => CreateReply::Error(format!("{e}")),
            };
            Response { rid, reply: Reply::Create(reply) }
        }
        Request::Collect { rid, sandbox_id, exec_root } => {
            let status = match backend.collect(&sandbox_id, &exec_root) {
                Ok(()) => Status::Ok,
                Err(e) => Status::Error(format!("{e}")),
            };
            Response { rid, reply: Reply::Collect(status) }
        }
        Request::Destroy { rid, sandbox_id } => {
            backend.destroy(&sandbox_id);
            Response { rid, reply: Reply::Destroy(Status::Ok) }
        }
        Request::Negotiate { .. } => unreachable!("negotiate is answered inline in serve(), before queueing"),
        Request::Push { .. } => unreachable!("push is applied inline in serve(), never queued"),
    }
}

/// Answers the Negotiate handshake: VERSION_1 is the only protocol version, so reject only if
/// Bazel's offered set excludes it.
fn negotiate(rid: u64, versions: &[u32]) -> Response {
    if !versions.contains(&proto::VERSION_1) {
        return Response { rid, reply: Reply::Negotiate(NegotiateReply::Error("sandboxfs: no shared protocol version".into())) };
    }
    Response { rid, reply: Reply::Negotiate(NegotiateReply::Ok { version: proto::VERSION_1 }) }
}

/// A minimal MPMC work queue (std-only): workers block on `pop` until an item
/// arrives or the reader closes the queue at stdin EOF.
struct Queue {
    inner: Mutex<(VecDeque<(Request, std::time::Instant)>, bool)>,
    cv: Condvar,
}

impl Queue {
    fn new() -> Self {
        Queue { inner: Mutex::new((VecDeque::new(), false)), cv: Condvar::new() }
    }
    fn push(&self, r: Request) {
        self.inner.lock().unwrap().0.push_back((r, std::time::Instant::now()));
        self.cv.notify_one();
    }
    fn close(&self) {
        self.inner.lock().unwrap().1 = true;
        self.cv.notify_all();
    }
    fn pop(&self) -> Option<(Request, std::time::Instant)> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(r) = g.0.pop_front() {
                return Some(r);
            }
            if g.1 {
                return None;
            }
            g = self.cv.wait(g).unwrap();
        }
    }
}

/// Read a base-128 varint length prefix one byte at a time; None at EOF.
fn read_len<R: Read>(r: &mut R) -> Option<u64> {
    let mut shift = 0u64;
    let mut v = 0u64;
    loop {
        let mut buf = [0u8; 1];
        match r.read(&mut buf) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let b = buf[0];
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// varint(len) + payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    let mut v = payload.len() as u64;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_resolution() {
        let cfs = |f, e| matches!(resolve(f, e), Ok(Kind::Cfs));
        let lazy = |f, e| matches!(resolve(f, e), Ok(Kind::Lazy));
        assert!(cfs(None, None), "default backend");
        assert!(cfs(None, Some("cfs")), "env selects cfs");
        assert!(lazy(None, Some("LazyFS")), "env is case-insensitive");
        assert!(lazy(Some("lazyfs"), Some("cfs")), "flag wins over env");
        assert!(resolve(None, Some("nope")).is_err(), "unknown name errors");
    }

    /// A backend the metrics daemon observes: it names a path prefix for kdebug attribution.
    struct ObservedBackend;
    impl Backend for ObservedBackend {
        fn create(&self, _sandbox_id: &str, _manifest_bytes: &[u8], _store: &BlobStore) -> io::Result<CreateOutcome> {
            Ok(CreateOutcome::Created("/sandbox/path".into()))
        }
        fn collect(&self, _sandbox_id: &str, _exec_root: &str) -> io::Result<()> {
            Ok(())
        }
        fn destroy(&self, _sandbox_id: &str) {}
        fn metrics_prefix(&self) -> Option<String> {
            Some("x".into())
        }
    }

    struct StubBackend;
    impl Backend for StubBackend {
        fn create(&self, _sandbox_id: &str, _manifest_bytes: &[u8], _store: &BlobStore) -> io::Result<CreateOutcome> {
            Ok(CreateOutcome::Created("/sandbox/path".into()))
        }
        fn collect(&self, _sandbox_id: &str, _exec_root: &str) -> io::Result<()> {
            Ok(())
        }
        fn destroy(&self, _sandbox_id: &str) {}
    }

    #[test]
    fn handle_create_reports_ok_path() {
        let req = Request::Create { rid: 1, sandbox_id: "sbx".into(), manifest_bytes: vec![] };
        match handle(&StubBackend, req, &BlobStore::new()).reply {
            Reply::Create(CreateReply::Ok { path }) => assert_eq!(path, "/sandbox/path"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// A backend reporting MissingContent is relayed as Create.Result.MissingContent, not an error,
    /// so Bazel pushes and retries rather than failing the action.
    #[test]
    fn handle_create_relays_missing_content() {
        struct MissBackend;
        impl Backend for MissBackend {
            fn create(&self, _s: &str, _m: &[u8], _store: &BlobStore) -> io::Result<CreateOutcome> {
                Ok(CreateOutcome::MissingContent(vec!["deadbeef".into()]))
            }
            fn collect(&self, _s: &str, _e: &str) -> io::Result<()> {
                Ok(())
            }
            fn destroy(&self, _s: &str) {}
        }
        let req = Request::Create { rid: 4, sandbox_id: "sbx".into(), manifest_bytes: vec![] };
        match handle(&MissBackend, req, &BlobStore::new()).reply {
            Reply::Create(CreateReply::MissingContent(h)) => assert_eq!(h, vec!["deadbeef".to_string()]),
            other => panic!("expected MissingContent, got {other:?}"),
        }
    }

    #[test]
    fn negotiate_accepts_shared_version() {
        match negotiate(1, &[proto::VERSION_1]).reply {
            Reply::Negotiate(NegotiateReply::Ok { version }) => {
                assert_eq!(version, proto::VERSION_1);
            }
            other => panic!("expected Negotiated, got {other:?}"),
        }
    }

    #[test]
    fn negotiate_errors_when_no_shared_version() {
        assert!(matches!(negotiate(2, &[999]).reply, Reply::Negotiate(NegotiateReply::Error(_))));
    }

    #[test]
    fn metrics_gate_off_without_prefix_even_when_armed() {
        std::env::remove_var("sandboxfs_metrics");
        let gate = MetricsGate::start("ws", Arc::new(StubBackend), "cfs", &["--metrics".to_string()]);
        assert!(gate.stop.is_none(), "no metrics prefix means no kdebug attribution, so no point arming");
    }

    #[test]
    fn metrics_gate_off_without_env_or_option() {
        std::env::remove_var("sandboxfs_metrics");
        let gate = MetricsGate::start("ws", Arc::new(ObservedBackend), "cfs", &[]);
        assert!(gate.stop.is_none());
    }

    #[test]
    fn metrics_gate_armed_by_metrics_backend_arg() {
        // The --sandbox_backend_arg=<name>=--metrics path: relayed via Negotiate.options, no env var.
        std::env::remove_var("sandboxfs_metrics");
        let gate = MetricsGate::start("ws", Arc::new(ObservedBackend), "cfs", &["--metrics".to_string()]);
        assert!(gate.stop.is_some());
        gate.finish();
    }

    #[test]
    fn framing_round_trips() {
        let payload = vec![1u8, 2, 3, 200, 255]; // >0x80 byte exercises the varint
        let f = frame(&payload);
        let mut c = io::Cursor::new(f);
        let len = read_len(&mut c).unwrap();
        assert_eq!(len, payload.len() as u64);
        let mut body = vec![0u8; len as usize];
        c.read_exact(&mut body).unwrap();
        assert_eq!(body, payload);
    }
}
