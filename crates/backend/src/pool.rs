// Per-workspace pool location + exclusive lock, shared by every backend. A workspace
// maps to a deterministic subtree under the pool root; an flock makes the first
// controller the owner and sends a second concurrent one to a private pid-keyed
// subtree (never contended).

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn pool_root() -> PathBuf {
    if let Ok(p) = std::env::var("SANDBOXFS_POOL") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".sandboxfs/pool")
}

/// The pool root to actually use: an explicit override (from a `--pool-root=<path>` backend
/// arg) wins outright; otherwise `pool_root()`'s default. No auto-relocation — `check_same_device`
/// is the gate for a cross-device mismatch; this just resolves which path to gate.
pub fn resolve_pool_root(explicit: Option<&str>) -> PathBuf {
    explicit.map(PathBuf::from).unwrap_or_else(pool_root)
}

/// Fails fast — instead of every create silently degrading to a cross-device copy
/// fallback and Collect's rename hard-failing with EXDEV ("Cross-device link") deep into a
/// build — when `root` and `workspace` don't share a device. A backend's projection and rename are
/// same-device-only, so this is a hard requirement, not a preference.
pub fn check_same_device(root: &Path, workspace: &Path) -> io::Result<()> {
    match (dev_of(root), dev_of(workspace)) {
        (Some(a), Some(b)) if a != b => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "pool root {root:?} and workspace {workspace:?} are on different volumes \
                 (projection and rename require the same device); set an explicit pool on the \
                 workspace's volume via --sandbox_backend_arg=<name>=--pool-root=<path>"
            ),
        )),
        _ => Ok(()),
    }
}

/// `st_dev` of the nearest existing ancestor of `path` (the path itself may not exist yet —
/// e.g. the pool root before its first create). Always terminates: "/" always exists.
fn dev_of(path: &Path) -> Option<u64> {
    let mut p = path;
    loop {
        if let Some(dev) = stat_dev(p) {
            return Some(dev);
        }
        p = p.parent()?;
    }
}

fn stat_dev(path: &Path) -> Option<u64> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath.as_ptr(), &mut st) } == 0 {
        Some(st.st_dev as u64)
    } else {
        None
    }
}

/// DJB2 of (backend, workspace path) + a filesystem-safe basename. Deterministic
/// across restarts so the same (backend, workspace) re-locks the same pool subtree.
/// The backend label is part of the key: the two backends' on-disk slot layouts are
/// incompatible, so the same workspace under each must key to a distinct subtree —
/// otherwise one backend's adopt() would try to reclaim the other's slots.
pub fn workspace_key(ns: &str, ws: &str) -> String {
    let mut h: u64 = 5381;
    for b in ns.bytes().chain(std::iter::once(0u8)).chain(ws.bytes()) {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    let base: String = Path::new(ws)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(40)
        .collect();
    format!("{base}-{ns}-{h:x}")
}

fn try_flock(f: &File) -> bool {
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Lock `<base>/<key>`; if another controller holds it, use a private
/// `<base>/<key>-<pid>` (never contended).
pub fn lock_dir(base: &Path, key: &str) -> io::Result<(PathBuf, File)> {
    for candidate in [key.to_string(), format!("{key}-{}", std::process::id())] {
        let dir = base.join(&candidate);
        std::fs::create_dir_all(&dir)?;
        let lf = OpenOptions::new().create(true).write(true).open(dir.join(".lock"))?;
        if try_flock(&lf) {
            return Ok((dir, lf));
        }
    }
    Err(io::Error::new(io::ErrorKind::WouldBlock, "could not lock a pool dir"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_pool_root_explicit_override_wins() {
        assert_eq!(resolve_pool_root(Some("/explicit/pool")), PathBuf::from("/explicit/pool"));
    }

    #[test]
    fn resolve_pool_root_falls_back_to_default() {
        assert_eq!(resolve_pool_root(None), pool_root());
    }

    #[test]
    fn dev_of_agrees_for_siblings_under_the_same_existing_dir() {
        let base = std::env::temp_dir();
        assert_eq!(dev_of(&base.join("a-nonexistent-child")), dev_of(&base.join("another-nonexistent-child")));
    }

    #[test]
    fn check_same_device_ok_when_devices_match() {
        let base = std::env::temp_dir();
        check_same_device(&base.join("pool"), &base.join("workspace")).expect("same device, should pass");
    }

    #[test]
    fn check_same_device_errors_with_actionable_message_across_volumes() {
        // Opportunistic: only meaningful where a second volume is actually mounted (this
        // environment happens to have one, matching the bug's real-world /Volumes report).
        let other = Path::new("/Volumes/quiet");
        if dev_of(other) == dev_of(Path::new("/tmp")) {
            return; // no second device available here; nothing to assert
        }
        let err = check_same_device(other, Path::new("/tmp")).expect_err("cross-device should error");
        assert!(err.to_string().contains("--pool-root"), "{err}");
    }
}
