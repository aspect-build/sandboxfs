//! Syscall wrappers, anchored at a directory fd wherever one is available.
//!
//! A slot path is 8-12 components deep and every operation in a morph walks it, so the `*at` forms
//! resolve one name against an fd the caller already holds instead of re-walking the whole path.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has NUL"))
}

fn cname(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name has NUL"))
}

/// A directory fd for `path`, opened `O_DIRECTORY`. Anchors every operation inside it.
pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = cstr(path)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::new(io::Error::last_os_error().kind(), format!("open_dir {}: {}", path.display(), io::Error::last_os_error())));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `mkdirat`. An existing directory is success; an existing non-directory is `AlreadyExists` for
/// the caller to clear.
pub fn mkdir_at(dir_fd: &OwnedFd, name: &str) -> io::Result<()> {
    let n = cname(name)?;
    if unsafe { libc::mkdirat(dir_fd.as_raw_fd(), n.as_ptr(), 0o755) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::EEXIST) {
        return Err(io::Error::new(e.kind(), format!("mkdirat {name}: {e}")));
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstatat(dir_fd.as_raw_fd(), n.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
    if ok && st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("mkdirat {name}: occupied by a non-directory")))
    }
}

/// `link(2)`, following a symlinked source so the sandbox gets the real inode.
///
/// EXDEV and EPERM both come back as `Unsupported`: the source cannot be linked from here and the
/// caller must fall back. EPERM is what a SIP-protected path answers, and it cannot be predicted —
/// the system volume is firmlinked into the data volume, so `st_dev` matches and only the attempt
/// tells you.
pub fn link_at(src: &Path, dir_fd: &OwnedFd, name: &str) -> io::Result<()> {
    let s = cstr(src)?;
    let n = cname(name)?;
    if unsafe { libc::linkat(libc::AT_FDCWD, s.as_ptr(), dir_fd.as_raw_fd(), n.as_ptr(), libc::AT_SYMLINK_FOLLOW) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EXDEV) | Some(libc::EPERM) | Some(libc::EMLINK) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, format!("cannot link {}: {e}", src.display())))
        }
        _ => Err(io::Error::new(e.kind(), format!("link {} -> {name}: {e}", src.display()))),
    }
}

pub fn symlink_at(target: &str, dir_fd: &OwnedFd, name: &str) -> io::Result<()> {
    let t = cname(target)?;
    let n = cname(name)?;
    if unsafe { libc::symlinkat(t.as_ptr(), dir_fd.as_raw_fd(), n.as_ptr()) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    Err(io::Error::new(e.kind(), format!("symlink {name} -> {target}: {e}")))
}

/// Unlink one name under `dir_fd`, whatever it is. A directory needs its contents gone first, so
/// that case hands off to the path-based recursive remove.
pub fn remove_at(dir_fd: &OwnedFd, name: &str, full: &Path) -> io::Result<()> {
    let n = cname(name)?;
    if unsafe { libc::unlinkat(dir_fd.as_raw_fd(), n.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Ok(()),
        Some(libc::EPERM) | Some(libc::EISDIR) | Some(libc::EACCES) => remove(full),
        _ => remove(full),
    }
}

/// Delete a path — file, symlink, or whole subtree. Missing is not an error.
///
/// A slot's directories are left writable by the morph, so the read-only-leaf repair that a
/// projection with 0555 trees needs does not arise here.
pub fn remove(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io::Error::new(e.kind(), format!("symlink_metadata {}: {e}", p.display()))),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("remove {}: {e}", p.display())))
}

pub fn mkdir_p(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p).map_err(|e| io::Error::new(e.kind(), format!("mkdir_p {}: {e}", p.display())))
}

/// The mode bits of `p`, following symlinks. `None` when it does not exist.
pub fn mode_of(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).ok().map(|m| m.permissions().mode())
}

pub fn set_mode(p: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io::Error::new(e.kind(), format!("chmod {} {mode:o}: {e}", p.display())))
}

/// Is there really something here? An empty directory does not count: that is what an
/// uninformative manifest entry leaves behind the first time it is materialized, and trusting mere
/// existence would let one bad materialization pass for content forever after.
pub fn has_real_content(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => std::fs::read_dir(p).map(|mut d| d.next().is_some()).unwrap_or(false),
        Ok(_) => true,
        Err(_) => false,
    }
}
