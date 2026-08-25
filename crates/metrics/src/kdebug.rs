// Direct kdebug session: own the kernel trace facility for the duration of a build
// window, drain raw events, hand them to the collector. Root-only (no entitlement,
// not SIP-gated). Event codes are pinned from /usr/share/misc/trace.codes and the
// KERN_KD* ops from <sys/sysctl.h>; struct layouts are XNU-private (kdebug_private.h)
// and marked to verify on the target. Approximate is the bar — a dropped event is
// counted (TRACE_LOST_EVENTS), not chased.

use std::io;
use std::mem::size_of;

const CTL_KERN: libc::c_int = 1;
const KERN_KDEBUG: libc::c_int = 24;

// KERN_KD* ops, verified in MacOSX.sdk <sys/sysctl.h>.
const KDENABLE: libc::c_int = 3;
const KDSETBUF: libc::c_int = 4;
const KDSETUP: libc::c_int = 6;
const KDREMOVE: libc::c_int = 7;
const KDREADTR: libc::c_int = 10;
const KDSET_TYPEFILTER: libc::c_int = 22;

// Event classes / subclasses (DBG_*) from <sys/kdebug.h>.
const DBG_FSYSTEM: u8 = 3;
const DBG_BSD: u8 = 4;
const DBG_TRACE: u8 = 7;
const DBG_FSRW: u8 = 1; // VFS reads/writes incl. VFS_LOOKUP
const DBG_DKRW: u8 = 2; // device-level block I/O

// Full event ids (debugid with func bits masked off), pinned from trace.codes.
pub const VFS_LOOKUP: u32 = 0x3010090;
pub const BSC_read: u32 = 0x40c000c;
pub const BSC_write: u32 = 0x40c0010;
pub const BSC_open: u32 = 0x40c0014;
pub const BSC_close: u32 = 0x40c0018;
pub const BSC_rename: u32 = 0x40c0200;
pub const BSC_pread: u32 = 0x40c0264;
pub const BSC_pwrite: u32 = 0x40c0268;
pub const BSC_read_nocancel: u32 = 0x40c0630;
pub const BSC_write_nocancel: u32 = 0x40c0634;
pub const BSC_open_nocancel: u32 = 0x40c0638;
pub const BSC_close_nocancel: u32 = 0x40c063c;
pub const BSC_pread_nocancel: u32 = 0x40c0678;
pub const BSC_pwrite_nocancel: u32 = 0x40c067c;
pub const BSC_openat: u32 = 0x40c073c;
pub const BSC_openat_nocancel: u32 = 0x40c0740;
pub const BSC_renameat: u32 = 0x40c0744;
pub const BSC_renameatx_np: u32 = 0x40c07a0;
pub const BSC_lseek: u32 = 0x40c031c;
pub const BSC_fsync: u32 = 0x40c017c;
pub const BSC_fdatasync: u32 = 0x40c02ec;
pub const BSC_getdirentries: u32 = 0x40c0310;
pub const BSC_getdirentries64: u32 = 0x40c0560;
pub const BSC_fgetattrlist: u32 = 0x40c0390;
pub const BSC_getattrlistbulk: u32 = 0x40c0734;
pub const BSC_stat: u32 = 0x40c02f0;
pub const BSC_stat64: u32 = 0x40c0548;
pub const BSC_stat_extended: u32 = 0x40c045c;
pub const BSC_lstat: u32 = 0x40c02f8;
pub const BSC_lstat64: u32 = 0x40c0550;
pub const BSC_fstatat: u32 = 0x40c0754;
pub const BSC_fstatat64: u32 = 0x40c0758;
pub const BSC_access: u32 = 0x40c0084;
pub const BSC_faccessat: u32 = 0x40c0748;
pub const BSC_getattrlist: u32 = 0x40c0370;
pub const BSC_getattrlistat: u32 = 0x40c0770;
pub const BSC_readlink: u32 = 0x40c00e8;
pub const BSC_readlinkat: u32 = 0x40c0764;
pub const BSC_mkdir: u32 = 0x40c0220;
pub const BSC_mkdirat: u32 = 0x40c076c;
pub const BSC_rmdir: u32 = 0x40c0224;
pub const BSC_unlink: u32 = 0x40c0028;
pub const BSC_unlinkat: u32 = 0x40c0760;
pub const BSC_symlink: u32 = 0x40c00e4;
pub const BSC_symlinkat: u32 = 0x40c0768;
pub const BSC_link: u32 = 0x40c0024;
pub const BSC_linkat: u32 = 0x40c075c;
pub const BSC_chdir: u32 = 0x40c0030;
pub const BSC_posix_spawn: u32 = 0x40c03d0;
pub const TRACE_DATA_NEWTHREAD: u32 = 0x7000004;
pub const TRACE_DATA_THREAD_TERMINATE: u32 = 0x700000c;
pub const TRACE_LOST_EVENTS: u32 = 0x7020008;

// Disk I/O issue events live in DBG_FSYSTEM/DBG_DKRW (0x302xxxx). The "Done" variant
// is the issue code | DKIO_DONE(0x4); we count issues (even low nibble) and read the
// byte size from arg4 (XNU: KERNEL_DEBUG(...DKRW..., buf, dev, blkno, iosize, 0)).
const DKRW_EVENTID_BASE: u32 = ((DBG_FSYSTEM as u32) << 24) | ((DBG_DKRW as u32) << 16);
pub fn is_diskio_issue(eventid: u32) -> bool {
    (eventid & 0xffff_0000) == DKRW_EVENTID_BASE && (eventid & 0x4) == 0
}

pub const FUNC_START: u32 = 1;
pub const FUNC_END: u32 = 2;

/// One kernel trace record. LP64 layout from XNU kdebug_private.h — 64 bytes.
/// `arg5` is the thread id; `cpuid` is informational. Verify size on the target.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KdBuf {
    pub timestamp: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub debugid: u32,
    pub cpuid: u32,
    pub unused: u64,
}
const _: () = assert!(size_of::<KdBuf>() == 64);

impl KdBuf {
    pub fn eventid(&self) -> u32 {
        self.debugid & 0xffff_fffc
    }
    pub fn func(&self) -> u32 {
        self.debugid & 0x3
    }
    pub fn tid(&self) -> u64 {
        self.arg5
    }
}

const TYPEFILTER_BYTES: usize = (256 * 256) / 8; // one bit per (class<<8|subclass)
const NBUFS: libc::c_int = 500_000; // ~32MB of kd_buf; drain keeps up, wrap on overrun

fn kd_op(op: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // KDSETBUF/KDENABLE encode their scalar in mib[3] (namelen 4); the rest are
    // namelen-3 no-arg ops.
    let mut mib = [CTL_KERN, KERN_KDEBUG, op, value];
    let namelen = if op == KDSETBUF || op == KDENABLE { 4 } else { 3 };
    let r = unsafe {
        libc::sysctl(mib.as_mut_ptr(), namelen, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An owned, enabled kdebug session. `read` drains pending events; `Drop` releases.
pub struct Session {
    buf: Vec<KdBuf>,
}

impl Session {
    // kdebug is single-owner; we take it over for the (opt-in) window, the way
    // fs_usage/latency do. Reliably detecting another live consumer isn't worth it —
    // macOS often leaves the facility initialized at idle, so a BUFINIT check just
    // false-blocks. KDREMOVE first clears any prior or leaked session.
    // Takes kdebug over unconditionally; owner-detection can wait until someone actually runs
    // Instruments during a metrics build.
    pub fn start() -> io::Result<Session> {
        let _ = kd_op(KDREMOVE, 0);
        kd_op(KDSETBUF, NBUFS)?;
        kd_op(KDSETUP, 0)?;
        set_typefilter()?;
        kd_op(KDENABLE, 1)?;
        Ok(Session { buf: vec![KdBuf { timestamp: 0, arg1: 0, arg2: 0, arg3: 0, arg4: 0, arg5: 0, debugid: 0, cpuid: 0, unused: 0 }; NBUFS as usize] })
    }

    /// Drain currently-buffered events. Returns the filled prefix of the internal
    /// buffer. A full return means the buffer was saturated — call again immediately.
    pub fn read(&mut self) -> io::Result<&[KdBuf]> {
        let mut mib = [CTL_KERN, KERN_KDEBUG, KDREADTR];
        // KDREADTR quirk (matches fs_usage): *len is byte-capacity on input, event
        // count on output. Verify on the target if counts look wrong.
        let mut len = self.buf.len() * size_of::<KdBuf>();
        let r = unsafe {
            libc::sysctl(mib.as_mut_ptr(), 3, self.buf.as_mut_ptr() as *mut _, &mut len, std::ptr::null_mut(), 0)
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(&self.buf[..len.min(self.buf.len())])
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = kd_op(KDENABLE, 0);
        let _ = kd_op(KDREMOVE, 0);
    }
}

/// Enable only the classes we decode: all of DBG_BSD (syscalls) and DBG_TRACE
/// (thread map + lost-event markers), plus DBG_FSYSTEM/{DBG_FSRW, DBG_DKRW}.
fn set_typefilter() -> io::Result<()> {
    let mut bitmap = vec![0u8; TYPEFILTER_BYTES];
    let mut set = |class: u8, sub: u8| {
        let csc = ((class as usize) << 8) | sub as usize;
        bitmap[csc >> 3] |= 1 << (csc & 7);
    };
    for sub in 0..=255u8 {
        set(DBG_BSD, sub);
        set(DBG_TRACE, sub);
    }
    set(DBG_FSYSTEM, DBG_FSRW);
    set(DBG_FSYSTEM, DBG_DKRW);

    let mut mib = [CTL_KERN, KERN_KDEBUG, KDSET_TYPEFILTER];
    let mut len = bitmap.len();
    let r = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, bitmap.as_mut_ptr() as *mut _, &mut len, std::ptr::null_mut(), 0)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
