// XPC control plane over the Mach service build.aspect.sandbox.metricsd. The daemon is
// the listener (root); the controller and CLI are clients. Peers are validated by
// code-signing requirement so arbitrary processes can't open windows or inject
// metrics. libxpc is C-only and its event handlers are Objective-C blocks, so we
// hand-roll a minimal global Block (matching the rest of this codebase's raw FFI).
// The handlers carry no captured state — they reach the daemon through the process
// global in lib.rs — so a stateless global block (never heap-copied) suffices.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::size_of;
use std::ptr;

type XObj = *mut c_void;
type XConn = XObj;

const MACH_SERVICE_LISTENER: u64 = 1 << 0;

const NAME: &[u8] = b"build.aspect.sandbox.metricsd\0";
const K_METHOD: &[u8] = b"method\0";
const K_BUILD: &[u8] = b"build_id\0";
const K_PREFIX: &[u8] = b"clone_prefix\0";
const K_PAYLOAD: &[u8] = b"payload\0"; // controller->daemon metrics report (line-based text)
const K_OK: &[u8] = b"ok\0";
const K_ERROR: &[u8] = b"error\0";
const K_RESULT: &[u8] = b"result\0";
const REQUIREMENT: &[u8] = b"anchor apple generic and certificate leaf[subject.OU] = \"2SZJVCZSQ6\"\0";

extern "C" {
    fn xpc_connection_create_mach_service(name: *const c_char, targetq: *mut c_void, flags: u64) -> XConn;
    fn xpc_connection_set_event_handler(conn: XConn, handler: *const c_void);
    fn xpc_connection_set_peer_code_signing_requirement(conn: XConn, req: *const c_char) -> c_int;
    fn xpc_connection_resume(conn: XConn);
    fn xpc_connection_send_message(conn: XConn, msg: XObj);
    fn xpc_connection_send_message_with_reply_sync(conn: XConn, msg: XObj) -> XObj;
    fn xpc_dictionary_create(keys: *const *const c_char, vals: *const XObj, count: usize) -> XObj;
    fn xpc_dictionary_create_reply(original: XObj) -> XObj;
    fn xpc_dictionary_get_remote_connection(dict: XObj) -> XConn;
    fn xpc_connection_get_pid(conn: XConn) -> libc::pid_t;
    fn xpc_dictionary_set_string(dict: XObj, key: *const c_char, val: *const c_char);
    fn xpc_dictionary_get_string(dict: XObj, key: *const c_char) -> *const c_char;
    fn xpc_dictionary_set_int64(dict: XObj, key: *const c_char, val: i64);
    fn xpc_dictionary_get_int64(dict: XObj, key: *const c_char) -> i64;
    fn xpc_get_type(obj: XObj) -> *const c_void;
    fn xpc_release(obj: XObj);
    fn dispatch_main() -> !;
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;
    static _xpc_type_error: c_void;
    static _NSConcreteGlobalBlock: c_void;
}

// A listener (and client) created with a NULL target queue has nowhere to run its
// event handler — peers connect at the mach level but are never delivered. Use the
// default-QoS global concurrent queue; our handlers serialize on the daemon mutex.
fn global_queue() -> *mut c_void {
    unsafe { dispatch_get_global_queue(0, 0) }
}

fn is_error(obj: XObj) -> bool {
    unsafe { xpc_get_type(obj) == &_xpc_type_error as *const c_void }
}

#[repr(C)]
struct Block {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: extern "C" fn(*mut Block, XObj),
    descriptor: *const BlockDescriptor,
}
#[repr(C)]
struct BlockDescriptor {
    reserved: u64,
    size: u64,
}
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

// A leaked global block wrapping a bare fn pointer. Global blocks are never heap
// copied by Block_copy, so the leak is the block's whole (process) lifetime.
fn global_block(invoke: extern "C" fn(*mut Block, XObj)) -> *const c_void {
    static DESC: BlockDescriptor = BlockDescriptor { reserved: 0, size: size_of::<Block>() as u64 };
    let b = Box::new(Block {
        isa: unsafe { &_NSConcreteGlobalBlock as *const c_void },
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke,
        descriptor: &DESC,
    });
    Box::leak(b) as *const Block as *const c_void
}

/// Serve the control plane forever (root LaunchDaemon entry).
pub fn serve() -> ! {
    unsafe {
        let listener = xpc_connection_create_mach_service(NAME.as_ptr() as _, global_queue(), MACH_SERVICE_LISTENER);
        if std::env::var_os("SANDBOXD_SKIP_PEER_CHECK").is_none() {
            xpc_connection_set_peer_code_signing_requirement(listener, REQUIREMENT.as_ptr() as _);
        }
        xpc_connection_set_event_handler(listener, global_block(on_new_peer));
        xpc_connection_resume(listener);
        eprintln!("metricsd: listening on build.aspect.sandbox.metricsd");
        dispatch_main()
    }
}

// Listener handler: each event is a freshly-accepted peer connection. Give it a
// message handler and resume it.
extern "C" fn on_new_peer(_b: *mut Block, peer: XObj) {
    if is_error(peer) {
        return;
    }
    unsafe {
        xpc_connection_set_event_handler(peer, global_block(on_message));
        xpc_connection_resume(peer);
    }
}

// Per-connection handler: decode the request dict, dispatch, reply.
extern "C" fn on_message(_b: *mut Block, event: XObj) {
    if is_error(event) {
        return; // peer disconnected / invalidated
    }
    unsafe {
        let method = get_str(event, K_METHOD);
        let build_id = get_str(event, K_BUILD);
        let prefix = get_str(event, K_PREFIX);
        let payload = get_str(event, K_PAYLOAD);
        let remote = xpc_dictionary_get_remote_connection(event);
        let peer_pid = xpc_connection_get_pid(remote);
        eprintln!("metricsd: {method} {build_id:?} (pid {peer_pid})");

        let reply = xpc_dictionary_create_reply(event);
        if reply.is_null() {
            return; // message wasn't sent expecting a reply
        }
        match crate::dispatch(&method, &build_id, &prefix, &payload, peer_pid) {
            Ok(result) => {
                xpc_dictionary_set_int64(reply, K_OK.as_ptr() as _, 1);
                if let Some(json) = result {
                    set_str(reply, K_RESULT, &json);
                }
            }
            Err(e) => {
                xpc_dictionary_set_int64(reply, K_OK.as_ptr() as _, 0);
                set_str(reply, K_ERROR, &e);
            }
        }
        xpc_connection_send_message(remote, reply);
        xpc_release(reply);
    }
}

/// Client call used by the CLI subcommands and the controller gate. Returns the
/// `result` string when present (query), None for begin/end success.
///
/// A sync XPC reply to a service that isn't registered (daemon down) blocks
/// forever, which must never stall a build. So the blocking call runs on a worker
/// thread we abandon on timeout — the hung thread lingers harmlessly until the
/// process exits.
// ponytail: thread+timeout instead of an async reply block + dispatch semaphore;
// switch to the latter only if a leaked thread per downed-daemon call ever matters.
pub fn call(method: &str, build_id: &str, clone_prefix: &str, payload: &str) -> Result<Option<String>, String> {
    let (method, build_id, clone_prefix, payload) =
        (method.to_string(), build_id.to_string(), clone_prefix.to_string(), payload.to_string());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(call_blocking(&method, &build_id, &clone_prefix, &payload));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(r) => r,
        Err(_) => Err("xpc: daemon not responding (is build.aspect.sandbox.metricsd loaded?)".to_string()),
    }
}

fn call_blocking(method: &str, build_id: &str, clone_prefix: &str, payload: &str) -> Result<Option<String>, String> {
    unsafe {
        let conn = xpc_connection_create_mach_service(NAME.as_ptr() as _, global_queue(), 0);
        xpc_connection_set_event_handler(conn, global_block(on_client_event));
        xpc_connection_resume(conn);

        let msg = xpc_dictionary_create(ptr::null(), ptr::null(), 0);
        set_str(msg, K_METHOD, method);
        set_str(msg, K_BUILD, build_id);
        set_str(msg, K_PREFIX, clone_prefix);
        set_str(msg, K_PAYLOAD, payload);

        let reply = xpc_connection_send_message_with_reply_sync(conn, msg);
        let out = if is_error(reply) {
            Err("xpc: no reply from daemon (not running, or peer validation failed)".to_string())
        } else if xpc_dictionary_get_int64(reply, K_OK.as_ptr() as _) == 1 {
            let r = get_str(reply, K_RESULT);
            Ok(if r.is_empty() { None } else { Some(r) })
        } else {
            Err(get_str(reply, K_ERROR))
        };
        xpc_release(msg);
        xpc_release(reply);
        xpc_release(conn);
        out
    }
}

extern "C" fn on_client_event(_b: *mut Block, _event: XObj) {}

unsafe fn get_str(dict: XObj, key: &[u8]) -> String {
    let p = xpc_dictionary_get_string(dict, key.as_ptr() as _);
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

unsafe fn set_str(dict: XObj, key: &[u8], val: &str) {
    // xpc_dictionary_set_string copies the value, so the CString can drop after.
    if let Ok(c) = CString::new(val) {
        xpc_dictionary_set_string(dict, key.as_ptr() as _, c.as_ptr());
    }
}
