// The controller protocol: the requests Bazel sends and the responses we frame back, matching
// `src/main/protobuf/sandbox.proto`. Digests are lowercase hex end to end.

use crate::wire::{string, Reader, Writer};

// host_mapping/directories are keyed by exec-path or digest strings and rebuilt from scratch on
// every decode, on the hot path for every action -- FxHash trades DoS-resistance (irrelevant here,
// keys come from our own trusted manifest, not attacker input) for meaningfully less per-lookup
// hashing cost than SipHash.

#[derive(Debug, PartialEq)]
pub enum Request {
    Create { rid: u64, sandbox_id: String, manifest_bytes: Vec<u8> },
    Destroy { rid: u64, sandbox_id: String },
    Collect { rid: u64, sandbox_id: String, exec_root: String },
    Negotiate { rid: u64, versions: Vec<u32>, options: Vec<String> },
    /// Directory structure blobs (field 1, keyed by digest hash) and leaf `content` (field 2,
    /// keyed by digest hash: bytes inline, or a host path to capture on receipt -- see
    /// `ContentSource`). Both are content-addressed and immutable; an entry need be pushed only
    /// once for the controller's lifetime. Fire-and-forget: no reply, no sandbox_id. Applied to
    /// the store before any later request that reads it -- see `blobstore` and the reader loop in
    /// sandboxd. A leaf with no `content` entry falls through to the `exec_root/<tree path>`
    /// derivation; a lost/evicted entry surfaces as the dependent Create's MissingContent.
    Push { blobs: Vec<(String, Vec<u8>)>, content: Vec<(String, ContentSource)> },
}

/// One `Push.content` leaf, and how the controller obtains its bytes. Content-addressed: any
/// source holding the digest is interchangeable. Per the wire contract the controller MUST capture
/// the bytes WHILE PROCESSING THE PUSH (a `location` path is a momentary assertion, live only at
/// push time), never deferring to Create time -- see the sandboxd Push handler and
/// `Backend::capture_content`. `retention` is a memory/eviction HINT only, never a validity signal.
#[derive(Debug, PartialEq)]
pub enum ContentSource {
    /// The bytes themselves, on the wire (virtual inputs -- param files -- with no host path).
    Inline(Vec<u8>),
    /// A host path to read and snapshot into the controller's own store on receipt.
    Location(String),
}

pub const VERSION_1: u32 = 0;

/// A `Create.Result`: exactly one arm. `Ok` carries the sandbox path and sets the `confinement`
/// oneof to `unconfined` -- our projected filesystem view IS the confinement, so Bazel must apply
/// NO OS jail on top (a default Seatbelt jail would, e.g., deny the action's $TMPDIR writes). This
/// is the new-proto spelling of the old `CONFINEMENT_NONE`. `MissingContent` is the recoverable
/// retry list -- directory-blob or leaf-content digests the store lacks; `Error` a terminal failure.
#[derive(Debug, PartialEq)]
pub enum CreateReply {
    Ok { path: String },
    MissingContent(Vec<String>),
    Error(String),
}

/// A `Destroy.Result` / `Collect.Result`: a bare success or a terminal error. Both ops share this
/// shape (an empty `Ok` message, or `Error`).
#[derive(Debug, PartialEq)]
pub enum Status {
    Ok,
    Error(String),
}

/// A `Negotiate.Result`: the protocol version the backend speaks, or a terminal error (e.g. no
/// shared version). Confinement is no longer advertised here -- Bazel states what it can enforce in
/// the Negotiate request, and the backend picks per-sandbox in `CreateReply::Ok`.
#[derive(Debug, PartialEq)]
pub enum NegotiateReply {
    Ok { version: u32 },
    Error(String),
}

/// `Response.result`, mirroring `Request.op` one-to-one. A `Push` has no reply, so no arm here.
#[derive(Debug, PartialEq)]
pub enum Reply {
    Create(CreateReply),
    Destroy(Status),
    Collect(Status),
    Negotiate(NegotiateReply),
}

pub struct Response {
    pub rid: u64,
    pub reply: Reply,
}

pub fn decode_request(data: &[u8]) -> Option<Request> {
    if data.is_empty() {
        return None;
    }
    let mut r = Reader::new(data);
    let mut rid = 0u64;
    let mut sandbox_id = String::new();
    let mut create: Option<Vec<u8>> = None;
    let mut is_destroy = false;
    let mut collect_exec_root: Option<String> = None;
    let mut negotiate: Option<(Vec<String>, Vec<u32>)> = None;
    let mut push: Option<(Vec<(String, Vec<u8>)>, Vec<(String, ContentSource)>)> = None;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 0) => rid = r.varint(),
            (2, 2) => sandbox_id = string(r.len_slice()?),
            (3, 2) => create = Some(unwrap_create_manifest(r.len_slice()?)), // Create{ Manifest manifest = 1 }
            (4, 2) => {
                r.len_slice()?; // Destroy{} (empty)
                is_destroy = true;
            }
            (5, 2) => collect_exec_root = Some(parse_collect_exec_root(r.len_slice()?)), // Collect{ exec_root = 1 }
            (6, 2) => negotiate = Some(parse_negotiate(r.len_slice()?)), // Negotiate{ options = 1, versions = 2 }
            (7, 2) => push = Some(parse_push(r.len_slice()?)), // Push{ blobs = 1, content = 2 }
            (_, w) => r.skip(w),
        }
    }
    if let Some(create) = create {
        return Some(Request::Create { rid, sandbox_id, manifest_bytes: create });
    }
    if is_destroy {
        return Some(Request::Destroy { rid, sandbox_id });
    }
    if let Some(exec_root) = collect_exec_root {
        return Some(Request::Collect { rid, sandbox_id, exec_root });
    }
    if let Some((options, versions)) = negotiate {
        return Some(Request::Negotiate { rid, versions, options });
    }
    if let Some((blobs, content)) = push {
        return Some(Request::Push { blobs, content });
    }
    None
}

/// `map<string, bytes>` entry. The value stays borrowed: it is a raw `Directory` blob and has to
/// round-trip byte for byte or its digest stops checking out.
fn parse_map_entry_bytes(b: &[u8]) -> Option<(String, &[u8])> {
    let mut k = String::new();
    let mut v: &[u8] = &[];
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => v = r.len_slice()?,
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((k, v))
}

/// `Push{ map<string,bytes> blobs = 1; map<string,Content> content = 2 }` -> owned `(digest hash,
/// Directory bytes)` pairs plus `(digest hash, ContentSource)` leaves. Directory bytes are copied
/// out (they move into the store), not borrowed; a `Content{inline}` likewise owns its bytes.
fn parse_push(b: &[u8]) -> (Vec<(String, Vec<u8>)>, Vec<(String, ContentSource)>) {
    let mut r = Reader::new(b);
    let mut blobs = Vec::new();
    let mut content = Vec::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((k, v)) = parse_map_entry_bytes(g) {
                        blobs.push((k, v.to_vec()));
                    }
                }
            }
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(entry) = parse_content_entry(g) {
                        content.push(entry);
                    }
                }
            }
            (_, w) => r.skip(w),
        }
    }
    (blobs, content)
}

/// One `map<string, Content>` entry: {1: digest hash, 2: Content}. `Content{ oneof source { bytes
/// inline = 1; string location = 2; } Retention retention = 3 }`. Retention is parsed but treated
/// as an eviction hint only (never a validity signal), so it does not ride in `ContentSource`.
fn parse_content_entry(b: &[u8]) -> Option<(String, ContentSource)> {
    let mut r = Reader::new(b);
    let mut digest = String::new();
    let mut source: Option<ContentSource> = None;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => digest = string(r.len_slice()?),
            (2, 2) => source = Some(parse_content_source(r.len_slice()?)?),
            (_, w) => r.skip(w),
        }
    }
    Some((digest, source?))
}

/// The `Content` message value: `oneof source { bytes inline = 1; string location = 2 }`, plus
/// `Retention retention = 3` (skipped -- hint only). Exactly one source arm is set.
fn parse_content_source(b: &[u8]) -> Option<ContentSource> {
    let mut r = Reader::new(b);
    let mut source: Option<ContentSource> = None;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => source = Some(ContentSource::Inline(r.len_slice()?.to_vec())),
            (2, 2) => source = Some(ContentSource::Location(string(r.len_slice()?))),
            (_, w) => r.skip(w),
        }
    }
    source
}

/// `Negotiate{ repeated string options = 1; repeated Version versions = 2; }`. One token per
/// `--sandbox_backend_arg` occurrence lands in `options`, opaque to Bazel and ours to interpret
/// (e.g. `--metrics`). `versions` is a proto3 enum, packed (wire type 2) by every standard
/// encoder but accepted unpacked too, per proto3 wire compat.
fn parse_negotiate(b: &[u8]) -> (Vec<String>, Vec<u32>) {
    let mut r = Reader::new(b);
    let mut options = Vec::new();
    let mut versions = Vec::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    options.push(string(g));
                }
            }
            (2, 0) => versions.push(r.varint() as u32),
            (2, 2) => {
                let Some(packed) = r.len_slice() else { break };
                let mut pr = Reader::new(packed);
                while let Some(v) = pr.next_varint() {
                    versions.push(v as u32);
                }
            }
            (_, w) => r.skip(w),
        }
    }
    (options, versions)
}

/// Pull `exec_root` (field 1) out of a `Collect` message.
fn parse_collect_exec_root(b: &[u8]) -> String {
    let mut r = Reader::new(b);
    let mut exec_root = String::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    exec_root = string(g);
                }
            }
            (_, w) => r.skip(w),
        }
    }
    exec_root
}

/// Pull raw `Manifest` bytes out of a `Create` message (field 1).
fn unwrap_create_manifest(b: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        if (field, wire) == (1, 2) {
            if let Some(g) = r.len_slice() {
                return g.to_vec();
            }
            break;
        }
        r.skip(wire);
    }
    Vec::new()
}

pub fn encode_response(resp: &Response) -> Vec<u8> {
    let mut w = Writer::default();
    w.uint(1, resp.rid);
    // Response.result mirrors Request.op: Create.Result=2, Destroy.Result=3, Collect.Result=4,
    // Negotiate.Result=5. Each is a nested message whose `outcome` oneof holds exactly one arm.
    match &resp.reply {
        Reply::Create(c) => w.msg(2, &encode_create_result(c)),
        Reply::Destroy(s) => w.msg(3, &encode_status(s)),
        Reply::Collect(s) => w.msg(4, &encode_status(s)),
        Reply::Negotiate(n) => w.msg(5, &encode_negotiate_result(n)),
    }
    w.out
}

/// `Create.Result{ oneof outcome { Ok ok = 1; MissingContent missing_content = 2; Error error = 3 } }`.
/// `Ok{ string path = 1; oneof confinement { CustomConfinement custom = 2; Unconfined unconfined = 3 } }`
/// -- we set `unconfined` (field 3, an empty message): the projected FS view is the confinement, so
/// Bazel applies no OS jail on top.
fn encode_create_result(c: &CreateReply) -> Vec<u8> {
    let mut w = Writer::default();
    match c {
        CreateReply::Ok { path } => {
            let mut ok = Writer::default();
            ok.str(1, path);
            ok.msg(3, &[]); // Unconfined: present, empty
            w.msg(1, &ok.out);
        }
        CreateReply::MissingContent(hashes) => {
            let mut mc = Writer::default();
            for h in hashes {
                mc.str(1, h); // repeated string digest_hashes = 1
            }
            w.msg(2, &mc.out);
        }
        CreateReply::Error(message) => w.msg(3, &encode_error(message)),
    }
    w.out
}

/// `Destroy.Result` / `Collect.Result{ oneof outcome { Ok ok = 1; Error error = 2 } }`; `Ok` is an
/// empty message.
fn encode_status(s: &Status) -> Vec<u8> {
    let mut w = Writer::default();
    match s {
        Status::Ok => w.msg(1, &[]),
        Status::Error(message) => w.msg(2, &encode_error(message)),
    }
    w.out
}

/// `Negotiate.Result{ oneof outcome { Ok ok = 1 { Version version = 1 }; Error error = 2 } }`.
fn encode_negotiate_result(n: &NegotiateReply) -> Vec<u8> {
    let mut w = Writer::default();
    match n {
        NegotiateReply::Ok { version } => {
            let mut ok = Writer::default();
            if *version != 0 {
                ok.uint(1, *version as u64);
            }
            w.msg(1, &ok.out);
        }
        NegotiateReply::Error(message) => w.msg(2, &encode_error(message)),
    }
    w.out
}

/// The shared terminal `Error{ string message = 1 }`.
fn encode_error(message: &str) -> Vec<u8> {
    let mut e = Writer::default();
    e.str(1, message);
    e.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    #[test]
    fn request_round_trip() {
        let mbytes = b"opaque manifest bytes".to_vec();
        let mut create = Writer::default();
        create.bytes(1, &mbytes);
        let mut w = Writer::default();
        w.uint(1, 99);
        w.str(2, "sbx-7");
        w.msg(3, &create.out);
        match decode_request(&w.out).expect("req") {
            Request::Create { rid, sandbox_id, manifest_bytes } => {
                assert_eq!(rid, 99);
                assert_eq!(sandbox_id, "sbx-7");
                assert_eq!(manifest_bytes, mbytes);
            }
            _ => panic!("expected create"),
        }

        let mut d = Writer::default();
        d.uint(1, 5);
        d.str(2, "sbx-9");
        d.msg(4, &[]);
        match decode_request(&d.out).expect("req") {
            Request::Destroy { rid, sandbox_id } => {
                assert_eq!(rid, 5);
                assert_eq!(sandbox_id, "sbx-9");
            }
            _ => panic!("expected destroy"),
        }

        let mut n = Writer::default();
        n.uint(1, 1);
        let mut neg = Writer::default();
        neg.str(1, "some-opt");
        neg.uint(2, VERSION_1 as u64);
        n.msg(6, &neg.out);
        match decode_request(&n.out).expect("req") {
            Request::Negotiate { rid, versions, options } => {
                assert_eq!(rid, 1);
                assert_eq!(versions, vec![VERSION_1]);
                assert_eq!(options, vec!["some-opt".to_string()]);
            }
            _ => panic!("expected negotiate"),
        }
    }

    #[test]
    fn response_encode() {
        let bytes = encode_response(&Response {
            rid: 3,
            reply: Reply::Create(CreateReply::Ok { path: "/p".into() }),
        });
        // rid=3 (field1 varint), then Create.Result (field2) holding Ok{path=1, unconfined=3}.
        assert_eq!(bytes[0], 0x08); // field-1 varint key (1<<3|0)
        // Walk in to the Ok message and assert it carries the Unconfined arm (field 3, empty msg),
        // NOT an unset confinement (which would ask Bazel for its default OS jail).
        let mut r = Reader::new(&bytes);
        r.varint();
        r.varint(); // rid
        assert_eq!(r.varint(), (2 << 3) | 2, "Create.Result is field 2");
        let cr = r.len_slice().unwrap();
        let mut cr = Reader::new(cr);
        assert_eq!(cr.varint(), (1 << 3) | 2, "Ok is outcome field 1");
        let ok = cr.len_slice().unwrap();
        let mut okr = Reader::new(ok);
        assert_eq!(okr.varint(), (1 << 3) | 2, "path is field 1");
        assert_eq!(string(okr.len_slice().unwrap()), "/p");
        assert_eq!(okr.varint(), (3 << 3) | 2, "unconfined is confinement oneof field 3");
        assert!(okr.len_slice().unwrap().is_empty(), "Unconfined is a present, empty message");
    }

    #[test]
    fn negotiated_round_trip() {
        let bytes =
            encode_response(&Response { rid: 7, reply: Reply::Negotiate(NegotiateReply::Ok { version: VERSION_1 }) });
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x08);
    }

    /// A Create reply wraps its outcome in a Create.Result (field 2), and the per-op arms use the
    /// literal field numbers from sandbox.proto: Ok=1 (path=1), MissingContent=2 (digest_hashes=1),
    /// Error=3. Decode the envelope by hand so an accidental field-number shift is caught.
    #[test]
    fn response_envelope_field_numbers() {
        let mb = encode_response(&Response {
            rid: 9,
            reply: Reply::Create(CreateReply::MissingContent(vec!["aa".into(), "bb".into()])),
        });
        let mut r = Reader::new(&mb);
        assert_eq!(r.varint(), 1 << 3, "rid key (field 1, wire type 0)");
        assert_eq!(r.varint(), 9);
        assert_eq!(r.varint(), (2 << 3) | 2, "Create.Result is field 2");
        let create_result = r.len_slice().unwrap();
        let mut cr = Reader::new(create_result);
        assert_eq!(cr.varint(), (2 << 3) | 2, "MissingContent is outcome field 2");
        let missing = cr.len_slice().unwrap();
        let mut mr = Reader::new(missing);
        assert_eq!(mr.varint(), (1 << 3) | 2, "digest_hashes is field 1");
        assert_eq!(string(mr.len_slice().unwrap()), "aa");
        assert_eq!(mr.varint(), (1 << 3) | 2);
        assert_eq!(string(mr.len_slice().unwrap()), "bb");

        // Destroy/Collect success carry an empty Ok (field 1); a Collect error is field 4 -> field 2.
        let d = encode_response(&Response { rid: 1, reply: Reply::Destroy(Status::Ok) });
        let mut dr = Reader::new(&d);
        dr.varint();
        dr.varint(); // rid
        assert_eq!(dr.varint(), (3 << 3) | 2, "Destroy.Result is field 3");
    }

    /// A Push request decodes its blob list from `map<string,bytes> blobs = 1` AND its leaf
    /// content from `map<string, Content> content = 2` — a Content whose `source` oneof is either
    /// `location = 2` (a host path to capture) or `inline = 1` (bytes on the wire).
    #[test]
    fn decode_request_reads_push_blobs_and_content() {
        let mut entry_a = Writer::default();
        entry_a.str(1, "hashA");
        entry_a.bytes(2, b"dirbytesA");
        let mut entry_b = Writer::default();
        entry_b.str(1, "hashB");
        entry_b.bytes(2, b"dirbytesB");
        // content[digL] = Content{ location = "_main/src/x.js" }
        let mut loc_src = Writer::default();
        loc_src.str(2, "_main/src/x.js"); // Content.location (oneof field 2)
        let mut loc_entry = Writer::default();
        loc_entry.str(1, "digL"); // map key
        loc_entry.msg(2, &loc_src.out); // map value = Content
        // content[digI] = Content{ inline = b"parambytes", retention = SINGLE_USE }
        let mut inl_src = Writer::default();
        inl_src.bytes(1, b"parambytes"); // Content.inline (oneof field 1)
        inl_src.uint(3, 1); // Content.retention = RETENTION_SINGLE_USE (ignored on decode)
        let mut inl_entry = Writer::default();
        inl_entry.str(1, "digI");
        inl_entry.msg(2, &inl_src.out);

        let mut push = Writer::default();
        push.msg(1, &entry_a.out);
        push.msg(1, &entry_b.out);
        push.msg(2, &loc_entry.out);
        push.msg(2, &inl_entry.out);
        let mut w = Writer::default();
        w.msg(7, &push.out); // Request.push = 7

        match decode_request(&w.out).expect("req") {
            Request::Push { blobs, content } => {
                assert_eq!(blobs, vec![("hashA".to_string(), b"dirbytesA".to_vec()), ("hashB".to_string(), b"dirbytesB".to_vec())]);
                assert_eq!(
                    content,
                    vec![
                        ("digL".to_string(), ContentSource::Location("_main/src/x.js".to_string())),
                        ("digI".to_string(), ContentSource::Inline(b"parambytes".to_vec())),
                    ]
                );
            }
            other => panic!("expected push, got {other:?}"),
        }
    }

    /// proto3 emits repeated enum fields packed (one length-delimited field 2 holding
    /// concatenated varints) — the form a real Java protobuf encoder will use for
    /// `Negotiate.versions`, distinct from the single-value unpacked form `request_round_trip`
    /// already covers.
    #[test]
    fn negotiate_versions_packed() {
        let mut packed = Writer::default();
        packed.varint(VERSION_1 as u64);
        packed.varint(5);
        let mut neg = Writer::default();
        neg.bytes(2, &packed.out); // Negotiate.versions, packed
        let mut w = Writer::default();
        w.uint(1, 42);
        w.msg(6, &neg.out);
        match decode_request(&w.out).expect("req") {
            Request::Negotiate { rid, versions, options } => {
                assert_eq!(rid, 42);
                assert_eq!(versions, vec![VERSION_1, 5]);
                assert!(options.is_empty());
            }
            _ => panic!("expected negotiate"),
        }
    }
}
