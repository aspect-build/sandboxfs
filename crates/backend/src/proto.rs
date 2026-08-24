// proto3 wire codec for the sandboxfs manifest + request/response contract, matching
// Bazel's `src/main/protobuf/sandbox.proto`. Mirrored in fskit-appex/Sandbox.swift `ProtoWire`.
//
// Bazel's WIRE Manifest is the canonical layout: mnemonic=1, exec_root=2, hash_function=3,
// input_root_digest=4 (a Digest message), outputs=5, writable_dirs=6, confinement_setting=7. The
// input tree is a REAPI Merkle tree shipped OUT OF BAND via `Push` and referenced here only by
// `input_root_digest`; the wire manifest carries no tree of its own.
//
// Our OWN persisted (self-contained) manifest -- what `adopt` reads back and the appex consumes --
// reuses this same parser and shares the canonical scalar fields 1-6, then adds private extension
// fields in the free range above Bazel's (7-15 reserved for Bazel growth): `directories` (14) is a
// `map<string digest_hex, bytes>` holding EVERY directory in the tree (root included, no separate
// root/children split -- input_root_digest is just the entry-point key into it), `host_mapping`
// (16) the per-digest resolved host sources, `origin_root_digest` (19) the wire identity a
// structurally re-hashed persisted tree was minted from. Values in
// `directories` are raw serialized REAPI `Directory` bytes, shipped verbatim (the hasher that
// produced the digest already produced these bytes, so re-hashing every one would be pure overhead
// -- only the root is worth the sanity check). Digests are lowercase-hex strings end to end.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::blobstore::BlobStore;

// host_mapping/directories are keyed by exec-path or digest strings and rebuilt from scratch on
// every decode, on the hot path for every action -- FxHash trades DoS-resistance (irrelevant here,
// keys come from our own trusted manifest, not attacker input) for meaningfully less per-lookup
// hashing cost than SipHash.
use rustc_hash::FxHashMap as HashMap;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Manifest {
    pub mnemonic: Option<String>,
    pub root: Option<Dir>,
    /// Declared outputs: in-sandbox path (where the action writes it, sandbox-root-relative
    /// `/<workspace>/<path>`) -> kind ("dir" or "file", the wire `Output.type`). Under path mapping
    /// the key is the MAPPED path; the unmapped destination Collect moves it to lives in
    /// `output_dests`.
    pub outputs: BTreeMap<String, String>,
    /// Path-mapping remap for Collect: output key -> the UNMAPPED sandbox-root-relative destination
    /// (`Output.dest`), present only for the outputs whose mapped in-sandbox path differs from where
    /// Bazel expects them. Empty without path mapping. Collect moves each output to its `output_dests`
    /// entry when set, else to the key itself.
    pub output_dests: BTreeMap<String, String>,
    pub writable_dirs: BTreeMap<String, String>,
    pub hash_function: Option<String>,
    /// Directory containing the workspace exec root (field 2). Anchors the DEFAULT content
    /// location: a leaf with no captured `Push.content` entry derives its host path as
    /// `exec_root/<tree path>`. Decode keeps that derivation LAZY -- a derivable file's `host_path`
    /// stays empty and the morph layer derives it at placement time, so the common case never
    /// allocates a per-file String.
    pub exec_root: Option<String>,
}

/// `locations`, re-keyed for lookup: parent dir path -> entry name -> value. Splitting the key
/// once at decode lets `build_dir` resolve its directory's map with ONE hash and each file/child
/// with a name-only lookup — no per-file `format!("{parent}/{name}")` key allocation.
type HostMap = crate::blobstore::LocationMap;

/// Resolve an explicit `locations` value to an absolute host path. Only exceptions reach here —
/// a file with no entry stays empty (derived as `exec_root/<tree path>` at placement time).
fn resolve_host(exec_root: Option<&str>, mapped: Option<&str>) -> String {
    match (exec_root, mapped) {
        (_, None) => String::new(),
        (Some(_), Some(v)) if v.starts_with('/') => v.to_string(),
        (Some(er), Some(v)) => format!("{er}/{v}"),
        (None, Some(v)) => v.to_string(),
    }
}

/// Why a `Dir.host_path` is set — lets a consumer (the morph layer's wholesale-clone counters)
/// attribute the decision instead of just seeing a non-empty string. `None` is the derive
/// default (Dir::default() carries no host path).
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirHostKind {
    #[default]
    None,
    /// An explicit `locations` entry (legacy wire shape / our own re-encodes).
    Explicit,
    /// REAPI `node_properties` marker `is_treeartifact`.
    TreeArtifact,
    /// REAPI `node_properties` marker `is_sourcedir`.
    SourceDir,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Dir {
    pub name: String,
    pub digest: String,
    /// Set when this directory is wholesale-backed by one real host directory, so it can be
    /// materialized wholesale instead of per-file. Children stay populated (the
    /// digest covers them, so a content change is still detected). Bazel signals this via a
    /// REAPI `node_properties` marker (`is_treeartifact` / `is_sourcedir`) on the Directory —
    /// `locations` carries only virtual-output and runfiles file mappings now, never a directory
    /// entry — so the host path is the default `exec_root/<path>` derivation, same as a file's.
    pub host_path: String,
    /// Why `host_path` is set; `None` iff `host_path` is empty.
    pub host_kind: DirHostKind,
    pub files: Vec<File>,
    pub directories: Vec<Dir>,
    pub symlinks: Vec<Symlink>,
    /// Set only when this Dir carries the well-known empty-Directory digest (Bazel ships no blob
    /// for it -- `node_properties` is excluded from a Directory's digest, so a tree-artifact/
    /// source-dir reached via a runfiles symlink farm collapses to this same "empty" hash instead
    /// of its real one) AND its accumulated path runs through a `<target>.runfiles/<repo>/`
    /// segment. A runfiles tree mirrors the real repo-relative structure exactly, so stripping that
    /// segment yields the same relative path a DIRECT reference to the same content would use --
    /// this is that candidate, UNVERIFIED (empty unless it applies). The morph layer must confirm
    /// real content actually lives there before ever trusting it; never treated as `host_path`
    /// itself, which would skip that verification.
    pub speculative_host_path: String,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct File {
    pub name: String,
    pub digest: String,
    /// Explicit host source (a `locations` exception, or legacy absolute mode). Empty for the
    /// common compact-mode file: the source is `exec_root/<tree path>`, derived by the morph
    /// layer at placement time — only files actually cloned ever materialize it.
    pub host_path: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Symlink {
    pub name: String,
    pub target: String,
}

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

/// `Push.content` `Retention` (sandbox.proto). Reuse across actions is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Retention {
    #[default]
    Reuse,
    SingleUse,
}

/// SHA-256 of the empty byte string -- what an empty REAPI `Directory` (no files, dirs,
/// symlinks, or node_properties) serializes to and hashes to. Bazel never ships a `directories`
/// entry for this digest: an all-default proto3 message serializes to zero bytes, so there is
/// nothing to send. A DirectoryNode pointing at it is a real, legitimately-empty directory in the
/// common case -- but `node_properties` is excluded from the digest, so a tree-artifact/source-dir
/// reached via a runfiles symlink farm (rather than its default position) ALSO collapses to this
/// exact digest despite having real content. Not a missing blob either way -- must be recognized
/// and stopped on, not treated as a map-lookup failure; see `strip_runfiles_prefix` for how the
/// morph layer gets a chance to recover the real content for the second case.
pub const EMPTY_DIRECTORY_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A Bazel runfiles tree mirrors the real repo-relative structure exactly under
/// `<target>.runfiles/<repo>/`. If `path` runs through such a segment, the repo-relative tail is
/// the SAME relative path a direct (non-runfiles) reference to the same content would use for its
/// own `exec_root/<path>` derivation. Returns `None` if `path` has no `.runfiles/` segment.
fn strip_runfiles_prefix(path: &str) -> Option<&str> {
    let after_marker = path.split_once(".runfiles/")?.1;
    let (_repo, tail) = after_marker.split_once('/')?;
    Some(tail)
}

/// `Version` enum values (sandbox.proto). Only one exists today.
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

/// SHA-256 via the platform's CommonCrypto (native; no crate, no hand-rolled crypto).
mod cc {
    extern "C" {
        pub fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    let mut out = [0u8; 32];
    unsafe { cc::CC_SHA256(b.as_ptr(), b.len() as u32, out.as_mut_ptr()) };
    hex_of(&out)
}

fn hex_of(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 0xf) as usize] as char);
    }
    s
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
    ok: bool,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0, ok: true }
    }

    fn varint(&mut self) -> u64 {
        let mut shift = 0u64;
        let mut v = 0u64;
        while self.i < self.b.len() {
            let byte = self.b[self.i];
            self.i += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return v;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }
        self.ok = false;
        0
    }

    /// Length-delimited payload slice; None (and ok=false) on truncation.
    fn len_slice(&mut self) -> Option<&'a [u8]> {
        let n = self.varint() as usize;
        if !self.ok || self.b.len().checked_sub(self.i).map_or(true, |rem| rem < n) {
            self.ok = false;
            return None;
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }

    fn skip(&mut self, wire: u64) {
        match wire {
            0 => {
                self.varint();
            }
            1 => {
                self.i += 8;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            2 => {
                self.len_slice();
            }
            5 => {
                self.i += 4;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            _ => self.ok = false,
        }
    }
}

fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A `Manifest` decoded against the session blob store. `Ready` carries the reconstructed tree;
/// `Missing` names the directory-blob digests the store lacked, which the controller relays as
/// `Create.Result.MissingContent` so Bazel pushes them and retries.
pub enum ManifestDecode {
    Ready(Manifest),
    Missing(Vec<String>),
}

/// The scalar/prefix fields of a `Manifest`, split out from the tree so the two decode paths --
/// self-contained (inline `directories`, for our own persisted manifests) and wire (tree resolved
/// from the session store) -- share one parse. `directories` is populated only by self-contained
/// manifests; Bazel's wire manifest carries none (the tree ships out of band via `Push`).
struct Header<'a> {
    m: Manifest,
    root_digest_hex: String,
    // The WIRE root digest (Bazel's input_root_digest) a persisted manifest was created from.
    // Field 4 of a persisted manifest is our own structural re-hash (it keys the field-14 blob
    // map), a different hash domain than the wire — adopt() matching slots against future wire
    // digests needs the original preserved, or every daemon restart re-morphs every tree
    // (measured: 65 sticky / 32 overlap on EVERY fresh daemon over a fully-built pool).
    origin_root_digest: String,
    host_mapping: HostMap,
    directories: HashMap<String, &'a [u8]>,
}

fn parse_header(data: &[u8]) -> Option<Header> {
    let mut r = Reader::new(data);
    let mut m = Manifest::default();
    let mut host_mapping: HostMap = HashMap::default();
    let mut root_digest_hex = String::new();
    let mut origin_root_digest = String::new();
    let mut directories: HashMap<String, &[u8]> = HashMap::default();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => m.mnemonic = Some(string(r.len_slice()?)),
            (2, 2) => m.exec_root = Some(string(r.len_slice()?)),
            (3, 2) => m.hash_function = Some(string(r.len_slice()?)),
            (4, 2) => root_digest_hex = digest_hash(r.len_slice()?).unwrap_or_default(),
            (5, 2) => {
                let (k, kind, dest) = parse_output_entry(r.len_slice()?)?;
                if !dest.is_empty() {
                    m.output_dests.insert(k.clone(), dest);
                }
                m.outputs.insert(k, kind);
            }
            (6, 2) => {
                let (k, v) = parse_map_entry(r.len_slice()?)?;
                m.writable_dirs.insert(k, v);
            }
            // 7 = confinement_setting: we return an unset confinement (Bazel's default jail), so
            // the settings that build a jail are irrelevant to us -- skip.
            (14, 2) => {
                let (k, v) = parse_map_entry_bytes(r.len_slice()?)?;
                directories.insert(k, v);
            }
            (16, 2) => {
                let (k, v) = parse_map_entry(r.len_slice()?)?;
                host_mapping.insert(k, v);
            }
            (19, 2) => origin_root_digest = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some(Header { m, root_digest_hex, origin_root_digest, host_mapping, directories })
}

/// Decode a SELF-CONTAINED manifest: one whose directory blobs ride inline in `directories`
/// (field 14). This is our own on-disk persistence format (see `encode`) and what the appex reads
/// -- never Bazel's wire manifest, which carries no tree (use `decode_wire`).
pub fn decode_manifest(data: &[u8]) -> Option<Manifest> {
    decode_manifest_opt(data, false)
}

pub fn decode_manifest_opt(data: &[u8], skip_root: bool) -> Option<Manifest> {
    if data.is_empty() {
        return None;
    }
    let mut h = parse_header(data)?;
    if !skip_root && !h.directories.is_empty() {
        // Self-contained manifests (persistence/appex) bake resolved host paths into their own
        // host_mapping; no session captured-content table applies.
        let empty = HostMap::default();
        match build_root(&h.root_digest_hex, &h.directories, &h.host_mapping, &empty, h.m.exec_root.as_deref()) {
            Ok(mut root) => {
                // Restore the wire-domain identity (see Header.origin_root_digest): field 11 was
                // only ever the structural key for the field-14 lookup above.
                if !h.origin_root_digest.is_empty() {
                    root.digest = h.origin_root_digest;
                }
                h.m.root = Some(root);
            }
            Err(e) => {
                eprintln!("sandboxfs: manifest decode: {e}");
                return None;
            }
        }
    }
    Some(h.m)
}

/// Decode Bazel's WIRE manifest: the tree is not inline, so resolve every directory blob from the
/// session `store` by walking the digest closure from `input_root_digest`. Returns `Missing` (with
/// every unresolved digest, not just the first) when the store lacks a blob the tree needs -- the
/// recoverable path Bazel retries after pushing them; `None` only for a malformed manifest.
pub fn decode_wire(data: &[u8], store: &BlobStore) -> Option<ManifestDecode> {
    if data.is_empty() {
        return None;
    }
    let mut h = parse_header(data)?;
    if let Some(er) = &h.m.exec_root {
        store.set_exec_root(er); // session-stable; lets Push-window capture resolve relative hosts
    }
    // A self-contained manifest (our own persisted form, and tests) carries its tree inline in
    // field 14 -- resolve straight from it, no store, never Missing. Bazel's wire manifest has no
    // field 14, so production always falls through to the store. Accepting both is a harmless
    // superset that keeps our persisted manifests round-trippable through the same entry point.
    let captured = store.captured();
    if !h.directories.is_empty() {
        match build_root(&h.root_digest_hex, &h.directories, &h.host_mapping, &captured, h.m.exec_root.as_deref()) {
            Ok(root) => h.m.root = Some(root),
            Err(e) => {
                eprintln!("sandboxfs: manifest decode: {e}");
                return None;
            }
        }
        return Some(ManifestDecode::Ready(h.m));
    }
    let (collected, missing) = resolve_closure(&h.root_digest_hex, store);
    if !missing.is_empty() {
        return Some(ManifestDecode::Missing(missing));
    }
    if !collected.is_empty() {
        // Borrow the resolved blobs as `&[u8]` for the shared tree walk; `collected` outlives it.
        let view: HashMap<String, &[u8]> = collected.iter().map(|(k, v)| (k.clone(), v.as_ref())).collect();
        match build_root(&h.root_digest_hex, &view, &h.host_mapping, &captured, h.m.exec_root.as_deref()) {
            Ok(root) => h.m.root = Some(root),
            Err(e) => {
                eprintln!("sandboxfs: manifest decode: {e}");
                return None;
            }
        }
    }
    Some(ManifestDecode::Ready(h.m))
}

/// Walk the directory-blob closure reachable from `root_digest_hex` against the store: every
/// `DirectoryNode` digest a resolved `Directory` references is itself resolved, transitively.
/// Returns the resolved blobs (for the tree walk) and the digests the store lacked. A blob that is
/// missing hides its own descendants, so a first pass may not surface every missing digest deep in
/// the tree -- Bazel pushes what we report and retries, converging in practice in one round since
/// it pushes the whole novel closure up front. The well-known empty-Directory digest is never in
/// the store (an all-default proto serializes to zero bytes, so Bazel ships no blob) and is not a
/// miss -- skip it, matching `build_dir`'s own empty-digest handling.
fn resolve_closure(root_digest_hex: &str, store: &BlobStore) -> (HashMap<String, Arc<[u8]>>, Vec<String>) {
    let mut collected: HashMap<String, Arc<[u8]>> = HashMap::default();
    let mut missing: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = Vec::new();
    if !root_digest_hex.is_empty() && root_digest_hex != EMPTY_DIRECTORY_DIGEST {
        stack.push(root_digest_hex.to_string());
    }
    while let Some(dg) = stack.pop() {
        if !seen.insert(dg.clone()) {
            continue;
        }
        match store.get(&dg) {
            Some(bytes) => {
                for child in child_dir_digests(&bytes) {
                    if child != EMPTY_DIRECTORY_DIGEST && !seen.contains(&child) {
                        stack.push(child);
                    }
                }
                collected.insert(dg, bytes);
            }
            None => missing.push(dg),
        }
    }
    missing.sort(); // stable order for the MissingContent reply (and deterministic tests)
    (collected, missing)
}

/// The `DirectoryNode` (field 2) child digests of a serialized REAPI `Directory` -- just enough of
/// a parse to walk the closure; the full model is built later by `build_dir`.
fn child_dir_digests(b: &[u8]) -> Vec<String> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((_, dg)) = parse_dir_node(g) {
                        out.push(dg);
                    }
                }
            }
            (_, w) => r.skip(w),
        }
        if !r.ok {
            break;
        }
    }
    out
}

/// Cheap partial parse: just `input_root_digest` (field 4) without the tree.
/// The lexicographically-first `outputs` key (field 5) without decoding the manifest — the
/// action-identity anchor for slot binding: unlike the input root digest, it is stable across
/// builds AND across input edits (an action keeps its declared outputs while its sources churn).
pub fn peek_first_output(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let mut best: Option<String> = None;
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (5, 2) => {
                let (k, _) = parse_map_entry(r.len_slice()?)?;
                if best.as_deref().is_none_or(|b| k.as_str() < b) {
                    best = Some(k);
                }
            }
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    best
}

pub fn peek_root_digest(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let mut r = Reader::new(data);
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        if key >> 3 == 4 && key & 7 == 2 {
            return digest_hash(r.len_slice()?);
        }
        r.skip(key & 7);
        if !r.ok {
            return None;
        }
    }
    None
}

/// Cheap partial parse: just `mnemonic` (field 1), skipping the tree and every map.
/// Hot-path safe — O(top-level fields) with O(1) length-skips, no allocation but the result.
pub fn peek_mnemonic(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let mut r = Reader::new(data);
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        if key >> 3 == 1 && key & 7 == 2 {
            return r.len_slice().map(string);
        }
        r.skip(key & 7);
        if !r.ok {
            return None;
        }
    }
    None
}

/// `Digest{ string hash = 1; int64 size_bytes = 2; }` -> hex hash.
fn digest_hash(b: &[u8]) -> Option<String> {
    let mut r = Reader::new(b);
    let mut hash = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => hash = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some(hash)
}

fn digest_hash_size(b: &[u8]) -> (String, u64) {
    let mut r = Reader::new(b);
    let mut hash = String::new();
    let mut size = 0u64;
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    hash = string(g);
                }
            }
            (2, 0) => size = r.varint(),
            (_, w) => r.skip(w),
        }
    }
    (hash, size)
}

/// Resolve and walk the root out of `directories` (field 14 = `map<digest_hex, bytes>` holding
/// EVERY directory in the tree, root included -- there is no separate root/children split on
/// the wire; `input_root_digest` is just the entry-point key).
fn build_root(
    root_digest_hex: &str,
    directories: &HashMap<String, &[u8]>,
    host_mapping: &HostMap,
    captured: &HostMap,
    exec_root: Option<&str>,
) -> Result<Dir, String> {
    if root_digest_hex == EMPTY_DIRECTORY_DIGEST {
        return Ok(Dir::default());
    }
    let root_bytes = *directories
        .get(root_digest_hex)
        .ok_or_else(|| format!("no directory blob for input_root_digest {root_digest_hex}"))?;

    // Cheap sanity check: the root we're about to walk is the one Bazel intended. Every other
    // directory's key is trusted as shipped (the hasher that produced input_root_digest already
    // produced these bytes verbatim, with no re-encode -- re-hashing every one of them here would
    // be pure overhead); the root is the single entry point worth the O(1) extra hash.
    let root_hash = sha256_hex(root_bytes);
    if root_hash != root_digest_hex {
        return Err(format!(
            "root digest mismatch: input_root_digest says {root_digest_hex}, root blob hashes to {root_hash}"
        ));
    }

    build_dir(root_bytes, "", root_digest_hex, directories, host_mapping, captured, exec_root, "")
}

/// REAPI `Directory{ repeated FileNode files = 1; repeated DirectoryNode directories = 2;
/// repeated SymlinkNode symlinks = 3; reserved 4; NodeProperties node_properties = 5; }`.
/// `path` is this dir's accumulated path; each leaf's host source is looked up in
/// host_mapping BY PATH.
fn build_dir(
    b: &[u8],
    name: &str,
    digest_hex: &str,
    child_index: &HashMap<String, &[u8]>,
    host_mapping: &HostMap,
    // Session captured-content table from Push (field 2), digest-keyed: digest -> the controller's
    // own captured host path (a `.content/<digest>` COW clone, valid for the controller's
    // lifetime). Resolution rule for a node with digest D: Manifest.host_mapping[D] (our persisted
    // form) > captured[D] > derived exec_root/<tree path>. Content-addressed, so any recorded host
    // is a valid source for every position carrying D.
    captured: &HostMap,
    exec_root: Option<&str>,
    path: &str,
) -> Result<Dir, String> {
    let lookup = |dg: &str| -> Option<&str> {
        if dg.is_empty() {
            return None;
        }
        host_mapping.get(dg).or_else(|| captured.get(dg)).map(|s| s.as_str())
    };
    let mut d = Dir {
        name: name.to_string(),
        digest: digest_hex.to_string(),
        host_path: resolve_host(exec_root, lookup(digest_hex)),
        ..Default::default()
    };
    let mut marker_kind: Option<DirHostKind> = None;
    let mut r = Reader::new(b);
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(f) = parse_file_node(g, host_mapping, captured, exec_root) {
                        d.files.push(f);
                    }
                }
            }
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((dn_name, dn_digest)) = parse_dir_node(g) {
                        let child_path = if path.is_empty() {
                            dn_name.clone()
                        } else {
                            format!("{}/{}", path, dn_name)
                        };
                        if dn_digest == EMPTY_DIRECTORY_DIGEST {
                            // A genuinely empty Directory serializes to zero bytes, so Bazel never
                            // ships a `directories` entry for it -- there's nothing to send. Stop
                            // here instead of looking it up. This digest is also what a real,
                            // non-empty tree-artifact/source-dir collapses to when reached via a
                            // runfiles symlink farm (node_properties excluded from the hash) -- if
                            // the path says we're inside one, hand the morph layer an unverified
                            // candidate for the position a direct reference would use instead.
                            let speculative_host_path = exec_root
                                .filter(|_| !child_path.is_empty())
                                .and_then(|er| strip_runfiles_prefix(&child_path).map(|tail| format!("{er}/{tail}")))
                                .unwrap_or_default();
                            d.directories.push(Dir { name: dn_name, digest: dn_digest, speculative_host_path, ..Default::default() });
                        } else {
                            // Any OTHER DirectoryNode digest that isn't in `directories` is a missing
                            // blob -- a protocol violation. Failing loudly here (instead of
                            // materializing an empty Dir) is the difference between a decode error
                            // that names the digest and a downstream execvp ENOENT with no clue why.
                            let cr = child_index.get(&dn_digest).ok_or_else(|| {
                                format!("no directory blob for digest {dn_digest} (dir {child_path:?})")
                            })?;
                            d.directories.push(build_dir(
                                cr, &dn_name, &dn_digest, child_index, host_mapping, captured, exec_root, &child_path,
                            )?);
                        }
                    }
                }
            }
            (3, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(s) = parse_symlink_node(g) {
                        d.symlinks.push(s);
                    }
                }
            }
            (5, 2) => {
                if let Some(g) = r.len_slice() {
                    marker_kind = node_property_dir_kind(g);
                }
            }
            (_, w) => r.skip(w),
        }
        if !r.ok {
            break;
        }
    }
    if !d.host_path.is_empty() {
        d.host_kind = DirHostKind::Explicit;
    } else if let Some(kind) = marker_kind {
        // No explicit override, but Bazel marked this Directory as a tree artifact or source dir
        // (REAPI node_properties — the wire's only signal for this now): the whole subtree is
        // exactly one real host directory at the default `exec_root/<path>`, same derivation a
        // file uses. The root (`path` empty) is the exec_root itself, never wholesale-clonable.
        if let (Some(er), false) = (exec_root, path.is_empty()) {
            d.host_path = format!("{er}/{path}");
            d.host_kind = kind;
        }
    }
    Ok(d)
}

/// `Directory.node_properties` (field 5) -> REAPI `NodeProperties{ repeated NodeProperty
/// properties = 1; ... }`, `NodeProperty{ string name = 1; string value = 2; }`. Bazel's
/// `MerkleTreeComputer` stamps `is_treeartifact` / `is_sourcedir` on tree-artifact and source-dir
/// Directories — the REAPI replacement for the old explicit `locations` directory entry, which
/// `locations` no longer carries at all.
fn node_property_dir_kind(b: &[u8]) -> Option<DirHostKind> {
    let mut r = Reader::new(b);
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => {
                let g = r.len_slice()?;
                match node_property_name(g).as_deref() {
                    Some("is_treeartifact") => return Some(DirHostKind::TreeArtifact),
                    Some("is_sourcedir") => return Some(DirHostKind::SourceDir),
                    _ => {}
                }
            }
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    None
}

fn node_property_name(b: &[u8]) -> Option<String> {
    let mut r = Reader::new(b);
    let mut name = None;
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return name;
        }
        match (key >> 3, key & 7) {
            (1, 2) => name = r.len_slice().map(string),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return name;
        }
    }
    name
}

/// REAPI `FileNode{ string name = 1; Digest digest = 2; bool is_executable = 4; }`.
/// is_executable is field 4 (field 3 reserved in v2).
/// Host sources are digest-keyed: a file's override is `host_mapping[digest]` (our persisted
/// form) then the session `captured[digest]` tier. Almost every file misses both and stays lazily
/// derived as `exec_root/<tree path>`.
fn parse_file_node(
    b: &[u8],
    host_mapping: &HostMap,
    captured: &HostMap,
    exec_root: Option<&str>,
) -> Option<File> {
    let mut r = Reader::new(b);
    let mut name = String::new();
    let mut digest = String::new();
    let mut size = 0u64;
    let mut exec = false;
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => name = string(r.len_slice()?),
            (2, 2) => {
                let (h, s) = digest_hash_size(r.len_slice()?);
                digest = h;
                size = s;
            }
            (4, 0) => exec = r.varint() != 0,
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    if name.is_empty() {
        return None;
    }
    let mapped = if digest.is_empty() {
        None
    } else {
        host_mapping.get(&digest).or_else(|| captured.get(&digest)).map(|s| s.as_str())
    };
    Some(File { host_path: resolve_host(exec_root, mapped), name, digest, size, executable: exec })
}

/// `DirectoryNode{ string name = 1; Digest digest = 2; }`.
fn parse_dir_node(b: &[u8]) -> Option<(String, String)> {
    let mut r = Reader::new(b);
    let mut name = String::new();
    let mut digest = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => name = string(r.len_slice()?),
            (2, 2) => digest = digest_hash(r.len_slice()?).unwrap_or_default(),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((name, digest))
}

/// `SymlinkNode{ string name = 1; string target = 2; }`.
fn parse_symlink_node(b: &[u8]) -> Option<Symlink> {
    let mut r = Reader::new(b);
    let mut s = Symlink::default();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => s.name = string(r.len_slice()?),
            (2, 2) => s.target = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some(s)
}

/// `map<string,string>` entry: {1: key, 2: value}.
fn parse_map_entry(b: &[u8]) -> Option<(String, String)> {
    let mut r = Reader::new(b);
    let mut k = String::new();
    let mut v = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => v = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((k, v))
}

/// `map<string, Output>` entry: {1: key, 2: Output}. Returns (key, kind, dest); `dest` is empty
/// unless path mapping set it (see `Manifest.output_dests`).
fn parse_output_entry(b: &[u8]) -> Option<(String, String, String)> {
    let mut r = Reader::new(b);
    let mut k = String::new();
    let mut kind = String::new();
    let mut dest = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => (kind, dest) = parse_output_value(r.len_slice()?)?,
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((k, kind, dest))
}

/// `Output{1: type, 2: dest}`: the value of a `Manifest.outputs` entry.
fn parse_output_value(b: &[u8]) -> Option<(String, String)> {
    let mut r = Reader::new(b);
    let mut kind = String::new();
    let mut dest = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => kind = string(r.len_slice()?),
            (2, 2) => dest = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((kind, dest))
}

/// `map<string,bytes>` entry: {1: key, 2: value}. Value stays a borrowed slice -- it's a raw
/// Directory blob and must round-trip byte-for-byte for its digest to still check out.
fn parse_map_entry_bytes<'a>(b: &'a [u8]) -> Option<(String, &'a [u8])> {
    let mut r = Reader::new(b);
    let mut k = String::new();
    let mut v: &[u8] = &[];
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => v = r.len_slice()?,
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((k, v))
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
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
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
        if !r.ok {
            return None;
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

/// `Push{ map<string,bytes> blobs = 1; map<string,Content> content = 2 }` -> owned `(digest hash,
/// Directory bytes)` pairs plus `(digest hash, ContentSource)` leaves. Directory bytes are copied
/// out (they move into the store), not borrowed; a `Content{inline}` likewise owns its bytes.
fn parse_push(b: &[u8]) -> (Vec<(String, Vec<u8>)>, Vec<(String, ContentSource)>) {
    let mut r = Reader::new(b);
    let mut blobs = Vec::new();
    let mut content = Vec::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
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
        if !r.ok {
            break;
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
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => digest = string(r.len_slice()?),
            (2, 2) => source = Some(parse_content_source(r.len_slice()?)?),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
        }
    }
    Some((digest, source?))
}

/// The `Content` message value: `oneof source { bytes inline = 1; string location = 2 }`, plus
/// `Retention retention = 3` (skipped -- hint only). Exactly one source arm is set.
fn parse_content_source(b: &[u8]) -> Option<ContentSource> {
    let mut r = Reader::new(b);
    let mut source: Option<ContentSource> = None;
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            return None;
        }
        match (key >> 3, key & 7) {
            (1, 2) => source = Some(ContentSource::Inline(r.len_slice()?.to_vec())),
            (2, 2) => source = Some(ContentSource::Location(string(r.len_slice()?))),
            (_, w) => r.skip(w),
        }
        if !r.ok {
            return None;
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
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    options.push(string(g));
                }
            }
            (2, 0) => versions.push(r.varint() as u32),
            (2, 2) => {
                let Some(packed) = r.len_slice() else { break };
                let mut pr = Reader::new(packed);
                while pr.i < pr.b.len() {
                    versions.push(pr.varint() as u32);
                    if !pr.ok {
                        break;
                    }
                }
            }
            (_, w) => r.skip(w),
        }
        if !r.ok {
            break;
        }
    }
    (options, versions)
}

/// Pull `exec_root` (field 1) out of a `Collect` message.
fn parse_collect_exec_root(b: &[u8]) -> String {
    let mut r = Reader::new(b);
    let mut exec_root = String::new();
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        match (key >> 3, key & 7) {
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
    while r.i < r.b.len() {
        let key = r.varint();
        if !r.ok {
            break;
        }
        if key >> 3 == 1 && key & 7 == 2 {
            if let Some(g) = r.len_slice() {
                return g.to_vec();
            }
            break;
        }
        r.skip(key & 7);
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

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.out.push(v as u8);
    }
    fn key(&mut self, field: u32, wire: u32) {
        self.varint(((field << 3) | wire) as u64);
    }
    fn bytes(&mut self, field: u32, b: &[u8]) {
        self.key(field, 2);
        self.varint(b.len() as u64);
        self.out.extend_from_slice(b);
    }
    fn str(&mut self, field: u32, s: &str) {
        self.bytes(field, s.as_bytes());
    }
    fn msg(&mut self, field: u32, b: &[u8]) {
        self.bytes(field, b);
    }
    fn uint(&mut self, field: u32, v: u64) {
        self.key(field, 0);
        self.varint(v);
    }
    fn bool(&mut self, field: u32, v: bool) {
        self.uint(field, if v { 1 } else { 0 });
    }
}

/// Inverse of decode: flatten the nested model back into a self-contained REAPI tree (inline
/// `directories`, field 14). This is the on-disk persistence format `adopt` reads back and what the
/// appex consumes -- NOT Bazel's wire manifest. Each `Directory` is serialized once; its SHA-256 is
/// the digest the decoder re-derives. Layout is `tree prefix` then `outputs`; the two are split so a
/// slot whose input tree is unchanged can re-persist fresh outputs (see `encode_outputs`) without
/// re-hashing the tree.
pub fn encode(m: &Manifest) -> Vec<u8> {
    let mut out = encode_tree_prefix(m);
    encode_outputs_into(&mut out, &m.outputs, &m.output_dests, &m.writable_dirs);
    out
}

/// A self-contained manifest MINUS `outputs`/`writable_dirs` (canonical fields 5/6). Those change
/// per action even when the input tree is byte-identical, so a slot caches this once (it carries
/// the re-hashed tree) and appends fresh outputs on every re-persist -- keeping the sticky hot path
/// off the tree re-hash.
pub fn encode_tree_prefix(m: &Manifest) -> Vec<u8> {
    let mut w = Writer::default();
    if let Some(er) = &m.exec_root {
        w.str(2, er);
    }
    if let Some(root) = &m.root {
        let mut children: Vec<(String, Vec<u8>)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut host_mapping: BTreeMap<String, String> = BTreeMap::new();
        let (root_bytes, root_dg, root_size) =
            encode_dir(root, &mut children, &mut seen, &mut host_mapping, m.exec_root.as_deref(), "");
        w.msg(4, &encode_digest(&root_dg, root_size));
        // input_root_digest (field 4) here is the structural re-hash keying field 14; the tree's
        // WIRE identity (what future sticky claims compare against) rides separately in field 19 so
        // decode can restore it.
        if !root.digest.is_empty() && root.digest != root_dg {
            w.str(19, &root.digest);
        }
        for (k, v) in &host_mapping {
            w.msg(16, &encode_map_entry(k, v));
        }
        // field 14: map<string digest, bytes directory>, root included alongside every other dir.
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root_bytes));
        for (dg, bytes) in &children {
            w.msg(14, &encode_map_entry_bytes(dg, bytes));
        }
    }
    if let Some(v) = &m.mnemonic {
        w.str(1, v);
    }
    if let Some(v) = &m.hash_function {
        w.str(3, v);
    }
    w.out
}

/// Just the `outputs`/`writable_dirs` maps (canonical fields 5/6), appended to a cached tree prefix
/// to form a full self-contained manifest. proto3 is order-independent, so appending after field 14
/// is equivalent to inlining.
pub fn encode_outputs(
    outputs: &BTreeMap<String, String>,
    output_dests: &BTreeMap<String, String>,
    writable_dirs: &BTreeMap<String, String>,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_outputs_into(&mut out, outputs, output_dests, writable_dirs);
    out
}

fn encode_outputs_into(
    out: &mut Vec<u8>,
    outputs: &BTreeMap<String, String>,
    output_dests: &BTreeMap<String, String>,
    writable_dirs: &BTreeMap<String, String>,
) {
    let mut w = Writer { out: std::mem::take(out) };
    for (k, kind) in outputs {
        w.msg(5, &encode_output_entry(k, kind, output_dests.get(k).map(String::as_str).unwrap_or("")));
    }
    for (k, v) in writable_dirs {
        w.msg(6, &encode_map_entry(k, v));
    }
    *out = w.out;
}

/// On-wire host_mapping value for a path, or None to omit. In compact mode (exec_root set) a file
/// whose host equals `exec_root/path` is omitted (the decoder derives it); other paths are stored
/// relative to exec_root, or absolute (leading '/') when they fall outside it. Dirs are never
/// omitted — host_path on a dir is the explicit whole-subtree-clone signal the decoder won't derive.
fn host_value(exec_root: Option<&str>, path: &str, host_path: &str, is_file: bool) -> Option<String> {
    let Some(er) = exec_root else { return Some(host_path.to_string()) };
    if is_file && host_path == format!("{er}/{path}") {
        return None;
    }
    Some(host_path.strip_prefix(&format!("{er}/")).map(|s| s.to_string()).unwrap_or_else(|| host_path.to_string()))
}

fn encode_dir(
    d: &Dir,
    children: &mut Vec<(String, Vec<u8>)>,
    seen: &mut HashSet<String>,
    host_mapping: &mut BTreeMap<String, String>,
    exec_root: Option<&str>,
    path: &str,
) -> (Vec<u8>, String, u64) {
    let mut w = Writer::default();
    let mut files: Vec<&File> = d.files.iter().collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    for f in files {
        w.msg(1, &encode_file_node(f));
        if !f.host_path.is_empty() && !f.digest.is_empty() {
            let p = if path.is_empty() {
                f.name.clone()
            } else {
                format!("{}/{}", path, f.name)
            };
            if let Some(v) = host_value(exec_root, &p, &f.host_path, true) {
                host_mapping.insert(f.digest.clone(), v);
            }
        }
    }
    let mut dirs: Vec<&Dir> = d.directories.iter().collect();
    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    for sub in dirs {
        let sub_path = if path.is_empty() {
            sub.name.clone()
        } else {
            format!("{}/{}", path, sub.name)
        };
        let (sub_bytes, sub_dg, sub_size) = encode_dir(sub, children, seen, host_mapping, exec_root, &sub_path);
        w.msg(2, &encode_dir_node(&sub.name, &sub_dg, sub_size));
        if seen.insert(sub_dg.clone()) {
            children.push((sub_dg, sub_bytes));
        }
    }
    let mut syms: Vec<&Symlink> = d.symlinks.iter().collect();
    syms.sort_by(|a, b| a.name.cmp(&b.name));
    for s in syms {
        w.msg(3, &encode_symlink_node(s));
    }
    let dg = sha256_hex(&w.out);
    // Digest-keyed location entry for a wholesale-backed dir — keyed by the digest just computed,
    // which is why it inserts here rather than at entry.
    if !d.host_path.is_empty() && !path.is_empty() {
        if let Some(v) = host_value(exec_root, path, &d.host_path, false) {
            host_mapping.insert(dg.clone(), v);
        }
    }
    let size = w.out.len() as u64;
    (std::mem::take(&mut w.out), dg, size)
}

fn encode_digest(hash: &str, size: u64) -> Vec<u8> {
    let mut w = Writer::default();
    if !hash.is_empty() {
        w.str(1, hash);
    }
    if size != 0 {
        w.uint(2, size);
    }
    w.out
}

fn encode_file_node(f: &File) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, &f.name);
    if !f.digest.is_empty() || f.size != 0 {
        w.msg(2, &encode_digest(&f.digest, f.size));
    }
    if f.executable {
        w.bool(4, true);
    }
    w.out
}

fn encode_dir_node(name: &str, hash: &str, size: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, name);
    w.msg(2, &encode_digest(hash, size));
    w.out
}

fn encode_symlink_node(s: &Symlink) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, &s.name);
    w.str(2, &s.target);
    w.out
}

fn encode_map_entry(k: &str, v: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, k);
    w.str(2, v);
    w.out
}

/// `map<string, Output>` entry: {1: key, 2: Output{1: type, 2: dest}}. `dest` is written only when
/// path mapping set it (see `Manifest.output_dests`).
fn encode_output_entry(k: &str, kind: &str, dest: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, k);
    let mut v = Writer::default();
    v.str(1, kind);
    if !dest.is_empty() {
        v.str(2, dest);
    }
    w.msg(2, &v.out);
    w.out
}

fn encode_map_entry_bytes(k: &str, v: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, k);
    w.bytes(2, v);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            mnemonic: Some("CppCompile".into()),
            hash_function: Some("SHA256".into()),
            exec_root: None,
            outputs: BTreeMap::from([("out/a.o".into(), "file".into())]),
            output_dests: BTreeMap::from([("out/a.o".into(), "/_main/bazel-out/k8/a.o".into())]),
            writable_dirs: BTreeMap::from([("tmp".into(), "/var/tmp/x".into())]),
            root: Some(Dir {
                name: "".into(),
                digest: String::new(),
                host_path: String::new(),
                files: vec![File {
                    name: "top.c".into(),
                    digest: "aa11".into(),
                    host_path: "/host/top.c".into(),
                    size: 42,
                    executable: false,
                }],
                directories: vec![Dir {
                    name: "sub".into(),
                    digest: String::new(),
                    host_path: String::new(),
                    files: vec![File {
                        name: "tool".into(),
                        digest: "bb22".into(),
                        host_path: "/host/tool".into(),
                        size: 7,
                        executable: true,
                    }],
                    symlinks: vec![Symlink { name: "link".into(), target: "../top.c".into() }],
                    directories: vec![],
                    ..Default::default()
                }],
                symlinks: vec![],
                ..Default::default()
            }),
        }
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let bytes = encode(&m);
        let back = decode_manifest(&bytes).expect("decode");

        // Scalars survive.
        assert_eq!(back.mnemonic, m.mnemonic);
        assert_eq!(back.hash_function, m.hash_function);
        assert_eq!(back.outputs, m.outputs);
        assert_eq!(back.output_dests, m.output_dests);
        assert_eq!(back.writable_dirs, m.writable_dirs);

        // Tree shape + leaf fields survive (digests assigned by the encoder for dirs).
        let r = back.root.as_ref().expect("root");
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].name, "top.c");
        assert_eq!(r.files[0].host_path, "/host/top.c");
        assert_eq!(r.files[0].digest, "aa11");
        assert_eq!(r.files[0].size, 42);
        assert_eq!(r.directories.len(), 1);
        let sub = &r.directories[0];
        assert_eq!(sub.name, "sub");
        assert_eq!(sub.files[0].name, "tool");
        assert!(sub.files[0].executable);
        assert_eq!(sub.files[0].host_path, "/host/tool");
        assert_eq!(sub.symlinks[0].target, "../top.c");

        // Root digest is non-empty (SHA-256 of the serialized root Directory) and
        // peek agrees with the full decode.
        assert!(!r.digest.is_empty());
        assert_eq!(peek_root_digest(&bytes).as_deref(), Some(r.digest.as_str()));
    }

    #[test]
    fn persisted_manifest_preserves_the_wire_root_digest() {
        // Production trees arrive with Bazel's input_root_digest as their identity — a different
        // hash domain than the structural field-11 re-hash that keys field 14. adopt()'s sticky
        // matching runs on this identity, so a persist/decode cycle must hand it back verbatim
        // (before field 19 every daemon restart re-morphed every tree: 65 sticky / 32 overlap on
        // a fully-built pool).
        let mut m = sample();
        m.root.as_mut().unwrap().digest = "wire-root-digest-from-bazel".into();
        let back = decode_manifest(&encode(&m)).expect("decode");
        assert_eq!(back.root.unwrap().digest, "wire-root-digest-from-bazel");
    }

    #[test]
    fn compact_exec_root_round_trips_and_shrinks() {
        // Compact mode: host paths under exec_root are derived (omitted) or stored relative; the
        // decoder must reconstruct the exact absolute host paths, and the encoding must be smaller.
        let er = "/cache/execroot";
        let mut m = Manifest {
            exec_root: Some(er.into()),
            root: Some(Dir {
                files: vec![
                    // derivable: host == exec_root/<path> -> omitted from host_mapping
                    File { name: "a.c".into(), digest: "d1".into(), host_path: format!("{er}/a.c"), size: 1, executable: false },
                ],
                directories: vec![Dir {
                    name: "rf".into(),
                    files: vec![
                        // exception: a runfiles file pointing back to a real source under exec_root
                        File { name: "x.js".into(), digest: "d2".into(), host_path: format!("{er}/_main/src/x.js"), size: 2, executable: false },
                        // out-of-tree absolute exception (not under exec_root)
                        File { name: "y".into(), digest: "d3".into(), host_path: "/opt/tool/y".into(), size: 3, executable: true },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let compact = encode(&m);
        // Same manifest WITHOUT exec_root (legacy absolute host_mapping) for a size baseline.
        let mut legacy = m.clone();
        legacy.exec_root = None;
        let legacy_bytes = encode(&legacy);
        assert!(compact.len() < legacy_bytes.len(), "compact ({}) < legacy ({})", compact.len(), legacy_bytes.len());

        let back = decode_manifest(&compact).expect("decode compact");
        assert_eq!(back.exec_root.as_deref(), Some(er));
        let r = back.root.as_ref().unwrap();
        assert_eq!(r.files[0].host_path, "", "derivable host path stays lazy (morph derives exec_root/<path> at placement)");
        let rf = &r.directories[0];
        assert_eq!(rf.files[0].host_path, format!("{er}/_main/src/x.js"), "relative exception reconstructed");
        assert_eq!(rf.files[1].host_path, "/opt/tool/y", "out-of-tree absolute exception preserved");

        let _ = &mut m;
    }

    #[test]
    fn compact_preserves_real_manifest_host_paths() {
        // Opt-in: CFS_REAL_MANIFEST=/path/to/manifest.pb (a captured legacy manifest). Decode it,
        // re-encode in compact mode (exec_root derived from a file's host path), decode again, and
        // assert every file's absolute host path is byte-identical — proving the compact format is
        // lossless on real Bazel tree shapes (runfiles, generated dirs, deep node_modules).
        let Some(path) = std::env::var_os("CFS_REAL_MANIFEST") else { return };
        let bytes = std::fs::read(path).expect("read manifest");
        let legacy = decode_manifest(&bytes).expect("decode legacy");
        let root = legacy.root.as_ref().expect("root");

        // Normalizes the lazy contract: an empty host_path means "derive exec_root/<tree path>",
        // so collecting with the manifest's exec_root yields the absolute path either way.
        fn collect(d: &Dir, path: &str, exec_root: Option<&str>, out: &mut Vec<(String, String)>) {
            for f in &d.files {
                let p = if path.is_empty() { f.name.clone() } else { format!("{path}/{}", f.name) };
                let h = if f.host_path.is_empty() { format!("{}/{p}", exec_root.expect("derived path needs exec_root")) } else { f.host_path.clone() };
                out.push((p, h));
            }
            for sub in &d.directories {
                let p = if path.is_empty() { sub.name.clone() } else { format!("{path}/{}", sub.name) };
                collect(sub, &p, exec_root, out);
            }
        }
        let mut legacy_paths = Vec::new();
        collect(root, "", legacy.exec_root.as_deref(), &mut legacy_paths);
        // exec_root = host_path of a DERIVABLE file (host == exec_root/tree_path) minus its full path.
        let er = legacy_paths
            .iter()
            .find_map(|(p, h)| h.strip_suffix(&format!("/{p}")).map(str::to_string))
            .expect("a file whose host path ends with its tree path");

        let mut compact_model = legacy.clone();
        compact_model.exec_root = Some(er);
        let compact = encode(&compact_model);
        assert!(compact.len() < bytes.len(), "compact {} < legacy {}", compact.len(), bytes.len());
        let back = decode_manifest(&compact).expect("decode compact");

        let mut b = Vec::new();
        collect(back.root.as_ref().unwrap(), "", back.exec_root.as_deref(), &mut b);
        let mut a = legacy_paths.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b, "compact decode reconstructs identical (path, host_path) for every file");
        eprintln!("real manifest: {} -> {} bytes ({:.2}x)", bytes.len(), compact.len(), bytes.len() as f64 / compact.len() as f64);
    }

    #[test]
    fn request_round_trip() {
        let mbytes = encode(&sample());
        // hand-encode a Create request
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

        // destroy
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

        // negotiate
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

    /// Build a wire manifest (input_root_digest only, NO inline field 14) plus the raw Directory
    /// blobs it references, so a test can push some/all into a store and drive `decode_wire`.
    fn wire_manifest_and_blobs() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        // root -> { file a.c } + { dir "sub" -> { file tool } }
        let mut sub = Writer::default();
        let mut tool_dg = Writer::default();
        tool_dg.str(1, "toolhash");
        let mut tool = Writer::default();
        tool.str(1, "tool");
        tool.msg(2, &tool_dg.out);
        sub.msg(1, &tool.out);
        let sub_bytes = sub.out.clone();
        let sub_dg = sha256_hex(&sub_bytes);

        let mut a_dg = Writer::default();
        a_dg.str(1, "ahash");
        let mut a = Writer::default();
        a.str(1, "a.c");
        a.msg(2, &a_dg.out);
        let mut root = Writer::default();
        root.msg(1, &a.out); // files
        root.msg(2, &dir_node("sub", &sub_bytes)); // directories
        let root_bytes = root.out.clone();
        let root_dg = sha256_hex(&root_bytes);

        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);
        let mut w = Writer::default();
        w.msg(4, &root_digest.out); // input_root_digest only -- no field 14
        w.str(2, "/exec/root");

        let blobs = vec![(root_dg, root_bytes), (sub_dg, sub_bytes)];
        (w.out, blobs)
    }

    #[test]
    fn decode_wire_resolves_tree_from_the_store() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        let store = BlobStore::new();
        store.insert_many(blobs);
        match decode_wire(&manifest, &store).expect("decode") {
            ManifestDecode::Ready(m) => {
                let root = m.root.expect("root");
                assert_eq!(root.files[0].name, "a.c");
                let sub = root.directories.iter().find(|d| d.name == "sub").expect("sub");
                assert_eq!(sub.files[0].name, "tool");
            }
            ManifestDecode::Missing(_) => panic!("all blobs present, should be Ready"),
        }
    }

    /// The resolution contract: Manifest.host_mapping (our persisted form, field 16) beats the
    /// session captured-content tier, which beats the exec_root/<tree path> derivation (lazy empty
    /// host_path). Captured values are the controller's OWN absolute paths (resolved at capture
    /// time), so they pass through resolve_host unchanged.
    #[test]
    fn decode_wire_resolves_manifest_then_captured_then_derived() {
        let (mut manifest, blobs) = wire_manifest_and_blobs();
        // host_mapping override for a.c (field 16), keyed by its DIGEST.
        let mut loc = Writer::default();
        loc.str(1, "ahash");
        loc.str(2, "/scratch/a.c");
        let mut w = Writer { out: manifest };
        w.msg(16, &loc.out);
        manifest = w.out;

        let store = BlobStore::new();
        store.insert_many(blobs);
        // Captured content: an entry for a.c that MUST LOSE to the manifest host_mapping, and one
        // for sub/tool that applies (an absolute captured path).
        store.insert_captured("ahash".to_string(), "/pool/.content/ahash".to_string());
        store.insert_captured("toolhash".to_string(), "/pool/.content/toolhash".to_string());

        match decode_wire(&manifest, &store).expect("decode") {
            ManifestDecode::Ready(m) => {
                let root = m.root.expect("root");
                assert_eq!(root.files[0].host_path, "/scratch/a.c", "manifest host_mapping wins over captured");
                let sub = root.directories.iter().find(|d| d.name == "sub").expect("sub");
                assert_eq!(sub.files[0].host_path, "/pool/.content/toolhash", "captured tier used verbatim");
            }
            ManifestDecode::Missing(_) => panic!("all blobs present, should be Ready"),
        }
        // And with nothing captured for a path: stays lazily derived (empty host_path).
        let bare = BlobStore::new();
        let (manifest2, blobs2) = wire_manifest_and_blobs();
        bare.insert_many(blobs2);
        match decode_wire(&manifest2, &bare).expect("decode") {
            ManifestDecode::Ready(m) => {
                let root = m.root.expect("root");
                assert_eq!(root.files[0].host_path, "", "no override anywhere -> derived lazily at placement");
            }
            ManifestDecode::Missing(_) => panic!("should be Ready"),
        }
    }

    #[test]
    fn decode_wire_reports_missing_blobs_without_failing() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        // Push only the root; the child "sub" blob is absent.
        let store = BlobStore::new();
        store.insert_many(blobs[..1].to_vec());
        match decode_wire(&manifest, &store).expect("decode") {
            ManifestDecode::Missing(hashes) => {
                assert_eq!(hashes.len(), 1, "exactly the one absent child blob");
                assert_eq!(hashes[0], blobs[1].0, "the sub-dir digest");
            }
            ManifestDecode::Ready(_) => panic!("child blob missing, should be Missing"),
        }
    }

    #[test]
    fn decode_wire_missing_root_blob_reports_the_root_digest() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        let store = BlobStore::new(); // empty
        match decode_wire(&manifest, &store).expect("decode") {
            ManifestDecode::Missing(hashes) => {
                assert_eq!(hashes, vec![blobs[0].0.clone()], "just the root -- its children are unknown until it arrives");
            }
            ManifestDecode::Ready(_) => panic!("empty store, should be Missing"),
        }
    }

    /// Hand-builds a self-contained Manifest using the LITERAL field numbers — canonical Bazel
    /// fields (mnemonic=1, exec_root=2, hash_function=3, input_root_digest=4, outputs=5,
    /// writable_dirs=6) plus our persistence extensions (directories=14, host_mapping=16),
    /// independent of our own `encode()` — so a future edit that shifts encode and decode in the
    /// same wrong direction still gets caught.
    #[test]
    fn decode_manifest_reads_sandbox_proto_field_numbers() {
        let mut digest = Writer::default();
        digest.str(1, "d1");
        let mut file_node = Writer::default();
        file_node.str(1, "a.c");
        file_node.msg(2, &digest.out);
        let mut root_dir = Writer::default();
        root_dir.msg(1, &file_node.out);
        let root_dg = sha256_hex(&root_dir.out); // must match what build_root recomputes

        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);
        let mut locations_entry = Writer::default();
        locations_entry.str(1, "d1"); // digest-keyed: the file's digest, not its path
        locations_entry.str(2, "/host/a.c");
        let mut output_value = Writer::default();
        output_value.str(1, "file"); // Output.type
        let mut outputs_entry = Writer::default();
        outputs_entry.str(1, "out/a.o");
        outputs_entry.msg(2, &output_value.out); // Output submessage
        let mut writable_entry = Writer::default();
        writable_entry.str(1, "/tmp");
        writable_entry.str(2, "/var/tmp/x");

        let mut w = Writer::default();
        w.msg(4, &root_digest.out); // input_root_digest
        w.str(3, "SHA256"); // hash_function
        w.str(1, "CppCompile"); // mnemonic
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root_dir.out)); // directories[root_dg] = root (persistence)
        w.str(2, "/exec/root"); // exec_root
        w.msg(16, &locations_entry.out); // host_mapping (persistence)
        w.msg(5, &outputs_entry.out); // outputs
        w.msg(6, &writable_entry.out); // writable_dirs

        assert_eq!(peek_root_digest(&w.out).as_deref(), Some(sha256_hex(&root_dir.out).as_str()));
        assert_eq!(peek_mnemonic(&w.out).as_deref(), Some("CppCompile"));

        let m = decode_manifest(&w.out).expect("decode");
        assert_eq!(m.hash_function.as_deref(), Some("SHA256"));
        assert_eq!(m.mnemonic.as_deref(), Some("CppCompile"));
        assert_eq!(m.exec_root.as_deref(), Some("/exec/root"));
        assert_eq!(m.outputs.get("out/a.o").map(String::as_str), Some("file"));
        assert_eq!(m.writable_dirs.get("/tmp").map(String::as_str), Some("/var/tmp/x"));
        let root = m.root.expect("root");
        assert_eq!(root.files[0].name, "a.c");
        assert_eq!(root.files[0].host_path, "/host/a.c");
        // No path mapping in this manifest: Output.dest is unset, so no remap is recorded.
        assert!(m.output_dests.is_empty());
    }

    /// With `--experimental_output_paths=strip`, an output's `Output.dest` (field 2) carries the
    /// UNMAPPED exec path while the map key holds the MAPPED path the action writes to. Decode must
    /// split the two: `outputs` keeps the kind under the mapped key, `output_dests` records the
    /// unmapped destination for Collect. An Output with no `dest` records no remap.
    #[test]
    fn decode_manifest_splits_path_mapped_output_dest() {
        let mut mapped = Writer::default();
        mapped.str(1, "dir"); // Output.type
        mapped.str(2, "/_main/bazel-out/k8-fastbuild/bin/foo"); // Output.dest (unmapped)
        let mut mapped_entry = Writer::default();
        mapped_entry.str(1, "/_main/bazel-out/bin/foo"); // key: mapped in-sandbox path
        mapped_entry.msg(2, &mapped.out);

        let mut plain = Writer::default();
        plain.str(1, "file"); // Output.type, no dest -> no remap
        let mut plain_entry = Writer::default();
        plain_entry.str(1, "/_main/bazel-out/bin/bar.o");
        plain_entry.msg(2, &plain.out);

        let mut w = Writer::default();
        w.str(1, "Action"); // mnemonic, so the manifest is non-empty and decodes
        w.msg(5, &mapped_entry.out);
        w.msg(5, &plain_entry.out);

        let m = decode_manifest(&w.out).expect("decode");
        assert_eq!(m.outputs.get("/_main/bazel-out/bin/foo").map(String::as_str), Some("dir"));
        assert_eq!(m.outputs.get("/_main/bazel-out/bin/bar.o").map(String::as_str), Some("file"));
        assert_eq!(
            m.output_dests.get("/_main/bazel-out/bin/foo").map(String::as_str),
            Some("/_main/bazel-out/k8-fastbuild/bin/foo"),
        );
        // The unmapped output records no remap.
        assert!(!m.output_dests.contains_key("/_main/bazel-out/bin/bar.o"));
    }

    /// One `Directory{ files=1, node_properties=5 }`, optionally carrying a single
    /// `NodeProperty{name}` marker (no value needed for `is_treeartifact`/`is_sourcedir`).
    fn directory_with_marker(file_name: &str, marker: Option<&str>) -> Vec<u8> {
        let mut digest = Writer::default();
        digest.str(1, "fd1");
        let mut file_node = Writer::default();
        file_node.str(1, file_name);
        file_node.msg(2, &digest.out);
        let mut dir = Writer::default();
        dir.msg(1, &file_node.out); // Directory.files
        if let Some(name) = marker {
            let mut prop = Writer::default();
            prop.str(1, name); // NodeProperty.name
            let mut props = Writer::default();
            props.msg(1, &prop.out); // NodeProperties.properties
            dir.msg(5, &props.out); // Directory.node_properties
        }
        dir.out
    }

    fn dir_node(name: &str, child_bytes: &[u8]) -> Vec<u8> {
        let mut digest = Writer::default();
        digest.str(1, &sha256_hex(child_bytes));
        let mut node = Writer::default();
        node.str(1, name);
        node.msg(2, &digest.out);
        node.out
    }

    /// `locations` carries only file-level virtual-output/runfiles mappings now (per the new
    /// SandboxBackendSpawnRunner — tree artifacts and source dirs get no `locations` entry at
    /// all); the wholesale-clone signal for a directory is `Directory.node_properties` instead.
    /// Covers: `is_treeartifact` and `is_sourcedir` both derive the default host path, an
    /// unmarked directory stays unresolved, and an explicit `locations` entry (legacy/our own
    /// re-encodes) still wins over a marker if both are present.
    #[test]
    fn decode_manifest_resolves_dir_host_from_node_properties() {
        let tree_out = directory_with_marker("f.txt", Some("is_treeartifact"));
        let src_dir = directory_with_marker("f.txt", Some("is_sourcedir"));
        let plain = directory_with_marker("f.txt", None);
        // Distinct content from tree_out: digest-keyed locations are content-addressed, so a
        // byte-identical sibling would (correctly) share the override.
        let tree_out2 = directory_with_marker("g.txt", Some("is_treeartifact"));

        let mut root = Writer::default();
        root.msg(2, &dir_node("tree_out", &tree_out));
        root.msg(2, &dir_node("src_dir", &src_dir));
        root.msg(2, &dir_node("plain", &plain));
        root.msg(2, &dir_node("tree_out2", &tree_out2));

        let root_dg = sha256_hex(&root.out); // must match what build_root recomputes
        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);
        let mut explicit_override = Writer::default();
        explicit_override.str(1, &sha256_hex(&tree_out2)); // digest-keyed dir override
        explicit_override.str(2, "/explicit/override");

        let mut w = Writer::default();
        w.msg(4, &root_digest.out); // input_root_digest
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root.out)); // directories[root_dg] = root
        for c in [&tree_out, &src_dir, &plain, &tree_out2] {
            w.msg(14, &encode_map_entry_bytes(&sha256_hex(c), c)); // directories[dg] = c
        }
        w.str(2, "/exec/root"); // exec_root
        w.msg(16, &explicit_override.out); // locations: explicit override for tree_out2 only

        let m = decode_manifest(&w.out).expect("decode");
        let root = m.root.expect("root");
        let by_name = |n: &str| root.directories.iter().find(|d| d.name == n).unwrap();

        assert_eq!(by_name("tree_out").host_path, "/exec/root/tree_out", "is_treeartifact derives default");
        assert_eq!(by_name("tree_out").host_kind, DirHostKind::TreeArtifact);
        assert_eq!(by_name("src_dir").host_path, "/exec/root/src_dir", "is_sourcedir derives default");
        assert_eq!(by_name("src_dir").host_kind, DirHostKind::SourceDir);
        assert_eq!(by_name("plain").host_path, "", "no marker, no override -> not wholesale-clonable");
        assert_eq!(by_name("plain").host_kind, DirHostKind::None);
        assert_eq!(by_name("tree_out2").host_path, "/explicit/override", "explicit locations entry wins over the marker");
        assert_eq!(by_name("tree_out2").host_kind, DirHostKind::Explicit, "provenance reflects the override, not the marker");
    }

    /// A `DirectoryNode.digest` that resolves to nothing in `directories` is a missing blob --
    /// decode must fail loudly (None), never materialize an empty `Dir` in its place. That silent
    /// fallback is exactly what turned a wire bug into a downstream `execvp` ENOENT with no signal
    /// pointing back at the manifest.
    #[test]
    fn decode_manifest_fails_on_directory_node_with_no_matching_blob() {
        let real_child = directory_with_marker("f.txt", Some("is_treeartifact"));

        let mut root = Writer::default();
        root.msg(2, &dir_node("present", &real_child));
        // References a digest for content never added to `directories` below.
        root.msg(2, &dir_node("missing", b"this blob is never shipped"));

        let root_dg = sha256_hex(&root.out);
        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);

        let mut w = Writer::default();
        w.msg(4, &root_digest.out);
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root.out));
        w.msg(14, &encode_map_entry_bytes(&sha256_hex(&real_child), &real_child)); // only "present"'s blob, not "missing"'s

        assert!(decode_manifest(&w.out).is_none(), "missing directory blob must reject the whole manifest");
    }

    /// A DirectoryNode pointing at the well-known empty-Directory digest is a real, legitimately
    /// empty directory, not a missing blob -- Bazel never ships a `directories` entry for it (an
    /// all-default proto3 message serializes to zero bytes), so it must decode successfully with
    /// no children, not be rejected as a lookup miss.
    #[test]
    fn decode_manifest_resolves_empty_directory_without_a_shipped_blob() {
        let mut root = Writer::default();
        root.msg(2, &dir_node("empty_dir", b"")); // digest = SHA-256("") = EMPTY_DIRECTORY_DIGEST

        let root_dg = sha256_hex(&root.out);
        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);

        let mut w = Writer::default();
        w.msg(4, &root_digest.out);
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root.out)); // no entry for empty_dir's digest

        let m = decode_manifest(&w.out).expect("decode");
        let root = m.root.expect("root");
        let empty_dir = &root.directories[0];
        assert_eq!(empty_dir.name, "empty_dir");
        assert_eq!(empty_dir.digest, EMPTY_DIRECTORY_DIGEST);
        assert!(empty_dir.files.is_empty());
        assert!(empty_dir.directories.is_empty());
        assert!(empty_dir.speculative_host_path.is_empty(), "no runfiles segment in the path -> no candidate");
    }

    #[test]
    fn strip_runfiles_prefix_finds_the_repo_relative_tail() {
        assert_eq!(
            strip_runfiles_prefix("bin.runfiles/_main/node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn"),
            Some("node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn")
        );
        assert_eq!(strip_runfiles_prefix("node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn"), None, "no .runfiles/ segment at all");
        assert_eq!(strip_runfiles_prefix("bin.runfiles/_main"), None, "no tail after the repo segment");
    }

    /// The exact scenario chased live via `--sandbox_debug`: a tree-artifact/source-dir reached
    /// through a runfiles symlink farm collapses to the empty-Directory digest (node_properties
    /// excluded from the hash), same as a genuinely empty dir -- but its accumulated path runs
    /// through `<target>.runfiles/<repo>/`, so it gets a speculative_host_path candidate at the
    /// same repo-relative position a direct reference would resolve to.
    #[test]
    fn decode_manifest_gives_a_runfiles_nested_empty_dir_a_speculative_host_path() {
        let mut main_repo = Writer::default();
        main_repo.msg(2, &dir_node("acorn", b"")); // empty digest -- the runfiles-nested reference

        let mut runfiles = Writer::default();
        runfiles.msg(2, &dir_node("_main", &main_repo.out));

        let mut root = Writer::default();
        root.msg(2, &dir_node("bin.runfiles", &runfiles.out));

        let root_dg = sha256_hex(&root.out);
        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);

        let mut w = Writer::default();
        w.msg(4, &root_digest.out);
        w.str(2, "/exec/root");
        w.msg(14, &encode_map_entry_bytes(&root_dg, &root.out));
        w.msg(14, &encode_map_entry_bytes(&sha256_hex(&runfiles.out), &runfiles.out));
        w.msg(14, &encode_map_entry_bytes(&sha256_hex(&main_repo.out), &main_repo.out));

        let m = decode_manifest(&w.out).expect("decode");
        let root = m.root.expect("root");
        let acorn = &root.directories[0].directories[0].directories[0];
        assert_eq!(acorn.name, "acorn");
        assert_eq!(acorn.digest, EMPTY_DIRECTORY_DIGEST);
        assert_eq!(acorn.speculative_host_path, "/exec/root/acorn", "path is bin.runfiles/_main/acorn -> stripped tail is just acorn");
    }

    /// `input_root_digest` must match the SHA-256 of the assembled root bytes -- a corrupted or
    /// mismatched root is rejected rather than silently walked.
    #[test]
    fn decode_manifest_fails_on_root_digest_mismatch() {
        let mut file_node = Writer::default();
        file_node.str(1, "a.c");
        let mut root = Writer::default();
        root.msg(1, &file_node.out);

        let mut root_digest = Writer::default();
        root_digest.str(1, "not-the-real-hash");
        let mut w = Writer::default();
        w.msg(4, &root_digest.out);
        w.msg(14, &encode_map_entry_bytes("not-the-real-hash", &root.out));

        assert!(decode_manifest(&w.out).is_none(), "root digest mismatch must reject the whole manifest");
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
