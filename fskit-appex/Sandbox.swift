import Foundation
import CryptoKit

// MARK: - Canonical manifest model
//
// ONE definition shared by the appex (decode), the controller (decode + patch),
// and the harness (encode) — compiled into each target via the synchronized
// `shared/` folder. The authoritative cross-language contract is
// `proto/sandboxfs.proto` (Bazel's `src/main/protobuf/sandboxfs.proto`).
// The proto wire format is the ONLY accepted manifest encoding; `Codable`
// (snake_case keys) is kept solely for the human-facing debug dump
// (`dumpManifestIfRequested`), never as a wire input.
//
// WIRE SHAPE (the new contract): the input tree is a standard REAPI Merkle tree
// (`build.bazel.remote.execution.v2` Tree/Directory/FileNode/DirectoryNode/
// SymlinkNode) at field 14, content-addressed and host-agnostic; the root key is
// `input_root_digest` (field 11); and where each blob's bytes live on THIS host
// is kept out of the tree in `locations` (field 16, tree path -> host path).
// Fields 1-10 are the CONTROLLER's private prefix — Bazel never emits them. This
// in-memory model FLATTENS the REAPI tree back into a nested `ManifestDir`/
// `ManifestFile`/`ManifestSymlink` (the shape every consumer already expects),
// resolving each FileNode's `host_path` from `host_mapping` and each child
// Directory by digest from the flat `Tree.children` list.
//
// Digests are lowercase-hex strings end to end: the REAPI `Digest.hash` field is
// already hex, so no bytes<->hex conversion happens anywhere. The CAS index,
// nodeCache, and affinity signatures all key on these strings. A directory's
// digest is the SHA-256 of its serialized REAPI `Directory` (what Bazel computes
// for remote execution); the decoder recomputes it over the on-wire bytes only
// to index `Tree.children`, since a REAPI `Directory` carries no self-digest.

struct Manifest: Codable {
    /// Controller's per-checkout reconfigure token (proto field 1, in the 1-10
    /// controller prefix). Bazel never sets it; the controller append-patches it
    /// so the appex always sees an id change and (re)applies. The sandbox id /
    /// destroy key is NOT here — it rides on `Request.sandbox_id`.
    var id: String
    var mnemonic: String?                   // proto field 13
    /// Read-only input root, flattened from the REAPI `Tree` (field 14); its
    /// `digest` is `input_root_digest` (field 11).
    var root: ManifestDir?
    var outputs: [String: String]?          // 17
    var writableDirs: [String: String]?     // 18
    var hashFunction: String?               // 12
    /// Controller-set (proto field 7, controller prefix): true ⇒ the appex builds
    /// the whole tree (fresh slot); false ⇒ it morphs the existing tree in place.
    var fullBuild: Bool?
    enum CodingKeys: String, CodingKey {
        case id, mnemonic, root, outputs
        case hashFunction = "hash_function"
        case writableDirs = "writable_dirs"
        case fullBuild = "_full_build"
    }
}

struct ManifestDir: Codable {
    var name: String                        // 1
    var digest: String                      // 2 (bytes on the wire)
    var files: [ManifestFile]?              // 3
    var directories: [ManifestDir]?         // 4
    var symlinks: [ManifestSymlink]?        // 5
}

struct ManifestFile: Codable {
    var name: String                        // 1
    var digest: String                      // 2 (bytes on the wire)
    var hostPath: String                    // 3
    var size: UInt64                        // 4
    var executable: Bool?                   // 5
    enum CodingKeys: String, CodingKey {
        case name, digest, size, executable
        case hostPath = "host_path"
    }
}

struct ManifestSymlink: Codable {
    var name: String                        // 1
    var target: String                      // 2
}

extension ManifestFile {
    /// mach-O suffixes dyld maps + AMFI validates even without the exec bit (native
    /// node addons, shared libs, loadable bundles) — they pay the same per-dlopen
    /// code-sign stall through FSKit as exec-bit binaries.
    static let dyldLoadableSuffixes = [".node", ".dylib", ".so", ".bundle"]

    /// True when this file projects as a HOST SYMLINK instead of an FSKit-backed
    /// file. A binary exec'd/dlopen'd from the mount pays synchronous AMFI
    /// code-signature validation read back through the (slow) FSKit mount on EVERY
    /// launch; as a host symlink the kernel resolves to the real APFS file — amfid
    /// validates the cached copy and content reads bypass FSKit entirely.
    ///
    /// Scope: mach-O LOADABLES promote ANYWHERE — every dlopen of an FSKit-backed
    /// `.node`/`.dylib` pays the AMFI signature read through the mount per action
    /// (amfid caches by inode, and mount inodes are per-slot), while a host
    /// symlink validates once per build against the stable execroot inode.
    /// EXEC-BIT files promote only under `external/` (toolchain binaries): the
    /// historical NpmPackageExtract breakage came from promoting exec-bit
    /// SCRIPTS inside bazel-out packages wholesale — that class stays FSKit-backed.
    ///
    /// ONE definition shared by the appex (projection, reconcile identity) and the
    /// controller (prewarm skip) — the two sides MUST agree, and the predicate must
    /// stay a pure function of the node (the reconcile Merkle-skips unchanged dirs,
    /// so an unchanged file's projection has to be identical across checkouts).
    var projectsAsHostSymlink: Bool {
        if Self.dyldLoadableSuffixes.contains(where: { name.hasSuffix($0) }) { return true }
        // PERF: third-party package content in the pnpm store is read-dominated, and serving
        // every leaf through FSKit is the bulk of per-build read cost. Promote STORE CONTENT
        // FILES (leaves under .aspect_rules_js/) to host symlinks so reads hit real APFS and
        // bypass FSKit (and skip prewarm). Safe because this only ever promotes a FILE: every
        // directory stays FSKit-backed, so readdir/lookup along the path see only declared
        // entries — a leaf host symlink can't be used to enumerate undeclared siblings. The
        // sole residual (an action realpath'ing a leaf and walking `..` to the store root) is
        // contained by the rules_js fs-patches, which must stay enabled (register.cjs).
        if hostPath.range(of: "/.aspect_rules_js/") != nil { return true }
        let isExec = executable ?? false
        return isExec && hostPath.range(of: "/external/") != nil
    }
}

// MARK: - Reconfigure response (control-file read-back)

/// What the appex returns through `<mount>/sandboxfs_reconf` after a reconfigure.
struct ReconfigResponse {
    var id: String? = nil          // echoes the applied manifest token
    var error: String? = nil
    var invalidate: [String] = []  // conflict paths: controller unlinks + re-reconfigures
    var touch: [String] = []       // pre-existing dirs that gained names (negative purge)
    var sealed: Bool = false       // appex auto-sealed (clean reconcile); skip purge+seal
    // Appex-side self-timing, so the controller's recon-split can decompose the
    // reconfigure RPC without guessing: manifest read+parse µs, apply/reconcile
    // µs, and whether the decoded-tree cache hit.
    var parseUs: UInt32 = 0
    var applyUs: UInt32 = 0
    /// applyUs decomposition: target-index time (cached ⇒ ~0) vs the reconcile/
    /// build walk — settles WHERE a slow apply lives instead of arguing about it.
    var indexUs: UInt32 = 0
    var walkUs: UInt32 = 0
    var treeCacheHit: Bool = false
    /// First 12 hex chars of the applied manifest's root Merkle digest — logged
    /// per create so cross-build digest INSTABILITY (cache-defeating) is visible
    /// directly in the recon-split lines.
    var rootDg: String = ""
}


// MARK: - Request / Response (controller stdio protocol)

/// Length-delimited framing for the controller↔Bazel stdio stream: a base-128
/// varint byte-count followed by the message bytes. This is exactly protobuf's
/// `writeDelimitedTo`/`parseDelimitedFrom` (a.k.a. `BinaryDelimited`) wire format
/// — the same framing Bazel's persistent-worker protocol uses — so the Bazel side
/// can frame with the stock helper and we decode it here. (Supersedes the earlier
/// fixed `u32 LE` length prefix; we own both sides, so the cutover is atomic.)
enum DelimitedFrame {
    /// `varint(payload.count) + payload`.
    static func encode(_ payload: Data) -> Data {
        var frame = Data()
        var v = UInt64(payload.count)
        while v >= 0x80 { frame.append(UInt8(v & 0x7F) | 0x80); v >>= 7 }
        frame.append(UInt8(v))
        frame.append(payload)
        return frame
    }

    /// Decode the varint length prefix by pulling one byte at a time from `next`
    /// (which returns nil at EOF). Returns the body length, or nil on EOF before a
    /// complete varint (clean stream end or truncation) or a malformed/overlong
    /// varint. The caller then reads exactly that many body bytes.
    static func readLength(_ next: () -> UInt8?) -> UInt64? {
        var shift: UInt64 = 0, v: UInt64 = 0
        while shift <= 63 {
            guard let b = next() else { return nil }
            v |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return v }
            shift += 7
        }
        return nil   // varint exceeds 64 bits: corrupt frame
    }
}

/// One framed request from Bazel: `varint length + Request proto`. The sandbox id
/// (the destroy key) rides on the Request itself — shared by create and destroy —
/// not inside the manifest. The manifest bytes are kept RAW so the controller can
/// append-patch its prefix (id token + full_build) without re-encoding the tree.
enum WireRequest {
    case create(rid: UInt64, sandboxId: String, manifestBytes: Data)
    case destroy(rid: UInt64, sandboxId: String)
}

/// One framed reply: `Response{rid, oneof result}`. Exactly one arm is set; the
/// `error` arm means the op failed.
struct WireResponse {
    enum Result {
        case created(path: String, skipOutputCopy: Bool, eagerCreateOutputs: Bool)
        case destroyed
        case error(String)
    }
    var rid: UInt64
    var result: Result

    /// The error message when this is an `error` reply, else nil.
    var errorMessage: String? {
        if case .error(let m) = result { return m }
        return nil
    }
}

// MARK: - proto3 wire codec (hand-rolled; no swift-protobuf dependency)
//
// The wire format is just varints and length-delimited fields, and the schema
// is fixed — a specialized reader/writer is ~200 lines, allocation-light, and
// keeps the project dependency-free. Unknown fields are skipped (forward
// compatible); repeated scalars take the LAST value (proto3 semantics), which
// is what makes `patch` work by appending.
enum ProtoWire {

    // MARK: Reader

    private struct Reader {
        let p: UnsafePointer<UInt8>
        var i: Int
        let end: Int
        var ok = true

        init(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) {
            self.p = p; self.i = range.lowerBound; self.end = range.upperBound
        }

        mutating func varint() -> UInt64 {
            var shift: UInt64 = 0, v: UInt64 = 0
            while i < end {
                let b = p[i]; i += 1
                v |= UInt64(b & 0x7F) << shift
                if b & 0x80 == 0 { return v }
                shift += 7
                if shift > 63 { break }
            }
            ok = false
            return 0
        }

        /// Length-delimited payload range; nil (and ok=false) on truncation.
        mutating func lenRange() -> Range<Int>? {
            let n = Int(bitPattern: UInt(varint()))
            guard ok, n >= 0, end - i >= n else { ok = false; return nil }
            defer { i += n }
            return i..<(i + n)
        }

        mutating func skip(_ wire: UInt64) {
            switch wire {
            case 0: _ = varint()
            case 1: i += 8; if i > end { ok = false }
            case 2: _ = lenRange()
            case 5: i += 4; if i > end { ok = false }
            default: ok = false
            }
        }

        func string(_ r: Range<Int>) -> String {
            String(decoding: UnsafeBufferPointer(start: p + r.lowerBound, count: r.count), as: UTF8.self)
        }
    }

    // MARK: hashing / hex helpers

    /// Lowercase hex of a byte sequence (the in-memory digest representation).
    private static func hexOf<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var s = [UInt8](); s.reserveCapacity(16)
        for b in bytes { s.append(digits[Int(b >> 4)]); s.append(digits[Int(b & 0xF)]) }
        return String(decoding: s, as: UTF8.self)
    }

    /// SHA-256 (hex) of a slice of the wire buffer — used to recompute a child
    /// `Directory`'s digest from its on-wire serialized bytes so we can resolve
    /// the digest references in its parent's DirectoryNodes. Pinned to SHA-256:
    /// the proto contract states directory digests are SHA-256 of the serialized
    /// Directory (file content digests come verbatim off the wire, hash-agnostic).
    private static func sha256Hex(_ p: UnsafePointer<UInt8>, _ r: Range<Int>) -> String {
        var h = SHA256()
        h.update(bufferPointer: UnsafeRawBufferPointer(start: p + r.lowerBound, count: r.count))
        return hexOf(h.finalize())
    }

    private static func sha256Hex(_ data: Data) -> String { hexOf(SHA256.hash(data: data)) }

    // MARK: Manifest decode

    static func decodeManifest(_ data: Data, skipRoot: Bool = false) -> Manifest? {
        guard !data.isEmpty else { return nil }
        return data.withUnsafeBytes { raw -> Manifest? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return parseManifest(base, 0..<raw.count, skipRoot: skipRoot)
        }
    }

    /// Cheap partial parse: the root digest (`input_root_digest`, field 11) without
    /// touching the tree. Lets the appex key a decoded-tree cache and skip the full
    /// REAPI decode (and its per-child SHA-256 indexing) when the same tree bytes
    /// are re-sent (forced rebuilds, incremental re-runs of the same action).
    static func peekRootDigest(_ data: Data) -> String? {
        guard !data.isEmpty else { return nil }
        return data.withUnsafeBytes { raw -> String? in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            var r = Reader(p, 0..<raw.count)
            while r.i < r.end {
                let key = r.varint(); guard r.ok else { return nil }
                if key >> 3 == 11, key & 7 == 2 {           // input_root_digest (Digest)
                    guard let g = r.lenRange() else { return nil }
                    return digestHash(p, g)
                }
                r.skip(key & 7)
                guard r.ok else { return nil }
            }
            return nil
        }
    }

    private static func parseManifest(_ p: UnsafePointer<UInt8>, _ range: Range<Int>, skipRoot: Bool = false) -> Manifest? {
        var r = Reader(p, range)
        var m = Manifest(id: "")
        var outputs: [String: String] = [:]
        var writable: [String: String] = [:]
        var hostMapping: [String: String] = [:]
        var rootDigestHex = ""
        var treeRange: Range<Int>? = nil
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            // Controller prefix (fields 1-10): id token + full_build.
            case (1, 2): guard let g = r.lenRange() else { return nil }; m.id = r.string(g)
            case (7, 0): m.fullBuild = r.varint() != 0
            // Bazel fields.
            case (11, 2): guard let g = r.lenRange() else { return nil }; rootDigestHex = digestHash(p, g) ?? ""
            case (12, 2): guard let g = r.lenRange() else { return nil }; m.hashFunction = r.string(g)
            case (13, 2): guard let g = r.lenRange() else { return nil }; m.mnemonic = r.string(g)
            case (14, 2): guard let g = r.lenRange() else { return nil }; treeRange = g
            case (16, 2):
                guard let g = r.lenRange(), let e = parseMapEntry(p, g) else { return nil }
                hostMapping[e.0] = e.1
            case (17, 2):
                guard let g = r.lenRange(), let e = parseMapEntry(p, g) else { return nil }
                outputs[e.0] = e.1
            case (18, 2):
                guard let g = r.lenRange(), let e = parseMapEntry(p, g) else { return nil }
                writable[e.0] = e.1
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        if !outputs.isEmpty { m.outputs = outputs }
        if !writable.isEmpty { m.writableDirs = writable }
        // Flatten the REAPI tree into the nested model (unless the caller already
        // holds it via the digest-keyed cache).
        if !skipRoot, let tr = treeRange {
            m.root = buildTree(p, tr, rootDigestHex: rootDigestHex, hostMapping: hostMapping)
        }
        return m
    }

    /// `Digest{ string hash = 1; int64 size_bytes = 2; }` — return the hex hash.
    private static func digestHash(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> String? {
        var r = Reader(p, range)
        var hash = ""
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; hash = r.string(g)
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        return hash
    }

    /// `Digest` → (hex hash, size_bytes). size_bytes carries the file content size.
    private static func digestHashSize(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> (String, UInt64) {
        var r = Reader(p, range)
        var hash = ""; var size: UInt64 = 0
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            switch (key >> 3, key & 7) {
            case (1, 2): if let g = r.lenRange() { hash = r.string(g) }
            case (2, 0): size = r.varint()
            default: r.skip(key & 7)
            }
        }
        return (hash, size)
    }

    /// Decode the REAPI `Tree{ Directory root = 1; repeated Directory children = 2; }`
    /// into the nested `ManifestDir`. Children are referenced by digest from their
    /// parents' DirectoryNodes, so we first index every child by the SHA-256 of its
    /// on-wire bytes, then recurse from the root resolving each reference.
    private static func buildTree(_ p: UnsafePointer<UInt8>, _ range: Range<Int>,
                                  rootDigestHex: String, hostMapping: [String: String]) -> ManifestDir? {
        var r = Reader(p, range)
        var rootRange: Range<Int>? = nil
        var childRanges: [Range<Int>] = []
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; rootRange = g
            case (2, 2): guard let g = r.lenRange() else { return nil }; childRanges.append(g)
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        guard let rootRange else { return nil }
        var childIndex = [String: Range<Int>](minimumCapacity: childRanges.count)
        for cr in childRanges {
            let dg = sha256Hex(p, cr)
            if childIndex[dg] == nil { childIndex[dg] = cr }
        }
        return buildDir(p, rootRange, name: "", digestHex: rootDigestHex,
                        childIndex: childIndex, hostMapping: hostMapping, path: "")
    }

    /// `Directory{ repeated FileNode files = 1; repeated DirectoryNode directories = 2;
    /// repeated SymlinkNode symlinks = 3; }`. Resolves each DirectoryNode against the
    /// digest index and recurses. `path` is this directory's accumulated path (from the
    /// tree root); each leaf's host source is looked up in host_mapping BY PATH — the
    /// Merkle tree stays content-identical, so the namespace→host-source side channel is
    /// keyed by path (one entry per input), never by digest (which N paths can share).
    private static func buildDir(_ p: UnsafePointer<UInt8>, _ range: Range<Int>,
                                 name: String, digestHex: String,
                                 childIndex: [String: Range<Int>],
                                 hostMapping: [String: String], path: String) -> ManifestDir {
        var d = ManifestDir(name: name, digest: digestHex)
        var files: [ManifestFile] = []
        var dirs: [ManifestDir] = []
        var syms: [ManifestSymlink] = []
        var r = Reader(p, range)
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            switch (key >> 3, key & 7) {
            case (1, 2):
                if let g = r.lenRange(), let f = parseFileNode(p, g, path, hostMapping) { files.append(f) }
            case (2, 2):
                if let g = r.lenRange(), let dn = parseDirNode(p, g) {
                    let childPath = path.isEmpty ? dn.name : path + "/" + dn.name
                    if let cr = childIndex[dn.digest] {
                        dirs.append(buildDir(p, cr, name: dn.name, digestHex: dn.digest,
                                             childIndex: childIndex, hostMapping: hostMapping, path: childPath))
                    } else {
                        // No expansion in Tree.children (e.g. a wholesale host-mapped
                        // subtree Bazel chose not to enumerate): keep the node, empty.
                        dirs.append(ManifestDir(name: dn.name, digest: dn.digest))
                    }
                }
            case (3, 2):
                if let g = r.lenRange(), let s = parseSymlinkNode(p, g) { syms.append(s) }
            default: r.skip(key & 7)
            }
            guard r.ok else { break }
        }
        if !files.isEmpty { d.files = files }
        if !dirs.isEmpty { d.directories = dirs }
        if !syms.isEmpty { d.symlinks = syms }
        return d
    }

    /// REAPI `FileNode{ string name = 1; Digest digest = 2; reserved 3;
    /// bool is_executable = 4; reserved 5; NodeProperties node_properties = 6; }`.
    /// NOTE: `is_executable` is field 4 — field 3 is reserved in v2 (it was
    /// `OutputFile`'s slot), so reading the exec bit anywhere else silently yields
    /// false (absent field) without disturbing name/digest.
    private static func parseFileNode(_ p: UnsafePointer<UInt8>, _ range: Range<Int>,
                                      _ parentPath: String, _ hostMapping: [String: String]) -> ManifestFile? {
        var r = Reader(p, range)
        var name = "", digest = ""; var size: UInt64 = 0; var exec = false
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; name = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; (digest, size) = digestHashSize(p, g)
            case (4, 0): exec = r.varint() != 0
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        guard !name.isEmpty else { return nil }
        // Resolve host source BY PATH (not digest): the file's full path from the tree root.
        let fullPath = parentPath.isEmpty ? name : parentPath + "/" + name
        return ManifestFile(name: name, digest: digest, hostPath: hostMapping[fullPath] ?? "",
                            size: size, executable: exec ? true : nil)
    }

    /// `DirectoryNode{ string name = 1; Digest digest = 2; }`.
    private static func parseDirNode(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> (name: String, digest: String)? {
        var r = Reader(p, range)
        var name = "", digest = ""
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; name = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; digest = digestHash(p, g) ?? ""
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        return (name, digest)
    }

    /// `SymlinkNode{ string name = 1; string target = 2; }`.
    private static func parseSymlinkNode(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> ManifestSymlink? {
        var r = Reader(p, range)
        var s = ManifestSymlink(name: "", target: "")
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; s.name = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; s.target = r.string(g)
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        return s
    }

    /// `map<string,string>` entry: {1: key, 2: value}.
    private static func parseMapEntry(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> (String, String)? {
        var r = Reader(p, range)
        var k = "", v = ""
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; k = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; v = r.string(g)
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        return (k, v)
    }

    // MARK: Append-patch (the hot-path id/full_build rewrite)

    /// Stamp the controller's prefix — `id` token (field 1) and `full_build`
    /// (field 7), both in the reserved 1-10 controller range — onto Bazel's raw
    /// manifest WITHOUT re-encoding the tree. Bazel never emits these fields, but
    /// even if it did, proto3 concatenation semantics make the last occurrence of
    /// a scalar win, so appending is a valid (and O(1)) patch.
    static func patch(_ raw: Data, id: String, fullBuild: Bool) -> Data {
        var w = Writer()
        w.out = raw
        w.str(1, id)
        w.bool(7, fullBuild)
        return w.out
    }

    // MARK: Writer / encode (doctor probe, harness, tests — never the hot path)

    private struct Writer {
        var out = Data()
        mutating func varint(_ v: UInt64) {
            var v = v
            while v >= 0x80 { out.append(UInt8(v & 0x7F) | 0x80); v >>= 7 }
            out.append(UInt8(v))
        }
        mutating func key(_ field: Int, _ wire: Int) { varint(UInt64(field << 3 | wire)) }
        mutating func str(_ field: Int, _ s: String) { bytes(field, Data(s.utf8)) }
        mutating func bytes(_ field: Int, _ b: Data) {
            key(field, 2); varint(UInt64(b.count)); out.append(b)
        }
        mutating func msg(_ field: Int, _ b: Data) { bytes(field, b) }
        mutating func uint(_ field: Int, _ v: UInt64) { key(field, 0); varint(v) }
        mutating func bool(_ field: Int, _ v: Bool) { uint(field, v ? 1 : 0) }
    }

    // MARK: Manifest encode (doctor probe, harness, tests — never the hot path)
    //
    // The inverse of decode: flatten the nested model back into a REAPI `Tree`.
    // Each `Directory` is serialized ONCE; its SHA-256 is both the digest written
    // into the parent's DirectoryNode and the key the decoder re-derives from the
    // same on-wire bytes, so encode↔decode round-trips by construction. Identical
    // subtrees collapse to one `Tree.children` entry (deduped by digest). Host
    // paths are lifted out of the tree into `host_mapping` (first path wins per
    // digest, matching the Java builder's putIfAbsent).

    static func encode(_ m: Manifest) -> Data {
        var w = Writer()
        if !m.id.isEmpty { w.str(1, m.id) }                 // controller prefix: token
        if let v = m.fullBuild { w.bool(7, v) }             // controller prefix: full_build
        if let root = m.root {
            var children: [(digest: String, bytes: Data)] = []
            var seen = Set<String>()
            var hostMapping: [String: String] = [:]
            let (rootBytes, rootDg, rootSize) = encodeDir(root, &children, &seen, &hostMapping, "")
            w.msg(11, encodeDigest(rootDg, rootSize))       // input_root_digest
            for (k, v) in hostMapping.sorted(by: { $0.key < $1.key }) { w.msg(16, encodeMapEntry(k, v)) }
            for (k, v) in (m.outputs ?? [:]).sorted(by: { $0.key < $1.key }) { w.msg(17, encodeMapEntry(k, v)) }
            for (k, v) in (m.writableDirs ?? [:]).sorted(by: { $0.key < $1.key }) { w.msg(18, encodeMapEntry(k, v)) }
            var tree = Writer()
            tree.msg(1, rootBytes)                          // Tree.root
            for c in children { tree.msg(2, c.bytes) }      // Tree.children
            w.msg(14, tree.out)
        } else {
            for (k, v) in (m.outputs ?? [:]).sorted(by: { $0.key < $1.key }) { w.msg(17, encodeMapEntry(k, v)) }
            for (k, v) in (m.writableDirs ?? [:]).sorted(by: { $0.key < $1.key }) { w.msg(18, encodeMapEntry(k, v)) }
        }
        if let v = m.mnemonic { w.str(13, v) }
        if let v = m.hashFunction { w.str(12, v) }
        return w.out
    }

    /// Serialize one REAPI `Directory`; returns (bytes, digest hex, byte size) and
    /// registers descendant directories in `children`/`seen` and file paths in
    /// `hostMapping`. Children sorted by name so the digest is canonical.
    private static func encodeDir(_ d: ManifestDir,
                                  _ children: inout [(digest: String, bytes: Data)],
                                  _ seen: inout Set<String>,
                                  _ hostMapping: inout [String: String],
                                  _ path: String) -> (Data, String, UInt64) {
        var w = Writer()
        for f in (d.files ?? []).sorted(by: { $0.name < $1.name }) {
            w.msg(1, encodeFileNode(f))
            // Side channel is keyed BY PATH (not digest): one entry per input path, so
            // identical-content files at different paths never collapse to one source.
            if !f.hostPath.isEmpty {
                hostMapping[path.isEmpty ? f.name : path + "/" + f.name] = f.hostPath
            }
        }
        for sub in (d.directories ?? []).sorted(by: { $0.name < $1.name }) {
            let subPath = path.isEmpty ? sub.name : path + "/" + sub.name
            let (subBytes, subDg, subSize) = encodeDir(sub, &children, &seen, &hostMapping, subPath)
            w.msg(2, encodeDirNode(sub.name, subDg, subSize))
            if seen.insert(subDg).inserted { children.append((subDg, subBytes)) }
        }
        for s in (d.symlinks ?? []).sorted(by: { $0.name < $1.name }) {
            w.msg(3, encodeSymlinkNode(s))
        }
        let bytes = w.out
        return (bytes, sha256Hex(bytes), UInt64(bytes.count))
    }

    private static func encodeDigest(_ hash: String, _ size: UInt64) -> Data {
        var w = Writer()
        if !hash.isEmpty { w.str(1, hash) }
        if size != 0 { w.uint(2, size) }
        return w.out
    }

    private static func encodeFileNode(_ f: ManifestFile) -> Data {
        var w = Writer()
        w.str(1, f.name)
        if !f.digest.isEmpty || f.size != 0 { w.msg(2, encodeDigest(f.digest, f.size)) }
        if f.executable == true { w.bool(4, true) }   // REAPI is_executable = 4 (field 3 reserved)
        return w.out
    }

    private static func encodeDirNode(_ name: String, _ hash: String, _ size: UInt64) -> Data {
        var w = Writer()
        w.str(1, name)
        w.msg(2, encodeDigest(hash, size))
        return w.out
    }

    private static func encodeSymlinkNode(_ s: ManifestSymlink) -> Data {
        var w = Writer()
        w.str(1, s.name)
        w.str(2, s.target)
        return w.out
    }

    private static func encodeMapEntry(_ k: String, _ v: String) -> Data {
        var w = Writer()
        w.str(1, k)
        w.str(2, v)
        return w.out
    }

    // MARK: Request / Response

    static func decodeRequest(_ data: Data) -> WireRequest? {
        guard !data.isEmpty else { return nil }
        var rid: UInt64 = 0
        var sandboxId = ""
        // Op collected first — rid/sandbox_id may arrive after the op field.
        var create: Data? = nil
        var isDestroy = false
        let parsed: Bool = data.withUnsafeBytes { raw -> Bool in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
            var r = Reader(p, 0..<raw.count)
            while r.i < r.end {
                let key = r.varint(); guard r.ok else { return false }
                switch (key >> 3, key & 7) {
                case (1, 0): rid = r.varint()
                case (2, 2): guard let g = r.lenRange() else { return false }; sandboxId = r.string(g)
                case (3, 2):                                // Create{ Manifest manifest = 1 }
                    guard let g = r.lenRange() else { return false }
                    create = unwrapCreateManifest(p, g)
                case (4, 2):                                // Destroy{} (empty)
                    guard r.lenRange() != nil else { return false }
                    isDestroy = true
                default: r.skip(key & 7)
                }
                guard r.ok else { return false }
            }
            return true
        }
        guard parsed else { return nil }
        if let create { return .create(rid: rid, sandboxId: sandboxId, manifestBytes: create) }
        if isDestroy { return .destroy(rid: rid, sandboxId: sandboxId) }
        return nil
    }

    /// Pull the raw `Manifest` bytes out of a `Create` message (field 1) so the
    /// controller can append-patch them. Empty `Create` yields empty bytes.
    private static func unwrapCreateManifest(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> Data {
        var r = Reader(p, range)
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            if key >> 3 == 1, key & 7 == 2 {
                if let g = r.lenRange() { return Data(bytes: p + g.lowerBound, count: g.count) }
                break
            }
            r.skip(key & 7)
        }
        return Data()
    }

    /// Encode a Request (Bazel-side simulation: harness + manual testing).
    static func encodeCreateRequest(rid: UInt64, sandboxId: String, manifestBytes: Data) -> Data {
        var create = Writer(); create.bytes(1, manifestBytes)
        var w = Writer()
        w.uint(1, rid)
        w.str(2, sandboxId)
        w.msg(3, create.out)
        return w.out
    }
    static func encodeDestroyRequest(rid: UInt64, sandboxId: String) -> Data {
        var w = Writer()
        w.uint(1, rid)
        w.str(2, sandboxId)
        w.msg(4, Data())                                    // Destroy{} (empty)
        return w.out
    }

    static func encodeResponse(_ resp: WireResponse) -> Data {
        var w = Writer()
        w.uint(1, resp.rid)
        switch resp.result {
        case .created(let path, let skip, let eager):
            var c = Writer()
            c.str(1, path)
            if skip { c.bool(2, true) }
            if eager { c.bool(3, true) }
            w.msg(2, c.out)
        case .destroyed:
            w.msg(3, Data())
        case .error(let message):
            var e = Writer(); e.str(1, message)
            w.msg(4, e.out)
        }
        return w.out
    }

    /// Decode a Response (harness/tests; the controller only encodes).
    static func decodeResponse(_ data: Data) -> WireResponse? {
        var rid: UInt64 = 0
        var result: WireResponse.Result? = nil
        let parsed: Bool = data.withUnsafeBytes { raw -> Bool in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return data.isEmpty }
            var r = Reader(p, 0..<raw.count)
            while r.i < r.end {
                let key = r.varint(); guard r.ok else { return false }
                switch (key >> 3, key & 7) {
                case (1, 0): rid = r.varint()
                case (2, 2): guard let g = r.lenRange() else { return false }; result = parseCreated(p, g)
                case (3, 2): guard r.lenRange() != nil else { return false }; result = .destroyed
                case (4, 2): guard let g = r.lenRange() else { return false }; result = .error(parseErrorMessage(p, g))
                default: r.skip(key & 7)
                }
                guard r.ok else { return false }
            }
            return true
        }
        guard parsed, let result else { return nil }
        return WireResponse(rid: rid, result: result)
    }

    /// `Created{ path=1, skip_output_copy=2, eager_create_outputs=3 }`.
    private static func parseCreated(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> WireResponse.Result {
        var r = Reader(p, range)
        var path = "", skip = false, eager = false
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            switch (key >> 3, key & 7) {
            case (1, 2): if let g = r.lenRange() { path = r.string(g) }
            case (2, 0): skip = r.varint() != 0
            case (3, 0): eager = r.varint() != 0
            default: r.skip(key & 7)
            }
        }
        return .created(path: path, skipOutputCopy: skip, eagerCreateOutputs: eager)
    }

    /// `Error{ message = 1 }`.
    private static func parseErrorMessage(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> String {
        var r = Reader(p, range)
        var message = ""
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            switch (key >> 3, key & 7) {
            case (1, 2): if let g = r.lenRange() { message = r.string(g) }
            default: r.skip(key & 7)
            }
        }
        return message
    }
}
