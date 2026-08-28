import Foundation

// The manifest the controller writes per sandbox, and the appex's in-memory model of it.
//
// WIRE SHAPE — what `encode` in crates/backend-fskit writes, one file per sandbox:
//
//   1  exec_root       anchors every file whose host_path the tree leaves derived
//   2  root            the input tree, nested (Dir{1 name, 2 digest, 3 host_path, 4 host_kind,
//                      5 speculative_host_path, 6 files, 7 dirs, 8 symlinks})
//   3  outputs         map<in-sandbox path, host scratch target>
//   4  writable_dirs   ditto
//
// The tree arrives in the shape this model already wants — the controller resolves the REAPI
// Merkle closure and flattens it before writing — so decoding is a plain recursive walk with no
// digest re-indexing. A file's `host_path` is usually empty, meaning the standard derivation
// `exec_root/<tree path>`, which the walk fills in as it descends: shipping it per file would
// add an absolute path per node to a manifest that can hold six figures of them.
//
// Digests are lowercase-hex end to end; the CAS index keys on those strings.

struct Manifest {
    /// The sandbox id. Not on the wire — the volume stamps it from the manifest's filename.
    var id: String = ""
    /// Where a file's content lives when the tree leaves its `host_path` derived.
    var execRoot: String = ""
    var root: ManifestDir?
    var outputs: [String: String]?
    var writableDirs: [String: String]?
    /// True when the whole tree is to be built rather than reconciled in place.
    var fullBuild: Bool?
}

struct ManifestDir {
    var name: String
    var digest: String
    var files: [ManifestFile]?
    var directories: [ManifestDir]?
    var symlinks: [ManifestSymlink]?
}

struct ManifestFile {
    var name: String
    var digest: String
    var hostPath: String
    var size: UInt64
    var executable: Bool?
}

struct ManifestSymlink {
    var name: String
    var target: String
}

extension ManifestFile {
    /// True when this file projects as a HOST SYMLINK rather than an FSKit-backed file.
    ///
    /// Serving a file's bytes ourselves costs one VNOP round trip per read, and the kernel does
    /// NOT reuse those pages across sandboxes: 120 actions reading the same 60 inputs measured
    /// 7,200 reads through the appex, ~22µs each, which is the whole of this backend's deficit
    /// against darwin-sandbox. A host symlink hands the read to APFS instead — the bytes come
    /// from the shared host page cache, warm after the first action touches them, and an exec'd
    /// or dlopen'd binary gets its AMFI signature validated once against the stable host inode
    /// instead of per launch through the mount.
    ///
    /// Only ever a FILE: every directory stays ours, so readdir and lookup along the path see
    /// only declared entries and a leaf symlink cannot be used to enumerate undeclared siblings.
    /// What it does give up is write ISOLATION — an action that writes to one of its own inputs
    /// reaches the real file, where an FSKit-backed input would have refused. Bazel forbids that
    /// anyway, and darwin-sandbox links its inputs for the same reason; this backend's contract
    /// is a projected VIEW of real content, not the copy-on-write isolation cfs provides.
    ///
    /// A file with no host path (nothing pushed, nothing derivable) stays ours: there is nothing
    /// to point at.
    var projectsAsHostSymlink: Bool { !hostPath.isEmpty }
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

/// proto3 decoding, hand-rolled: the wire is varints and length-delimited fields and the schema
/// is fixed, so a reader is a page of code and the project stays dependency-free. Unknown fields
/// are skipped, so a controller that adds one cannot break us.
enum ProtoWire {

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

    static func decodeManifest(_ data: Data, skipRoot: Bool = false) -> Manifest? {
        guard !data.isEmpty else { return nil }
        return data.withUnsafeBytes { raw -> Manifest? in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return parseManifest(base, 0..<raw.count, skipRoot: skipRoot)
        }
    }

    /// The root tree's digest without walking the tree — enough to key the decoded-tree cache
    /// and skip the whole decode when the same tree is sent again.
    static func peekRootDigest(_ data: Data) -> String? {
        guard !data.isEmpty else { return nil }
        return data.withUnsafeBytes { raw -> String? in
            guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            var r = Reader(p, 0..<raw.count)
            while r.i < r.end {
                let key = r.varint(); guard r.ok else { return nil }
                if key >> 3 == 2, key & 7 == 2 {                    // root Dir
                    guard let g = r.lenRange() else { return nil }
                    var d = Reader(p, g)
                    while d.i < d.end {
                        let k = d.varint(); guard d.ok else { return nil }
                        if k >> 3 == 2, k & 7 == 2 {                // Dir.digest
                            guard let dg = d.lenRange() else { return nil }
                            return d.string(dg)
                        }
                        d.skip(k & 7)
                        guard d.ok else { return nil }
                    }
                    return nil
                }
                r.skip(key & 7)
                guard r.ok else { return nil }
            }
            return nil
        }
    }

    private static func parseManifest(_ p: UnsafePointer<UInt8>, _ range: Range<Int>, skipRoot: Bool = false) -> Manifest? {
        var r = Reader(p, range)
        var m = Manifest()
        var outputs: [String: String] = [:]
        var writable: [String: String] = [:]
        var rootRange: Range<Int>? = nil
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; m.execRoot = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; rootRange = g
            case (3, 2):
                guard let g = r.lenRange(), let e = parseMapEntry(p, g) else { return nil }
                outputs[e.0] = e.1
            case (4, 2):
                guard let g = r.lenRange(), let e = parseMapEntry(p, g) else { return nil }
                writable[e.0] = e.1
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        if !outputs.isEmpty { m.outputs = outputs }
        if !writable.isEmpty { m.writableDirs = writable }
        if !skipRoot, let rr = rootRange {
            m.root = parseDir(p, rr, execRoot: m.execRoot, path: "")
        }
        return m
    }

    /// One `Dir`. `path` is this directory's tree-relative path, which is what a child's derived
    /// host source hangs off — so the derivation costs a string join per node and no wire bytes.
    private static func parseDir(_ p: UnsafePointer<UInt8>, _ range: Range<Int>,
                                 execRoot: String, path: String) -> ManifestDir {
        var d = ManifestDir(name: "", digest: "")
        var files: [ManifestFile] = []
        var dirs: [ManifestDir] = []
        var syms: [ManifestSymlink] = []
        var r = Reader(p, range)
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { break }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return d }; d.name = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return d }; d.digest = r.string(g)
            case (6, 2):
                guard let g = r.lenRange() else { return d }
                if let f = parseFile(p, g, execRoot: execRoot, path: path) { files.append(f) }
            case (7, 2):
                guard let g = r.lenRange() else { return d }
                // The child's name leads its own message, so peek it to extend the path.
                let name = peekName(p, g)
                dirs.append(parseDir(p, g, execRoot: execRoot, path: join(path, name)))
            case (8, 2):
                guard let g = r.lenRange() else { return d }
                if let s = parseSymlink(p, g) { syms.append(s) }
            default: r.skip(key & 7)
            }
            guard r.ok else { break }
        }
        if !files.isEmpty { d.files = files }
        if !dirs.isEmpty { d.directories = dirs }
        if !syms.isEmpty { d.symlinks = syms }
        return d
    }

    private static func parseFile(_ p: UnsafePointer<UInt8>, _ range: Range<Int>,
                                  execRoot: String, path: String) -> ManifestFile? {
        var f = ManifestFile(name: "", digest: "", hostPath: "", size: 0, executable: nil)
        var r = Reader(p, range)
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return nil }
            switch (key >> 3, key & 7) {
            case (1, 2): guard let g = r.lenRange() else { return nil }; f.name = r.string(g)
            case (2, 2): guard let g = r.lenRange() else { return nil }; f.digest = r.string(g)
            case (3, 2): guard let g = r.lenRange() else { return nil }; f.hostPath = r.string(g)
            case (4, 0): f.size = r.varint()
            case (5, 0): f.executable = r.varint() != 0
            default: r.skip(key & 7)
            }
            guard r.ok else { return nil }
        }
        // An empty host_path means the standard derivation: this file's bytes live at the same
        // tree path under the exec root.
        if f.hostPath.isEmpty && !execRoot.isEmpty {
            f.hostPath = execRoot + "/" + join(path, f.name)
        }
        return f
    }

    private static func parseSymlink(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> ManifestSymlink? {
        var s = ManifestSymlink(name: "", target: "")
        var r = Reader(p, range)
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

    /// A message's `name` (field 1) without decoding the rest of it.
    private static func peekName(_ p: UnsafePointer<UInt8>, _ range: Range<Int>) -> String {
        var r = Reader(p, range)
        while r.i < r.end {
            let key = r.varint(); guard r.ok else { return "" }
            if key >> 3 == 1, key & 7 == 2 {
                guard let g = r.lenRange() else { return "" }
                return r.string(g)
            }
            r.skip(key & 7)
            guard r.ok else { return "" }
        }
        return ""
    }

    private static func join(_ path: String, _ name: String) -> String {
        path.isEmpty ? name : path + "/" + name
    }

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
}
