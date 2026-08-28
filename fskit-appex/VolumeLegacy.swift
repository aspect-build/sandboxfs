//
//  VolumeLegacy.swift
//  sandbox-fs
//
//  The legacy macOS-26 volume: conforms to the deprecated FSVolume.Operations family
//  (pre-FSKit-V3). Path-URL backed; the controller morphs the tree via real syscalls
//  against stable paths. Kept for macOS 26 deployment — FSUnaryFileSystem selects it on
//  <= 26 as the mmap backend's old-OS fallback (macOS 27+ uses VolumeMmap).
//  Shares SandboxFSItem / OpCounters with it.
//

import Foundation
import FSKit
import os
import Synchronization

final class VolumeLegacy: FSVolume {
    let resource: FSPathURLResource
    let logger = Logger(subsystem: "sandboxfs", category: "Legacy")
    let counters = OpCounters()

    let root = VirtualRoot.makeRoot()
    let virtualRoot = VirtualRoot()

    private var lastAppliedId: String?
    private var reconfigureSeq = 0

    /// Serializes the morph against root-facing reads. FSKit does not guarantee
    /// serial dispatch within an appex, and the controller drives the morph by
    /// issuing concurrent create/remove syscalls (each a write VNOP that mutates the
    /// graph + CAS) while the action may be reading — so every graph/CAS mutation and
    /// the cold-build swap take this lock. Immutable subtrees (an unchanged dir's
    /// children) are read lock-free; only the mutating VNOPs and the build contend.
    private let morphLock = NSLock()
    // The write VNOPs are `async`, and `NSLock.lock()`/`unlock()` are unavailable
    // from async contexts (a Swift 6 error). We never hold the lock across an `await`
    // — every critical section is straight-line synchronous work — so we acquire it
    // through these synchronous shims, where the calls are legal. `withLock` is not
    // an option here: its body would have to return non-Sendable `FSItem` values.
    @inline(__always) func lockMorph() { morphLock.lock() }
    @inline(__always) func unlockMorph() { morphLock.unlock() }

    // MARK: Content-addressed store (CAS)

    /// One content blob, shared by every path with the same digest. The shared
    /// `fileID` is the dedup mechanism: lifs derives the file handle from the fileID
    /// and hashes vnodes by FH (§2), so two items with the same fileID resolve to ONE
    /// kernel vnode + UBC — the blob is read off disk once no matter how many paths
    /// reference it. `linkCount` tracks live references so the entry is dropped when
    /// the last path is removed (and a future same-digest file re-registers fresh).
    final class CASEntry {
        let fileID: UInt64
        let backingPath: String
        let size: UInt64
        let executable: Bool
        var linkCount: Int = 0
        init(fileID: UInt64, backingPath: String, size: UInt64, executable: Bool) {
            self.fileID = fileID; self.backingPath = backingPath
            self.size = size; self.executable = executable
        }
    }
    /// digest → shared content blob. Same content ⇒ same fileID ⇒ one vnode (§4.2).
    private var casIndex: [String: CASEntry] = [:]

    /// Pool of UNLINKED file FSItem instances keyed by content digest. When the
    /// controller unlinks a changed/removed file, `removeItem` parks the instance
    /// here instead of dropping it; a later manifest wanting the same digest takes
    /// it back (`makeFileItem`) — the instance keeps its fileID, so the kernel
    /// rebinds the SAME vnode (FH = f(fileID)) and the UBC stays warm. Digest-keyed
    /// (not path-keyed) so flip-flopping content reattaches anywhere. Bounded by
    /// `filePoolLimit` (each pooled item may pin an mmap), LRU by `lastUsedSeq`.
    private var filePool: [String: SandboxFSItem] = [:]

    /// Pool of UNLINKED symlink FSItem instances keyed by TARGET — the symlink
    /// counterpart of `filePool`, preserving FSItem identity (fileID → same kernel
    /// vnode on rebind) across remove/re-add cycles. Holds both tree symlinks
    /// (pnpm-style store links flip-flopping between alternating actions) and
    /// promoted host-symlink binaries (which also carry their content digest; the
    /// take path re-checks it, since the same hostPath can change content).
    private var symlinkPool: [String: SandboxFSItem] = [:]

    /// Decoded-tree cache keyed by the root Merkle digest. Forced/incremental
    /// rebuilds re-send byte-identical trees (only the appended id/full_build
    /// patch differs); decoding a six-figure-node tree per create was the
    /// dominant reconfigure-RPC cost (~26ms for a 128KB Rollup manifest). A ~µs
    /// `peekRootDigest` partial parse keys the hit; on a hit only the small
    /// non-tree fields are decoded. Accessed only from the (controller-serialized)
    /// reconfigure path. Tiny LRU — trees are a few MB decoded.
    var treeCache: [String: ManifestDir] = [:]
    var treeCacheOrder: [String] = []
    let treeCacheLimit = 64
    /// The tree-derived half of the target index, cached alongside `treeCache` by
    /// the same root digest: rebuilding it was the 8.4ms `apply` cost on every
    /// cache-hit create. Outputs/writable_dirs overlay it per create (tiny).
    struct TreeIndex {
        var files: [String: TargetFile] = [:]
    }
    var treeIndexCache: [String: TreeIndex] = [:]
    /// Touch dirs from the LAST reconfigure still awaiting their sentinel purge.
    /// Each sentinel create retires its dir; when the set empties the appex seals
    /// the window itself — the controller never writes a separate "seal".
    private var pendingTouch: Set<String> = []
    // Self-timing for the recon-split decomposition (reported in the response).
    var lastParseUs: UInt32 = 0
    var lastParseCacheHit = false


    // MARK: Morph target index (path → backing)

    /// What the CURRENT manifest says each mount-relative path should be. Rebuilt on
    /// every reconfigure BEFORE the controller issues its morph syscalls, so that a
    /// controller-issued `creat(<mount>/<rel>)` lands in `createItem`, which looks the
    /// reconstructed path up here to bind the right CAS blob.
    struct TargetFile { let digest: String; let hostPath: String; let size: UInt64; let exec: Bool }
    private var targetFiles: [String: TargetFile] = [:]

    /// Output + writable_dir paths (mount-relative, NO leading slash). These project
    /// as symlinks to writable host scratch; the action writes THROUGH the symlink so
    /// results land on the host with no copy-out. To keep that zero-copy path, we
    /// advertise these nodes read-only to the action: the write VNOPs refuse to
    /// remove/replace/rename them (which would let a tool buffer the output in our
    /// ephemeral FS — the temp-then-rename pattern that was emptying outputs). The
    /// controller still (re)projects and tears them down inside a write window.
    private var protectedPaths: Set<String> = []

    /// When true, the controller is in a write window (reconfigure/morph or destroy)
    /// and output mutations are allowed; when false, the action is running and output
    /// paths are read-only. Opened by the reconfigure read, closed by the seal read,
    /// reopened by the drain read. Guarded by morphLock.
    private var draining = false

    /// Strip a single leading "/" so manifest paths (e.g. "/_main/…") match the
    /// no-leading-slash relPaths produced by `relPath(of:)`.
    private func normRel(_ p: String) -> String { p.hasPrefix("/") ? String(p.dropFirst()) : p }

    /// Cap on pooled file instances. Each pooled file can hold a live mmap — one
    /// pinned host vnode / open-file-table slot — so an unbounded pool eventually
    /// hits the process open-files limit. Derived from RLIMIT_NOFILE so we stay well
    /// under whatever the host allows.
    private let filePoolLimit: Int

    private static func computeFilePoolLimit() -> Int {
        var lim = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &lim) == 0 else { return 8192 }
        // rlim_cur may be an "unlimited" sentinel; clamp to a sane ceiling.
        let soft = lim.rlim_cur > UInt64(Int.max) ? 65536 : min(Int(lim.rlim_cur), 1_048_576)
        return max(1024, soft * 3 / 4)   // leave headroom for the process's other fds
    }

    init(resource: FSPathURLResource) {
        self.resource = resource
        self.filePoolLimit = Self.computeFilePoolLimit()
        // Fresh volumeID per instance: a fixed constant collides across mounts
        // ("VolumeID is being used…") and lets fskitd misroute VNOPs to the wrong instance.
        super.init(
            volumeID: FSVolume.Identifier(uuid: UUID()),
            volumeName: FSFileName(string: "sandboxfs")
        )
        virtualRoot.install(under: root, counters: counters)
    }
}

extension VolumeLegacy: FSVolume.PathConfOperations {
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumLinkCount: Int { -1 }
    var maximumXattrSize: Int { Int.max }
    var maximumFileSize: UInt64 { UInt64.max }
}

// MARK: - Helpers

private func mergeAttributes(_ existing: FSItem.Attributes, request: FSItem.SetAttributesRequest) {
    if request.isValid(.uid) { existing.uid = request.uid }
    if request.isValid(.gid) { existing.gid = request.gid }
    if request.isValid(.type) { existing.type = request.type }
    if request.isValid(.mode) { existing.mode = request.mode }
    if request.isValid(.linkCount) { existing.linkCount = request.linkCount }
    if request.isValid(.flags) { existing.flags = request.flags }
    if request.isValid(.size) { existing.size = request.size }
    if request.isValid(.allocSize) { existing.allocSize = request.allocSize }
    if request.isValid(.fileID) { existing.fileID = request.fileID }
    if request.isValid(.parentID) { existing.parentID = request.parentID }

    var ts = timespec()
    timespec_get(&ts, TIME_UTC)        // was a zeroed struct: times landed at epoch 1970
    if request.isValid(.accessTime) { request.accessTime = ts; existing.accessTime = ts }
    if request.isValid(.changeTime) { request.changeTime = ts; existing.changeTime = ts }
    if request.isValid(.modifyTime) { request.modifyTime = ts; existing.modifyTime = ts }
    if request.isValid(.addedTime) { request.addedTime = ts; existing.addedTime = ts }
    if request.isValid(.birthTime) { request.birthTime = ts; existing.birthTime = ts }
    if request.isValid(.backupTime) { request.backupTime = ts; existing.backupTime = ts }
}

/// Splice `src` into `dst` at byte offset `off`, pwrite-style: zero-fill any gap
/// (write past EOF), overwrite the overlapping region, and extend with the tail.
/// Bytes of `dst` beyond `off + src.count` are left intact.
private func spliceData(_ dst: inout Data, _ src: Data, at off: Int) {
    if off > dst.count { dst.append(Data(count: off - dst.count)) }
    let overlap = min(src.count, dst.count - off)
    if overlap > 0 { dst.replaceSubrange(off..<(off + overlap), with: src.prefix(overlap)) }
    if src.count > overlap { dst.append(src.suffix(from: overlap)) }
}

// MARK: - Volume operations

extension VolumeLegacy: FSVolume.Operations {
    // WRITABLE (not .readOnly): the morph is applied by the controller issuing real
    // kernel-mediated syscalls against stable paths — unlink (the only selective
    // cache-invalidation primitive, §2) for removed/changed entries and create/
    // symlink for added/changed ones. A read-only mount forces MNT_RDONLY and EROFSes
    // every write VNOP, including remove, which would block the invalidation
    // primitive entirely. No atime in lifs (§2), so a writable mount adds ZERO extra
    // RPCs on the read path — we pay only for the morph's edits. Action-side
    // mutations are accepted and self-heal on the next morph (+ COW in `write`).
    @objc var requestedMountOptions: FSVolume.MountOptions { [] }

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let c = FSVolume.SupportedCapabilities()
        // Gates VNOP_LINK and lets us advertise linkCount > 1 honestly: same-content
        // files share one CAS fileID (one vnode), which IS a hard link from lifs's FH
        // perspective (§4.2). createLink also realizes explicit action-issued links.
        c.supportsHardLinks = true
        c.supportsSymbolicLinks = true
        c.supportsPersistentObjectIDs = false
        c.doesNotSupportVolumeSizes = true
        c.supportsHiddenFiles = true
        c.supports64BitObjectIDs = true
        c.supportsFastStatFS = true           // statfs is cheap; hint the kernel
        c.doesNotSupportRootTimes = true
        // Case-sensitive: lookups are exact string matches (and Bazel paths are
        // case-sensitive). Must match the lookup behavior or the kernel mis-caches.
        c.caseFormat = .sensitive
        return c
    }

    var volumeStatistics: FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: "sandboxfs")
        result.blockSize = 1024000
        result.ioSize = 1024000
        result.totalBlocks = 1024000
        result.availableBlocks = 1024000
        result.freeBlocks = 1024000
        result.totalFiles = 1024000
        result.freeFiles = 1024000
        return result
    }

    // The manifest model (tree-shaped, mirrors Bazel's REAPI Directory/FileNode/
    // SymlinkNode) is the shared `Manifest`/`ManifestDir`/… in shared/ProtoWire.swift,
    // one per mount. `id` is the per-checkout change token; every node carries a
    // Bazel-computed digest used to reuse FSItem instances across checkouts (see
    // materialize*). `outputs`/`writable_dirs` are flat sandboxPath -> host-target
    // maps projected as symlinks. `fullBuild` is authoritative (controller-set) —
    // we must NOT infer "cold" from an empty tree, because a writable mount can have
    // `.fseventsd`/AppleDouble junk dropped at the root before the first real
    // reconfigure, which would make the heuristic skip the build and leave an empty
    // sandbox.
    //
    // Proto wire format only (proto/sandboxfs.proto) — the encoding bbazel emits
    // and the controller append-patches.
    func parseManifest(_ data: Data) -> Manifest? {
        if let rd = ProtoWire.peekRootDigest(data), !rd.isEmpty,
           let cached = treeCache[rd],
           var m = ProtoWire.decodeManifest(data, skipRoot: true) {
            lastParseCacheHit = true
            // LRU: refresh recency on hit.
            if let i = treeCacheOrder.firstIndex(of: rd) {
                treeCacheOrder.remove(at: i)
                treeCacheOrder.append(rd)
            }
            m.root = cached
            return m
        }
        lastParseCacheHit = false
        guard let m = ProtoWire.decodeManifest(data) else { return nil }
        if let r = m.root, !r.digest.isEmpty {
            if treeCache[r.digest] == nil {
                treeCacheOrder.append(r.digest)
                if treeCacheOrder.count > treeCacheLimit {
                    let evicted = treeCacheOrder.removeFirst()
                    treeCache[evicted] = nil
                    treeIndexCache[evicted] = nil
                }
            }
            treeCache[r.digest] = r
        }
        return m
    }

    /// Create (or descend into) the directory chain `components` under `parent`,
    /// returning the deepest directory.
    @discardableResult
    func addParents(components: [String.SubSequence], under parent: SandboxFSItem) -> SandboxFSItem {
        var parent = parent
        for component in components {
            let key = String(component)
            if let existing = parent.children[key] {
                parent = existing
            } else {
                let child = SandboxFSItem(name: FSFileName(string: key))
                child.attributes.parentID = parent.attributes.fileID
                child.attributes.type = .directory
                child.attributes.mode = 0o755
                child.attributes.gid = 20
                child.attributes.uid = 501
                parent.addItem(child)
                parent = child
            }
        }
        return parent
    }

    /// Project a symlink at `sandboxPath` with `target` verbatim (no resolution or
    /// validation, à la Bazel's createSymbolicLink). Used for `writable_dirs` and
    /// arbitrary input `symlinks`; `readSymbolicLink` returns the target unchanged.
    func addSymlink(sandboxPath: String, target: String, under root: SandboxFSItem, kind: StaticString) {
        var components = sandboxPath.split(separator: "/")
        guard let name = components.popLast() else {
            logger.error("\(kind, privacy: .public) with empty path: \(sandboxPath, privacy: .public)")
            return
        }
        let parent = addParents(components: components, under: root)
        let link = FSFileName(string: target)
        let child = SandboxFSItem(name: FSFileName(string: String(name)))
        child.attributes.type = .symlink
        child.attributes.mode = UInt32(S_IFLNK | 0o777)
        child.attributes.size = UInt64(link.data.count)
        child.linkname = link
        // Only FILE outputs get hide-until-written. Writable_dirs are directories the
        // action writes INTO (e.g. TEST_TMPDIR) — they must stay visible, or the action
        // can't enter/create in them (was: tests failing `mkdir _tmp: Read-only`).
        child.projected = ("\(kind)" == "output")
        parent.addItem(child)
    }

    /// Build a file FSItem bound to the CAS blob for `digest`. Reuse order:
    ///   1. `filePool` — an unlinked instance with this exact digest. Reattaching it
    ///      keeps its fileID, so the kernel resolves the path back to the SAME vnode
    ///      (FH = f(fileID)) and the UBC/mmap stay warm. Re-registers the CAS entry.
    ///   2. `casIndex` — another live path already carries this content: share its
    ///      fileID + backing so all paths resolve to ONE vnode (read-once, §4.2).
    ///   3. fresh — register a new blob.
    /// `digest` is stored on the item so removeItem can unref/pool and write can
    /// detect a shared blob for COW. Trusts the manifest's size/exec bit — no stat(2).
    func makeFileItem(name: String, digest: String, hostPath: String, size: UInt64, exec: Bool) -> SandboxFSItem {
        if let pooled = filePool.removeValue(forKey: digest) {
            pooled.name = FSFileName(string: name)
            pooled.lastUsedSeq = reconfigureSeq
            // Re-back from THIS node's own host_path. The pool is keyed only by content
            // digest, so a pooled instance may have been created for a different path with
            // identical content (a source file and its copy_to_bin output share a digest).
            // Keeping the old backingPath can point at an output not yet produced →
            // openBackingFile ENOENT. Content is identical so a live warm mmap stays valid;
            // this only corrects a future cold (re)open.
            pooled.backingPath = hostPath
            if let e = casIndex[digest] {
                e.linkCount += 1
                pooled.attributes.linkCount = UInt32(max(1, e.linkCount))
            } else {
                let e = CASEntry(fileID: pooled.attributes.fileID.rawValue,
                                 backingPath: pooled.backingPath ?? hostPath,
                                 size: size, executable: exec)
                e.linkCount = 1
                casIndex[digest] = e
            }
            return pooled
        }
        let entry: CASEntry
        if let e = casIndex[digest] {
            entry = e
        } else {
            entry = CASEntry(fileID: SandboxFSItem.getNextID(), backingPath: hostPath, size: size, executable: exec)
            casIndex[digest] = entry
        }
        entry.linkCount += 1
        let item = SandboxFSItem(name: FSFileName(string: name))
        item.digest = digest
        // Share the CAS entry's fileID (one vnode per content ⇒ kernel reads the blob
        // once), but read from THIS node's OWN host_path — NOT entry.backingPath. Same
        // digest can occur at different paths (source vs its identical copy_to_bin output),
        // and the entry's stored path may be an output that doesn't exist at read time.
        // The node's own host_path is the input Bazel guarantees exists.
        item.backingPath = hostPath
        item.attributes.fileID = FSItem.Identifier(rawValue: entry.fileID) ?? .invalid
        item.attributes.type = .file
        item.attributes.mode = UInt32(S_IFREG) | (exec ? 0o755 : 0o644)
        item.attributes.size = size
        item.attributes.allocSize = size
        item.attributes.linkCount = UInt32(max(1, entry.linkCount))
        return item
    }

    /// Materialize a manifest Directory into an FSItem subtree — always built fresh. A
    /// directory the kernel already knows is NEVER moved appex-side: XNU updates a dir vnode's
    /// identity (v_parent/v_name, what getcwd's path reconstruction walks) only on rename(2),
    /// so reattaching one here leaves stale identity and getcwd fails ENOENT inside the subtree
    /// (observed: node uv_cwd crash). Only the controller relocates a directory, by rename.
    /// Files reuse pooled instances via `makeFileItem` — a file is never a cwd, so rebinding
    /// its fileID without a rename is safe.
    private func materializeDir(_ d: ManifestDir) -> SandboxFSItem {
        let item = SandboxFSItem(name: FSFileName(string: d.name))
        item.digest = d.digest
        item.attributes.type = .directory
        item.attributes.mode = 0o755
        item.attributes.uid = 501
        item.attributes.gid = 20
        // Collect every child, then set them in one sorted pass — `addItem` per child
        // is an O(n) sorted insert each, so a wide dir would be O(n²) to build.
        var kids: [SandboxFSItem] = []
        kids.reserveCapacity((d.files?.count ?? 0) + (d.directories?.count ?? 0) + (d.symlinks?.count ?? 0))
        for f in d.files ?? [] {
            kids.append(materializeFile(f))
        }
        for sub in d.directories ?? [] {
            kids.append(materializeDir(sub))
        }
        for s in d.symlinks ?? [] {
            kids.append(materializeSymlink(s))
        }
        item.replaceChildren(with: kids)
        setDirSize(item)
        return item
    }

    /// Report a realistic dirent-table size (~name length + record overhead per
    /// entry, plus "." and ".."); a dir reporting size 0 is wrong for tools that
    /// stat it.
    private func setDirSize(_ item: SandboxFSItem) {
        let dirBytes = item.children.values.reduce(32) { $0 + (($1.name.string?.utf8.count ?? 0) + 16) }
        item.attributes.size = UInt64(dirBytes)
        item.attributes.allocSize = UInt64((dirBytes + 4095) / 4096 * 4096)
    }

    /// Materialize a file node: exec'd/loadable toolchain binaries become host
    /// symlinks (see `ManifestFile.projectsAsHostSymlink` in shared/ — the AMFI
    /// dodge); everything else goes through the CAS / file pool (`makeFileItem`).
    /// The promoted symlink CARRIES the file's content digest so the reconcile can
    /// match manifest-file vs graph-symlink by content identity, independent of
    /// representation.
    private func materializeFile(_ f: ManifestFile) -> SandboxFSItem {
        if f.projectsAsHostSymlink {
            // Identity-pooled like every other node kind: same hostPath + same
            // content digest ⇒ reuse the instance ⇒ same fileID ⇒ warm vnode.
            if let pooled = symlinkPool[f.hostPath], pooled.digest == f.digest {
                symlinkPool[f.hostPath] = nil
                pooled.name = FSFileName(string: f.name)
                pooled.lastUsedSeq = reconfigureSeq
                return pooled
            }
            let item = SandboxFSItem(name: FSFileName(string: f.name))
            item.attributes.type = .symlink
            item.attributes.mode = UInt32(S_IFLNK | 0o777)
            let link = FSFileName(string: f.hostPath)
            item.attributes.size = UInt64(link.data.count)
            item.linkname = link
            item.digest = f.digest   // content identity; NOT CAS-registered (no reads served)
            return item
        }
        return makeFileItem(name: f.name, digest: f.digest, hostPath: f.hostPath,
                            size: f.size, exec: f.executable ?? false)
    }

    /// Materialize a tree symlink, reusing the pooled instance for this exact
    /// target when one exists — preserving FSItem identity (fileID) so the kernel
    /// rebinds the SAME vnode instead of minting a cold one on every remove/re-add
    /// cycle (pnpm store links flip-flop constantly between alternating actions).
    /// Tree symlinks carry no digest (nil on both sides ⇒ the pooled-digest check
    /// degenerates to target equality, which IS their content identity).
    private func materializeSymlink(_ s: ManifestSymlink) -> SandboxFSItem {
        if let pooled = symlinkPool[s.target], pooled.digest == nil {
            symlinkPool[s.target] = nil
            pooled.name = FSFileName(string: s.name)
            pooled.lastUsedSeq = reconfigureSeq
            return pooled
        }
        let item = SandboxFSItem(name: FSFileName(string: s.name))
        item.attributes.type = .symlink
        item.attributes.mode = UInt32(S_IFLNK | 0o777)
        let link = FSFileName(string: s.target)
        item.attributes.size = UInt64(link.data.count)
        item.linkname = link
        return item
    }

    /// Mount-relative path of `item` (root → ""), by walking parent pointers. The
    /// write VNOPs use it to look up a controller-issued morph syscall's target in
    /// the manifest index (e.g. `creat(<mount>/a/b/c)` → relPath "a/b/c").
    func relPath(of item: SandboxFSItem) -> String {
        if item === root { return "" }
        var comps: [String] = []
        var cur: SandboxFSItem? = item
        while let c = cur, c !== root {
            comps.append(c.name.string ?? "")
            cur = c.parent
        }
        return comps.reversed().joined(separator: "/")
    }

    /// The fixed root items every projection carries alongside the manifest tree:
    /// the virtual files plus the Spotlight/fseventsd opt-out sentinels.

    /// True for the appex's own infrastructure files. Their VNOPs are NOT counted: the
    /// `@sandboxfs_perf` reader (CLI `stats`, the app dashboard) polls them constantly, so
    /// counting its lookups and reads makes "ops served" climb with no build running.
    private func isReserved(_ item: FSItem) -> Bool { item is GeneratedItem }

    /// True when root holds only the virtual items — the cold-mount state where a
    /// full build (rather than a controller-morphed delta) is warranted.
    private func inputTreeIsEmpty() -> Bool {
        for child in root.sortedChildren where !(child is GeneratedItem) {
            return false
        }
        return true
    }

    /// Flatten the manifest into path→backing maps the write VNOPs consult when the
    /// controller morphs by issuing create/symlink syscalls at stable paths. Rebuilt
    /// on every reconfigure, BEFORE the controller starts issuing those syscalls.
    /// The TREE half is pure in the root digest and cached (walking a big tree was
    /// the dominant apply cost once decode was cached); Swift dict CoW makes the
    /// cached assignment O(1). The outputs overlay is per-create and tiny.
    private func buildTargetIndex(_ manifest: Manifest) {
        let dg = manifest.root?.digest ?? ""
        if !dg.isEmpty, let cached = treeIndexCache[dg] {
            targetFiles = cached.files
        } else {
            var idx = TreeIndex()
            func walk(_ d: ManifestDir, _ prefix: String) {
                for f in d.files ?? [] {
                    let rel = prefix.isEmpty ? f.name : prefix + "/" + f.name
                    idx.files[rel] = TargetFile(digest: f.digest, hostPath: f.hostPath,
                                                size: f.size, exec: f.executable ?? false)
                }
                for sub in d.directories ?? [] {
                    let rel = prefix.isEmpty ? sub.name : prefix + "/" + sub.name
                    walk(sub, rel)
                }
            }
            if let r = manifest.root { walk(r, "") }
            if !dg.isEmpty { treeIndexCache[dg] = idx }   // evicted with treeCache
            targetFiles = idx.files
        }
        protectedPaths.removeAll(keepingCapacity: true)
        for (rel, _) in manifest.outputs ?? [:] {
            protectedPaths.insert(normRel(rel))      // read-only to the action; write-through to host
        }
        for (rel, _) in manifest.writableDirs ?? [:] {
            protectedPaths.insert(normRel(rel))
        }
    }

    // NOTE: output teardown is KERNEL-MEDIATED now — the controller unlinks each
    // output path at DESTROY time (off the critical path), which purges the
    // namecache entry AND removes the graph node in one stroke. The old appex-side
    // dropOutputs left kernel ghosts that the next create then had to unlink
    // anyway; "drain" is purely the window-open command today.

    /// Cold projection: build the entire input tree directly under the mount root
    /// (stable paths — no s<seq> wrapper) alongside the virtual files. Runs once per
    /// mount (when the tree is empty); later reconfigures reconcile the existing
    /// tree in place, so unchanged paths are never touched and stay warm (§4.1).
    private func buildFullTree(_ manifest: Manifest) {
        var top: [SandboxFSItem] = virtualRoot.items
        if let r = manifest.root {
            for f in r.files ?? [] { top.append(materializeFile(f)) }
            for d in r.directories ?? [] { top.append(materializeDir(d)) }
            for s in r.symlinks ?? [] { top.append(materializeSymlink(s)) }
        }
        root.replaceChildren(with: top)
        for (sandboxPath, target) in manifest.outputs ?? [:] {
            addSymlink(sandboxPath: sandboxPath, target: target, under: root, kind: "output")
        }
        for (sandboxPath, target) in manifest.writableDirs ?? [:] {
            addSymlink(sandboxPath: sandboxPath, target: target, under: root, kind: "writable_dir")
        }
        if let dg = manifest.root?.digest, !dg.isEmpty { root.digest = dg }
    }

    // MARK: Reconcile (the morph-mode rebuild)

    /// Converge the live graph to `manifest` appex-side — the construction half of
    /// the frontier-morph protocol. The controller has already issued the kernel
    /// INVALIDATION syscalls (unlink for changed/removed files+symlinks, and the removal of
    /// each topmost removed dir), so every name this walk adds is either freshly purged or
    /// never existed. The walk:
    ///   • Merkle-skips dirs whose stored digest equals the manifest's (the whole
    ///     subtree is byte-identical — untouched, fully warm).
    ///   • Recurses into dirs whose digest changed.
    ///   • ADDS missing children: dirs built fresh; files reattached from the file pool by
    ///     digest, else CAS-bound fresh.
    ///   • NEVER detaches or replaces an existing conflicting child appex-side —
    ///     the kernel may hold a warm namecache entry for it, and only a
    ///     kernel-mediated syscall can purge that. Conflicts (a name the controller
    ///     should have unlinked but didn't — crash recovery) are REPORTED in the
    ///     reconfigure response's `invalidate` list; the controller unlinks them
    ///     and reconfigures again, and the second pass adds the replacements.
    ///   • Leaves unknown extra DIRS in place (output-parent chains the controller
    ///     mkdir'd live outside the manifest tree; removing them appex-side would
    ///     strand warm kernel entries). Unknown extra files/symlinks are conflicts.
    /// Returns the conflict paths and the touch dirs (both mount-relative).
    private func reconcileTree(_ manifest: Manifest) -> (conflicts: [String], touch: [String]) {
        var conflicts: [String] = []
        var touch: [String] = []
        if let r = manifest.root {
            // Root-level Merkle skip: if the graph already carries this exact tree
            // (same root digest, no write-VNOP mutation since — those nil the
            // stamp), the whole input-tree walk is a no-op. The common case for a
            // re-run action landing on the slot it last used.
            if !r.digest.isEmpty && root.digest == r.digest {
                // tree unchanged — outputs only
            } else {
                reconcileDir(root, r, relPath: "", conflicts: &conflicts, touch: &touch)
                root.digest = r.digest.isEmpty ? nil : r.digest
            }
        }
        reconcileOutputs(manifest, conflicts: &conflicts, touch: &touch)
        return (conflicts, touch)
    }

    /// Project the outputs/writable_dirs appex-side during the reconcile — they
    /// are ordinary ADDS now: the controller kernel-unlinked the previous action's
    /// output names at DESTROY (purging the namecache), so the paths are free, and
    /// any dir gaining a name lands in `touch` for the sentinel purge. Scaffold
    /// parents outside the manifest tree are created appex-side too. A stale
    /// occupant (crash before destroy's unlinks ran) is a conflict — the heal pass
    /// kernel-unlinks it and the second reconcile projects cleanly.
    private func reconcileOutputs(_ manifest: Manifest, conflicts: inout [String], touch: inout [String]) {
        var all = manifest.outputs ?? [:]
        // Only FILE outputs get hide-until-written; writable_dirs must stay visible (the
        // action writes into them — TEST_TMPDIR etc.). Track which keys are file outputs.
        let fileOutputKeys = Set((manifest.outputs ?? [:]).keys.map(normRel))
        for (k, v) in manifest.writableDirs ?? [:] { all[k] = v }
        for (sandboxPath, target) in all {
            let rel = normRel(sandboxPath)
            let comps = rel.split(separator: "/").map(String.init)
            guard let leaf = comps.last, !leaf.isEmpty else { continue }
            // Descend/create the parent chain. Touch a PRE-EXISTING dir that gains
            // a name; freshly created chain dirs can't hold kernel negatives.
            var parent = root
            var prefix = ""
            var parentIsFresh = false
            var broken = false
            for c in comps.dropLast() {
                let parentRel = prefix
                prefix = prefix.isEmpty ? c : prefix + "/" + c
                if let next = parent.children[c] {
                    guard next.attributes.type == .directory else {
                        conflicts.append(prefix); broken = true; break
                    }
                    parent = next
                    parentIsFresh = false
                } else {
                    let child = SandboxFSItem(name: FSFileName(string: c))
                    child.attributes.type = .directory
                    child.attributes.mode = UInt32(S_IFDIR | 0o755)
                    child.attributes.uid = 501
                    child.attributes.gid = 20
                    let risky = parent.addIsRisky(c)
                    parent.addItem(child)
                    if !parentIsFresh && risky { touch.append(parentRel) }
                    parent = child
                    parentIsFresh = true
                }
            }
            if broken { continue }
            if let existing = parent.children[leaf] {
                if existing.attributes.type == .symlink && existing.linkname?.string == target { continue }
                conflicts.append(rel)        // stale occupant; kernel purge needed
                continue
            }
            let link = FSFileName(string: target)
            let item = SandboxFSItem(name: FSFileName(string: leaf))
            item.attributes.type = .symlink
            item.attributes.mode = UInt32(S_IFLNK | 0o777)
            item.attributes.size = UInt64(link.data.count)
            item.linkname = link
            item.projected = fileOutputKeys.contains(rel)   // file outputs only; writable_dirs stay visible
            let risky = parent.addIsRisky(leaf)
            parent.addItem(item)
            if !parentIsFresh && risky { touch.append(comps.dropLast().joined(separator: "/")) }
        }
    }

    private func reconcileDir(_ item: SandboxFSItem, _ d: ManifestDir, relPath: String,
                              conflicts: inout [String], touch: inout [String]) {
        let isRoot = item === root
        func rel(_ name: String) -> String { relPath.isEmpty ? name : relPath + "/" + name }
        var toAdd: [SandboxFSItem] = []

        for f in d.files ?? [] {
            let r = rel(f.name)
            if protectedPaths.contains(r) { continue }   // outputs are controller-projected
            if let existing = item.children[f.name] {
                // Match by CONTENT digest, not representation: a promoted host
                // symlink (exec'd toolchain binary) carries the file's digest too.
                if existing.digest != nil && existing.digest == f.digest { continue }
                conflicts.append(r)                       // stale occupant; kernel purge needed
            } else {
                toAdd.append(materializeFile(f))
            }
        }
        for s in d.symlinks ?? [] {
            let r = rel(s.name)
            if protectedPaths.contains(r) { continue }
            if let existing = item.children[s.name] {
                if existing.attributes.type == .symlink && existing.linkname?.string == s.target { continue }
                conflicts.append(r)
            } else {
                toAdd.append(materializeSymlink(s))
            }
        }
        for sub in d.directories ?? [] {
            let r = rel(sub.name)
            if let existing = item.children[sub.name] {
                if existing.attributes.type == .directory {
                    if existing.digest == sub.digest { continue }   // Merkle skip — warm
                    reconcileDir(existing, sub, relPath: r, conflicts: &conflicts, touch: &touch)
                    existing.digest = sub.digest
                    setDirSize(existing)
                } else {
                    conflicts.append(r)
                }
            } else {
                toAdd.append(materializeDir(sub))
            }
        }

        if !toAdd.isEmpty {
            if toAdd.count > 4 {
                // Bulk: one sorted pass instead of N O(n) sorted inserts.
                var keep = item.sortedChildren
                keep.append(contentsOf: toAdd)
                item.replaceChildren(with: keep)
            } else {
                for child in toAdd { item.addItem(child) }
            }
            setDirSize(item)
            // This dir EXISTED before the reconcile (the walk only recurses into
            // pre-existing items; fresh subtrees are built whole by materializeDir)
            // and just gained names — but a negative entry is PER NAME: it needs a
            // sentinel purge only if one of the names just added was itself
            // probed-and-missed here at some point. Adds of never-probed names
            // (the typical extract-action input set) cost nothing.
            if toAdd.contains(where: { item.addIsRisky($0.name.string ?? "") }) {
                touch.append(relPath)
            }
        }
        // Extra children not in the manifest: leave dirs (output-parent chains the
        // controller mkdir'd; appex-side removal would strand warm kernel entries),
        // report files/symlinks the controller should have unlinked (crash heal).
        var desired = Set<String>()
        for f in d.files ?? [] { desired.insert(f.name) }
        for s in d.symlinks ?? [] { desired.insert(s.name) }
        for child in item.sortedChildren where child.attributes.type != .directory {
            if isRoot, child is GeneratedItem { continue }
            let name = child.name.string ?? ""
            if desired.contains(name) { continue }
            // Host-junk artifacts (AppleDouble companions, Finder droppings) are not
            // stale inputs — never conflict on them. createItem refuses "._*" now,
            // but a mount predating that guard may still carry one; reporting it
            // would wedge the heal loop (the kernel xattr shim regenerates the
            // AppleDouble after every unlink).
            if name.hasPrefix("._") || name == ".DS_Store" { continue }
            let r = rel(name)
            if protectedPaths.contains(r) { continue }
            conflicts.append(r)
        }
    }

    /// Apply `manifest` at STABLE paths under the mount root (no s<seq> wrapper).
    ///
    /// Two modes, decided by the controller's authoritative `fullBuild` flag:
    ///   • COLD (fresh mount): build the whole tree in one pass and swap it under
    ///     root — nothing is kernel-cached yet, so a wholesale swap is safe.
    ///   • RECONCILE (a reused slot on a persistent mount): converge the existing
    ///     graph to the manifest appex-side (see `reconcileTree`). The controller
    ///     has ALREADY issued the kernel invalidation syscalls (unlink per
    ///     changed/removed file, and the removal of each topmost removed dir) BEFORE
    ///     this reconfigure, so every name the reconcile adds is
    ///     freshly purged or never existed. Unchanged subtrees are Merkle-skipped —
    ///     never touched, namecache + attr cache + UBC stay warm.
    ///
    /// Either way the target index is refreshed first (output projection and any
    /// controller-issued create still resolve through it). `root` itself is never
    /// replaced. Returns dir="" and the reconcile's conflict list in `invalidate`
    /// (paths the controller must unlink and re-reconfigure — crash healing).
    @discardableResult
    func applyManifest(_ manifest: Manifest) -> ReconfigResponse {
        lockMorph(); defer { unlockMorph() }
        let tApply0 = DispatchTime.now()
        reconfigureSeq += 1
        // Open the controller write window: the morph that follows this reconfigure
        // (re)projects the output symlinks, which are otherwise read-only. The
        // controller closes it (seal) before the action runs.
        draining = true
        let tIdx0 = DispatchTime.now()
        buildTargetIndex(manifest)
        let indexUs = UInt32(clamping: (DispatchTime.now().uptimeNanoseconds &- tIdx0.uptimeNanoseconds) / 1_000)
        // Authoritative build signal from the controller; fall back to the
        // tree-empty heuristic only when absent (e.g. the initial empty manifest at
        // activate, before any controller create).
        let cold = manifest.fullBuild ?? inputTreeIsEmpty()
        var conflicts: [String] = []
        var touch: [String] = []
        let tWalk0 = DispatchTime.now()
        if cold {
            buildFullTree(manifest)
        } else {
            (conflicts, touch) = reconcileTree(manifest)
        }
        let walkUs = UInt32(clamping: (DispatchTime.now().uptimeNanoseconds &- tWalk0.uptimeNanoseconds) / 1_000)
        lastAppliedId = manifest.id
        // AUTO-SEAL: when the reconcile is clean (no conflicts to heal, no dirs
        // needing a sentinel purge) the controller has NOTHING left to do in the
        // write window — seal here and tell it so. Otherwise ARM the pending-touch
        // set: each controller sentinel create retires its dir, and the LAST one
        // seals the window from inside `createItem` — so the controller never
        // writes a separate "seal" on the happy path either. A controller that
        // needs the window anyway (error paths) just writes "drain" to reopen.
        var sealed = false
        if conflicts.isEmpty && touch.isEmpty {
            draining = false
            sealed = true
            pendingTouch = []
        } else {
            pendingTouch = conflicts.isEmpty ? Set(touch) : []
        }
        let applyUs = UInt32(clamping: (DispatchTime.now().uptimeNanoseconds &- tApply0.uptimeNanoseconds) / 1_000)
        var r = ReconfigResponse()
        r.id = manifest.id
        r.invalidate = conflicts
        r.touch = touch
        r.sealed = sealed
        r.parseUs = lastParseUs
        r.applyUs = applyUs
        r.indexUs = indexUs
        r.walkUs = walkUs
        r.treeCacheHit = lastParseCacheHit
        r.rootDg = String((manifest.root?.digest ?? "").prefix(12))
        trimPools()
        if !conflicts.isEmpty {
            logger.warning("reconcile: \(conflicts.count, privacy: .public) conflict(s) need kernel purge (heal pass)")
        }
        logger.info("applied manifest id=\(manifest.id, privacy: .public) mode=\(cold ? "build" : "reconcile", privacy: .public)")
        return r
    }

    /// Bound the pools: each pooled file may hold an mmap (a pinned host vnode / fd-table
    /// slot), so they are LRU-capped. Runs at the end of a reconfigure, which the CONTRACT
    /// guarantees is quiesced, so dropping a victim races no in-flight (lock-free) read.
    private func trimPools() {
        if filePool.count > filePoolLimit {
            let victims = filePool
                .sorted { $0.value.lastUsedSeq < $1.value.lastUsedSeq }
                .prefix(filePool.count - filePoolLimit)
            for (key, _) in victims {
                // Drop the reference ONLY — no munmap here: the kernel may still
                // serve reads through a cached vnode bound to this item, and
                // unmapping under a reader is a mount-wide SIGBUS. `deinit`
                // unmaps once the kernel reclaims; the pages are clean and
                // reclaimable meanwhile.
                filePool[key] = nil
            }
            logger.info("filePool trim: evicted \(victims.count, privacy: .public) (now \(self.filePool.count, privacy: .public)/\(self.filePoolLimit, privacy: .public))")
        }
        if symlinkPool.count > filePoolLimit {
            // Symlink items hold no mmap/fd — the cap only bounds graph memory.
            let victims = symlinkPool
                .sorted { $0.value.lastUsedSeq < $1.value.lastUsedSeq }
                .prefix(symlinkPool.count - filePoolLimit)
            for (key, _) in victims { symlinkPool[key] = nil }
            logger.info("symlinkPool trim: evicted \(victims.count, privacy: .public) (now \(self.symlinkPool.count, privacy: .public)/\(self.filePoolLimit, privacy: .public))")
        }
    }

    func activate(options: FSTaskOptions) async throws -> FSItem {
        counters.bump(.activate)
        loadManifest(fullBuild: true)   // cold-build the whole tree from the resource URL
        return root
    }

    /// (Re)read the manifest from the resource URL and apply it. `fullBuild: true`
    /// cold-builds the whole tree (activate); `false` reconciles the live tree in place
    /// — the `sandboxfs_refresh*` lookup trigger.
    private func loadManifest(fullBuild: Bool) {
        guard let data = FileManager.default.contents(atPath: resource.url.path),
              var m = parseManifest(data) else {
            logger.error("manifest unreadable at \(self.resource.url.path, privacy: .public)")
            return
        }
        m.fullBuild = fullBuild
        applyManifest(m)
        // Pull model: no controller write-window — force read-only after applying.
        lockMorph(); draining = false; unlockMorph()
    }

    func deactivate(options: FSDeactivateOptions = []) async throws {
        var stack: [SandboxFSItem] = [root]
        stack.append(contentsOf: filePool.values)
        stack.append(contentsOf: symlinkPool.values)
        while let item = stack.popLast() {
            item.releaseBackingFile()
            stack.append(contentsOf: item.children.values)
        }
    }

    func mount(options: FSTaskOptions) async throws {
        logger.info("mount \(options.taskOptions)")
    }

    func unmount() async {
        let snapshot = counters.snapshotAndReset()
        logger.notice("=== sandboxfs op counts ===")
        for (op, count) in snapshot {
            logger.notice("  \(op.rawValue, privacy: .public): \(count)")
        }
    }

    func synchronize(flags: FSSyncFlags) async throws {}

    func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        if !isReserved(item) { counters.bump(.attributes) }
        guard let item = item as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        // Virtual files: refresh size and bump mtime so the kernel buffer cache (keyed
        // by size+mtime) treats every stat as a new revision.
        if let provider = (item as? GeneratedItem)?.render {
            // Size MUST equal the served length (dataProvider pads control responses to
            // a constant size — see init). A size > served length makes the F_NOCACHE
            // read a short-read-before-EOF, delivered to the controller as 0.
            let size = UInt64(provider().count)
            item.attributes.size = size
            item.attributes.allocSize = size
            var ts = timespec()
            timespec_get(&ts, TIME_UTC)
            item.attributes.modifyTime = ts
            item.attributes.changeTime = ts
        }
        return item.attributes
    }

    func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        counters.bump(.setAttributes)
        guard let item = item as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        // Read-only to the ACTION, like every other mutating VNOP. This was the
        // one ungated mutation: a sealed-mode truncate(2) zeroed an input's
        // advertised size, and because the item persists across checkouts with
        // its digest unchanged, the corruption OUTLIVED the action. Native
        // darwin-sandbox inputs are read-only too — failing here matches it.
        lockMorph(); defer { unlockMorph() }
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }
        mergeAttributes(item.attributes, request: newAttributes)
        return item.attributes
    }

    func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        // Reconfigure trigger: a lookup of `sandboxfs_refresh<nonce>` re-reads the
        // manifest from the resource URL and reconciles the live tree in place. The
        // nonce keeps each trigger a distinct name (no negative-cache shadowing).
        if name.string?.hasPrefix("sandboxfs_refresh") == true {
            loadManifest(fullBuild: false)
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        // Don't count lookups of the reserved root files — the perf/control-channel
        // pollers hit these every cycle and would inflate "ops served".
        if !(directory === root && (name.string.map(virtualRoot.names.contains) ?? false)) {
            counters.bump(.lookupItem)
        }
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        // Lock: a concurrent morph (addItem/removeItem) mutates the `children` dict;
        // reading it unsynchronized would crash. The warm path never reaches here
        // (the kernel serves cached lookups), so this only contends on cold/changed.
        lockMorph(); defer { unlockMorph() }
        // Lookup names come from namei — arbitrary action-controlled bytes, NOT
        // guaranteed UTF-8. A force-unwrap here let any non-UTF8 probe (old
        // tarballs with Latin-1 names) crash the appex = kill the whole mount.
        // We key children by String, so a non-decodable name simply doesn't exist.
        guard let key = name.string else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        if let item = directory.children[key] {
            return (item, name)
        }
        // Miss: lifs may now plant a negative namecache entry for this name —
        // remember WHICH name, so a future appex-side add of that exact name (and
        // only that) triggers a sentinel purge here.
        directory.noteMiss(key)
        throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
    }

    func reclaimItem(_ item: FSItem) async throws { if !isReserved(item) { counters.bump(.reclaimItem) } }

    func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        counters.bump(.readSymbolicLink)
        guard let item = item as? SandboxFSItem, item.attributes.type == .symlink, let link = item.linkname else {
            throw fs_errorForPOSIXError(POSIXError.ENOLINK.rawValue)
        }
        return link
    }

    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest) async throws -> (FSItem, FSFileName) {
        counters.bump(.createItem)
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        lockMorph(); defer { unlockMorph() }
        let nameStr = name.string ?? ""
        let rel = directory === root ? nameStr : relPath(of: directory) + "/" + nameStr

        // Sentinel creates are PURGE EVENTS, not files: reaching this VNOP means
        // the kernel just fired cache_purge_negatives(dir) for a successful create.
        // Clear the dir's per-name miss ledger, retire it from the pending touch
        // set, and SEAL the window after the last one — the controller's separate
        // seal write is gone. The returned item is a GHOST (never linked into the
        // graph): nothing enumerates or resolves it, which also saves the unlink
        // round trip. Names are unique per purge (".sandboxfs_negpurge.<n>"), so
        // the next purge of the same dir is a fresh create — an existing name
        // would resolve positively and skip the kernel purge. Allowed even when
        // sealed: it's harmless (the kernel purge already happened) and the
        // heal-pass union can outlive the armed set.
        if nameStr.hasPrefix(".sandboxfs_negpurge") {
            directory.clearMisses()
            pendingTouch.remove(directory === root ? "" : relPath(of: directory))
            if draining && pendingTouch.isEmpty { draining = false }
            let ghost = SandboxFSItem(name: name)
            ghost.attributes.type = .file
            ghost.attributes.mode = UInt32(S_IFREG | 0o600)
            ghost.attributes.parentID = directory.attributes.fileID
            return (ghost, name)
        }

        // The mount tree is read-only to the ACTION: in-mount mutations are refused so
        // the action writes only THROUGH output/writable_dir symlinks to host scratch
        // (zero-copy, the Bazel model). Mutations are allowed only inside the
        // controller's write window (draining) — its morph builds the tree.
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }

        // AppleDouble companions ("._<name>") must never materialize: xattrs are
        // inhibited on this volume, so the kernel's vn_setxattr dot-underscore shim
        // falls back to creating these whenever a host process stamps quarantine/
        // provenance xattrs (Bazel does) — and it REGENERATES them after every
        // unlink, which wedges the reconcile heal loop forever. EPERM makes the
        // originating (best-effort) setxattr fail cleanly instead. Inputs are
        // appex-projected, so a legitimate "._*" never arrives through createItem.
        if nameStr.hasPrefix("._") { throw fs_errorForPOSIXError(POSIXError.EPERM.rawValue) }

        // Morph re-resolution: when the controller `creat`s a path the current
        // manifest backs with host content, bind that CAS blob (dedup + correct
        // bytes) instead of an empty writable file — this is how a CHANGED input is
        // re-projected after its stale vnode was unlinked. Regular files only; dirs
        // (mkdir) and action-created files with no manifest entry fall through to a
        // plain in-memory item the action populates via `write`.
        let item: SandboxFSItem
        if type == .file, let tf = targetFiles[rel] {
            item = makeFileItem(name: nameStr, digest: tf.digest, hostPath: tf.hostPath, size: tf.size, exec: tf.exec)
        } else {
            item = SandboxFSItem(name: name)
            mergeAttributes(item.attributes, request: newAttributes)
            item.attributes.type = type
            if type == .directory, item.attributes.mode == 0 {
                item.attributes.mode = UInt32(S_IFDIR | 0o755)
            }
        }
        item.attributes.parentID = directory.attributes.fileID
        directory.addItem(item)
        directory.clearMisses()         // the kernel just purged this dir's negatives
        root.digest = nil                // tree mutated: next reconcile must walk
        return (item, name)
    }

    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName) async throws -> (FSItem, FSFileName) {
        counters.bump(.createSymbolicLink)
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        lockMorph(); defer { unlockMorph() }
        // Read-only to the action; only the controller's morph (draining) may project.
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }
        let item = SandboxFSItem(name: name)
        mergeAttributes(item.attributes, request: newAttributes)
        item.attributes.parentID = directory.attributes.fileID
        item.attributes.type = .symlink
        item.attributes.mode = UInt32(S_IFLNK | 0o777)
        item.attributes.size = UInt64(contents.data.count)
        item.linkname = contents
        // NOT marked hide-until-written: this VNOP path isn't how file outputs are
        // projected (those go via reconcileOutputs/addSymlink), and marking it could hide
        // a writable-dir symlink created here.
        directory.addItem(item)
        directory.clearMisses()         // the kernel just purged this dir's negatives
        root.digest = nil
        return (item, contents)
    }

    /// Hard link: add a second name referencing `item`'s content. We mint a new
    /// FSItem that SHARES the target's fileID (→ same FH → same kernel vnode + UBC,
    /// §2) and backing, and bump the CAS link count so the blob survives until the
    /// last name is removed. supportsHardLinks must be true for the kernel to call us.
    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        counters.bump(.createLink)
        guard let target = item as? SandboxFSItem, let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        lockMorph(); defer { unlockMorph() }
        // Read-only to the action; only the controller's morph (draining) may link.
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }
        let link = SandboxFSItem(name: name)
        link.digest = target.digest
        link.backingPath = target.backingPath
        link.data = target.data
        link.linkname = target.linkname
        link.attributes.type = target.attributes.type
        link.attributes.mode = target.attributes.mode
        link.attributes.size = target.attributes.size
        link.attributes.allocSize = target.attributes.allocSize
        link.attributes.fileID = target.attributes.fileID      // same fileID → shared vnode
        if let d = target.digest, let e = casIndex[d] {
            e.linkCount += 1
            link.attributes.linkCount = UInt32(max(1, e.linkCount))
        } else {
            link.attributes.linkCount = max(1, target.attributes.linkCount)
        }
        link.attributes.parentID = directory.attributes.fileID
        directory.addItem(link)
        directory.clearMisses()         // the kernel just purged this dir's negatives
        root.digest = nil
        return name
    }

    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        counters.bump(.removeItem)
        guard let item = item as? SandboxFSItem, let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        lockMorph(); defer { unlockMorph() }
        // Read-only to the action; only the controller's morph (draining) may remove.
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }
        directory.removeItem(item)
        root.digest = nil                // tree mutated: next reconcile must walk
        // CAS unref: drop the shared blob index entry when its last path goes, so a
        // future same-digest file re-registers fresh. FILES only — a promoted host
        // symlink carries a digest for identity but was never CAS-registered. Do NOT
        // munmap here — the kernel may still hold the vnode until reclaim; the
        // mapping frees on deinit.
        if item.attributes.type == .file, let d = item.digest, let e = casIndex[d] {
            e.linkCount -= 1
            if e.linkCount <= 0 { casIndex[d] = nil }
        }
        // Park unlinked CAS-backed files in the digest pool: a later manifest wanting
        // this content reattaches the SAME instance (same fileID → same kernel vnode →
        // warm UBC). The pool overwrite case (same digest unlinked twice) keeps the
        // newest instance; the older one frees once the kernel reclaims its vnode.
        if let d = item.digest, item.attributes.type == .file {
            item.lastUsedSeq = reconfigureSeq
            filePool[d] = item
        } else if item.attributes.type == .symlink, let t = item.linkname?.string {
            // Symlinks pool by TARGET (their content identity): a re-added link to
            // the same target rebinds the same vnode — missing the kernel cache is
            // a full lookup+readlink RPC pair per link, and pnpm trees have
            // thousands of them. Output symlinks are excluded: their per-action
            // scratch targets never recur, so pooling them only displaces useful
            // entries (the controller unlinks them at destroy).
            let rel = directory === root ? (name.string ?? "")
                                         : relPath(of: directory) + "/" + (name.string ?? "")
            if !protectedPaths.contains(rel) {
                item.lastUsedSeq = reconfigureSeq
                symlinkPool[t] = item
            }
        }
    }

    /// Move an item within the graph. Used if the controller morph (or an action)
    /// renames; the kernel rename path also purges the namecache for both names.
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?) async throws -> FSFileName {
        counters.bump(.renameItem)
        guard let item = item as? SandboxFSItem,
              let src = sourceDirectory as? SandboxFSItem,
              let dst = destinationDirectory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }
        lockMorph(); defer { unlockMorph() }
        // Read-only to the action; only the controller's morph (draining) may rename.
        // (Blocks the temp-then-rename-over-output pattern that emptied outputs — the
        // tool must write THROUGH the output symlink to host scratch instead.)
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }

        if let over = overItem as? SandboxFSItem {
            dst.removeItem(over)
            if over.attributes.type == .file, let d = over.digest, let e = casIndex[d] {
                e.linkCount -= 1
                if e.linkCount <= 0 { casIndex[d] = nil }
            }
        }
        src.removeItem(item)
        item.name = destinationName
        dst.addItem(item)
        dst.clearMisses()                // rename's create-op purged dst's negatives
        root.digest = nil
        return destinationName
    }

    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier, attributes: FSItem.GetAttributesRequest?, packer: FSDirectoryEntryPacker) async throws -> FSDirectoryVerifier {
        counters.bump(.enumerateDirectory)
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        // Snapshot the ordered children + verifier atomically under the morph lock so
        // a concurrent edit can't tear the array we page over; pack from the snapshot.
        lockMorph()
        let snapshot = directory.sortedChildren
        let cv = directory.contentVersion
        unlockMorph()

        // Hide controller-projected outputs that the action hasn't written yet: a
        // declared output's write-through symlink is created at morph time, but on host
        // scratch the target file does not exist until the action emits it. Native leaves
        // the path absent until written; matching that here stops a broad-glob tool (tsc,
        // `exclude: []`) from picking up its own pending output as an input → TS5055. The
        // stat is paid only for projected-output children (few; zero on input-only dirs);
        // writable-dir targets exist (controller mkdir'd them) so they stay visible. Done
        // outside the morph lock — the snapshot array is already a copy.
        let entries = snapshot.filter { child in
            guard child.projected, let target = child.linkname?.string else { return true }
            // The write-through scratch target is eager-created as an EMPTY placeholder
            // before the action runs (so tools like uutils `cp` can write through a
            // non-dangling symlink). So "exists" can't mean "written". Show a file output
            // only once it has content (>0 bytes); a writable-dir target (always present)
            // stays visible. While it's absent or a 0-byte placeholder it's hidden, so a
            // broad-glob tool (tsc, `exclude: []`) doesn't pick up its own pending output
            // as an input → TS5055. Edge: a genuinely-empty file output stays hidden until
            // written — acceptable (the action writes/reads it by path, not via readdir).
            var st = stat()
            guard stat(target, &st) == 0 else { return false }
            if (st.st_mode & S_IFMT) == S_IFDIR { return true }
            return st.st_size > 0
        }

        // The two paths need DIFFERENT content (FSVolume.h): on readdir (attributes ==
        // nil) the kernel doesn't synthesize "." / ".." so we pack them; on
        // getattrlistbulk it supplies them and packing would duplicate. A single walk
        // is all-readdir or all-bulk (distinct kext loops, no mid-walk flip), so the
        // cookie space is consistent: "." / ".." take cookies 0/1 (the `prefix`).
        let wantsAttrs = (attributes != nil)
        let prefix = wantsAttrs ? 0 : 2
        let total = prefix + entries.count

        // Cookie is the index of the next entry; valid range [0, total] (0 starts,
        // total is EOF). Compare on UInt64 BEFORE narrowing — a stale cookie above
        // Int.max would trap `Int(_:)`. Out of range → kernel restarts.
        guard cookie.rawValue <= UInt64(total) else {
            throw FSError(.invalidDirectoryCookie)
        }
        let start = Int(cookie.rawValue)
        // On resume the kernel echoes back our verifier; if it no longer matches the
        // dir mutated mid-walk and our index cookie is stale — reject so it restarts.
        if start != 0, verifier.rawValue != UInt64(cv &+ 1) {
            throw FSError(.invalidDirectoryCookie)
        }

        // For the root, "." and ".." are identical (both root); root.parentID is the
        // .parentOfRoot sentinel, so use the root's own fileID.
        let dotDotID = directory.attributes.fileID == .rootDirectory
            ? directory.attributes.fileID
            : directory.attributes.parentID

        var idx = start
        while idx < total {
            let nextCookie = FSDirectoryCookie(UInt64(idx + 1))
            let accepted: Bool
            if !wantsAttrs && idx == 0 {
                accepted = packer.packEntry(name: FSFileName(string: "."),
                                            itemType: .directory,
                                            itemID: directory.attributes.fileID,
                                            nextCookie: nextCookie,
                                            attributes: nil)
            } else if !wantsAttrs && idx == 1 {
                accepted = packer.packEntry(name: FSFileName(string: ".."),
                                            itemType: .directory,
                                            itemID: dotDotID,
                                            nextCookie: nextCookie,
                                            attributes: nil)
            } else {
                let item = entries[idx - prefix]
                // Pack attributes only on the bulk path. On readdir the kernel drops
                // them (it builds dirents from name/type/fileID), and they can shrink
                // entries-per-batch → more round-trips. Ours are in-memory, so passing
                // the full struct on the bulk path is free (unwanted fields ignored).
                accepted = packer.packEntry(
                    name: item.name,
                    itemType: item.attributes.type,
                    itemID: item.attributes.fileID,
                    nextCookie: nextCookie,
                    attributes: wantsAttrs ? item.attributes : nil
                )
            }
            if !accepted { break }   // buffer full: kernel re-calls with last accepted cookie
            idx += 1
        }
        // Content-derived verifier: stable while children are unchanged, bumped on
        // mutation, so a mid-walk change is caught on resume (above). Plain readdir
        // (VNOP_READDIR) is uncached and re-issues every syscall — don't cap the pack
        // loop; the bulk path caches only an intra-enumeration prefetch window. `&+ 1`
        // keeps it nonzero (an empty dir's contentVersion 0 would collide with
        // FSDirectoryVerifierInitial).
        return FSDirectoryVerifier(cv &+ 1)
    }
}

extension VolumeLegacy: FSVolume.OpenCloseOperations {
    // We don't track per-handle state (fds cached for the volume lifetime), so
    // open/close round-trips are pure overhead — tell the kernel to skip them.
    @objc var isOpenCloseInhibited: Bool { true }

    func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        if !isReserved(item) { counters.bump(.openItem) }
        guard let item = item as? SandboxFSItem, item.backingPath != nil else { return }
        try item.openBackingFile()
    }

    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        if !isReserved(item) { counters.bump(.closeItem) }
        // No-op: fd stays cached for the lifetime of the volume.
    }
}

extension VolumeLegacy: FSVolume.ReadWriteOperations {
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        // Reads of sandboxfs_perf / sandboxfs_reconf are the pollers themselves — not
        // build I/O — so they don't count toward "ops served".
        if !isReserved(item) { counters.bump(.read) }
        guard let item = item as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }

        // Virtual files (e.g. sandboxfs_perf) compute fresh bytes on each read.
        let inMemory: Data? = (item as? GeneratedItem)?.render?() ?? item.data
        if let data = inMemory {
            let start = Int(offset)
            let available = max(0, data.count - start)
            let n = min(min(length, buffer.length), available)
            guard n > 0 else { return 0 }
            data.withUnsafeBytes { src in
                _ = buffer.withUnsafeMutableBytes { dst in
                    memcpy(dst.baseAddress, src.baseAddress!.advanced(by: start), n)
                }
            }
            return n
        }

        guard item.backingPath != nil, item.attributes.size > 0 else { return 0 }

        // Map lazily on first read; gate on the mapping too so we don't re-enter
        // openBackingFile (and its lock) on every read once the fd is closed.
        if item.mapping.load(ordering: .relaxed) == nil && item.fileDescriptor < 0 {
            try item.openBackingFile()
        }

        // Prefer mmap: skip the pread syscall and a copy. Lock-free — the acquire
        // load pairs with the publishing release store, so mmapLen is guaranteed
        // visible; the mapping is stable for the item's lifetime.
        if let mmap = item.mapping.load(ordering: .acquiring) {
            let start = Int(offset)
            let available = max(0, item.mmapLen - start)
            let n = min(min(length, buffer.length), available)
            guard n > 0 else { return 0 }
            // Demote SEQUENTIAL → NORMAL on the first out-of-order read (a re-scan
            // from 0 stays sequential-classed). Relaxed ordering: a raced spurious
            // demotion is harmless, and concurrent interleaved streams SHOULD
            // demote (free-behind hurts the other stream).
            let prevEnd = item.lastReadEnd.exchange(start + n, ordering: .relaxed)
            if start != 0, prevEnd != start,
               !item.madviseDemoted.exchange(true, ordering: .relaxed) {
                madvise(mmap, item.mmapLen, MADV_NORMAL)
            }
            counters.bump(.readData)
            _ = buffer.withUnsafeMutableBytes { dst in
                memcpy(dst.baseAddress, mmap.advanced(by: start), n)
            }
            return n
        }

        // Fallback (mmap failed): pread through the retained fd.
        let requested = min(length, buffer.length)
        let fd = item.fileDescriptor
        counters.bump(.readData)
        let n = buffer.withUnsafeMutableBytes { dst -> Int in
            pread(fd, dst.baseAddress, requested, offset)
        }
        if n < 0 {
            let err = errno
            logger.error("pread(fd=\(fd), len=\(requested), off=\(offset)) failed errno=\(err) (\(String(cString: strerror(err)), privacy: .public))")
            throw fs_errorForPOSIXError(err)
        }
        return n
    }

    func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        counters.bump(.write)
        guard let item = item as? SandboxFSItem else { return 0 }

        lockMorph(); defer { unlockMorph() }
        // Read-only to the action — it writes outputs THROUGH symlinks to host, never
        // in-mount. (The controller's morph never writes file content either, so this
        // path is effectively unreached; the COW below is a defensive safety net.)
        if !draining { throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue) }

        // Copy-on-write (§6): a write to CAS-backed or host-backed content would
        // corrupt the shared blob — and the host file — for every other path and
        // every future build. Fork a private copy: snapshot current bytes, drop the
        // CAS link + backing, mint a fresh unique fileID, then mutate the private
        // buffer. The read path prefers `data`, so reads see the fork.
        // (Caveat: siblings still bound to the OLD shared fileID's kernel vnode may
        // briefly serve pre-fork bytes from the shared UBC until reclaim. Sandbox
        // inputs are read-only by convention, so this is a self-heal safety net for
        // misbehaving actions; the next morph unlinks + re-resolves cleanly.)
        if item.digest != nil || item.backingPath != nil {
            var bytes = item.currentBytes()
            if let d = item.digest, let e = casIndex[d] {
                e.linkCount -= 1
                if e.linkCount <= 0 { casIndex[d] = nil }
            }
            item.digest = nil
            item.backingPath = nil
            // The old mapping stays alive (deinit unmaps): the read path prefers
            // `data` from here on, and unmapping under a concurrent reader on the
            // shared old vnode would SIGBUS the mount.
            item.attributes.fileID = FSItem.Identifier(rawValue: SandboxFSItem.getNextID()) ?? .invalid
            item.attributes.linkCount = 1
            spliceData(&bytes, contents, at: Int(offset))
            item.data = bytes
        } else {
            var bytes = item.data ?? Data()
            spliceData(&bytes, contents, at: Int(offset))
            item.data = bytes
        }
        item.attributes.size = UInt64(item.data?.count ?? 0)
        item.attributes.allocSize = item.attributes.size
        return contents.count
    }
}

extension VolumeLegacy: FSVolume.XattrOperations {
    // We serve no xattrs: the reconfigure/seal/drain control channel moved to writes
    // on the `sandboxfs_reconf` magic file (see the `write` VNOP). Inhibiting xattr
    // ops tells the kernel to skip the VNOPs entirely; the methods below are dead
    // stubs kept only to satisfy the protocol.
    @objc var xattrOperationsInhibited: Bool { true }

    func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        throw fs_errorForPOSIXError(ENOATTR)
    }

    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy) async throws {
        throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
    }

    func xattrs(of item: FSItem) async throws -> [FSFileName] {
        return []
    }
}
