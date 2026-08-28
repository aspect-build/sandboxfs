//
//  VolumeMmap.swift
//  sandbox-fs
//
//  macOS 27+ userspace volume: serves file reads from an mmap of the backing file
//  (pread fallback), over the FSVolume.Handler family that replaces the deprecated
//  FSVolume.Operations protocols. Owns its engine (tree build / reconcile / morph /
//  CAS) and reuses only the API-agnostic infrastructure (SandboxFSItem, OpCounters,
//  Manifest/ProtoWire). The FSUnaryFileSystem picks this class on macOS 27+ via
//  `if #available`; <= 26 keeps the legacy VolumeLegacy.
//

import Foundation
import FSKit
import os
import Synchronization

@available(macOS 27.0, *)
final class VolumeMmap: FSVolume {
    let resource: FSPathURLResource
    let logger = Logger(subsystem: "sandboxfs", category: "Volume")
    let counters = OpCounters()

    let root = VirtualRoot.makeRoot()
    let virtualRoot = VirtualRoot()

    /// Covers the root's child set: sandboxes are built and evicted concurrently.
    private let rootLock = NSLock()
    /// Looking this up (plus a sandbox id) evicts that sandbox — a lookup is the only VNOP a
    /// controller can issue against a read-only mount without a file to write to.
    private static let evictSentinel = "sandboxfs_evict_"

    private var lastAppliedId: String?
    private var reconfigureSeq = 0

    // No lock between reconcile and reads: a `sandboxfs_refresh` reconfigure is
    // contractually issued only when the mount is quiescent (the action is not reading),
    // so the tree mutation never races a lookup/enumerate.

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
    /// Output + writable_dir paths (mount-relative, no leading slash). These project as
    /// symlinks to host scratch; `reconcileDir` leaves them in place (never prunes them
    /// as "removed"). Recomputed on each apply.
    private var protectedPaths: Set<String> = []

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

@available(macOS 27.0, *)
extension VolumeMmap: FSVolume.PathConfOperations {
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumLinkCount: Int { -1 }
    var maximumXattrSize: Int { Int.max }
    var maximumFileSize: UInt64 { UInt64.max }
}

// MARK: - Volume operations

@available(macOS 27.0, *)
extension VolumeMmap: FSVolume.Handler {
    // Read-only: the action reads inputs through the mount and writes outputs THROUGH
    // symlinks to host scratch (never in-mount), so no write VNOP is ever legitimate.
    // The tree is built/reconciled internally (activate / sandboxfs_refresh), not by
    // kernel-mediated writes.
    @objc var requestedMountOptions: FSVolume.MountOptions { [.readOnly] }

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
            // LRU: refresh recency on hit.
            if let i = treeCacheOrder.firstIndex(of: rd) {
                treeCacheOrder.remove(at: i)
                treeCacheOrder.append(rd)
            }
            m.root = cached
            return m
        }
        guard let m = ProtoWire.decodeManifest(data) else { return nil }
        if let r = m.root, !r.digest.isEmpty {
            if treeCache[r.digest] == nil {
                treeCacheOrder.append(r.digest)
                if treeCacheOrder.count > treeCacheLimit {
                    let evicted = treeCacheOrder.removeFirst()
                    treeCache[evicted] = nil
                }
            }
            treeCache[r.digest] = r
        }
        return m
    }

    // The reconfigure response read back through the control file: the raw

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

    /// Materialize a manifest Directory into an FSItem subtree — always built
    /// fresh. A directory the kernel already knows is NEVER moved appex-side: XNU updates a
    /// dir vnode's identity (v_parent/v_name, what getcwd's path reconstruction walks) only on
    /// rename(2), so reattaching one here leaves stale identity and getcwd fails ENOENT inside
    /// the subtree (observed: node uv_cwd crash). Only the controller relocates a directory, by
    /// rename. Files reuse pooled instances via `makeFileItem` — a file is never a cwd, so
    /// rebinding its fileID without a rename is safe.
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

    /// The fixed root items every projection carries alongside the manifest tree:
    /// the virtual files plus the Spotlight/fseventsd opt-out sentinels.

    /// True when root holds only the virtual items — the cold-mount state where a
    /// full build (rather than a controller-morphed delta) is warranted.
    private func inputTreeIsEmpty() -> Bool {
        for child in root.sortedChildren where !(child is GeneratedItem) {
            return false
        }
        return true
    }

    /// Output / writable_dir paths (mount-relative, no leading slash). reconcileDir
    /// leaves these in place rather than pruning them as "removed".
    private func computeProtectedPaths(_ manifest: Manifest) -> Set<String> {
        var p = Set<String>()
        for rel in (manifest.outputs ?? [:]).keys { p.insert(normRel(rel)) }
        for rel in (manifest.writableDirs ?? [:]).keys { p.insert(normRel(rel)) }
        return p
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
    /// INVALIDATION syscalls (unlink for changed/removed files+symlinks, one rename
    /// and the removal of each topmost removed dir), so every name this walk adds
    /// is either freshly purged or never existed. The walk:
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
    /// An item the reconcile wants the kernel to drop its cache for. `removed`
    /// distinguishes a changed-file rebind (false → `.invalidate`, name stays) from a
    /// true removal (true → `.revoke`). Only files are actioned (see `revokeFromCache`).
    struct RevokeOp {
        let item: SandboxFSItem
        let removed: Bool
    }

    private func reconcileTree(_ manifest: Manifest, revoke: inout [RevokeOp]) -> [String] {
        var touch: [String] = []
        let outputParents = outputParentPaths(manifest)
        if let r = manifest.root {
            if !r.digest.isEmpty && root.digest == r.digest {
                // tree unchanged — outputs only
            } else {
                reconcileDir(root, r, relPath: "", outputParents: outputParents, revoke: &revoke, touch: &touch)
                root.digest = r.digest.isEmpty ? nil : r.digest
            }
        }
        reconcileOutputs(manifest, revoke: &revoke, touch: &touch)
        return touch
    }

    private func reconcileOutputs(_ manifest: Manifest, revoke: inout [RevokeOp], touch: inout [String]) {
        var all = manifest.outputs ?? [:]
        let fileOutputKeys = Set((manifest.outputs ?? [:]).keys.map(normRel))
        for (k, v) in manifest.writableDirs ?? [:] { all[k] = v }
        for (sandboxPath, target) in all {
            let rel = normRel(sandboxPath)
            let comps = rel.split(separator: "/").map(String.init)
            guard let leaf = comps.last, !leaf.isEmpty else { continue }
            var parent = root
            var prefix = ""
            var parentIsFresh = false
            for c in comps.dropLast() {
                let parentRel = prefix
                prefix = prefix.isEmpty ? c : prefix + "/" + c
                if let next = parent.children[c], next.attributes.type == .directory {
                    parent = next
                    parentIsFresh = false
                } else {
                    if let occ = parent.children[c] { casUnref(occ); parent.removeItem(occ); revoke.append(RevokeOp(item: occ, removed: true)) }
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
            if let existing = parent.children[leaf] {
                if existing.attributes.type == .symlink && existing.linkname?.string == target { continue }
                casUnref(existing); parent.removeItem(existing); revoke.append(RevokeOp(item: existing, removed: true))
            }
            let link = FSFileName(string: target)
            let item = SandboxFSItem(name: FSFileName(string: leaf))
            item.attributes.type = .symlink
            item.attributes.mode = UInt32(S_IFLNK | 0o777)
            item.attributes.size = UInt64(link.data.count)
            item.linkname = link
            item.projected = fileOutputKeys.contains(rel)
            let risky = parent.addIsRisky(leaf)
            parent.addItem(item)
            if !parentIsFresh && risky { touch.append(comps.dropLast().joined(separator: "/")) }
        }
    }

    /// SPIKE (FSKit V3 cache-handler): the appex converges the tree itself and
    /// `setCacheState`s removed/changed items (collected into `revoke`, invalidated
    /// lock-free by the caller) instead of relying on the controller's unlink morph.
    private func reconcileDir(_ item: SandboxFSItem, _ d: ManifestDir, relPath: String,
                              outputParents: Set<String>,
                              revoke: inout [RevokeOp], touch: inout [String]) {
        let isRoot = item === root
        func rel(_ name: String) -> String { relPath.isEmpty ? name : relPath + "/" + name }
        var toAdd: [SandboxFSItem] = []
        var desired = Set<String>()

        for f in d.files ?? [] {
            desired.insert(f.name)
            let r = rel(f.name)
            if protectedPaths.contains(r) { continue }
            if let existing = item.children[f.name] {
                if existing.digest != nil && existing.digest == f.digest { continue }
                // CHANGED content: rebind in place so the kernel vnode stays warm, then
                // setCacheState(.invalidate) (caller, via revoke) drops the stale pages →
                // the same vnode re-reads the new backing. Falls back to remove+add only
                // for representation flips (host-symlink promotion) rebindFile rejects.
                if rebindFile(existing, to: f) { revoke.append(RevokeOp(item: existing, removed: false)); continue }
                casUnref(existing); item.removeItem(existing); revoke.append(RevokeOp(item: existing, removed: true))
            }
            toAdd.append(materializeFile(f))
        }
        for s in d.symlinks ?? [] {
            desired.insert(s.name)
            let r = rel(s.name)
            if protectedPaths.contains(r) { continue }
            if let existing = item.children[s.name] {
                if existing.attributes.type == .symlink && existing.linkname?.string == s.target { continue }
                casUnref(existing); item.removeItem(existing); revoke.append(RevokeOp(item: existing, removed: true))
            }
            toAdd.append(materializeSymlink(s))
        }
        for sub in d.directories ?? [] {
            desired.insert(sub.name)
            let r = rel(sub.name)
            if let existing = item.children[sub.name] {
                if existing.attributes.type == .directory {
                    if existing.digest == sub.digest { continue }
                    reconcileDir(existing, sub, relPath: r, outputParents: outputParents, revoke: &revoke, touch: &touch)
                    existing.digest = sub.digest
                    setDirSize(existing)
                } else {
                    casUnref(existing); item.removeItem(existing); revoke.append(RevokeOp(item: existing, removed: true))
                    toAdd.append(materializeDir(sub))
                }
            } else {
                toAdd.append(materializeDir(sub))
            }
        }

        if !toAdd.isEmpty {
            if toAdd.count > 4 {
                var keep = item.sortedChildren
                keep.append(contentsOf: toAdd)
                item.replaceChildren(with: keep)
            } else {
                for child in toAdd { item.addItem(child) }
            }
            setDirSize(item)
            if toAdd.contains(where: { item.addIsRisky($0.name.string ?? "") }) {
                touch.append(relPath)
            }
        }

        for child in item.sortedChildren {
            let name = child.name.string ?? ""
            if desired.contains(name) { continue }
            if isRoot, child is GeneratedItem { continue }
            if name.hasPrefix("._") || name == ".DS_Store" { continue }
            let r = rel(name)
            if protectedPaths.contains(r) { continue }
            if child.attributes.type == .directory && outputParents.contains(r) { continue }
            casUnref(child); item.removeItem(child); revoke.append(RevokeOp(item: child, removed: true))
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
    /// Build (cold) or reconcile (refresh) the live tree to `manifest`. `root` itself is
    /// never replaced. Reconcile collects a `revoke` list for kernel-cache invalidation —
    /// actioned by `revokeFromCache` (see #1).
    func applyManifest(_ manifest: Manifest) {
        reconfigureSeq += 1
        protectedPaths = computeProtectedPaths(manifest)
        let cold = manifest.fullBuild ?? inputTreeIsEmpty()
        var revoke: [RevokeOp] = []
        if cold {
            buildFullTree(manifest)
        } else {
            _ = reconcileTree(manifest, revoke: &revoke)
        }
        lastAppliedId = manifest.id
        trimPools()
        for op in revoke { revokeFromCache(op) }
        logger.notice("mmap applied id=\(manifest.id, privacy: .public) mode=\(cold ? "build" : "reconcile", privacy: .public) revoked=\(revoke.count, privacy: .public)")
    }

    /// Bound the file and symlink pools (each pooled file may pin an mmap / host vnode).
    /// Runs at the end of an apply, which the contract guarantees is quiesced, so
    /// dropping a victim races no in-flight read; `deinit` unmaps once the kernel
    /// reclaims (never munmap here — that would SIGBUS a lock-free reader).
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

    func activate(options: FSTaskOptions) async throws -> FSActivateResult {
        counters.bump(.activate)
        return FSActivateResult(rootItem: root)!
    }

    /// The FSKit on this OS calls `activateVolumeWithOptions:` / `deactivateVolumeWithOptions:`,
    /// which the SDK we build against does not declare — its `FSVolume.Handler` still spells them
    /// `activateWithOptions:` / `deactivateWithOptions:`. Both names reach the same code, so the
    /// volume activates whichever the running framework asks for. (Confirmed against the runtime's
    /// own BridgeSupport: same reply-block shape, `(result, error)`.)
    @objc(activateVolumeWithOptions:replyHandler:)
    func activateVolume(options: FSTaskOptions, replyHandler: @escaping (FSActivateResult?, Error?) -> Void) {
        counters.bump(.activate)
        replyHandler(FSActivateResult(rootItem: root), nil)
    }

    @objc(deactivateVolumeWithOptions:replyHandler:)
    func deactivateVolume(options: FSDeactivateOptions, replyHandler: @escaping (Error?) -> Void) {
        Task { [weak self] in
            try? await self?.deactivate(options: options)
            replyHandler(nil)
        }
    }

    /// One mount serves every sandbox of a workspace: `<mount>/<id>` is built the first time
    /// anything looks it up, out of `<resource>/<id>.pb`, and dropped when the controller looks
    /// up `sandboxfs_evict_<id>` at destroy. So the FSKit mount is paid once per workspace
    /// rather than once per action, and an action's tree costs nothing until it is touched.
    ///
    /// Actions run concurrently against the one mount, so unlike the single-manifest volume
    /// this is NOT quiesced: `rootLock` covers every mutation of the root's child set.
    /// Resolve a sandbox id to its subroot, building it on first touch. Holds `rootLock` across
    /// the whole thing, hit included: several actions are created and torn down at once, so an
    /// unsynchronized read of the root's child set races an insert.
    private func sandboxRoot(_ id: String) -> SandboxFSItem? {
        rootLock.lock()
        defer { rootLock.unlock() }
        if let live = root.children[id] { return live }
        let path = resource.url.appendingPathComponent(id + ".pb").path
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        guard var m = parseManifest(data) else {
            logger.error("manifest unparseable at \(path, privacy: .public)")
            return nil
        }
        m.id = id
        let item = buildSandbox(m, named: id)
        root.addItem(item)
        logger.debug("built sandbox \(id, privacy: .public) (\(item.children.count, privacy: .public) top-level)")
        return item
    }

    /// Drop a sandbox's subtree. The controller does this at destroy, before it deletes the
    /// manifest, so a long build doesn't accumulate every action's tree. Items the kernel still
    /// holds vnodes for stay alive until it reclaims them — `deinit` unmaps then.
    private func evictSandbox(_ id: String) {
        rootLock.lock()
        defer { rootLock.unlock() }
        guard let item = root.children[id] else { return }
        root.removeItem(item)
        var stack: [SandboxFSItem] = [item]
        while let it = stack.popLast() {
            if let dg = it.digest, it.attributes.type == .file, let e = casIndex[dg] {
                e.linkCount -= 1
                if e.linkCount <= 0 { casIndex[dg] = nil }
            }
            stack.append(contentsOf: it.children.values)
        }
        logger.debug("evicted sandbox \(id, privacy: .public)")
    }

    /// The sandbox's own root: its input tree, plus a symlink per declared output and writable
    /// dir pointing at the host scratch target the action writes through to.
    private func buildSandbox(_ manifest: Manifest, named id: String) -> SandboxFSItem {
        let item = SandboxFSItem(name: FSFileName(string: id))
        item.attributes.type = .directory
        item.attributes.mode = UInt32(S_IFDIR | 0o755)
        item.attributes.uid = 501
        item.attributes.gid = 20
        var kids: [SandboxFSItem] = []
        if let r = manifest.root {
            for f in r.files ?? [] { kids.append(materializeFile(f)) }
            for d in r.directories ?? [] { kids.append(materializeDir(d)) }
            for s in r.symlinks ?? [] { kids.append(materializeSymlink(s)) }
        }
        item.replaceChildren(with: kids)
        for (path, target) in manifest.outputs ?? [:] {
            addSymlink(sandboxPath: path, target: target, under: item, kind: "output")
        }
        for (path, target) in manifest.writableDirs ?? [:] {
            addSymlink(sandboxPath: path, target: target, under: item, kind: "writable_dir")
        }
        item.digest = manifest.root?.digest
        setDirSize(item)
        return item
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

    func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem, context: FSContext) async throws -> FSGetAttributesResult {
        counters.bump(.attributes)
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
        return FSGetAttributesResult(attributes: item.attributes)!
    }

    func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem, context: FSContext) async throws -> FSSetAttributesResult {
        counters.bump(.setAttributes)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    func lookupItem(named name: FSFileName, in directory: FSItem, context: FSContext) async throws -> FSLookupItemResult {
        counters.bump(.lookupItem)
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        // Lookup names come from namei — arbitrary action-controlled bytes, NOT
        // guaranteed UTF-8. A force-unwrap here let any non-UTF8 probe (old
        // tarballs with Latin-1 names) crash the appex = kill the whole mount.
        // We key children by String, so a non-decodable name simply doesn't exist.
        guard let key = name.string else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        // The root resolves sandbox ids: building one on first touch is what makes the
        // projection lazy, and the evict sentinel is how the controller tears one down.
        if directory === root {
            if let id = key.dropPrefixIfPresent(Self.evictSentinel) {
                evictSandbox(id)
                throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
            }
            guard let item = sandboxRoot(key) else {
                throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
            }
            return FSLookupItemResult(foundItem: item, itemName: name, itemAttributes: item.attributes)!
        }
        guard let item = directory.children[key] else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        return FSLookupItemResult(foundItem: item, itemName: name, itemAttributes: item.attributes)!
    }

    func reclaimItem(_ item: FSItem) async throws {
        if !(item is GeneratedItem) { counters.bump(.reclaimItem) }
    }

    func readSymbolicLink(_ item: FSItem, context: FSContext) async throws -> FSReadSymlinkResult {
        counters.bump(.readSymbolicLink)
        guard let item = item as? SandboxFSItem, item.attributes.type == .symlink, let link = item.linkname else {
            throw fs_errorForPOSIXError(POSIXError.ENOLINK.rawValue)
        }
        return FSReadSymlinkResult(contents: link, symlinkAttributes: item.attributes)!
    }

    func createItem(named name: FSFileName, type: FSItem.ItemType, in directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, context: FSContext) async throws -> FSCreateItemResult {
        counters.bump(.createItem)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    func createSymbolicLink(named name: FSFileName, in directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName, context: FSContext) async throws -> FSCreateSymlinkResult {
        counters.bump(.createSymbolicLink)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    /// Hard link: add a second name referencing `item`'s content. We mint a new
    /// FSItem that SHARES the target's fileID (→ same FH → same kernel vnode + UBC,
    /// §2) and backing, and bump the CAS link count so the blob survives until the
    /// last name is removed. supportsHardLinks must be true for the kernel to call us.
    func createLink(to item: FSItem, named name: FSFileName, in directory: FSItem, context: FSContext) async throws -> FSCreateLinkResult {
        counters.bump(.createLink)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    func removeItem(_ item: FSItem, named name: FSFileName, from directory: FSItem, context: FSContext) async throws -> FSRemoveItemResult {
        counters.bump(.removeItem)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    /// Move an item within the graph. Used if the controller morph (or an action)
    /// renames; the kernel rename path also purges the namecache for both names.
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?, context: FSContext) async throws -> FSRenameItemResult {
        counters.bump(.renameItem)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }

    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier, attributes: FSItem.GetAttributesRequest?, packer: FSDirectoryEntryPacker, context: FSContext) async throws -> FSEnumerateDirectoryResult {
        // Listing the mount root walks the same child set that creates and evictions mutate.
        if directory === root { rootLock.lock() }
        defer { if directory === root { rootLock.unlock() } }
        counters.bump(.enumerateDirectory)
        guard let directory = directory as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
        }
        let snapshot = directory.sortedChildren
        let cv = directory.contentVersion

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
        return FSEnumerateDirectoryResult(verifier: UInt64(cv &+ 1))!
    }
}

@available(macOS 27.0, *)
// EXPERIMENT (IDEAS.md lever #0): DataCacheHandler conformance REMOVED.
//
// The mmap volume conformed to FSVolume.DataCacheHandler purely for `setCacheState` (changed-file
// .invalidate at reconcile). But the protocol forces an open()/close() VNOP per opened
// file — measured ~14.7k + 14.7k ≈ 29k round-trips/build that V1 inhibited
// (`isOpenCloseInhibited = true`). The deferred-close caching those buy is a non-lever
// (warm access is already kernel-served), and `setCacheState` only saves a controller
// unlink on the FEW changed files per checkout — a bad trade.
//
// Dropping the conformance: (a) the kernel should stop dispatching open/close (the thing
// this experiment measures — watch openItem/closeItem → 0 in sandboxfs_perf); (b) reads
// are UNAFFECTED — ReadWriteHandler.read maps the backing lazily on first read itself
// (see readBytes), it never depended on open(); (c) changed/removed-file kernel-cache
// purge reverts to the controller morph (appexHandlesFiles=false in Pool.swift), the
// V1-proven, lease-free path that reconcileTree already assumes (see applyManifest doc).
// Nothing marks an item as opened any more, so revokeFromCache no-ops (see below). To
// revert: restore this extension, re-add the opened flag on SandboxFSItem, and set
// appexHandlesFiles back to the macOS-27 gate.

@available(macOS 27.0, *)
extension VolumeMmap {
    /// Discard the kernel's caches for a removed/changed item and evict its name.
    /// `.revoke` is the only action that reclaims the vnode → `cache_purge` (Q2),
    /// which drops the name from the parent's namecache and any child entries.
    /// MUST run without the morph lock held (the kernel may reenter VNOPs — Q5).
    /// Discard the kernel cache for a FILE the reconcile touched. Established by the
    /// 2026-06-18 setCacheState experiments (see memory `setcachestate-needs-live-fh`):
    ///   • changed content (rebound in place) → `.invalidate`: drops stale UBC pages so
    ///     the warm vnode re-reads the new backing. Cold/un-opened files have nothing
    ///     cached → no-op.
    ///   • removed file → `.revoke`: a warm (opened) file's vnode is childless, so it
    ///     reclaims → `cache_purge` drops the name. A cold file has no held vnode, so
    ///     the next lookup falls through to the (now-pruned) tree → natural ENOENT.
    /// DIRECTORIES are skipped: setCacheState cannot evict a dir whose warm children pin
    /// its vnode (the call succeeds but no reclaim → no cache_purge). Removed directories
    /// are evicted by the controller's kernel-mediated unlink (the morph).
    func revokeFromCache(_ op: RevokeOp) {
        // OPEN ISSUE (#1): no-op. `setCacheState` went away with the DataCacheHandler
        // conformance, and there is no controller unlink in the pull model — so a refresh
        // that CHANGES or REMOVES a file does not purge the kernel's UBC/namecache for it.
        // Refresh is reliable only for ADDED names. Restoring DataCacheHandler+setCacheState
        // (at the cost of the open/close VNOP storm) is what would close this.
        _ = op
    }

    /// CAS unref on removal: drop the shared blob index entry when its last path goes.
    func casUnref(_ item: SandboxFSItem) {
        guard item.attributes.type == .file, let d = item.digest, let e = casIndex[d] else { return }
        e.linkCount -= 1
        if e.linkCount <= 0 { casIndex[d] = nil }
    }

    /// SPIKE: rebind a CHANGED regular file IN PLACE — keep the same FSItem (so its
    /// fileID/kernel vnode stays warm), drop the old backing, repoint to the new
    /// content. The caller then `setCacheState(.invalidate)`s it so the kernel
    /// re-reads the same vnode against the new backing. Returns false for cases that
    /// need a fresh item (representation flips to/from a host symlink), so the caller
    /// falls back to remove+add. Regular-file content change is the common reconcile
    /// case (and the only one setCacheState can serve — dirs/symlinks have no handle).
    func rebindFile(_ existing: SandboxFSItem, to f: ManifestFile) -> Bool {
        guard existing.attributes.type == .file, existing.backingPath != nil,
              existing.linkname == nil, !f.projectsAsHostSymlink else { return false }
        casUnref(existing)
        existing.releaseBackingFile()      // munmap/close → next read re-opens new backing
        existing.data = nil
        existing.digest = f.digest
        existing.backingPath = f.hostPath
        let exec = f.executable ?? false
        existing.attributes.size = f.size
        existing.attributes.allocSize = f.size
        existing.attributes.mode = UInt32(S_IFREG) | (exec ? 0o755 : 0o644)
        if let e = casIndex[f.digest] {
            e.linkCount += 1
        } else {
            let e = CASEntry(fileID: existing.attributes.fileID.rawValue,
                             backingPath: f.hostPath, size: f.size, executable: exec)
            e.linkCount = 1
            casIndex[f.digest] = e
        }
        return true
    }

    /// Ancestor path prefixes of every output / writable_dir — scaffolding dirs the
    /// reconcile must NOT prune as "removed" (reconcileOutputs re-projects them).
    func outputParentPaths(_ manifest: Manifest) -> Set<String> {
        var s: Set<String> = []
        var all = manifest.outputs ?? [:]
        for (k, v) in manifest.writableDirs ?? [:] { all[k] = v }
        for key in all.keys {
            var prefix = ""
            for c in normRel(key).split(separator: "/").map(String.init).dropLast() {
                prefix = prefix.isEmpty ? c : prefix + "/" + c
                s.insert(prefix)
            }
        }
        return s
    }
}

@available(macOS 27.0, *)
extension VolumeMmap: FSVolume.ReadWriteHandler {
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> FSReadFileResult {
        guard let s = item as? SandboxFSItem else { throw fs_errorForPOSIXError(POSIXError.EIO.rawValue) }
        let n = try await readBytes(from: item, at: offset, length: length, into: buffer)
        return FSReadFileResult(bytesRead: n, itemAttributes: s.attributes)!
    }

    private func readBytes(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        counters.bump(.read)
        guard let item = item as? SandboxFSItem else {
            throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
        }

        // Virtual files (e.g. sandboxfs_perf) compute
        // fresh bytes on each read. On FSKit V3 the read result carries INLINE attributes,
        // so refresh the advertised size to the served length here — otherwise the
        // kernel would see a stale size (0) and clamp the control-channel read-back
        // to 0 bytes (breaking the reconfigure handshake).
        if let provider = (item as? GeneratedItem)?.render {
            let size = UInt64(provider().count)
            item.attributes.size = size
            item.attributes.allocSize = size
        }
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

    func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> FSWriteFileResult {
        let n = try await writeBytes(contents: contents, to: item, at: offset)
        let attrs = (item as? SandboxFSItem)?.attributes ?? root.attributes
        return FSWriteFileResult(bytesWritten: n, itemAttributes: attrs, freeSpace: .noUpdate)!
    }

    private func writeBytes(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        counters.bump(.write)
        throw fs_errorForPOSIXError(POSIXError.EROFS.rawValue)   // read-only mount
    }
}

@available(macOS 27.0, *)
extension VolumeMmap: FSVolume.XattrHandler {
    // We serve no xattrs: the reconfigure/seal/drain control channel moved to writes
    // on the `sandboxfs_reconf` magic file (see the `write` VNOP). Inhibiting xattr
    // ops tells the kernel to skip the VNOPs entirely; the methods below are dead
    // stubs kept only to satisfy the protocol.
    @objc var xattrOperationsInhibited: Bool { true }

    func xattr(named name: FSFileName, of item: FSItem, context: FSContext) async throws -> FSGetXattrResult {
        throw fs_errorForPOSIXError(ENOATTR)
    }

    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, context: FSContext) async throws -> FSSetXattrResult {
        throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
    }

    func xattrs(of item: FSItem, context: FSContext) async throws -> FSListXattrsResult {
        return FSListXattrsResult(xattrNames: [])!
    }
}
