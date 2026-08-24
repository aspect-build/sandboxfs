//
//  SandboxFSFileSystem.swift
//  sandbox-fs
//
//  Created by Sahin Yort on 2026-05-28.
//

import Foundation
import FSKit
import os
import Synchronization

// MARK: - File system entry point

@objc
class SandboxFSFileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations & FSManageableResourceMaintenanceOperations {
    private let logger = Logger(subsystem: "sandboxfs", category: "FS")

    // Block-device file systems must conform to the maintenance protocol and pass a
    // check before the system mounts them; our CAS image is always valid, so check/
    // format are no-op successes.
    func startCheck(task: FSTask, options: FSTaskOptions) throws -> Progress {
        task.logMessage("sandboxfs-koio: check OK (spike no-op)")
        task.didComplete(error: nil)
        let p = Progress(totalUnitCount: 1); p.completedUnitCount = 1
        return p
    }
    func startFormat(task: FSTask, options: FSTaskOptions) throws -> Progress {
        task.didComplete(error: nil)
        let p = Progress(totalUnitCount: 1); p.completedUnitCount = 1
        return p
    }

    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler reply: @escaping ((any Error)?) -> Void) {
        logger.debug("unloadResource: \(resource, privacy: .public)")
        if let pathResource = resource as? FSPathURLResource {
            pathResource.url.stopAccessingSecurityScopedResource()
        }
        reply(nil)
    }

    func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void) {
        logger.debug("probeResource: \(resource, privacy: .public)")
        replyHandler(
            FSProbeResult.usable(
                name: "sandboxfs",
                containerID: FSContainerIdentifier(uuid: UUID(uuidString: "4912d97f-937f-499e-8270-3abf7b69bc49")!)
            ),
            nil
        )
    }

    /// Userspace mmap reads over a path-URL resource (the mmap volume; ≤ 26 falls back to
    /// the legacy Operations volume). The volume reads its frozen manifest from the
    /// resource URL once at activation — there is no reconfigure.
    func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, (any Error)?) -> Void) {
        logger.debug("loadResource: \(resource, privacy: .public)")
        guard let pathResource = resource as? FSPathURLResource else {
            replyHandler(nil, fs_errorForPOSIXError(POSIXError.EINVAL.rawValue))
            return
        }
        // Best-effort: with FSRequiresSecurityScopedPathURLResources=false the kernel hands
        // a NON-scoped path URL, so this returns false — which is NOT fatal. The appex reads
        // the manifest (and host content) via its absolute-path entitlement, not this scope.
        // Hard-failing here was the "Loading resource: Permission denied" (EACCES) mount fail.
        if !pathResource.url.startAccessingSecurityScopedResource() {
            logger.debug("resource \(pathResource.url.path, privacy: .public) is not security-scoped; proceeding")
        }
        containerStatus = .ready
        if #available(macOS 27.0, *) {
            replyHandler(VolumeMmap(resource: pathResource), nil)
        } else {
            replyHandler(VolumeLegacy(resource: pathResource), nil)
        }
    }
}

// MARK: - In-memory inode

final class SandboxFSItem: FSItem {
    // Atomic: once the volume is writable the kernel can dispatch `createItem`
    // concurrently, so the old non-atomic `static var` raced two items onto one id
    // (§7). `wrappingAdd` returns the pre-increment value as the fresh id.
    private static let nextID = Atomic<UInt64>(FSItem.Identifier.rootDirectory.rawValue + 1)
    static func getNextID() -> UInt64 {
        nextID.wrappingAdd(1, ordering: .relaxed).oldValue
    }

    // `var` (not `let`): renameItem rewrites it in place. Stays in sync with the
    // parent's `children` key (renameItem re-keys both).
    var name: FSFileName
    let id = SandboxFSItem.getNextID()

    /// Parent in the live graph (weak — children hold the strong refs). Lets a write
    /// VNOP reconstruct an item's mount-relative path by walking to the root, which
    /// is how `createItem` resolves the morph target's backing from the manifest
    /// index by path. Set by addItem/replaceChildren/addParents, cleared on remove.
    weak var parent: SandboxFSItem?

    var attributes = FSItem.Attributes()
    var xattrs: [FSFileName: Data] = [:]
    var data: Data?
    var linkname: FSFileName?

    /// Controller-projected output / writable-dir symlink (created via the
    /// `createSymbolicLink` VNOP during the morph). Such an entry is HIDDEN from
    /// `enumerateDirectory` until its write-through target exists on host scratch, so a
    /// tool that globs its own output directory (e.g. tsc with a broad `include`) does
    /// not see an un-written output as an input (TS5055 "would overwrite input file").
    /// `lookupItem` is NOT filtered, so the action's `open(O_CREAT)` write-through still
    /// resolves. Matches native, where a declared output doesn't exist until written.
    var isProjectedOutput = false

    /// Content digest (manifest hex) when this is a CAS-backed file. `removeItem`
    /// uses it to find the shared CAS entry and decrement its link count; `write`
    /// uses it to detect a shared blob that must be copied-on-write before mutation.
    var digest: String?

    var backingPath: String?
    /// Set true the first time the kernel opens this item (DataCacheHandler.open). Only
    /// an opened file has a live FH that `setCacheState` can target; revoking a
    /// never-opened file is a guaranteed `kIOReturnBadArgument` no-op, so the mmap volume skips that
    /// failing round-trip (it has no cached data/vnode to go stale anyway).
    var wasOpened = false
    /// The reconfigure seq this item last entered/left the live tree at. Drives the
    /// filePool/stash LRU eviction — entries older than the current checkout are
    /// evictable.
    var lastUsedSeq: Int = 0
    /// The NAMES whose lookups in this DIRECTORY returned ENOENT — each such miss
    /// may have planted a kernel negative namecache entry (lifs caches them
    /// per-name). Filled by `lookupItem` on a miss; cleared whenever a
    /// kernel-mediated create lands in this dir (the kernel purges the dir's
    /// negatives wholesale at that moment). Gates touch reporting PER NAME: a dir
    /// gaining names appex-side needs a sentinel purge only if one of those exact
    /// names was probed-and-missed. Capped — an overflowing set degrades to
    /// "any add is risky" (`missedOverflow`).
    var missedNames: Set<String>? = nil
    var missedOverflow = false
    static let missedNamesCap = 512

    @inline(__always) func noteMiss(_ name: String) {
        if missedOverflow { return }
        var set = missedNames ?? Set()
        set.insert(name)
        if set.count > Self.missedNamesCap {
            missedOverflow = true
            missedNames = nil
        } else {
            missedNames = set
        }
    }

    /// The kernel just purged this dir's negative entries (a create landed here).
    @inline(__always) func clearMisses() {
        missedNames = nil
        missedOverflow = false
    }

    /// Would adding `name` here risk being shadowed by a cached negative entry?
    @inline(__always) func addIsRisky(_ name: String) -> Bool {
        missedOverflow || (missedNames?.contains(name) ?? false)
    }
    /// If set, `read` serves fresh bytes from this instead of `data` (virtual files).
    var dataProvider: (() -> Data)?
    private(set) var fileDescriptor: Int32 = -1
    /// The live mmap of the backing file. PUBLISHED with a release store AFTER
    /// `mmapLen` is set, and read with an acquire load on the LOCK-FREE read
    /// path: a plain pointer field let a racing reader observe the pointer
    /// before the length on weakly-ordered ARM (torn publication → mmapLen read
    /// as 0 → silent 0-byte short read). `mmapLen` is valid only after an
    /// acquire load of this returns non-nil.
    let mapping = Atomic<UnsafeMutableRawPointer?>(nil)
    private(set) var mmapLen: Int = 0
    /// Read-pattern watermark: end offset of the last read served. SEQUENTIAL
    /// madvise is the right call for the dominant profile (compilers slurping
    /// sources start-to-finish) but actively WRONG for big random-access
    /// artifacts (tar/OCI layers: trailer/index first, then seeks) — wrong-region
    /// readahead plus free-behind evicting host pages other slots will re-read.
    /// The first non-sequential read demotes the mapping to MADV_NORMAL; those
    /// readers typically seek immediately, so the penalty window is ~zero.
    let lastReadEnd = Atomic<Int>(0)
    let madviseDemoted = Atomic<Bool>(false)
    private let openLock = NSLock()

    private static let itemLogger = Logger(subsystem: "sandboxfs", category: "Item")

    /// By-name index for `lookupItem` (O(1)); the kernel resolves every path
    /// component through lookup, so this stays a dictionary.
    private(set) var children: [String: SandboxFSItem] = [:]

    /// Same children in stable name-sorted order, kept sorted on every mutation so
    /// `enumerateDirectory` serves it directly — no per-call sort, no lazy cache to
    /// invalidate. The kernel re-issues enumerateDirectory on every readdir and
    /// resumes paginated calls by index, so an already-ordered listing is what makes
    /// resume cheap (same property APFS gets from its ordered B-tree). Order matches
    /// the old `children.keys.sorted()`: String's default `<`. Read-only after build,
    /// so concurrent enumerations are pure reads and need no lock.
    private(set) var sortedChildren: [SandboxFSItem] = []

    /// Lower-bound index in `sortedChildren` for `key` (first name >= key).
    private func childIndex(for key: String) -> Int {
        var lo = 0, hi = sortedChildren.count
        while lo < hi {
            let mid = (lo &+ hi) / 2
            if sortedChildren[mid].name.string! < key { lo = mid &+ 1 } else { hi = mid }
        }
        return lo
    }

    /// Bumped on every change to `children`. Returned by `enumerateDirectory` as the
    /// `FSDirectoryVerifier`. Frozen for a reused (unchanged) instance since only
    /// add/remove/replaceChildren touch it — so it's stable across checkouts and the
    /// persistent root re-enumerates only after a rebuild bumps it.
    private(set) var contentVersion: UInt64 = 0

    init(name: FSFileName) {
        self.name = name
        attributes.fileID = FSItem.Identifier(rawValue: id) ?? .invalid
        attributes.size = 0
        attributes.allocSize = 0
        attributes.flags = 0
        // Populate the FULL standard attribute set here so EVERY item satisfies the
        // attribute mask FSKit requests. macOS 26 betas validate completeness and
        // FAULT ("Reported attributes are incomplete") if a requested standard attr
        // (linkCount/uid/gid/accessTime were the gaps) is absent from the valid set;
        // older releases tolerated a partial set. type/mode are set by each item-type
        // creator; parentID by addItem (root sets its own). Specific items override
        // uid/gid (e.g. root → 0/0).
        attributes.linkCount = 1
        attributes.uid = 501
        attributes.gid = 20

        var ts = timespec()
        timespec_get(&ts, TIME_UTC)
        attributes.accessTime = ts
        attributes.addedTime = ts
        attributes.birthTime = ts
        attributes.changeTime = ts
        attributes.modifyTime = ts
    }

    func addItem(_ item: SandboxFSItem) {
        item.attributes.parentID = self.attributes.fileID
        item.parent = self
        let key = item.name.string!
        let i = childIndex(for: key)
        if children[key] != nil, i < sortedChildren.count, sortedChildren[i].name.string! == key {
            sortedChildren[i] = item            // same name → same slot, replace in place
        } else {
            sortedChildren.insert(item, at: i)
        }
        children[key] = item
        contentVersion += 1
    }

    func removeItem(_ item: SandboxFSItem) {
        let key = item.name.string!
        let i = childIndex(for: key)
        if i < sortedChildren.count, sortedChildren[i].name.string! == key {
            sortedChildren.remove(at: i)
        }
        if item.parent === self { item.parent = nil }
        children[key] = nil
        contentVersion += 1
    }

    /// Set the entire child set in one shot — used both to swap a freshly-built
    /// subtree under the root during rebuild and to populate a freshly-materialized
    /// directory. Each child is reparented; the ordered view is sorted once here
    /// (O(n log n)), so building a wide directory is O(n log n), not O(n²).
    func replaceChildren(with newChildren: [SandboxFSItem]) {
        var map: [String: SandboxFSItem] = [:]
        map.reserveCapacity(newChildren.count)
        for child in newChildren {
            child.attributes.parentID = self.attributes.fileID
            child.parent = self
            map[child.name.string!] = child
        }
        children = map
        sortedChildren = newChildren.sorted { $0.name.string! < $1.name.string! }
        contentVersion += 1
    }

    /// Map the backing file, then CLOSE the fd immediately — the mmap survives the
    /// close and the read path only memcpy's from `mmapPtr`. Holding the fd open
    /// would leak one descriptor per cached file (the file pool keeps items alive across
    /// checkouts) until the host hits ENFILE; the mapping only pins a vnode (a much
    /// higher, reclaimable limit). Serialized by `openLock` — runs once per item, the
    /// read path is lock-free. On mmap failure we keep the fd for the pread fallback.
    func openBackingFile() throws {
        openLock.lock()
        defer { openLock.unlock() }
        if mapping.load(ordering: .relaxed) != nil || fileDescriptor >= 0 { return }
        guard let backingPath else { return }
        guard attributes.size > 0 else { return }   // empty file: nothing to map, never open
        let fd = open(backingPath, O_RDONLY)
        if fd < 0 {
            let err = errno
            SandboxFSItem.itemLogger.error("open(\(backingPath, privacy: .public)) failed: errno=\(err) (\(String(cString: strerror(err)), privacy: .public))")
            throw fs_errorForPOSIXError(err)
        }
        // SIGBUS guard (§6): NEVER trust the manifest size for the map length. If the
        // host file is shorter than the manifest claims (truncated/racing build),
        // mapping past EOF and touching those pages raises SIGBUS, which crashes the
        // whole appex (one mount). Clamp to the real on-disk size from fstat.
        var st = stat()
        let realSize = (fstat(fd, &st) == 0) ? Int(st.st_size) : 0
        let size = min(Int(attributes.size), realSize)
        guard size > 0 else { close(fd); return }
        let p = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
        if p != MAP_FAILED {
            mmapLen = size                      // set BEFORE the publishing store
            // MOST sandbox inputs are read start-to-finish (compilers slurping
            // sources/headers), so hint sequential access: aggressive readahead on
            // the cold first read, and free host pages behind us — once bytes are
            // memcpy'd into the mount UBC, cross-checkout warmth rides the reused
            // vnode/UBC, so freeing host pages trims the 2× resident cost. NOT all
            // inputs though — big tar/OCI artifacts are read randomly — so the
            // read path demotes to MADV_NORMAL on the first non-sequential read
            // (see `lastReadEnd`).
            madvise(p, size, MADV_SEQUENTIAL)
            close(fd)               // mapping survives the close; frees the fd
            mapping.store(p, ordering: .releasing)   // publish LAST (pairs with acquire loads)
        } else {
            fileDescriptor = fd     // rare: keep fd so read() can pread
        }
    }

    /// No-op: the fd is closed right after mmap; teardown happens in `releaseBackingFile`.
    func closeBackingFile() {}

    /// Snapshot the item's current bytes into a private buffer — used by write's
    /// copy-on-write fork (§6) to capture a shared/host-backed blob before it stops
    /// being shared. Prefers an already-written `data` buffer, else the mmap, else a
    /// fresh map of the backing file; empty if none.
    func currentBytes() -> Data {
        if let data { return data }
        if mapping.load(ordering: .relaxed) == nil && fileDescriptor < 0 { try? openBackingFile() }
        if let p = mapping.load(ordering: .acquiring), mmapLen > 0 {
            return Data(bytes: p, count: mmapLen)
        }
        return Data()
    }

    /// Tear down the mapping/fd. ONLY safe where no concurrent lock-free reader
    /// can exist: `deinit` (kernel already reclaimed the vnode) and `deactivate`
    /// (unmount). Eviction paths deliberately DON'T call this — they just drop
    /// their reference and let `deinit` unmap when the kernel lets go, because
    /// munmapping under a reader mid-memcpy is a SIGBUS for the whole mount.
    func releaseBackingFile() {
        openLock.lock()
        defer { openLock.unlock() }
        if let p = mapping.exchange(nil, ordering: .acquiringAndReleasing), mmapLen > 0 {
            munmap(p, mmapLen)
            mmapLen = 0
        }
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }
    }

    // ARC frees an old item once the kernel reclaims its last reference; this unmaps
    // at that point. Idempotent, so the `deactivate()` walk is safe too.
    deinit { releaseBackingFile() }
}

// MARK: - Op counters

final class OpCounters {
    /// One op's call count, an `Atomic` so `bump` is lock-free. `Atomic` is
    /// non-copyable, hence a reference type reached through the immutable-after-init
    /// `counters` map.
    final class Counter {
        let count = Atomic<Int>(0)
        @inline(__always) func bump() { count.wrappingAdd(1, ordering: .relaxed) }
    }

    /// Every counted op must be registered here: the map is built once and never
    /// mutated, so lookups need no lock. A `bump` for an unregistered key is silently
    /// dropped — add new ops here.
    private static let knownOps = [
        "activate", "attributes", "lookupItem", "setAttributes", "reclaimItem",
        "readSymbolicLink", "enumerateDirectory", "read", "readData", "getXattr",
        "openItem", "closeItem",
        // Morph (write) VNOPs — driven by the controller's unlink/create syscalls.
        "createItem", "createSymbolicLink", "createLink", "removeItem", "write", "renameItem",
        // Reconfigure-path telemetry (not VNOPs): decoded-tree cache efficacy.
        "treeCacheHit", "treeCacheMiss",
        // KOIO volume (block-device): offload + content-addressed node cache (CAVI).
        "blockmap", "completeIO", "nodeCacheHit", "nodeCacheMiss", "nmCollapse",
    ]

    private let counters: [String: Counter]

    // Direct handles for the per-VNOP hot ops: the read path bumps these with NO string
    // hash / dict probe (`counters.lookupItem.bump()`). They're the same Counter instances
    // registered in `counters`, so the string API, snapshot, and renderText still see them.
    let lookupItem: Counter
    let attributes: Counter
    let enumerateDirectory: Counter
    let blockmap: Counter
    let completeIO: Counter
    let read: Counter
    let reclaimItem: Counter

    init() {
        var map = [String: Counter](minimumCapacity: Self.knownOps.count)
        for op in Self.knownOps { map[op] = Counter() }
        counters = map
        lookupItem = map["lookupItem"]!
        attributes = map["attributes"]!
        enumerateDirectory = map["enumerateDirectory"]!
        blockmap = map["blockmap"]!
        completeIO = map["completeIO"]!
        read = map["read"]!
        reclaimItem = map["reclaimItem"]!
    }

    // String API — cold ops, the mmap volume, and any op without a direct handle. Hashes the
    // key; fine off the hot path.
    func bump(_ key: String) {
        counters[key]?.count.wrappingAdd(1, ordering: .relaxed)
    }
    func snapshot() -> [(String, Int)] {
        counters
            .map { ($0.key, $0.value.count.load(ordering: .relaxed)) }
            .filter { $0.1 > 0 }
            .sorted { $0.1 > $1.1 }
    }
    func snapshotAndReset() -> [(String, Int)] {
        var out: [(String, Int)] = []
        for (name, c) in counters {
            let n = c.count.exchange(0, ordering: .relaxed)
            if n > 0 { out.append((name, n)) }
        }
        return out.sorted { $0.1 > $1.1 }
    }
    func reset() {
        for c in counters.values { c.count.store(0, ordering: .relaxed) }
    }
    // Round the rendered size up to a block. `attributes()` advertises the size and
    // the kernel clamps the following `read()` to it; but reading sandboxfs_perf
    // itself bumps counters, so the re-render at read time is longer than the
    // stat-time size and the kernel would clip the trailing ops. A full block of
    // slack absorbs the handful of bumps between one stat and its read.
    private static let renderBlock = 4096
    func renderText() -> Data {
        var lines = "op\tcount\n"
        for (name, count) in snapshot() {   // only ops that fired, count-desc
            lines += "\(name)\t\(count)\n"
        }
        var data = Data(lines.utf8)
        // Pad with spaces after the final newline (the TSV parser ignores them) so
        // the advertised size always exceeds the slightly-longer read-time re-render.
        let block = Self.renderBlock
        let padded = ((data.count / block) + 2) * block
        data.append(contentsOf: repeatElement(0x20, count: padded - data.count))
        return data
    }
}

