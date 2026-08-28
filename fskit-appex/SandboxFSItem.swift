import Foundation
import FSKit
import os
import Synchronization

/// One node of the projected tree: a file, directory or symlink. Instance identity IS inode
/// identity — the kernel binds a vnode per `attributes.fileID`, so reusing an instance across
/// checkouts is what keeps its namecache entry and UBC warm.
class SandboxFSItem: FSItem {
    /// Kernel can dispatch two operations at the same time, so ID generation has to be atomic.
    private static let nextID = Atomic<UInt64>(FSItem.Identifier.rootDirectory.rawValue + 1)
    static func getNextID() -> UInt64 {
        nextID.wrappingAdd(1, ordering: .relaxed).oldValue
    }

    /// Renameable item; mv /a to /b moves it in place.
    var name: FSFileName

    /// Where this item points to, optional, set if the item is a link
    var linkname: FSFileName?

    /// Weak ref to the parent item, set by addItem/replaceChildren/addParents, cleared on remove.
    weak var parent: SandboxFSItem?

    var attributes = FSItem.Attributes()
    var xattrs: [FSFileName: Data] = [:]
    var data: Data?

    /// A controller-projected output symlink. HIDDEN from `enumerateDirectory` until its
    /// write-through target exists on host scratch, so a tool that globs its own output
    /// directory doesn't see an unwritten output as an input (tsc TS5055). `lookupItem` is
    /// not filtered, so the action's own `open(O_CREAT)` still resolves.
    var projected = false

    /// Content digest (manifest hex) when this is a CAS-backed file. `removeItem` finds the
    /// shared CAS entry by it to unref; `write` detects a shared blob to copy before mutating.
    var digest: String?

    var backingPath: String?

    /// The reconfigure this item last entered or left a pool at. Orders LRU eviction of the
    /// file and symlink pools.
    var lastUsedSeq = 0

    init(name: FSFileName) {
        self.name = name
        attributes.fileID = FSItem.Identifier(rawValue: Self.getNextID()) ?? .invalid
        attributes.size = 0
        attributes.allocSize = 0
        attributes.flags = 0
        // FSKit FAULTS ("Reported attributes are incomplete") if a requested standard attr is
        // missing, so every item carries the full set from birth. type/mode come from each
        // item-type creator, parentID from addItem; root overrides uid/gid.
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

    /// The NAMES whose lookups in this DIRECTORY returned ENOENT, each of which may have planted
    /// a kernel negative namecache entry. Adding one of those exact names later needs a sentinel
    /// purge to unshadow it; an overflowing set degrades to "any add is risky".
    private var missedNames: Set<String> = []
    private var missedOverflow = false
    private static let missedNamesCap = 512

    @inline(__always) final func noteMiss(_ name: String) {
        if missedOverflow { return }
        missedNames.insert(name)
        if missedNames.count > Self.missedNamesCap {
            missedOverflow = true
            missedNames = []
        }
    }

    /// The kernel just purged this dir's negative entries (a create landed here).
    @inline(__always) final func clearMisses() {
        missedNames = []
        missedOverflow = false
    }

    /// Would adding `name` here risk being shadowed by a cached negative entry?
    @inline(__always) final func addIsRisky(_ name: String) -> Bool {
        missedOverflow || missedNames.contains(name)
    }

    /// By-name index for `lookupItem` (O(1)); the kernel resolves every path component through
    /// lookup, so this stays a dictionary.
    private(set) var children: [String: SandboxFSItem] = [:]

    /// The same children in name order, kept sorted on every mutation so `enumerateDirectory`
    /// serves it directly — the kernel re-issues the enumeration on every readdir and resumes
    /// paginated calls by index, which an already-ordered listing makes cheap. Read-only after
    /// build, so concurrent enumerations need no lock.
    private(set) var sortedChildren: [SandboxFSItem] = []

    /// Bumped on every change to `children`, and returned as the `FSDirectoryVerifier`. Frozen
    /// for a reused (unchanged) instance, so a persistent dir re-enumerates only after a rebuild.
    private(set) var contentVersion: UInt64 = 0

    /// Lower-bound index in `sortedChildren` for `key` (first name >= key).
    private func childIndex(for key: String) -> Int {
        var lo = 0, hi = sortedChildren.count
        while lo < hi {
            let mid = (lo &+ hi) / 2
            if sortedChildren[mid].name.string! < key { lo = mid &+ 1 } else { hi = mid }
        }
        return lo
    }

    final func addItem(_ item: SandboxFSItem) {
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

    final func removeItem(_ item: SandboxFSItem) {
        let key = item.name.string!
        let i = childIndex(for: key)
        if i < sortedChildren.count, sortedChildren[i].name.string! == key {
            sortedChildren.remove(at: i)
        }
        if item.parent === self { item.parent = nil }
        children[key] = nil
        contentVersion += 1
    }

    /// Set the entire child set in one shot — swapping in a freshly built subtree, or populating
    /// a directory as it materializes. Sorts once, so a wide directory costs O(n log n), not O(n²).
    final func replaceChildren(with newChildren: [SandboxFSItem]) {
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

    private(set) var fileDescriptor: Int32 = -1

    /// The live mmap of the backing file. PUBLISHED with a release store AFTER `mmapLen` is set,
    /// and read with an acquire load on the LOCK-FREE read path: a plain pointer field let a
    /// racing reader observe the pointer before the length on weakly-ordered ARM (torn
    /// publication → silent 0-byte short read). `mmapLen` is valid only once an acquire load of
    /// this returns non-nil.
    let mapping = Atomic<UnsafeMutableRawPointer?>(nil)
    private(set) var mmapLen: Int = 0

    /// End offset of the last read served. Sequential madvise suits the dominant profile
    /// (compilers slurping sources) but is actively wrong for big random-access artifacts
    /// (tar/OCI layers), so the first non-sequential read demotes the mapping to MADV_NORMAL.
    let lastReadEnd = Atomic<Int>(0)
    let madviseDemoted = Atomic<Bool>(false)

    private let openLock = NSLock()
    private static let itemLogger = Logger(subsystem: "sandboxfs", category: "Item")

    /// Map the backing file, then CLOSE the fd immediately — the mapping survives it and only
    /// pins a vnode, whereas holding the fd would leak a descriptor per pooled file until the
    /// host hits ENFILE. Serialized by `openLock`, runs once per item; the read path is lock-free.
    final func openBackingFile() throws {
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
        // NEVER trust the manifest size for the map length: if the host file is shorter than it
        // claims, touching a page past EOF raises SIGBUS and takes the whole appex — and with it
        // the mount — down. Clamp to what is really on disk.
        var st = stat()
        let realSize = (fstat(fd, &st) == 0) ? Int(st.st_size) : 0
        let size = min(Int(attributes.size), realSize)
        guard size > 0 else { close(fd); return }
        let p = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
        if p != MAP_FAILED {
            mmapLen = size                      // set BEFORE the publishing store
            // Readahead for the cold first read, and free host pages behind us: once bytes are
            // memcpy'd into the mount UBC the warmth rides the reused vnode, so the second
            // resident copy is waste. Demoted on the first non-sequential read (`lastReadEnd`).
            madvise(p, size, MADV_SEQUENTIAL)
            close(fd)               // mapping survives the close; frees the fd
            mapping.store(p, ordering: .releasing)   // publish LAST (pairs with acquire loads)
        } else {
            fileDescriptor = fd     // rare: keep fd so read() can pread
        }
    }

    /// Snapshot the item's current bytes — write's copy-on-write fork, capturing a shared or
    /// host-backed blob before it stops being shared.
    final func currentBytes() -> Data {
        if let data { return data }
        if mapping.load(ordering: .relaxed) == nil && fileDescriptor < 0 { try? openBackingFile() }
        if let p = mapping.load(ordering: .acquiring), mmapLen > 0 {
            return Data(bytes: p, count: mmapLen)
        }
        return Data()
    }

    /// Tear down the mapping/fd. ONLY safe where no concurrent lock-free reader can exist:
    /// `deinit` (the kernel already reclaimed the vnode) and `deactivate` (unmount). Eviction
    /// deliberately doesn't call this — it drops its reference and lets `deinit` unmap, because
    /// munmapping under a reader mid-memcpy is a SIGBUS for the whole mount.
    final func releaseBackingFile() {
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

    deinit { releaseBackingFile() }
}

extension String {
    /// The remainder after `prefix`, or nil when the string doesn't start with it.
    func dropPrefixIfPresent(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}
