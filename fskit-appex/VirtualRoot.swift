import Foundation
import FSKit

/// An item the appex generates rather than projects: the mount's marker, its counters, and the
/// OS opt-out sentinels. Never part of the manifest tree, so reconcile walks skip it and its
/// VNOPs stay out of the op counters — the perf reader and the dashboard poll these constantly,
/// and counting their own traffic would make "ops served" climb with no build running.
final class GeneratedItem: SandboxFSItem {
    /// Fresh bytes on every read, for an item whose content is computed. `attributes` restates
    /// the served length at stat time, so whatever this returns must match the advertised size.
    let render: (() -> Data)?

    init(_ name: String, render: (() -> Data)? = nil) {
        self.render = render
        super.init(name: FSFileName(string: name))
    }
}

/// The items every sandboxfs mount carries at its root, owned here so the two volumes cannot
/// drift apart on what they are, what they are called, or which of them count as build I/O.
final class VirtualRoot {
    /// Marks the tree as a sandboxfs projection — the same signal cfs writes at a slot root.
    static let markerName = "@sandboxfs"
    static let perfName = "@sandboxfs_perf"

    /// The counters file's advertised size. An F_NOCACHE read clamps to the size stat reported,
    /// and the served length MUST equal it or a short read before EOF arrives as zero bytes —
    /// so `render` always pads to exactly this.
    private static let perfSize = 64 * 1024

    private(set) var items: [GeneratedItem] = []

    /// Names of the root items, for the gates that see a name before they see an item.
    private(set) var names: Set<String> = []

    /// The mount root. Not a `GeneratedItem`: the manifest tree is reconciled INTO it.
    static func makeRoot() -> SandboxFSItem {
        let item = SandboxFSItem(name: FSFileName(string: "/"))
        item.attributes.parentID = .parentOfRoot
        item.attributes.fileID = .rootDirectory
        item.attributes.uid = 0
        item.attributes.gid = 0
        item.attributes.linkCount = 1
        item.attributes.type = .directory
        item.attributes.mode = UInt32(S_IFDIR | 0b111_000_000)
        item.attributes.allocSize = 1
        item.attributes.size = 1
        return item
    }

    func install(under root: SandboxFSItem, counters: OpCounters) {
        let marker = GeneratedItem(Self.markerName)
        marker.attributes.type = .file
        marker.attributes.mode = UInt32(S_IFREG | 0o444)
        marker.data = Data("0.0.0".utf8)
        marker.attributes.size = UInt64(marker.data?.count ?? 0)
        marker.attributes.allocSize = marker.attributes.size

        let perf = GeneratedItem(Self.perfName) {
            var d = counters.renderText()
            if d.count < Self.perfSize {
                d.append(Data(repeating: 0x20, count: Self.perfSize - d.count))
            }
            return d.prefix(Self.perfSize)
        }
        perf.attributes.type = .file
        perf.attributes.mode = UInt32(S_IFREG | 0o444)
        perf.attributes.size = UInt64(Self.perfSize)
        perf.attributes.allocSize = UInt64(Self.perfSize)

        // Spotlight's opt-out: mds skips a volume whose root carries this. `nobrowse` only
        // discourages the service swarm; this turns indexing off at the source (mds and
        // XprotectService were hammering the same fskitd broker that serves page faults).
        let noIndex = GeneratedItem(".metadata_never_index")
        noIndex.attributes.type = .file
        noIndex.attributes.mode = UInt32(S_IFREG | 0o444)

        // fseventsd's opt-out: with `no_log` present it stops journaling the volume (it spiked
        // to 156% CPU during builds — every morph edit is an event). Pre-owning the directory
        // also stops fseventsd trying to create it on a sealed, EROFS mount.
        let fseventsd = GeneratedItem(".fseventsd")
        fseventsd.attributes.type = .directory
        fseventsd.attributes.mode = UInt32(S_IFDIR | 0o755)
        fseventsd.attributes.uid = 501
        fseventsd.attributes.gid = 20
        let noLog = GeneratedItem("no_log")
        noLog.attributes.type = .file
        noLog.attributes.mode = UInt32(S_IFREG | 0o444)
        fseventsd.replaceChildren(with: [noLog])
        fseventsd.attributes.size = 64
        fseventsd.attributes.allocSize = 4096

        items = [marker, perf, noIndex, fseventsd]
        names = Set(items.compactMap { $0.name.string })
        for item in items { root.addItem(item) }
    }
}
