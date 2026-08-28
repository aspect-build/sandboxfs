import Foundation
import Synchronization

/// Per-op call counts for the whole volume: the `sandboxfs_perf` virtual file renders them and
/// `unmount` logs them.
final class OpCounters {
    /// Every counted op. Bumping takes a case, so an op nobody declared is a compile error
    /// rather than a silently dropped count.
    enum Op: String, CaseIterable {
        case openItem, closeItem
        case activate, attributes, lookupItem, setAttributes, reclaimItem
        case readSymbolicLink, enumerateDirectory, read, readData
        case createItem, createSymbolicLink, createLink, removeItem, write, renameItem
    }

    /// One op's count, an `Atomic` so `bump` is lock-free. `Atomic` is non-copyable, hence a
    /// reference type reached through the immutable-after-init `counters` map.
    private final class Counter {
        let count = Atomic<Int>(0)
    }

    /// Built once and never mutated, so lookups need no lock. Keyed by the CASE, whose hash is
    /// its ordinal — a VNOP bump hashes no string.
    private let counters = Dictionary(uniqueKeysWithValues: Op.allCases.map { ($0, Counter()) })

    @inline(__always) func bump(_ op: Op) {
        counters[op]?.count.wrappingAdd(1, ordering: .relaxed)
    }

    func snapshot() -> [(Op, Int)] {
        counters
            .map { ($0.key, $0.value.count.load(ordering: .relaxed)) }
            .filter { $0.1 > 0 }
            .sorted { $0.1 > $1.1 }
    }

    func snapshotAndReset() -> [(Op, Int)] {
        counters
            .map { ($0.key, $0.value.count.exchange(0, ordering: .relaxed)) }
            .filter { $0.1 > 0 }
            .sorted { $0.1 > $1.1 }
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
        for (op, count) in snapshot() {   // only ops that fired, count-desc
            lines += "\(op.rawValue)\t\(count)\n"
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
