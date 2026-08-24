//
//  ContentView.swift
//  sandbox
//
//  Build Profiler — a live dashboard over the sandboxfs metrics daemon. Tails the daemon's
//  XPC feed (cursor-based) and derives every view — realtime per-workspace metrics, the
//  retained history, and the build-spans timeline — from the feed.
//

import SwiftUI
import Charts

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255)
    }
}

// Stable colour + legend order for the raw syscall names the daemon emits
// (crates/metrics/src/collect.rs). read/write keep their brand colours so the
// throughput and syscall charts agree; the rest are evenly spaced around the wheel.
enum Sc {
    static let order = [
        "read", "pread", "write", "pwrite",
        "open", "openat", "stat", "lstat", "fstatat", "access",
        "getattrlist", "getattrlistat", "getattrlistbulk", "fgetattrlist",
        "getdirentries", "readlink", "close", "lseek", "fsync", "fdatasync",
        "mkdir", "rmdir", "unlink", "rename", "symlink", "link",
        "chdir", "posix_spawn",
    ]
    static func color(_ name: String) -> Color {
        switch name {
        case "read", "pread":   return Color(hex: 0x007AFF)
        case "write", "pwrite": return Color(hex: 0xFF6B00)
        default:
            let i = order.firstIndex(of: name)
                ?? abs(name.utf8.reduce(0) { $0 &+ Int($1) }) % order.count
            return Color(hue: Double(i) / Double(order.count), saturation: 0.62, brightness: 0.78)
        }
    }
    // Syscalls present in a build, busiest first — drives chart series + legend order.
    static func present(_ samples: [Sample]) -> [String] {
        var total: [String: Int] = [:]
        for s in samples { for (k, v) in s.ops { total[k, default: 0] += v } }
        return total.filter { $0.value > 0 }.keys.sorted { total[$0]! > total[$1]! }
    }
}

struct Sample: Identifiable {
    var id: Date { t }        // bucket start — stable across polls so Charts can diff/interpolate
    let t: Date
    let ops: [String: Int]    // raw per-syscall counts that second
    let readBytes: Int
    let writeBytes: Int
    var total: Int { ops.values.reduce(0, +) }
}

struct Build: Identifiable {
    let id: String                 // build_id (execroot path)
    let name: String               // workspace name (from execroot/DO_NOT_BUILD_HERE)
    let backend: String            // cfs | lazyfs
    let started: Date
    var ended: Date?               // nil while running
    var procs: Int
    var opCounts: [String: Int]    // full per-syscall totals
    var bytesRead: Int
    var bytesWritten: Int
    var filesServed: Int
    var dirsServed: Int
    var sandboxCreates: Int
    var createUsSum: Double
    var createCount: Int
    var mnemonics: [MnemonicStat] // this build's sandbox creates by Bazel action mnemonic
    var series: [Sample]
    var createRates: [CreateRate] // sandbox creates over time (count + avg laydown per interval)

    var active: Bool { ended == nil }
    var avgCreateUs: Double { createCount > 0 ? createUsSum / Double(createCount) : 0 }
    var totalOps: Int { opCounts.values.reduce(0, +) }   // total IO operations (kdebug, cumulative per workspace)
}

struct MnemonicStat: Identifiable {
    let id: String                 // bazel Action mnemonic
    var creates: Int
    var usSum: Double
    var count: Int
    var maxUs: Double              // slowest single create — surfaces the outlier the avg hides
    var avgUs: Double { count > 0 ? usSum / Double(count) : 0 }
}

// Sandbox creates landing in one ~1s interval: how many, and how long they took on
// average — the "how long did sandboxes take to create" series, over time.
struct CreateRate: Identifiable {
    var id: Date { t }
    let t: Date
    let n: Int
    let laydownUs: Double
    var avgUs: Double { n > 0 ? laydownUs / Double(n) : 0 }
}

// One build as a span on the timeline: when it ran and what it did. The thing the old
// dashboard never had — a Gantt of builds with their durations + per-build totals.
struct BuildSpan: Identifiable {
    let id: String
    let workspace: String
    let name: String
    let backend: String
    let start: Date
    let end: Date?                 // nil while running
    let creates: Int
    let bytes: Int
    let syscalls: Int
    var active: Bool { end == nil }
    func duration(_ now: Date) -> TimeInterval { max(0, (end ?? now).timeIntervalSince(start)) }
}

struct Fleet {
    var builds: Int
    var bytesRead: Int
    var bytesWritten: Int
    var files: Int
    var dirs: Int
    var byMnemonic: [MnemonicStat]
    var creates: Int { byMnemonic.reduce(0) { $0 + $1.creates } }
    var avgCreateUs: Double {
        let n = byMnemonic.reduce(0) { $0 + $1.count }
        return n > 0 ? byMnemonic.reduce(0.0) { $0 + $1.usSum } / Double(n) : 0
    }
}

@Observable
final class DashboardModel {
    private(set) var now: Date
    private(set) var builds: [Build]
    private(set) var fleet: Fleet
    private(set) var buildSpans: [BuildSpan] = []   // build timeline (Gantt), newest last
    private(set) var opsHistory: [Int] = []   // fleet ops/s for the header sparkline
    var paused = false
    var focusID: Build.ID?              // workspace shown in the focus view

    private(set) var connected = true   // false when the daemon isn't answering
    private var polling = false
    private var timer: Timer?
    private let pollInterval = 0.15     // tail the feed near the daemon's 100ms bucket rate

    // The daemon retains the timeline and answers `feed(since:)` with everything after the
    // cursor; we keep per-workspace rings and merge each tail in. The cursor overlaps by a
    // few buckets and we cut the ring at the incoming edge, so the in-progress bucket
    // updates correctly and nothing is skipped.
    private var cursor: UInt64 = 0
    private var sampleRings: [String: [Sample]] = [:]
    private var createRings: [String: [CreateRate]] = [:]
    private let seriesCap = 2000

    init() {
        now = Date()
        builds = []
        fleet = Fleet(builds: 0, bytesRead: 0, bytesWritten: 0, files: 0, dirs: 0, byMnemonic: [])
        let timer = Timer(timeInterval: pollInterval, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    deinit { timer?.invalidate() }

    var domain: ClosedRange<Date> {
        let start = builds.map(\.started).min() ?? now.addingTimeInterval(-600)
        return start...now
    }

    private func tick() {
        guard !paused, !polling else { return }
        polling = true
        let since = cursor
        Task.detached { [weak self] in
            let feed = try? MetricsClient.feed(since: since)
            await MainActor.run {
                self?.polling = false
                withAnimation(.linear(duration: self?.pollInterval ?? 0.4)) { self?.apply(feed) }
            }
        }
    }

    private var nameCache: [String: String] = [:]

    // Bazel writes the source workspace path into <execroot>/DO_NOT_BUILD_HERE; its last
    // component is the friendly workspace name. Cached per execroot; falls back to the
    // execroot's own last component when the file isn't readable.
    private func workspaceName(_ execroot: String) -> String {
        if let n = nameCache[execroot] { return n }
        let fallback = (execroot as NSString).lastPathComponent
        let file = (execroot as NSString).appendingPathComponent("DO_NOT_BUILD_HERE")
        let resolved = (try? String(contentsOfFile: file, encoding: .utf8))
            .map { ($0.trimmingCharacters(in: .whitespacesAndNewlines) as NSString).lastPathComponent }
            .flatMap { $0.isEmpty ? nil : $0 } ?? fallback
        nameCache[execroot] = resolved
        return resolved
    }

    private func apply(_ feed: Feed?) {
        guard let feed else { connected = false; return }
        connected = true
        now = feed.now > 0 ? date(feed.now) : Date()

        var maxT: UInt64 = 0
        var built: [Build] = []
        for ws in feed.workspaces where !ws.workspace.isEmpty {  // "" lane is the unattributed floor
            // merge the sample/create tails into this workspace's rings, cutting at the
            // incoming edge so the re-fetched live bucket replaces (not duplicates).
            if let cut = ws.samples.first?.t {
                maxT = max(maxT, ws.samples.last?.t ?? cut)
                let incoming = ws.samples.map { Sample(t: date($0.t), ops: $0.ops.mapValues(Int.init), readBytes: Int($0.readBytes), writeBytes: Int($0.writeBytes)) }
                merge(&sampleRings[ws.workspace, default: []], incoming, cut: date(cut), keyed: \.t)
            }
            if let cut = ws.creates.first?.t {
                maxT = max(maxT, ws.creates.last?.t ?? cut)
                let incoming = ws.creates.map { CreateRate(t: date($0.t), n: Int($0.n), laydownUs: Double($0.laydownUs)) }
                merge(&createRings[ws.workspace, default: []], incoming, cut: date(cut), keyed: \.t)
            }
            built.append(build(ws))
        }
        built.sort { $0.id < $1.id }
        builds = built

        buildSpans = feed.builds.map { s in
            BuildSpan(id: "\(s.workspace)#\(s.startMs)", workspace: s.workspace, name: workspaceName(s.workspace),
                      backend: s.backend, start: date(s.startMs), end: s.endMs.map(date),
                      creates: Int(s.creates), bytes: Int(s.bytesRead + s.bytesWritten), syscalls: Int(s.syscalls))
        }.sorted { $0.start < $1.start }

        var fMnem: [String: MnemonicStat] = [:]
        for b in built {
            for m in b.mnemonics {
                fMnem[m.id, default: MnemonicStat(id: m.id, creates: 0, usSum: 0, count: 0, maxUs: 0)].creates += m.creates
                fMnem[m.id]!.count += m.count
                fMnem[m.id]!.usSum += m.usSum
                fMnem[m.id]!.maxUs = max(fMnem[m.id]!.maxUs, m.maxUs)
            }
        }
        fleet = Fleet(
            builds: feed.builds.filter { $0.endMs != nil }.count,
            bytesRead: built.reduce(0) { $0 + $1.bytesRead }, bytesWritten: built.reduce(0) { $0 + $1.bytesWritten },
            files: built.reduce(0) { $0 + $1.filesServed }, dirs: built.reduce(0) { $0 + $1.dirsServed },
            byMnemonic: Array(fMnem.values))

        if maxT > 0 { cursor = maxT > 300 ? maxT - 300 : 0 } // overlap a few buckets next tail

        if focusID == nil || !builds.contains(where: { $0.id == focusID }) { focusID = builds.first?.id }
        let ops = builds.filter(\.active).reduce(0) { $0 + ($1.series.last?.total ?? 0) }
        opsHistory.append(ops)
        if opsHistory.count > 60 { opsHistory.removeFirst() }
    }

    private func date(_ ms: UInt64) -> Date { Date(timeIntervalSince1970: Double(ms) / 1000) }

    /// Replace the ring's tail at/after the incoming edge, then append — the daemon overlaps
    /// a few buckets so the in-progress one updates in place and nothing is skipped.
    private func merge<T>(_ ring: inout [T], _ incoming: [T], cut: Date, keyed t: (T) -> Date) {
        ring.removeAll { t($0) >= cut }
        ring += incoming
        if ring.count > seriesCap { ring.removeFirst(ring.count - seriesCap) }
    }

    private func build(_ ws: WSMetrics) -> Build {
        let t = ws.totals
        let creates = Int(t.creates), laydown = Double(t.laydownUs)
        let mn = t.mnemonics.map { MnemonicStat(id: $0.name, creates: Int($0.creates), usSum: Double($0.laydownUs), count: Int($0.creates), maxUs: Double($0.maxUs)) }
        return Build(
            id: ws.workspace, name: workspaceName(ws.workspace), backend: ws.backend,
            started: date(ws.startMs), ended: ws.endMs.map(date),
            procs: Int(t.procs), opCounts: t.ops.mapValues(Int.init),
            bytesRead: Int(t.bytesRead), bytesWritten: Int(t.bytesWritten),
            filesServed: Int(t.files), dirsServed: Int(t.dirs),
            sandboxCreates: creates, createUsSum: laydown, createCount: creates,
            mnemonics: mn, series: sampleRings[ws.workspace] ?? [],
            createRates: createRings[ws.workspace] ?? [])
    }
}


// ───────────────────────── shared UI kit ─────────────────────────

enum Theme {
    static let mono  = Font.system(.body, design: .monospaced)
    static let small = Font.system(.caption, design: .monospaced)
    static let tiny  = Font.system(.caption2, design: .monospaced)
    static let dim   = Color.secondary
    static let accent = Color(red: 0.30, green: 0.45, blue: 0.85)
    static let green  = Color(red: 0.20, green: 0.60, blue: 0.35)
    static let warn   = Color(red: 0.85, green: 0.45, blue: 0.10)
}

func eyebrow(_ s: String) -> some View {
    Text(s.uppercased()).font(Theme.tiny).tracking(1).foregroundStyle(Theme.dim)
}

enum Fmt {
    static func count(_ n: Int) -> String {
        let v = Double(n)
        if v >= 1e9 { return String(format: "%.1fG", v / 1e9) }
        if v >= 1e6 { return String(format: "%.1fM", v / 1e6) }
        if v >= 1e3 { return String(format: "%.1fk", v / 1e3) }
        return "\(n)"
    }
    static func bytes(_ n: Int) -> String {
        var v = Double(n); let u = ["B", "KB", "MB", "GB", "TB"]; var i = 0
        while v >= 1024, i < u.count - 1 { v /= 1024; i += 1 }
        return String(format: v < 10 && i > 0 ? "%.1f %@" : "%.0f %@", v, u[i])
    }
    static func dur(_ us: Double) -> String {
        us >= 1000 ? String(format: "%.1f ms", us / 1000) : "\(Int(us)) µs"
    }
}

struct Sparkline: View {
    let values: [Int]
    var color: Color = Theme.accent
    var body: some View {
        Canvas { ctx, size in
            guard values.count > 1, let mx = values.max(), mx > 0 else { return }
            let sx = size.width / CGFloat(values.count - 1)
            func pt(_ i: Int) -> CGPoint {
                CGPoint(x: CGFloat(i) * sx, y: size.height - CGFloat(values[i]) / CGFloat(mx) * (size.height - 2) - 1)
            }
            var line = Path(); line.move(to: pt(0))
            for i in 1..<values.count { line.addLine(to: pt(i)) }
            ctx.stroke(line, with: .color(color), lineWidth: 1.5)
        }
    }
}

extension DashboardModel {
    /// The workspace the layouts focus on (selected, else first).
    var focused: Build? { builds.first { $0.id == focusID } ?? builds.first }
}

struct ContentView: View {
    @State private var model = DashboardModel()

    var body: some View {
        CompactView(model: model)
            .frame(minWidth: 1120, minHeight: 680)
            .preferredColorScheme(.light)
            .font(Theme.mono)
            .background(Color(nsColor: .windowBackgroundColor))
    }
}

#Preview { ContentView() }
