import SwiftUI
import Charts

// "Compact" — metrics that matter, grouped by time scope. Header: this-build + fleet
// numbers (with SF Symbols). Below: the live charts (ops/sec, throughput, syscalls, actions).
struct CompactView: View {
    @Bindable var model: DashboardModel

    private let span: TimeInterval = 60   // realtime window the charts scroll over

    var body: some View {
        let b = model.focused
        let f = model.fleet
        let now = model.now
        let domain = now.addingTimeInterval(-span)...now
        let pts = liveTail(b?.series ?? [], now: now, span: span)
        let createPts = liveCreateTail(b?.createRates ?? [], now: now, span: span)
        VStack(alignment: .leading, spacing: 26) {
            fleetHeader(f)

            VStack(alignment: .leading, spacing: 8) {
                workspaceHeader(b)
                workspaceGrid(b)
            }

            HStack(alignment: .top, spacing: 24) {
                chartCard("Ops / sec", Fmt.count(pts.last?.total ?? 0) + " now") {
                    Chart(pts) { s in
                        AreaMark(x: .value("t", s.t), y: .value("ops", s.total))
                            .foregroundStyle(.linearGradient(colors: [Theme.accent.opacity(0.28), Theme.accent.opacity(0.02)],
                                                             startPoint: .top, endPoint: .bottom))
                        LineMark(x: .value("t", s.t), y: .value("ops", s.total))
                            .foregroundStyle(Theme.accent).lineStyle(.init(lineWidth: 1.5))
                    }
                    .chartYAxis { axisCount { Text(Fmt.count($0)) } }
                    .chartXScale(domain: domain)
                    .chartXAxis { timeAxis() }
                }
                chartCard("Throughput",
                          Fmt.bytes((pts.last.map { $0.readBytes + $0.writeBytes }) ?? 0) + "/s") {
                    Chart(pts.flatMap { s in
                        [Flow(t: s.t, kind: "read", v: s.readBytes), Flow(t: s.t, kind: "write", v: s.writeBytes)]
                    }) { d in
                        LineMark(x: .value("t", d.t), y: .value("B/s", d.v))
                            .foregroundStyle(by: .value("io", d.kind))
                            .lineStyle(.init(lineWidth: 1.5))
                            .interpolationMethod(.monotone)
                    }
                    .chartForegroundStyleScale(["read": Sc.color("read"), "write": Sc.color("write")])
                    .chartLegend(position: .top, alignment: .trailing)
                    .chartYAxis { axisCount { Text(Fmt.bytes($0)) } }
                    .chartXScale(domain: domain)
                    .chartXAxis { timeAxis() }
                }
            }

            HStack(alignment: .top, spacing: 24) {
                SyscallChart(pts: pts, domain: domain)
                CreatesCard(build: b, pts: createPts, domain: domain)
            }

            BuildTimeline(spans: model.buildSpans, now: model.now)
        }
        .padding(28)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .modifier(ScrollWrap())
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .overlay(alignment: .topTrailing) { statusBadge.padding(18) }
        .background(Color(hex: 0xFBFBFD))
    }

    // Logo + fleet-wide numbers on one baseline, with the realtime fleet heartbeat
    // (ops/sec history) drawn faintly behind them.
    private func fleetHeader(_ f: Fleet) -> some View {
        HStack(alignment: .center, spacing: 28) {
            logo
            fleetStat("builds", Fmt.count(f.builds))
            fleetStat("creates", Fmt.count(f.creates))
            fleetStat("avg create", Fmt.dur(f.avgCreateUs))
            fleetStat("served", Fmt.bytes(f.bytesRead + f.bytesWritten))
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
        .background(alignment: .bottom) { heartbeat.frame(height: 46) }
    }

    private var logo: some View {
        Image(nsImage: .logoMark)
            .resizable().interpolation(.high).renderingMode(.template)
            .frame(width: 30, height: 30)
            .foregroundStyle(Color(red: 0, green: 0.533, blue: 1))
    }

    private func fleetStat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.system(size: 18, weight: .semibold, design: .monospaced)).fixedSize()
            Text(label).font(Theme.tiny).foregroundStyle(Theme.dim)
        }
    }

    // Faint scrolling area of fleet ops/sec — the "is anything happening" pulse. Y starts
    // at 0 with headroom so peaks rise from the baseline instead of flattening/clipping.
    private var heartbeat: some View {
        let hi = Double(max(model.opsHistory.max() ?? 1, 1)) * 1.25
        return Chart(Array(model.opsHistory.enumerated()), id: \.offset) { i, v in
            AreaMark(x: .value("i", i), y: .value("ops", v))
                .foregroundStyle(.linearGradient(colors: [Theme.accent.opacity(0.16), .clear],
                                                 startPoint: .top, endPoint: .bottom))
            LineMark(x: .value("i", i), y: .value("ops", v))
                .foregroundStyle(Theme.accent.opacity(0.30)).lineStyle(.init(lineWidth: 1))
                .interpolationMethod(.monotone)
        }
        .chartYScale(domain: 0...hi)
        .chartXScale(range: .plotDimension(padding: 0))
        .chartXAxis(.hidden).chartYAxis(.hidden).chartLegend(.hidden)
        .allowsHitTesting(false)
    }

    private func workspaceGrid(_ b: Build?) -> some View {
        let creates = b?.sandboxCreates ?? 0
        let files = b?.filesServed ?? 0
        let dirs = b?.dirsServed ?? 0
        let avg = b?.avgCreateUs ?? 0
        return grid([("clock", "avg create", Fmt.dur(avg), true),
                     ("plus.app", "creates", Fmt.count(creates), false),
                     ("bolt", "io ops", Fmt.count(b?.totalOps ?? 0), false),
                     ("cpu", "processes", "\(b?.procs ?? 0)", false),
                     ("arrow.down.circle", "bytes read", Fmt.bytes(b?.bytesRead ?? 0), false),
                     ("arrow.up.circle", "bytes written", Fmt.bytes(b?.bytesWritten ?? 0), false),
                     ("doc", "files", Fmt.count(files), false),
                     ("folder", "dirs", Fmt.count(dirs), false)])
    }

    // Click to pause/resume; turns amber when paused, red when the daemon goes quiet.
    private var statusBadge: some View {
        let (label, color, icon): (String, Color, String) =
            !model.connected ? ("OFFLINE", Color(hex: 0xD0021B), "bolt.slash.fill")
            : model.paused   ? ("PAUSED", Theme.warn, "pause.fill")
            :                  ("LIVE", Theme.green, "bolt.horizontal.fill")
        return Button { if model.connected { model.paused.toggle() } } label: {
            HStack(spacing: 5) {
                Image(systemName: icon).font(.system(size: 10)).foregroundStyle(color)
                Text(label).font(Theme.tiny).tracking(1).foregroundStyle(color)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
        }
        .buttonStyle(.plain)
    }

    // The workspace name is a dropdown selector over every known build; backend badge
    // and elapsed sit alongside it.
    private func workspaceHeader(_ b: Build?) -> some View {
        HStack(spacing: 8) {
            Menu {
                ForEach(model.builds) { w in
                    Button { model.focusID = w.id } label: {
                        Text("\(w.active ? "●" : "○")  \(w.name)")
                    }
                }
            } label: {
                HStack(spacing: 6) {
                    Circle().fill((b?.active ?? false) ? Theme.green : Theme.dim).frame(width: 7, height: 7)
                    Text((b?.name ?? "no workspace").uppercased())
                        .font(Theme.tiny).tracking(1).foregroundStyle(.primary)
                    Image(systemName: "chevron.down").font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(Theme.dim)
                }
            }
            .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()

            if let b {
                Text(b.backend.uppercased())
                    .font(Theme.tiny).tracking(0.5).foregroundStyle(Theme.accent)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Theme.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 3))
                Spacer(minLength: 8)
                Text(elapsed(b)).font(Theme.tiny).monospacedDigit().foregroundStyle(Theme.dim)
            }
        }
    }

    private func elapsed(_ b: Build) -> String {
        let s = max(0, (b.ended ?? model.now).timeIntervalSince(b.started))
        if s >= 3600 { return String(format: "%.1fh", s / 3600) }
        if s >= 60 { return "\(Int(s) / 60)m \(Int(s) % 60)s" }
        return "\(Int(s))s"
    }

    private func grid(_ items: [(String, String, String, Bool)]) -> some View {
        HStack(alignment: .top, spacing: 24) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, it in
                VStack(alignment: .leading, spacing: 2) {
                    Text(it.2).font(.system(size: 18, weight: .semibold, design: .monospaced))
                        .foregroundStyle(it.3 ? Theme.accent : .primary).fixedSize()
                    Text(it.1).font(Theme.tiny).foregroundStyle(Theme.dim)
                }
            }
        }
    }
}

private extension NSImage {
    // Backgroundless brand mark (white-on-transparent), rendered from the .icon's SVG and
    // bundled as a resource; tinted at the call site via .renderingMode(.template).
    static let logoMark: NSImage =
        Bundle.main.url(forResource: "logomark", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) } ?? NSApplication.shared.applicationIconImage
}

private struct ScrollWrap: ViewModifier {
    func body(content: Content) -> some View {
        ScrollView { content }
    }
}

private struct Flow: Identifiable { var id: String { "\(kind)\(t.timeIntervalSince1970)" }; let t: Date; let kind: String; let v: Int }

private func chartCard(_ title: String, _ value: String,
                       @ViewBuilder _ chart: () -> some View) -> some View {
    VStack(alignment: .leading, spacing: 6) {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            eyebrow(title)
            Spacer()
            Text(value).font(Theme.small).monospacedDigit().foregroundStyle(Theme.dim)
        }
        chart().frame(height: 118)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
}

private func timeAxis() -> some AxisContent {
    AxisMarks(values: .automatic(desiredCount: 3)) { _ in
        AxisGridLine().foregroundStyle(.black.opacity(0.05))
        AxisValueLabel(format: .dateTime.minute().second()).font(Theme.tiny).foregroundStyle(Theme.dim)
    }
}

private func axisCount(@ViewBuilder _ label: @escaping (Int) -> some View) -> some AxisContent {
    AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { v in
        AxisGridLine().foregroundStyle(.black.opacity(0.05))
        AxisValueLabel { if let n = v.as(Int.self) { label(n).font(Theme.tiny).foregroundStyle(Theme.dim) } }
    }
}

// Realtime zero-tail: keep the in-window sparse buckets, and when the build has gone idle
// (no bucket within the last ~0.5s) hold a flat zero line out to `now`, so the chart reads
// as flat-and-scrolling rather than frozen on the last value. `now` stops advancing when
// the user pauses — that's when the view freezes to inspect history.
private func liveTail(_ samples: [Sample], now: Date, span: TimeInterval) -> [Sample] {
    let cutoff = now.addingTimeInterval(-span)
    var pts = samples.filter { $0.t >= cutoff }
    if (samples.last?.t ?? .distantPast) < now.addingTimeInterval(-0.5) {
        let drop = pts.last?.t.addingTimeInterval(0.1) ?? cutoff
        pts.append(Sample(t: drop, ops: [:], readBytes: 0, writeBytes: 0))
        pts.append(Sample(t: now, ops: [:], readBytes: 0, writeBytes: 0))
    }
    return pts
}

private func liveCreateTail(_ samples: [CreateRate], now: Date, span: TimeInterval) -> [CreateRate] {
    let cutoff = now.addingTimeInterval(-span)
    var pts = samples.filter { $0.t >= cutoff }
    if (samples.last?.t ?? .distantPast) < now.addingTimeInterval(-1.5) {  // creates are ~1s samples
        let drop = pts.last?.t.addingTimeInterval(0.1) ?? cutoff
        pts.append(CreateRate(t: drop, n: 0, laydownUs: 0))
        pts.append(CreateRate(t: now, n: 0, laydownUs: 0))
    }
    return pts
}

// Per-syscall ops/sec; hover drops a rule and a tooltip of that second's values.
private struct SyscallChart: View {
    let pts: [Sample]
    let domain: ClosedRange<Date>
    @State private var hover: Date?

    var body: some View {
        let calls = Sc.present(pts)
        chartCard("Syscalls", "ops/s") {
            Chart {
                ForEach(pts) { s in
                    ForEach(calls, id: \.self) { c in
                        LineMark(x: .value("t", s.t), y: .value("ops", s.ops[c] ?? 0))
                            .foregroundStyle(by: .value("syscall", c))
                            .lineStyle(.init(lineWidth: 1.3))
                            .interpolationMethod(.monotone)
                    }
                }
                if let h = hover, let s = nearest(h) {
                    RuleMark(x: .value("t", s.t))
                        .foregroundStyle(.black.opacity(0.18)).lineStyle(.init(lineWidth: 1))
                        .annotation(position: .topLeading, spacing: 0,
                                    overflowResolution: .init(x: .fit(to: .chart), y: .fit(to: .chart))) {
                            tooltip(s, calls: calls)
                        }
                }
            }
            .chartForegroundStyleScale(domain: calls, range: calls.map(Sc.color))
            .chartLegend(.hidden)
            .chartYAxis { axisCount { Text(Fmt.count($0)) } }
            .chartXScale(domain: domain)
            .chartXAxis { timeAxis() }
            .chartOverlay { proxy in
                hoverCatcher(proxy) { x in hover = x.flatMap { proxy.value(atX: $0) as Date? } }
            }
        }
    }

    private func nearest(_ d: Date) -> Sample? {
        pts.min { abs($0.t.timeIntervalSince(d)) < abs($1.t.timeIntervalSince(d)) }
    }

    private func tooltip(_ s: Sample, calls: [String]) -> some View {
        let rows = calls.map { ($0, s.ops[$0] ?? 0) }.filter { $0.1 > 0 }.sorted { $0.1 > $1.1 }
        return VStack(alignment: .leading, spacing: 2) {
            Text(s.t, format: .dateTime.hour().minute().second())
                .font(Theme.tiny).foregroundStyle(Theme.dim)
            ForEach(rows.prefix(8), id: \.0) { name, v in
                HStack(spacing: 5) {
                    Circle().fill(Sc.color(name)).frame(width: 6, height: 6)
                    Text(name).font(Theme.tiny)
                    Spacer(minLength: 10)
                    Text(Fmt.count(v)).font(Theme.tiny).monospacedDigit().foregroundStyle(Theme.dim)
                }
            }
        }
        .padding(8)
        .background(.white, in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.black.opacity(0.08)))
        .frame(width: 168)
    }
}


// Sandbox create time, switchable between the over-time chart and a per-mnemonic table.
// The table surfaces the outliers the averaged chart hides (MAX = slowest single create).
private struct CreatesCard: View {
    let build: Build?
    let pts: [CreateRate]
    let domain: ClosedRange<Date>
    @State private var table = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                eyebrow("Sandbox create time")
                Spacer()
                Text(Fmt.dur(pts.last?.avgUs ?? 0)).font(Theme.small).monospacedDigit().foregroundStyle(Theme.dim)
                Picker("", selection: $table) {
                    Image(systemName: "chart.xyaxis.line").tag(false)
                    Image(systemName: "tablecells").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize().controlSize(.mini)
            }
            if table {
                CreatesTable(mnems: (build?.mnemonics ?? []).filter { $0.creates > 0 }.sorted { $0.maxUs > $1.maxUs })
                    .frame(height: 118, alignment: .top)
            } else {
                chart.frame(height: 118)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var chart: some View {
        Chart(pts) { c in
            LineMark(x: .value("t", c.t), y: .value("avg µs", c.avgUs))
                .foregroundStyle(Theme.accent).lineStyle(.init(lineWidth: 1.5))
                .interpolationMethod(.monotone)
            if c.n > 0 {   // only mark real samples; the idle zero-tail stays a flat line, no bouncing point
                PointMark(x: .value("t", c.t), y: .value("avg µs", c.avgUs))
                    .symbolSize(12).foregroundStyle(Theme.accent)
            }
        }
        .chartYAxis { axisCount { Text(Fmt.dur(Double($0))) } }
        .chartXScale(domain: domain)
        .chartXAxis { timeAxis() }
    }
}

// Sandbox creates per Bazel mnemonic, sorted slowest-outlier first. MAX is the slowest
// single create of that mnemonic — the outlier the average hides; the worst is amber.
private struct CreatesTable: View {
    let mnems: [MnemonicStat]
    private let topN = 7

    var body: some View {
        let sum = Double(max(mnems.reduce(0) { $0 + $1.creates }, 1))
        let outlier = mnems.max { $0.maxUs < $1.maxUs }?.id
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 0) {
                cell("MNEMONIC", .leading, 0, dim: true)
                cell("CREATES", .trailing, 56, dim: true)
                cell("AVG", .trailing, 64, dim: true)
                cell("MAX", .trailing, 64, dim: true)
                cell("%", .trailing, 38, dim: true)
            }
            Rectangle().fill(.black.opacity(0.08)).frame(height: 1)
            ForEach(mnems.prefix(topN)) { m in
                let warn = m.id == outlier
                HStack(spacing: 0) {
                    cell(m.id, .leading, 0, tint: warn ? Theme.warn : .primary)
                    cell(Fmt.count(m.creates), .trailing, 56)
                    cell(Fmt.dur(m.avgUs), .trailing, 64)
                    cell(Fmt.dur(m.maxUs), .trailing, 64, tint: warn ? Theme.warn : .primary)
                    cell(String(format: "%.0f%%", Double(m.creates) / sum * 100), .trailing, 38, dim: true)
                }
            }
            if mnems.count > topN {
                Text("+ \(mnems.count - topN) more").font(Theme.tiny).foregroundStyle(Theme.dim)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func cell(_ s: String, _ align: Alignment, _ w: CGFloat, dim: Bool = false, tint: Color = .primary) -> some View {
        Text(s).font(Theme.small).monospacedDigit().lineLimit(1)
            .foregroundStyle(dim ? Theme.dim : tint)
            .frame(width: w == 0 ? nil : w, alignment: align)
            .frame(maxWidth: w == 0 ? .infinity : nil, alignment: align)
    }
}

// The build timeline: each build window as a bar from start to end on its workspace lane —
// a Gantt the old dashboard never had. Running builds are green and extend to `now`.
private struct BuildTimeline: View {
    let spans: [BuildSpan]
    let now: Date

    var body: some View {
        let recent = Array(spans.suffix(40))
        let lanes = Set(recent.map(\.name)).count
        VStack(alignment: .leading, spacing: 6) {
            eyebrow("Build timeline")
            if recent.isEmpty {
                Text("no builds yet — run a build with sandboxfs_metrics=1")
                    .font(Theme.small).foregroundStyle(Theme.dim)
                    .frame(maxWidth: .infinity, minHeight: 70, alignment: .leading)
            } else {
                Chart(recent) { s in
                    BarMark(xStart: .value("start", s.start),
                            xEnd: .value("end", s.end ?? now),
                            y: .value("workspace", s.name),
                            height: .fixed(12))
                        .foregroundStyle(s.active ? Theme.green : Theme.accent)
                        .cornerRadius(3)
                }
                .chartXAxis { timeAxis() }
                .chartYAxis { AxisMarks(position: .leading) { AxisValueLabel().font(Theme.tiny).foregroundStyle(Theme.dim) } }
                .frame(height: CGFloat(max(1, lanes)) * 30 + 24)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// Shared hover hit-area: reports the cursor's x within the plot (nil when it leaves).
// Callers convert that pixel x to a data value via proxy.value(atX:). macOS-native.
private func hoverCatcher(_ proxy: ChartProxy, _ update: @escaping (CGFloat?) -> Void) -> some View {
    GeometryReader { geo in
        if let plot = proxy.plotFrame {
            let rect = geo[plot]
            Rectangle().fill(.clear).contentShape(Rectangle())
                .onContinuousHover { phase in
                    if case .active(let p) = phase { update(p.x - rect.minX) }
                    else { update(nil) }
                }
        }
    }
}

#Preview { CompactView(model: DashboardModel()) }
