import AppKit
import Darwin
import Foundation
import ScreenSaver

final class ProcessColumnsScreenSaverView: ScreenSaverView {
    private struct ProcessSample {
        var name: String
        var cpu: Double
    }

    private struct Trail {
        var head: CGFloat
        var speed: CGFloat
        var offset: Int
    }

    private struct Column {
        var process: ProcessSample
        var x: CGFloat
        var trails: [Trail]
    }

    private let fontSize: CGFloat = 17
    private let rowHeight: CGFloat = 17
    private let refreshInterval: TimeInterval = 3.0
    private let minimumSpeed: CGFloat = 0.35
    private let maximumSpeed: CGFloat = 4.0
    private let maximumColumns = 40
    private let minimumColumns = 12
    private let minimumColumnWidth: CGFloat = 46
    private let trailsPerColumn = 3
    private var columns: [Column] = []
    private var lastSize: CGSize = .zero
    private var lastRefresh: Date = .distantPast

    override init?(frame: NSRect, isPreview: Bool) {
        super.init(frame: frame, isPreview: isPreview)
        animationTimeInterval = 1.0 / 30.0
        refreshProcesses(force: true)
        rebuildColumns(for: frame.size)
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        animationTimeInterval = 1.0 / 30.0
        refreshProcesses(force: true)
        rebuildColumns(for: bounds.size)
    }

    override var hasConfigureSheet: Bool {
        false
    }

    override var configureSheet: NSWindow? {
        nil
    }

    override func startAnimation() {
        super.startAnimation()
        refreshProcesses(force: true)
        rebuildColumns(for: bounds.size)
    }

    override func animateOneFrame() {
        refreshProcesses(force: false)

        if bounds.size != lastSize {
            rebuildColumns(for: bounds.size)
        }

        for columnIndex in columns.indices {
            for trailIndex in columns[columnIndex].trails.indices {
                columns[columnIndex].trails[trailIndex].head += columns[columnIndex].trails[trailIndex].speed

                let resetThreshold = bounds.height + CGFloat(columns[columnIndex].process.name.count + 8) * rowHeight
                if columns[columnIndex].trails[trailIndex].head > resetThreshold {
                    columns[columnIndex].trails[trailIndex] = makeTrail(height: bounds.height, processName: columns[columnIndex].process.name, aboveScreen: true)
                }
            }
        }

        setNeedsDisplay(bounds)
    }

    override func draw(_ rect: NSRect) {
        guard let context = NSGraphicsContext.current?.cgContext else { return }

        if columns.isEmpty || bounds.size != lastSize {
            refreshProcesses(force: true)
            rebuildColumns(for: bounds.size)
        }

        context.setFillColor(NSColor.black.cgColor)
        context.fill(bounds)

        let font = NSFont.monospacedSystemFont(ofSize: fontSize, weight: .medium)
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center

        for column in columns {
            let letters = Array(column.process.name.uppercased()).map(String.init)
            guard !letters.isEmpty else { continue }

            for trail in column.trails {
                let trailLength = max(letters.count * 3, 18)

                for offset in 0..<trailLength {
                    let y = trail.head - CGFloat(offset) * rowHeight
                    guard y > -rowHeight, y < bounds.height + rowHeight else { continue }

                    let intensity = 1.0 - CGFloat(offset) / CGFloat(trailLength)
                    let isHead = offset == 0
                    let color: NSColor

                    if isHead {
                        color = NSColor(calibratedRed: 0.82, green: 1.0, blue: 0.82, alpha: 1.0)
                    } else {
                        color = NSColor(calibratedRed: 0.0, green: 0.95, blue: 0.15, alpha: max(0.1, intensity * 0.78))
                    }

                    let attributes: [NSAttributedString.Key: Any] = [
                        .font: font,
                        .foregroundColor: color,
                        .paragraphStyle: paragraph
                    ]

                    let letterIndex = (offset + trail.offset) % letters.count
                    let drawRect = NSRect(x: column.x, y: bounds.height - y, width: fontSize * 1.05, height: rowHeight)
                    letters[letterIndex].draw(in: drawRect, withAttributes: attributes)
                }
            }
        }
    }

    private func refreshProcesses(force: Bool) {
        guard force || Date().timeIntervalSince(lastRefresh) >= refreshInterval else { return }
        lastRefresh = Date()

        let samples = loadProcessSamples()
        guard !samples.isEmpty else { return }

        let oldColumns = columns
        let visibleSamples = selectVisibleSamples(from: samples, for: bounds.size)
        columns = makeColumns(from: visibleSamples, size: bounds.size, preserving: oldColumns)
    }

    private func loadProcessSamples() -> [ProcessSample] {
        let libprocSamples = loadLibprocSamples()
        let sysctlSamples = loadSysctlSamples()
        let psSamples = loadPsSamples()
        let mergedSamples = mergeSamples(libprocSamples + sysctlSamples + psSamples)

        if mergedSamples.count >= 8 {
            return mergedSamples
        }

        let workspaceSamples = workspaceSamples()
        let fallbackMergedSamples = mergeSamples(mergedSamples + workspaceSamples)

        return fallbackMergedSamples.count >= 8 ? fallbackMergedSamples : fallbackSamples()
    }

    private func loadLibprocSamples() -> [ProcessSample] {
        var totals: [String: Double] = [:]
        var seenCounts: [String: Int] = [:]
        let pidCapacity = 32768
        var pids = [pid_t](repeating: 0, count: Int(pidCapacity))
        let pidCount = pids.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else { return 0 }
            return proc_listallpids(baseAddress, Int32(buffer.count * MemoryLayout<pid_t>.size))
        }

        guard pidCount > 0 else {
            return []
        }

        for pid in pids.prefix(Int(pidCount)) where pid > 0 {
            var nameBuffer = [CChar](repeating: 0, count: Int(MAXCOMLEN + 1))
            let nameLength = nameBuffer.withUnsafeMutableBufferPointer { buffer -> Int32 in
                guard let baseAddress = buffer.baseAddress else { return 0 }
                return proc_name(pid, baseAddress, UInt32(buffer.count))
            }
            guard nameLength > 0 else { continue }

            let rawName = String(cString: nameBuffer)
            let name = sanitizedProcessName(rawName)
            guard !name.isEmpty else { continue }

            seenCounts[name, default: 0] += 1

            var taskInfo = proc_taskinfo()
            let taskInfoSize = MemoryLayout<proc_taskinfo>.size
            let bytesRead = withUnsafeMutablePointer(to: &taskInfo) { pointer -> Int32 in
                pointer.withMemoryRebound(to: UInt8.self, capacity: taskInfoSize) { reboundPointer in
                    proc_pidinfo(pid, PROC_PIDTASKINFO, 0, reboundPointer, Int32(taskInfoSize))
                }
            }
            if bytesRead == Int32(taskInfoSize) {
                let cpuNanoseconds = taskInfo.pti_total_user + taskInfo.pti_total_system
                totals[name, default: 0.0] += Double(cpuNanoseconds)
            }
        }

        let samples = seenCounts.map { name, count in
            ProcessSample(name: name, cpu: max(totals[name] ?? 0.0, Double(count)))
        }
        return samples
    }

    private func loadSysctlSamples() -> [ProcessSample] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var byteCount = 0

        guard sysctl(&mib, UInt32(mib.count), nil, &byteCount, nil, 0) == 0, byteCount > 0 else {
            return []
        }

        let processCount = byteCount / MemoryLayout<kinfo_proc>.stride
        guard processCount > 0 else { return [] }

        var processes = [kinfo_proc](repeating: kinfo_proc(), count: processCount)
        let result = processes.withUnsafeMutableBufferPointer { buffer -> Int32 in
            sysctl(&mib, UInt32(mib.count), buffer.baseAddress, &byteCount, nil, 0)
        }
        guard result == 0 else { return [] }

        var totals: [String: Double] = [:]

        for process in processes {
            let rawName = withUnsafeBytes(of: process.kp_proc.p_comm) { rawBuffer -> String in
                let characters = rawBuffer.bindMemory(to: CChar.self)
                guard let baseAddress = characters.baseAddress else { return "" }
                return String(cString: baseAddress)
            }
            let name = sanitizedProcessName(rawName)
            guard !name.isEmpty else { continue }

            let cpuWeight = max(Double(process.kp_proc.p_pctcpu), 1.0)
            totals[name, default: 0.0] += cpuWeight
        }

        return totals.map { ProcessSample(name: $0.key, cpu: $0.value) }
    }

    private func loadPsSamples() -> [ProcessSample] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "comm=,pcpu="]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
        } catch {
            return []
        }

        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return [] }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        var totals: [String: Double] = [:]
        var seenCounts: [String: Int] = [:]

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let command = parts.first else { continue }

            let executableName = URL(fileURLWithPath: String(command)).lastPathComponent
            let name = sanitizedProcessName(executableName)
            guard !name.isEmpty else { continue }

            let cpu = parts.last.flatMap { Double($0) } ?? 0.0
            totals[name, default: 0.0] += max(cpu, 0.1)
            seenCounts[name, default: 0] += 1
        }

        return seenCounts.map { name, count in
            ProcessSample(name: name, cpu: max(totals[name] ?? 0.0, Double(count) * 0.1))
        }
    }

    private func mergeSamples(_ samples: [ProcessSample]) -> [ProcessSample] {
        var totals: [String: Double] = [:]

        for sample in samples where !sample.name.isEmpty {
            totals[sample.name, default: 0.0] += sample.cpu
        }

        return totals.map { ProcessSample(name: $0.key, cpu: $0.value) }
    }

    private func selectVisibleSamples(from samples: [ProcessSample], for size: CGSize) -> [ProcessSample] {
        let capacity = visibleColumnCount(for: size)
        let topSamples = samples
            .sorted { first, second in
                if first.cpu == second.cpu {
                    return first.name.localizedCaseInsensitiveCompare(second.name) == .orderedAscending
                }

                return first.cpu > second.cpu
            }
            .prefix(capacity)

        let sortedSamples = topSamples.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }

        return fillColumnsIfNeeded(sortedSamples, minimumCount: capacity)
    }

    private func visibleColumnCount(for size: CGSize) -> Int {
        let clearColumnCapacity = max(1, Int(size.width / minimumColumnWidth))
        return min(maximumColumns, max(minimumColumns, clearColumnCapacity))
    }

    private func rebuildColumns(for size: CGSize) {
        guard size.width > 0, size.height > 0 else { return }

        lastSize = size
        let samples = columns.map(\.process)
        columns = makeColumns(from: samples.isEmpty ? selectVisibleSamples(from: loadProcessSamples(), for: size) : samples, size: size, preserving: columns)
    }

    private func makeColumns(from samples: [ProcessSample], size: CGSize, preserving oldColumns: [Column]) -> [Column] {
        guard size.width > 0, size.height > 0, !samples.isEmpty else { return [] }

        let slotWidth = size.width / CGFloat(samples.count)
        let maxCPU = max(samples.map(\.cpu).max() ?? 0.0, 0.1)

        return samples.enumerated().map { index, sample in
            let drawWidth = fontSize * 1.05
            let x = CGFloat(index) * slotWidth + max(0, (slotWidth - drawWidth) / 2.0)
            let existing = oldColumns.first { $0.process.name == sample.name }
            let speed = speed(forCPU: sample.cpu, maxCPU: maxCPU)
            let trails = existing?.trails.map { Trail(head: $0.head, speed: speed * CGFloat.random(in: 0.86...1.14), offset: $0.offset) }
                ?? makeTrails(height: size.height, processName: sample.name, baseSpeed: speed)

            return Column(process: sample, x: x, trails: trails)
        }
    }

    private func makeTrails(height: CGFloat, processName: String, baseSpeed: CGFloat) -> [Trail] {
        (0..<trailsPerColumn).map { index in
            var trail = makeTrail(height: height, processName: processName, aboveScreen: false)
            let spacing = height / CGFloat(trailsPerColumn)
            trail.head = CGFloat(index) * spacing + CGFloat.random(in: 0...(spacing * 0.65))
            trail.speed = baseSpeed * CGFloat.random(in: 0.86...1.14)
            return trail
        }
    }

    private func makeTrail(height: CGFloat, processName: String, aboveScreen: Bool) -> Trail {
        let nameLength = max(processName.count, 1)
        let head = aboveScreen
            ? -CGFloat.random(in: 0...(height * 0.2))
            : CGFloat.random(in: -height...height)

        return Trail(
            head: head,
            speed: CGFloat.random(in: minimumSpeed...maximumSpeed),
            offset: Int.random(in: 0..<nameLength)
        )
    }

    private func speed(forCPU cpu: Double, maxCPU: Double) -> CGFloat {
        let normalized = CGFloat(min(max(cpu / maxCPU, 0.0), 1.0))
        return maximumSpeed - normalized * (maximumSpeed - minimumSpeed)
    }

    private func sanitizedProcessName(_ name: String) -> String {
        let allowed = name.filter { character in
            character.isLetter || character.isNumber || character == "_" || character == "-"
        }

        return String(allowed.prefix(18))
    }

    private func workspaceSamples() -> [ProcessSample] {
        let names = Set(NSWorkspace.shared.runningApplications.compactMap { application in
            sanitizedProcessName(application.localizedName ?? application.executableURL?.lastPathComponent ?? "")
        })

        let samples = names.sorted {
            $0.localizedCaseInsensitiveCompare($1) == .orderedAscending
        }.map {
            ProcessSample(name: $0, cpu: 1.0)
        }

        return samples.isEmpty ? fallbackSamples() : samples
    }

    private func fillColumnsIfNeeded(_ samples: [ProcessSample], minimumCount: Int) -> [ProcessSample] {
        guard samples.count < minimumCount else { return samples }

        var result = samples
        var existingNames = Set(result.map(\.name))

        for fallback in fallbackSamples() where result.count < minimumCount {
            guard !existingNames.contains(fallback.name) else { continue }
            result.append(fallback)
            existingNames.insert(fallback.name)
        }

        return result.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    private func fallbackSamples() -> [ProcessSample] {
        [
            "ACTIVITYMONITOR", "AIRPLAYXPCH", "AKD", "APFSUSERAGENT",
            "BIRDD", "BLUETOOTHD", "CALLSERVICESD", "CLOUDPHOTOD",
            "CORESERVICESD", "CORESPEECHD", "DISTNOTED", "DOCK",
            "FINDER", "GAMECONTROLLERD", "HIDD", "ICONSD",
            "IMDPERSISTENT", "KERNELMANAGERD", "LAUNCHD", "LOCATIOND",
            "LOGD", "MDS", "MEDIAANALYSISD", "NOTIFICATIONCENTER",
            "NSURLSESSIOND", "PBOARD", "POWERD", "RUNNINGBOARDD",
            "SCREENSHARINGD", "SECD", "SHARINGD", "SIRIACTIONS",
            "SOFTWAREUPDATED", "SPOTLIGHT", "SYSPOLICYD", "SYSTEMUISERVER",
            "TRUSTD", "USERNOTED", "WINDOWSERVER", "XPCSERVICES"
        ].map {
            ProcessSample(name: $0, cpu: 1.0)
        }
    }
}
