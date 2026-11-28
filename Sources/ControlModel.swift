import Foundation
import Combine

@MainActor
protocol RestoreTransport: AnyObject {
    var onDevicesChanged: (([DiscoveredDevice]) -> Void)? { get set }
    var onStateChanged: ((BLEConnectionState) -> Void)? { get set }
    var onTrace: ((String, String) -> Void)? { get set }
    func startScan()
    func stopScan()
    func connect(to id: UUID)
    func disconnect()
    func authenticate(password: String?) async throws
    func request(type: UInt8, payload: [UInt8], timeout: TimeInterval) async throws -> [UInt8]
}

struct RestoreLogEntry: Codable { let utc: String, event: String, detail: String }

@MainActor
final class ControlModel: ObservableObject {
    enum Phase: Equatable {
        case disconnected, scanning, connecting, discovering, authenticating, passwordRequired
        case reading, ready, incompatible, failed
    }
    @Published private(set) var phase: Phase = .disconnected
    @Published private(set) var devices: [DiscoveredDevice] = []
    @Published private(set) var connectedName = ""
    @Published private(set) var snapshot: RestoreSnapshot?
    @Published private(set) var confirmedMode: RestoreMode?
    @Published private(set) var pendingMode: RestoreMode?
    @Published private(set) var pending = false
    @Published private(set) var notice = "连接后读取设备实际模式"
    @Published private(set) var logs: [RestoreLogEntry] = []
    @Published private(set) var exportURL: URL?
    @Published var bluetoothPassword = ""
    @Published var autoRefresh = true
    private let bluetooth: any RestoreTransport
    private var session = UUID()
    private var hasPeripheralConnection = false
    private var task: Task<Void,Never>?
    private var pollTask: Task<Void,Never>?
    private var discardedLogs = 0
    var ready: Bool { phase == .ready && confirmedMode != nil }
    var connected: Bool { phase == .connecting || hasPeripheralConnection }
    var status: String {
        switch phase {
        case .disconnected: return "未连接 · 模式待确认"
        case .scanning: return "正在扫描"
        case .connecting: return "正在连接"
        case .discovering: return "正在订阅通知"
        case .authenticating: return "正在验证密码与 A0"
        case .passwordRequired: return "等待蓝牙密码"
        case .reading: return "正在读取实际模式"
        case .ready: return pending ? "等待设备确认" : "模式已同步"
        case .incompatible: return "固件或 GATT 不匹配"
        case .failed: return "状态待确认"
        }
    }
    init(bluetooth: (any RestoreTransport)? = nil) {
        self.bluetooth = bluetooth ?? BLEController()
        self.bluetooth.onDevicesChanged = { [weak self] in self?.devices = $0 }
        self.bluetooth.onStateChanged = { [weak self] in self?.handle($0) }
        self.bluetooth.onTrace = { [weak self] in self?.log($0,$1) }
    }
    func log(_ event: String, _ detail: String) {
        logs.append(RestoreLogEntry(utc: ISO8601DateFormatter().string(from: Date()),event: event,detail: detail))
        if logs.count > 3000 { logs.removeFirst(); discardedLogs += 1 }
    }
    private func invalidate(clearSnapshot: Bool = false) {
        session = UUID(); task?.cancel(); task = nil; pollTask?.cancel(); pollTask = nil
        confirmedMode = nil; pendingMode = nil; pending = false
        if clearSnapshot { snapshot = nil }
    }
    func startScan() { invalidate(clearSnapshot:true); bluetooth.startScan() }
    func stopScan() { bluetooth.stopScan(); phase = .disconnected; notice = "扫描已停止" }
    func connect(_ device: DiscoveredDevice) {
        invalidate(clearSnapshot:true); connectedName = device.name; bluetooth.connect(to:device.id)
    }
    func disconnect() { invalidate(); bluetooth.disconnect(); phase = .disconnected; notice = "已断开；模块上的模式不会自动关闭" }
    func submitPassword() {
        let password = bluetoothPassword; bluetoothPassword = ""
        guard password.utf8.count == 4 else { notice = "请输入四字节蓝牙密码"; return }
        authenticate(password:password)
    }
    func refresh() {
        guard ready, !pending else { return }
        let active = session; pending = true
        task = Task { [weak self] in
            guard let self else { return }
            do {
                let value = try await readSnapshot()
                try Task.checkCancellation(); guard active == session else { return }
                apply(value); pending = false; notice = "已重新读取实际模式"
            } catch { if active == session { fail(error) } }
        }
    }
    func toggle(_ mode: RestoreMode, enabled: Bool) { selectMode(enabled ? mode : .off) }
    func selectMode(_ target: RestoreMode) {
        guard ready, !pending, confirmedMode != target else { return }
        let active = session; pending = true; pendingMode = target; notice = "等待确认 \(target.title)"
        task = Task { [weak self] in
            guard let self else { return }
            do {
                let response = try await bluetooth.request(type:0xD2,payload:[target.rawValue,target.rawValue ^ 0xFF],timeout:6)
                do {
                    let ack = try RestoreSnapshot.decode(response)
                    guard ack.mode == target else { throw RestoreError.modeNotConfirmed }
                } catch RestoreError.snapshotChanged {
                    log("写入应答正在更新", "改用 D1 查询实际模式，不重发 D2")
                }
                let actual = try await readSnapshot()
                try Task.checkCancellation(); guard session == active else { return }
                apply(actual); pending = false; pendingMode = nil
                notice = actual.mode == target ? "设备已确认 \(actual.mode.title)" : "设备当前为 \(actual.mode.title)，目标未确认"
            } catch { if active == session { fail(error) } }
        }
    }
    private func apply(_ value: RestoreSnapshot) {
        if let previous = snapshot, previous.modeGeneration != value.modeGeneration || previous.mode != value.mode {
            log("模式区段变化", "\(previous.mode.title)/\(previous.modeGeneration) → \(value.mode.title)/\(value.modeGeneration)")
        }
        snapshot = value; confirmedMode = value.mode
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        if let data = try? encoder.encode(value), let text = String(data:data,encoding:.utf8) { log("有效快照",text) }
    }
    private func readSnapshot() async throws -> RestoreSnapshot {
        for attempt in 0..<3 {
            let data = try await bluetooth.request(type:0xD1,payload:Array("RSTD".utf8),timeout:6)
            do { return try RestoreSnapshot.decode(data) }
            catch RestoreError.snapshotChanged {
                if attempt == 2 { throw RestoreError.snapshotChanged }
                try await Task.sleep(nanoseconds:180_000_000)
            }
        }
        throw RestoreError.snapshotChanged
    }
    private func authenticate(password: String?) {
        guard !pending else { return }
        let active = session; pending = true; phase = .authenticating; notice = "验证模块连接与密码"
        task = Task { [weak self] in
            guard let self else { return }
            do {
                try await bluetooth.authenticate(password:password)
                try Task.checkCancellation(); guard active == session else { return }
                phase = .reading; notice = "查询 D1 / RTD2"
                let value = try await readSnapshot()
                try Task.checkCancellation(); guard active == session else { return }
                apply(value); pending = false; phase = .ready; notice = "设备实际模式已同步"
                startPolling()
            } catch BLETransportError.passwordRequired {
                guard active == session else { return }; pending = false; phase = .passwordRequired; notice = "请输入模块的四字节蓝牙密码"
            } catch BLETransportError.incorrectPassword {
                guard active == session else { return }; pending = false; phase = .passwordRequired; notice = "密码未通过，请重新输入"
            } catch { if active == session { fail(error) } }
        }
    }
    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds:2_000_000_000) } catch { return }
                guard let self else { return }
                if autoRefresh && ready && !pending { refresh() }
            }
        }
    }
    func suspend() { autoRefresh = false; log("进入后台", "暂停自动读取，不自动切换模式") }
    func resume() { if ready { refresh() } }
    private func fail(_ error: Error) {
        log("操作失败",error.localizedDescription)
        invalidate()
        let needsPassword: Bool
        switch error {
        case BLETransportError.passwordRequired, BLETransportError.incorrectPassword: needsPassword = true
        default: needsPassword = false
        }
        if needsPassword {
            phase = .passwordRequired; notice = "模块要求重新验证密码；当前模式待确认，不自动重发模式设置。"
        } else { phase = .failed; notice = error.localizedDescription + "；实际模式待确认，请断开后重连。" }
    }
    private func handle(_ state: BLEConnectionState) {
        switch state {
        case .idle: invalidate(); hasPeripheralConnection = false; phase = .disconnected
        case .scanning: phase = .scanning; notice = "选择自己的 TSL8 模块"
        case .connecting(let name): connectedName = name; phase = .connecting
        case .discovering(let name): connectedName = name; hasPeripheralConnection = true; phase = .discovering
        case .compatible(let name): connectedName = name; hasPeripheralConnection = true; authenticate(password:nil)
        case .incompatible(let name): invalidate(); connectedName = name; hasPeripheralConnection = true; phase = .incompatible; notice = "未找到 FFF0/FFF1 通知与写入接口"
        case .unavailable(let reason): invalidate(); hasPeripheralConnection = false; phase = .failed; notice = reason
        case .failed(let reason): invalidate(); hasPeripheralConnection = false; phase = .failed; notice = reason
        }
    }
    func exportLogs() {
        struct Export: Encodable { let app: String, expectedFirmwareSHA: String, discardedLogs: Int; let events: [RestoreLogEntry] }
        do {
            let data = try JSONEncoder().encode(Export(app:"TSL8 Restore 1.1.2",expectedFirmwareSHA:RestoreSnapshot.firmwareSHA,
                discardedLogs:discardedLogs,events:logs))
            let folder = FileManager.default.urls(for:.documentDirectory,in:.userDomainMask)[0]
            let file = folder.appendingPathComponent("TSL8-Restore-\(Int(Date().timeIntervalSince1970)).json")
            try data.write(to:file,options:.atomic); exportURL = file
        } catch { notice = "日志导出失败：\(error.localizedDescription)" }
    }
}
