import CoreBluetooth
import Foundation

struct DiscoveredDevice: Identifiable, Equatable {
    let id: UUID
    let name: String
    let rssi: Int
}

enum BLEConnectionState: Equatable {
    case idle, scanning
    case connecting(String), discovering(String), compatible(String), incompatible(String)
    case unavailable(String), failed(String)
}

enum BLETransportError: LocalizedError {
    case bluetoothUnavailable, deviceNotFound, disconnected, busy, timedOut, writeUnavailable
    case passwordRequired, incorrectPassword, invalidDeviceInfo
    var errorDescription: String? {
        switch self {
        case .bluetoothUnavailable: return "蓝牙当前不可用"
        case .deviceNotFound: return "设备已离开扫描范围"
        case .disconnected: return "蓝牙连接已断开"
        case .busy: return "上一条设备指令尚未完成"
        case .timedOut: return "等待设备应答超时"
        case .writeUnavailable: return "设备没有可写的 FFF1 特征"
        case .passwordRequired: return "请输入模块的4位蓝牙密码"
        case .incorrectPassword: return "蓝牙密码不正确"
        case .invalidDeviceInfo: return "模块设备信息应答无效"
        }
    }
}

@MainActor
final class BLEController: NSObject, RestoreTransport, CBCentralManagerDelegate, CBPeripheralDelegate {
    var onTrace: ((String, String) -> Void)?
    private var connectionTimer: DispatchWorkItem?
    var onDevicesChanged: (([DiscoveredDevice]) -> Void)?
    var onStateChanged: ((BLEConnectionState) -> Void)?
    private(set) var state: BLEConnectionState = .idle { didSet { onStateChanged?(state) } }

    private lazy var central = CBCentralManager(
        delegate: self, queue: nil,
        options: [CBCentralManagerOptionShowPowerAlertKey: true]
    )
    private var scanRequested = false
    private var peripheralByID: [UUID: CBPeripheral] = [:]
    private var deviceByID: [UUID: DiscoveredDevice] = [:]
    private var currentPeripheral: CBPeripheral?
    private var writeCharacteristic: CBCharacteristic?
    private var notifyCharacteristic: CBCharacteristic?
    private var parser = TSLPacketParser()
    private var pending: PendingCommand?
    private var passwordChallenge = false
    private var authenticationTraffic = true

    override init() {
        super.init()
        _ = central
    }

    func startScan() {
        scanRequested = true
        deviceByID.removeAll()
        peripheralByID.removeAll()
        publishDevices()
        guard central.state == .poweredOn else {
            state = .unavailable(Self.bluetoothStateDescription(central.state))
            return
        }
        beginScan()
    }

    func stopScan() {
        scanRequested = false
        central.stopScan()
        if case .scanning = state { state = .idle }
    }

    func connect(to id: UUID) {
        guard let peripheral = peripheralByID[id] else {
            state = .failed(BLETransportError.deviceNotFound.localizedDescription)
            return
        }
        stopScan()
        resetConnectionData()
        currentPeripheral = peripheral
        peripheral.delegate = self
        state = .connecting(deviceByID[id]?.name ?? Self.deviceName(peripheral, advertisement: nil))
        onTrace?("连接设备", peripheral.identifier.uuidString)
        let timer = DispatchWorkItem { [weak self, weak peripheral] in
            guard let self, let peripheral, self.currentPeripheral == peripheral else { return }
            self.failConnection(BLETransportError.timedOut)
        }
        connectionTimer = timer
        DispatchQueue.main.asyncAfter(deadline:.now() + 15, execute:timer)
        central.connect(peripheral, options: [CBConnectPeripheralOptionNotifyOnDisconnectionKey: true])
    }

    func disconnect() {
        scanRequested = false
        central.stopScan()
        finishPending(with: .failure(BLETransportError.disconnected))
        if let currentPeripheral { central.cancelPeripheralConnection(currentPeripheral) }
        resetConnectionData()
        currentPeripheral = nil
        state = .idle
    }

    func authenticate(password: String?) async throws {
        authenticationTraffic = true
        try await PasswordAuthentication.run(password:password,
            exchange: { [self] type,payload,timeout in
                try await self.exchange(type:type,payload:payload,expectedTypes:[0xA0,0xA8],timeout:timeout)
            }, challenge: { [self] in passwordChallenge },
            clearChallenge: { [self] in passwordChallenge = false })
    }

    func request(type: UInt8, payload: [UInt8], timeout: TimeInterval = 5) async throws -> [UInt8] {
        guard !passwordChallenge else { throw BLETransportError.passwordRequired }
        if type == 0xD1 || type == 0xD2 { authenticationTraffic = false }
        let response = try await exchange(type:type,payload:payload,expectedTypes:[type,0xA8],timeout:timeout)
        if response.type == 0xA8 { throw BLETransportError.passwordRequired }
        return response.payload
    }

    private func exchange(
        type: UInt8,
        payload: [UInt8],
        expectedTypes: Set<UInt8>,
        subcommand: UInt8? = nil,
        timeout: TimeInterval
    ) async throws -> TSLPacket {
        try Task.checkCancellation()
        guard pending == nil else { throw BLETransportError.busy }
        guard let peripheral = currentPeripheral,
              peripheral.state == .connected,
              let characteristic = writeCharacteristic else { throw BLETransportError.writeUnavailable }
        let packet = TSLPacket.encode(type: type, payload: payload)
        let token = UUID()
        onTrace?("发送指令", type == 0xA8 ? "A8 密码已隐藏" : "TYPE=\(String(format: "%02X",type)) BYTES=\(packet.count)")
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let command = PendingCommand(
                    id: token,
                    expectedTypes: expectedTypes,
                    subcommand: subcommand,
                    continuation: continuation
                )
                pending = command
                let timeoutWork = DispatchWorkItem { [weak self, weak command] in
                    guard let self, let command, self.pending === command else { return }
                    self.onTrace?("应答超时", "TYPE=\(String(format: "%02X",type))；断开后重新确认，避免迟到包混入新请求")
                    self.failConnection(BLETransportError.timedOut)
                }
                command.timeoutWork = timeoutWork
                DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)
                let writeType: CBCharacteristicWriteType = characteristic.properties.contains(.writeWithoutResponse)
                    ? .withoutResponse : .withResponse
                peripheral.writeValue(packet, for: characteristic, type: writeType)
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                guard let self, self.pending?.id == token else { return }
                self.failConnection(CancellationError())
            }
        }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            if scanRequested { beginScan() }
        } else {
            central.stopScan()
            finishPending(with: .failure(BLETransportError.bluetoothUnavailable))
            let peripheral = currentPeripheral
            currentPeripheral = nil
            resetConnectionData()
            if let peripheral { central.cancelPeripheralConnection(peripheral) }
            state = .unavailable(Self.bluetoothStateDescription(central.state))
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        peripheralByID[peripheral.identifier] = peripheral
        let device = DiscoveredDevice(
            id: peripheral.identifier,
            name: Self.deviceName(peripheral, advertisement: advertisementData),
            rssi: RSSI.intValue
        )
        deviceByID[device.id] = device
        publishDevices()
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard peripheral == currentPeripheral else { return }
        let name = deviceByID[peripheral.identifier]?.name ?? Self.deviceName(peripheral, advertisement: nil)
        state = .discovering(name)
        peripheral.delegate = self
        peripheral.discoverServices(nil)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard peripheral == currentPeripheral else { return }
        finishPending(with: .failure(error ?? BLETransportError.disconnected))
        resetConnectionData()
        currentPeripheral = nil
        state = .failed(error?.localizedDescription ?? "连接失败")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard peripheral == currentPeripheral else { return }
        finishPending(with: .failure(error ?? BLETransportError.disconnected))
        resetConnectionData()
        currentPeripheral = nil
        state = error == nil ? .idle : .failed(error!.localizedDescription)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard peripheral == currentPeripheral else { return }
        if let error { failConnection(error); return }
        onTrace?("服务列表", (peripheral.services ?? []).map { $0.uuid.uuidString }.joined(separator:","))
        guard let service = peripheral.services?.first(where: { $0.uuid == CBUUID(string: "FFF0") }) else {
            state = .incompatible(Self.deviceName(peripheral, advertisement: nil)); return
        }
        peripheral.discoverCharacteristics(nil, for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard peripheral == currentPeripheral else { return }
        if let error { failConnection(error); return }
        let characteristics = service.characteristics ?? []
        onTrace?("特征列表", characteristics.map { "\($0.uuid.uuidString):\($0.properties.rawValue)" }.joined(separator:","))
        let fff1 = characteristics.first(where: { $0.uuid == CBUUID(string: "FFF1") })
        let canWrite = fff1?.properties.contains(.write) == true ||
            fff1?.properties.contains(.writeWithoutResponse) == true
        guard let fff1, canWrite else {
            state = .incompatible(Self.deviceName(peripheral, advertisement: nil)); return
        }
        writeCharacteristic = fff1
        if fff1.properties.contains(.notify) || fff1.properties.contains(.indicate) {
            notifyCharacteristic = fff1
        } else {
            notifyCharacteristic = characteristics.first(where: {
                $0.uuid == CBUUID(string: "FFE0") &&
                    ($0.properties.contains(.notify) || $0.properties.contains(.indicate))
            })
        }
        guard let notifyCharacteristic else {
            state = .incompatible(Self.deviceName(peripheral, advertisement: nil)); return
        }
        peripheral.setNotifyValue(true, for: notifyCharacteristic)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard peripheral == currentPeripheral, characteristic == notifyCharacteristic else { return }
        if let error { failConnection(error); return }
        guard characteristic.isNotifying else {
            state = .incompatible(Self.deviceName(peripheral, advertisement: nil)); return
        }
        connectionTimer?.cancel(); connectionTimer = nil
        onTrace?("通知订阅完成", characteristic.uuid.uuidString)
        state = .compatible(Self.deviceName(peripheral, advertisement: nil))
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard peripheral == currentPeripheral, characteristic == notifyCharacteristic else { return }
        if let error { failConnection(error); return }
        guard let data = characteristic.value else { return }
        if !authenticationTraffic {
            onTrace?("通知原始片段", data.map { String(format:"%02X",$0) }.joined(separator:" "))
        } else { onTrace?("认证通知片段", "字节数=\(data.count)；认证载荷不写入日志") }
        for packet in parser.append(data) {
            onTrace?("有效协议帧", "TYPE=\(String(format:"%02X",packet.type)) LEN=\(packet.payload.count) HEAD=\(packet.payload.prefix(packet.type == 0xA0 ? 4 : 16).map { String(format:"%02X",$0) }.joined(separator:" "))")
            if AuthenticationReplyGate.requiresPassword(packet) {
                passwordChallenge = true
                onTrace?("需要密码认证", "A8 状态=\(packet.payload.first ?? 255)；收到 A0 不会清除密码要求")
            }
            guard let pending, pending.expectedTypes.contains(packet.type) else { continue }
            if let subcommand = pending.subcommand {
                guard packet.payload.count >= 4,
                      packet.payload[2] == 0xD9,
                      packet.payload[3] == subcommand else { continue }
            }
            finishPending(with: .success(packet))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard peripheral == currentPeripheral, characteristic == writeCharacteristic else { return }
        if let error { failConnection(error) }
    }

    private func failConnection(_ error: Error) {
        finishPending(with:.failure(error))
        let peripheral = currentPeripheral
        currentPeripheral = nil
        resetConnectionData()
        if let peripheral { central.cancelPeripheralConnection(peripheral) }
        state = .failed(error.localizedDescription + "；实际模式待确认")
    }

    private func beginScan() {
        central.stopScan()
        central.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        state = .scanning
    }
    private func publishDevices() {
        let devices = deviceByID.values.sorted {
            if $0.rssi == $1.rssi {
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
            return $0.rssi > $1.rssi
        }
        onDevicesChanged?(devices)
    }
    private func resetConnectionData() {
        connectionTimer?.cancel(); connectionTimer = nil
        writeCharacteristic = nil
        notifyCharacteristic = nil
        parser.reset()
        passwordChallenge = false
        authenticationTraffic = true
    }
    private func finishPending(with result: Result<TSLPacket, Error>) {
        guard let pending else { return }
        self.pending = nil
        pending.timeoutWork?.cancel()
        switch result {
        case .success(let payload): pending.continuation.resume(returning: payload)
        case .failure(let error): pending.continuation.resume(throwing: error)
        }
    }
    private static func deviceName(_ peripheral: CBPeripheral, advertisement: [String: Any]?) -> String {
        if let localName = advertisement?[CBAdvertisementDataLocalNameKey] as? String,
           !localName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return localName }
        if let name = peripheral.name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return name }
        return "未命名 BLE 设备"
    }
    private static func bluetoothStateDescription(_ state: CBManagerState) -> String {
        switch state {
        case .poweredOff: return "系统蓝牙已关闭"
        case .unauthorized: return "未授予蓝牙权限"
        case .unsupported: return "此设备不支持蓝牙低功耗"
        case .resetting: return "系统蓝牙正在重置"
        case .unknown: return "正在初始化系统蓝牙"
        case .poweredOn: return "蓝牙可用"
        @unknown default: return "蓝牙状态未知"
        }
    }

    private static func validateDeviceInfo(_ payload: [UInt8]) throws {
        guard payload.count >= 18, payload[3] & 0x01 == 0x01 else {
            throw BLETransportError.invalidDeviceInfo
        }
    }
}

@MainActor
private final class PendingCommand {
    let id: UUID
    let expectedTypes: Set<UInt8>
    let subcommand: UInt8?
    let continuation: CheckedContinuation<TSLPacket, Error>
    var timeoutWork: DispatchWorkItem?
    init(id: UUID, expectedTypes: Set<UInt8>, subcommand: UInt8?, continuation: CheckedContinuation<TSLPacket, Error>) {
        self.id = id
        self.expectedTypes = expectedTypes
        self.subcommand = subcommand
        self.continuation = continuation
    }
}
