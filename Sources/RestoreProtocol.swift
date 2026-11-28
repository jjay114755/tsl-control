import Foundation

enum RestoreMode: UInt8, CaseIterable, Identifiable, Codable {
    case off = 0
    case modeA = 1
    case modeB = 2

    var id: UInt8 { rawValue }
    var title: String {
        switch self {
        case .off: return "关闭"
        case .modeA: return "A 条件回送"
        case .modeB: return "B P4 覆盖"
        }
    }
    var shortTitle: String {
        switch self {
        case .off: return "OFF"
        case .modeA: return "A"
        case .modeB: return "B"
        }
    }
}

struct RestoreSnapshot: Equatable, Codable {
    static let firmwareSHA = "7865c3402c633d024a4d8ef32e00b9b9c36836ce80ad4a7a333931c447e071c7"
    let rawPayloadHex: String
    static let byteCount = 256
    let mode: RestoreMode
    let sequence: UInt32
    let queueDepth: UInt32
    let candidates: UInt32
    let wrongRoute: UInt32
    let wrongDLC: UInt32
    let policySkips: UInt32
    let attempts: UInt32
    let nativeReturnZero: UInt32
    let nativeReturnNonzero: UInt32
    let failureEvents: UInt32
    let maxDuration: UInt32
    let lastDuration: UInt32
    let lastNativeReturn: UInt32
    let queueDrops: UInt32
    let modeGeneration: UInt32

    static func decode(_ response: [UInt8]) throws -> RestoreSnapshot {
        let payload = try normalizedPayload(response)
        guard payload[4] == 0x02,
              let mode = RestoreMode(rawValue: payload[5]),
              u16(payload, 6) == UInt16(byteCount) else {
            throw RestoreError.invalidSnapshot(Self.summary(response))
        }
        let sequence = u32(payload, 8)
        guard sequence & 1 == 0, sequence == u32(payload, 112) else {
            throw RestoreError.snapshotChanged
        }
        let queueEnd = u32(payload, 104)
        let queueStart = u32(payload, 108)
        guard queueStart & 1 == 0, queueStart == queueEnd else {
            throw RestoreError.snapshotChanged
        }
        return RestoreSnapshot(
            rawPayloadHex: summaryAll(payload),
            mode: mode,
            sequence: sequence,
            queueDepth: u32(payload, 16),
            candidates: u32(payload, 20),
            wrongRoute: u32(payload, 24),
            wrongDLC: u32(payload, 28),
            policySkips: u32(payload, 32),
            attempts: u32(payload, 36),
            nativeReturnZero: u32(payload, 40),
            nativeReturnNonzero: u32(payload, 44),
            failureEvents: u32(payload, 48),
            maxDuration: u32(payload, 52),
            lastDuration: u32(payload, 56),
            lastNativeReturn: u32(payload, 60),
            queueDrops: u32(payload, 72),
            modeGeneration: u32(payload, 76)
        )
    }

    private static func u16(_ data: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }
    private static func u32(_ data: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(data[offset]) |
            (UInt32(data[offset + 1]) << 8) |
            (UInt32(data[offset + 2]) << 16) |
            (UInt32(data[offset + 3]) << 24)
    }

    private static func summaryAll(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    private static func normalizedPayload(_ response: [UInt8]) throws -> [UInt8] {
        guard response.count == byteCount, Array(response.prefix(4)) == Array("RTD2".utf8) else {
            throw RestoreError.invalidSnapshot(summary(response))
        }
        return response
    }

    private static func summary(_ response: [UInt8]) -> String {
        let prefix = response.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
        return "长度 \(response.count)，头部 \(prefix.isEmpty ? "空" : prefix)"
    }
}

enum RestoreError: LocalizedError {
    case invalidSnapshot(String), snapshotChanged, modeNotConfirmed
    var errorDescription: String? {
        switch self {
        case .invalidSnapshot(let detail): return "RTD2 快照无效（\(detail)）。请核对配套 BIN 并导出日志"
        case .snapshotChanged: return "读取期间诊断快照发生变化，请重试"
        case .modeNotConfirmed: return "设备未确认目标模式"
        }
    }
}

