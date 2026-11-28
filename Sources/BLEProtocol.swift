import Foundation

struct TSLPacket: Equatable {
    static let firstHeader: UInt8 = 0x55
    static let secondHeader: UInt8 = 0x7F
    static let maximumPayloadLength = 1039
    let type: UInt8
    let payload: [UInt8]

    static func encode(type: UInt8, payload: [UInt8]) -> Data {
        precondition(payload.count <= UInt16.max)
        let high = UInt8((payload.count >> 8) & 0xFF)
        let low = UInt8(payload.count & 0xFF)
        var bytes = [firstHeader, secondHeader, type, high, low]
        bytes.append(contentsOf: payload)
        bytes.append(checksum(type: type, payload: payload))
        return Data(bytes)
    }

    static func checksum(type: UInt8, payload: [UInt8]) -> UInt8 {
        let length = payload.count
        let seed = UInt32(type) + UInt32((length >> 8) & 0xFF) + UInt32(length & 0xFF)
        return UInt8((payload.reduce(seed) { $0 + UInt32($1) }) & 0xFF)
    }
}

struct TSLPacketParser {
    private var buffer: [UInt8] = []

    mutating func reset() { buffer.removeAll(keepingCapacity: true) }

    mutating func append(_ data: Data) -> [TSLPacket] {
        buffer.append(contentsOf: data)
        var packets: [TSLPacket] = []
        while true {
            while buffer.count >= 2 &&
                    (buffer[0] != TSLPacket.firstHeader || buffer[1] != TSLPacket.secondHeader) {
                buffer.removeFirst()
            }
            guard buffer.count >= 6 else { break }
            let length = (Int(buffer[3]) << 8) | Int(buffer[4])
            guard length <= TSLPacket.maximumPayloadLength else {
                buffer.removeFirst()
                continue
            }
            let totalLength = length + 6
            guard buffer.count >= totalLength else { break }
            let candidate = Array(buffer.prefix(totalLength))
            let type = candidate[2]
            let payload = Array(candidate[5..<(5 + length)])
            guard candidate.last == TSLPacket.checksum(type: type, payload: payload) else {
                buffer.removeFirst()
                continue
            }
            buffer.removeFirst(totalLength)
            packets.append(TSLPacket(type: type, payload: payload))
        }
        return packets
    }
}

// Runtime information alone does not satisfy the firmware's session flag.
enum AuthenticationReplyGate {
    static func requiresPassword(_ packet: TSLPacket) -> Bool {
        packet.type == 0xA8 && [UInt8(0),UInt8(0xFE),UInt8(0xFF)].contains(packet.payload.first ?? 0xFF)
    }
}

@MainActor
enum PasswordAuthentication {
    static func validateRuntime(_ packet: TSLPacket) throws {
        guard packet.type == 0xA0, packet.payload.count >= 18, packet.payload[3] & 1 == 1 else {
            throw BLETransportError.invalidDeviceInfo
        }
    }
    static func run(password: String?,
                    exchange: (UInt8,[UInt8],TimeInterval) async throws -> TSLPacket,
                    challenge: () -> Bool, clearChallenge: () -> Void) async throws {
        if let key = password {
            guard key.utf8.count == 4 else { throw BLETransportError.passwordRequired }
            clearChallenge()
            let reply = try await exchange(0xA8,Array(key.utf8),8)
            if reply.type == 0xA0 { try validateRuntime(reply) }
            else if reply.type != 0xA8 || reply.payload.first != 1 { throw BLETransportError.incorrectPassword }
        } else {
            let first = try await exchange(0xA0,[],5)
            guard !challenge(), !AuthenticationReplyGate.requiresPassword(first) else { throw BLETransportError.passwordRequired }
            if first.type == 0xA0 { try validateRuntime(first) }
            else if first.payload.first != 1 { throw BLETransportError.passwordRequired }
        }
        for _ in 0..<2 {
            try await Task.sleep(nanoseconds:120_000_000)
            guard !challenge() else { throw BLETransportError.passwordRequired }
            let proof = try await exchange(0xA0,[],5)
            guard !challenge(), proof.type == 0xA0 else { throw BLETransportError.passwordRequired }
            try validateRuntime(proof)
        }
    }
}
