import Foundation
import Combine

@MainActor
final class FakeTransport: RestoreTransport {
    var onDevicesChanged: (([DiscoveredDevice]) -> Void)?
    var onStateChanged: ((BLEConnectionState) -> Void)?
    var onTrace: ((String,String) -> Void)?
    var mode = 0, generation = 0, writes = 0
    var fixtures: [String:[UInt8]]
    var tornWrite = false, failWrite = false
    init(_ fixtures: [String:[UInt8]]) { self.fixtures = fixtures }
    func startScan() { onStateChanged?(.scanning) }
    func stopScan() { onStateChanged?(.idle) }
    func connect(to id: UUID) { onStateChanged?(.compatible("FAKE")) }
    func disconnect() { onStateChanged?(.idle) }
    func authenticate(password: String?) async throws {}
    func request(type: UInt8, payload: [UInt8], timeout: TimeInterval) async throws -> [UInt8] {
        await Task.yield()
        if type == 0xD2 {
            precondition(payload.count == 2 && payload[0] ^ 255 == payload[1])
            mode = Int(payload[0]); generation += 1; writes += 1
            if failWrite { throw BLETransportError.timedOut }
        }
        var b = fixtures["query_\(mode)"]!
        for i in 0..<4 { b[76+i] = UInt8((generation >> (i*8)) & 255) }
        if type == 0xD2 && tornWrite { b[8] = 3 }
        return b
    }
}

@main
struct NativeTests {
    @MainActor
    static func wait(_ model: ControlModel) async throws {
        for _ in 0..<1000 { if !model.pending { return }; try await Task.sleep(nanoseconds:1_000_000) }
        fatalError("model stalled")
    }
    @MainActor
    static func main() async throws {
        let file = CommandLine.arguments[1]
        let json = try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:file))) as! [String:Any]
        let entries = json["fixtures"] as! [String:[String:Any]]
        var fixtures: [String:[UInt8]] = [:]
        for (name,entry) in entries {
            if let hex = entry["payload_hex"] as? String {
                let chars = Array(hex); fixtures[name] = stride(from:0,to:chars.count,by:2).map { UInt8(String(chars[$0...($0+1)]),radix:16)! }
            }
        }
        for name in ["current_uninitialized","set_0","set_1","set_2"] { _ = try RestoreSnapshot.decode(fixtures[name]!) }
        for name in ["old_uninitialized","torn"] {
            do { _ = try RestoreSnapshot.decode(fixtures[name]!); fatalError("bad snapshot accepted") } catch is RestoreError {}
        }
        let raw = entries["set_2"]!["wire_hex"] as! String
        let chars = Array(raw), wire = Data(stride(from:0,to:chars.count,by:2).map { UInt8(String(chars[$0...($0+1)]),radix:16)! })
        for split in 0...wire.count {
            var parser = TSLPacketParser()
            let frames = parser.append(Data(wire.prefix(split))) + parser.append(Data(wire.dropFirst(split)))
            precondition(frames.count == 1 && frames[0].payload == fixtures["set_2"]!)
        }
        let authFile = URL(fileURLWithPath:file).deletingLastPathComponent().appendingPathComponent("auth_wire.json")
        let authJSON = try JSONSerialization.jsonObject(with:Data(contentsOf:authFile)) as! [String:Any]
        let authFrames = authJSON["frames"] as! [String]
        var authPackets: [TSLPacket] = []
        for rawHex in authFrames {
            let c = Array(rawHex)
            let bytes = Data(stride(from:0,to:c.count,by:2).map { UInt8(String(c[$0...($0+1)]),radix:16)! })
            var p = TSLPacketParser(); authPackets += p.append(bytes)
        }
        precondition(authPackets.count == 6)
        let challengePacket = authPackets[0], runtimePacket = authPackets[1]
        precondition(AuthenticationReplyGate.requiresPassword(challengePacket))
        precondition(!AuthenticationReplyGate.requiresPassword(runtimePacket))
        var challenged = true, authenticated = false
        var authWrites: [UInt8] = []
        let exchange: (UInt8,[UInt8],TimeInterval) async throws -> TSLPacket = { type,payload,_ in
            authWrites.append(type)
            if type == 0xA8 {
                guard payload == Array("ABCD".utf8) else { return TSLPacket(type:0xA8,payload:[0]) }
                authenticated = true; challenged = false; return runtimePacket
            }
            if !authenticated { challenged = true; return challengePacket }
            return runtimePacket
        }
        do {
            try await PasswordAuthentication.run(password:nil,exchange:exchange,challenge:{challenged},clearChallenge:{challenged=false})
            fatalError("Runtime/challenge must not bypass password")
        } catch BLETransportError.passwordRequired {}
        precondition(authWrites == [0xA0] && !authenticated)
        try await PasswordAuthentication.run(password:"ABCD",exchange:exchange,challenge:{challenged},clearChallenge:{challenged=false})
        precondition(authenticated && authWrites == [0xA0,0xA8,0xA0,0xA0])
        authenticated = false;challenged = true
        do {
            try await PasswordAuthentication.run(password:"WXYZ",exchange:exchange,challenge:{challenged},clearChallenge:{challenged=false})
            fatalError("Wrong key accepted")
        } catch BLETransportError.incorrectPassword {}
        let fake = FakeTransport(fixtures), model = ControlModel(bluetooth:fake)
        model.autoRefresh = false
        model.connect(DiscoveredDevice(id:UUID(),name:"FAKE",rssi:-40)); try await wait(model)
        precondition(model.ready && model.confirmedMode == .off)
        model.selectMode(.modeA);model.selectMode(.modeB);try await wait(model)
        precondition(fake.writes == 1 && model.confirmedMode == .modeA)
        fake.tornWrite = true; model.selectMode(.modeB);try await wait(model)
        precondition(fake.writes == 2 && model.confirmedMode == .modeB)
        fake.failWrite = true;model.selectMode(.off);try await wait(model)
        precondition(model.confirmedMode == nil && !model.ready && fake.mode == 0)
        model.disconnect()
        print("PASS native explicit password flow/log fixture, RTD2/BIN fixtures, all notification splits, mutual exclusion, torn ACK, unknown state after timeout")
    }
}
