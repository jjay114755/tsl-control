import SwiftUI

struct ControlView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = ControlModel()
    private let accent = Color(red: 0.04, green: 0.48, blue: 0.45)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    header
                    connectionSection
                    if model.phase == .passwordRequired { passwordSection }
                    if model.phase == .scanning { deviceList }
                    modeSection
                    if let snapshot = model.snapshot { diagnostics(snapshot) }
                    logSection
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 18)
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .tint(accent)
            .onChange(of: scenePhase) { phase in
                if phase == .active { model.resume() } else { model.suspend() }
            }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text("TSL8 Restore").font(.largeTitle.bold())
                Text("4.1.6 单固件模式控制").foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "arrow.triangle.2.circlepath.circle.fill")
                .font(.title).foregroundStyle(accent)
        }
    }

    private var connectionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 14) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.title2).frame(width: 48, height: 48)
                    .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                    .foregroundStyle(accent)
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.connectedName.isEmpty ? "附近设备" : model.connectedName)
                        .font(.headline).lineLimit(1)
                    HStack(spacing: 7) {
                        Circle().fill(model.ready ? Color.green : statusColor).frame(width: 7, height: 7)
                        Text(model.status).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if [.connecting, .discovering, .authenticating, .reading].contains(model.phase) { ProgressView() }
                if model.ready {
                    Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel("重新读取诊断快照")
                }
            }
            connectionButton
            Label(model.notice, systemImage: noticeSymbol)
                .font(.footnote)
                .foregroundStyle(model.phase == .failed ? .red : .secondary)
        }
        .padding(20)
        .background(.background, in: RoundedRectangle(cornerRadius: 8))
    }

    private var passwordSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("模块蓝牙密码", systemImage: "key.fill").font(.headline)
            SecureField("4位密码", text: $model.bluetoothPassword)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.asciiCapable)
                .padding(12)
                .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
            Button { model.submitPassword() } label: {
                Label("验证并读取", systemImage: "checkmark.shield")
                    .frame(maxWidth: .infinity).padding(.vertical, 5)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.bluetoothPassword.utf8.count != 4)
        }
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private var connectionButton: some View {
        if model.connected || model.phase == .incompatible {
            Button(role: .destructive) { model.disconnect() } label: {
                Label("断开连接", systemImage: "xmark.circle")
                    .frame(maxWidth: .infinity).padding(.vertical, 5)
            }.buttonStyle(.bordered)
        } else if model.phase == .scanning {
            Button { model.stopScan() } label: {
                Label("停止扫描", systemImage: "stop.circle")
                    .frame(maxWidth: .infinity).padding(.vertical, 5)
            }.buttonStyle(.bordered)
        } else {
            Button { model.startScan() } label: {
                Label("扫描 BLE 设备", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity).padding(.vertical, 5)
            }.buttonStyle(.borderedProminent)
        }
    }

    private var deviceList: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("可连接设备").font(.headline)
                Spacer()
                Text("\(model.devices.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            if model.devices.isEmpty {
                HStack { Spacer(); ProgressView(); Spacer() }.padding(.vertical, 18)
            } else {
                ForEach(model.devices) { device in
                    HStack(spacing: 12) {
                        Image(systemName: "wave.3.right.circle").font(.title3).foregroundStyle(accent)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(device.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            Text("RSSI \(device.rssi) dBm")
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { model.connect(device) } label: { Image(systemName: "link") }
                            .buttonStyle(.bordered).accessibilityLabel("连接 \(device.name)")
                    }
                    .padding(14)
                    .background(.background, in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    private var modeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Restore 模式").font(.title3.bold())
                Spacer()
                if model.pending { ProgressView().controlSize(.small) }
                Text(model.confirmedMode?.shortTitle ?? "待确认")
                    .font(.caption.bold().monospaced()).foregroundStyle(.secondary)
            }
            ForEach([RestoreMode.modeA, .modeB]) { mode in
                Toggle(isOn: Binding(
                    get: { model.confirmedMode == mode },
                    set: { model.toggle(mode, enabled:$0) }
                )) {
                    VStack(alignment:.leading, spacing:4) {
                        Text(mode.title).font(.headline)
                        Text(mode == .modeA ? "低六位已为 0x1B 才回送" : "覆盖低六位为 0x1B 后回送")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(!model.ready || model.pending)
                .accessibilityIdentifier("mode-\(mode.shortTitle)")
                Divider()
            }
            Button("关闭 Restore") { model.selectMode(.off) }
                .buttonStyle(.bordered)
                .disabled(!model.ready || model.pending || model.confirmedMode == .off)
            Text("重启默认关闭。蓝牙断开不会自动关闭模块模式；收到设备确认后才更新开关。")
                .font(.footnote).foregroundStyle(.secondary)
            if let target = model.pendingMode {
                Text("正在请求 \(target.title)…").font(.footnote)
            }
        }
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 8))
    }

    private func diagnostics(_ value: RestoreSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("运行诊断").font(.title3.bold())
                Spacer()
                Toggle("自动读取", isOn:$model.autoRefresh).font(.caption)
            }
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                metric("模式切换序号", value.modeGeneration)
                metric("候选帧", value.candidates)
                metric("发送尝试", value.attempts)
                metric("原生返回 0", value.nativeReturnZero)
                metric("原生非 0", value.nativeReturnNonzero)
                metric("失败记录", value.failureEvents)
                metric("队列丢帧", value.queueDrops)
                metric("最近返回码", value.lastNativeReturn)
                metric("路径不符", value.wrongRoute)
                metric("长度不符", value.wrongDLC)
                metric("策略跳过", value.policySkips)
                metric("最大耗时", value.maxDuration)
            }
            Text("数据显示最近一次有效快照；状态待确认时不能代表当前模式。耗时单位未校准；接口返回 0 不等于车辆接受。")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var logSection: some View {
        VStack(alignment:.leading, spacing:12) {
            HStack {
                Text("连接诊断").font(.title3.bold())
                Spacer()
                Button("生成导出文件") { model.exportLogs() }
            }
            if let url = model.exportURL {
                ShareLink(item:url) { Label("分享日志 JSON",systemImage:"square.and.arrow.up") }
            }
            ForEach(Array(model.logs.suffix(5).enumerated()), id: \.offset) { _,entry in
                Text("\(entry.event)：\(String(entry.detail.prefix(120)))")
                    .font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Text("配套 BIN：" + RestoreSnapshot.firmwareSHA)
                .font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            Text("日志含原始通知与完整快照（含最近失败帧），不记录密码。A 是条件回送对照，不等于原版 LITE。")
                .font(.footnote).foregroundStyle(.secondary)
        }.padding(18).background(.background,in:RoundedRectangle(cornerRadius:8))
    }

    private func metric(_ label: String, _ value: UInt32) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value.formatted()).font(.title3.bold().monospacedDigit())
        }
        .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
        .padding(12)
        .background(.background, in: RoundedRectangle(cornerRadius: 8))
    }

    private var noticeSymbol: String {
        switch model.phase {
        case .ready: return "checkmark.circle.fill"
        case .failed, .incompatible: return "exclamationmark.triangle.fill"
        case .scanning: return "dot.radiowaves.left.and.right"
        default: return "circle"
        }
    }
    private var statusColor: Color {
        switch model.phase {
        case .failed, .incompatible: return .orange
        case .scanning, .connecting, .discovering, .authenticating, .passwordRequired, .reading: return accent
        default: return .gray
        }
    }
}
