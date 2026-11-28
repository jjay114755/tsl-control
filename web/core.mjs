export const firmwareSHA = '7865c3402c633d024a4d8ef32e00b9b9c36836ce80ad4a7a333931c447e071c7';
export const names = ['关闭', 'A 条件回送', 'B 字段覆盖'];
export class ProtocolError extends Error { constructor(code, message) { super(message); this.code = code; } }
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ').toUpperCase();
export function encode(type, payload = []) {
  if (payload.length > 1039) throw new ProtocolError('length', '指令过长');
  const body = [type, payload.length >> 8, payload.length & 255, ...payload];
  return Uint8Array.from([0x55, 0x7f, ...body, body.reduce((a,b) => a+b, 0) & 255]);
}
export class Parser {
  constructor() { this.bytes = []; this.badChecksums = 0; }
  feed(chunk) {
    this.bytes.push(...chunk); const packets = [];
    while (this.bytes.length >= 6) {
      if (this.bytes[0] !== 85 || this.bytes[1] !== 127) { this.bytes.shift(); continue; }
      const n = (this.bytes[3] << 8) | this.bytes[4];
      if (n > 1039) { this.bytes.shift(); continue; }
      if (this.bytes.length < n+6) break;
      const raw = this.bytes.slice(0,n+6);
      if ((raw.slice(2,-1).reduce((a,b)=>a+b,0)&255) !== raw.at(-1)) {
        this.badChecksums++; this.bytes.shift(); continue;
      }
      this.bytes.splice(0,n+6); packets.push({type:raw[2], payload:Uint8Array.from(raw.slice(5,-1))});
    }
    return packets;
  }
}
export function decode(payload) {
  const b = Uint8Array.from(payload), detail = `长度 ${b.length}，头部 ${hex(b.slice(0,16)) || '空'}`;
  if (b.length !== 256 || hex(b.slice(0,4)) !== '52 54 44 32' || b[4] !== 2 || b[5] > 2 || b[6] !== 0 || b[7] !== 1)
    throw new ProtocolError('firmware', `固件快照不匹配（${detail}）。请核对配套 BIN，保留诊断日志。`);
  const view = new DataView(b.buffer), u32 = off => view.getUint32(off,true);
  if ((u32(8)&1) || u32(8)!==u32(112) || (u32(108)&1) || u32(104)!==u32(108))
    throw new ProtocolError('torn', '快照正在更新，稍后重读');
  const result = {mode:b[5], sequence:u32(8), generation:u32(76), candidates:u32(20), attempts:u32(36),
    zero:u32(40), nonzero:u32(44), failures:u32(48), queueDrops:u32(72), maxDuration:u32(52),
    policySkips:u32(32), lastReturn:u32(60), recentFailures:[], raw:hex(b)};
  for (let off=128;off<256;off+=32) {
    if (b[off+16]!==0x31 || b[off+17]!==3) continue;
    const tag=u32(off+28);
    result.recentFailures.push({ordinal:u32(off), timeNative:u32(off+4), code:u32(off+8),
      durationNative:u32(off+12), mode:(tag>>>8)&255, generationLow16:tag>>>16,
      input:hex(b.slice(off+16,off+28)), outputByte0:tag&255});
  }
  return result;
}

export class BLETransport {
  constructor(log = () => {}) { this.log=log; this.pending=null; this.onDisconnect=()=>{}; this.epoch=0; }
  async connect() {
    if (!globalThis.navigator?.bluetooth) throw new Error('请用 Windows Chrome/Edge 打开本机控制页；iPhone 请使用原生 APP。');
    this.close(); const epoch=this.epoch;
    this.device = await navigator.bluetooth.requestDevice({acceptAllDevices:true, optionalServices:[0xfff0]});
    if (epoch!==this.epoch) throw new Error('连接已取消');
    this.device.addEventListener('gattserverdisconnected', this.lost = () => {
      if (epoch!==this.epoch) return; this.close(new Error('蓝牙已断开，当前模式待确认'));
    });
    const server = await this.device.gatt.connect();
    const service=await server.getPrimaryService(0xfff0), chars=await service.getCharacteristics();
    this.write=chars.find(c=>c.uuid.toLowerCase().startsWith('0000fff1-') && (c.properties.write || c.properties.writeWithoutResponse));
    if (!this.write) throw new Error('缺少 FFF1 写入特征');
    this.notify=chars.find(c=>c===this.write && (c.properties.notify || c.properties.indicate)) ||
      chars.find(c=>c.uuid.toLowerCase().startsWith('0000ffe0-') && (c.properties.notify || c.properties.indicate));
    if (!this.notify) throw new Error('缺少 FFF1/FFE0 通知特征');
    this.parser=new Parser();
    this.notify.addEventListener('characteristicvaluechanged', this.receive = event => {
      if (epoch!==this.epoch) return;
      const d=event.target.value, raw=new Uint8Array(d.buffer,d.byteOffset,d.byteLength);
      this.receiveChunk(raw);
    });
    await this.notify.startNotifications();
    if (epoch!==this.epoch) throw new Error('连接已取消');
    this.log('通知已就绪',{name:this.device.name || 'TSL8',write:this.write.uuid,notify:this.notify.uuid});
    return this.device.name || 'TSL8';
  }
  receiveChunk(raw) {
    if(this.authTraffic!==false) this.log('认证通知片段',{length:raw.length});
    else this.log('RX片段',{hex:hex(raw)});
    for (const p of this.parser.feed(raw)) {
      this.log('RX帧',{type:p.type,length:p.payload.length,head:hex(p.payload.slice(0,p.type===0xa0?4:16))});
      if(p.type===0xa8 && [0,254,255].includes(p.payload[0]??255))this.passwordChallenge=true;
      const pending=this.pending;
      if (!pending?.types.includes(p.type)) continue;
      this.pending=null; clearTimeout(pending.timer); pending.resolve(p);
    }
  }
  request(type,payload=[],types=[type],timeout=6000) {
    if([0xd1,0xd2].includes(type) && this.passwordChallenge) return Promise.reject(new ProtocolError('password','模块要求密码认证'));
    if([0xd1,0xd2].includes(type))this.authTraffic=false;
    if([0xa0,0xa8].includes(type))this.authTraffic=true;
    if (this.pending) return Promise.reject(new Error('上一条指令尚未完成'));
    if (!this.device?.gatt.connected || !this.write) return Promise.reject(new Error('蓝牙未连接'));
    return new Promise((resolve,reject)=>{
      const pending={resolve,reject,types,type}; this.pending=pending;
      pending.timer=setTimeout(()=>{
        if (this.pending!==pending) return;
        this.log('应答超时',{type}); this.close(new ProtocolError('timeout','设备应答超时，连接已关闭；重连后重新查询实际模式'));
      },timeout);
      this.log('TX',{type,length:payload.length,hex:type===0xa8?'密码已隐藏':hex(encode(type,payload))});
      const data=encode(type,payload);
      const sending=this.write.properties.write ? this.write.writeValueWithResponse(data) : this.write.writeValueWithoutResponse(data);
      Promise.resolve(sending).catch(error=>{if(this.pending===pending)this.close(error);});
    });
  }
  close(reason=new Error('连接已关闭')) {
    this.epoch++;
    const pending=this.pending; this.pending=null;
    if (pending) { clearTimeout(pending.timer); pending.reject(reason); }
    if (this.notify && this.receive) this.notify.removeEventListener('characteristicvaluechanged',this.receive);
    if (this.device && this.lost) this.device.removeEventListener('gattserverdisconnected',this.lost);
    if (this.device?.gatt.connected) this.device.gatt.disconnect();
    this.write=null; this.notify=null; this.passwordChallenge=false;this.authTraffic=true;this.onDisconnect(reason);
  }
}

export class ModeController {
  constructor(transport, publish=()=>{}, log=()=>{}) {
    this.transport=transport; this.publish=publish; this.log=log; this.session=0;
    this.state={phase:'disconnected', mode:null, snapshot:null, pending:null, message:'连接后读取设备实际模式'};
    transport.onDisconnect=reason=>{this.session++;Object.assign(this.state,{phase:'disconnected',mode:null,pending:null,message:reason.message});this.emit();};
  }
  emit() { this.publish({...this.state}); }
  ensure(session) { if(session!==this.session) throw new ProtocolError('cancelled','操作已取消'); }
  async authenticate(password='') {
    const session=++this.session;
    this.state.phase='authenticating';this.state.mode=null;this.emit();
    try {
      if(password) {
        if(new TextEncoder().encode(password).length!==4)throw new ProtocolError('password','请输入四字节蓝牙密码');
        this.transport.passwordChallenge=false;
        const ack=await this.transport.request(0xa8,new TextEncoder().encode(password),[0xa0,0xa8]);
        this.ensure(session);
        if(ack.type===0xa0)this.validateA0(ack);
        else if(ack.payload[0]!==1)throw new ProtocolError('password','蓝牙密码未通过');
      } else {
        const first=await this.transport.request(0xa0,[],[0xa0,0xa8]);this.ensure(session);
        if(this.transport.passwordChallenge || (first.type===0xa8 && first.payload[0]!==1))
          throw new ProtocolError('password','请输入模块四字节蓝牙密码，再验证');
        if(first.type===0xa0)this.validateA0(first);
      }
      for(let proofs=0;proofs<2;proofs++) {
        await new Promise(resolve=>setTimeout(resolve,120)); this.ensure(session);
        if(this.transport.passwordChallenge)throw new ProtocolError('password','模块仍要求密码认证');
        const proof=await this.transport.request(0xa0,[],[0xa0,0xa8]);this.ensure(session);
        if(this.transport.passwordChallenge || proof.type!==0xa0)throw new ProtocolError('password','模块仍要求密码认证');
        this.validateA0(proof);
      }
      const snapshot=await this.readSnapshot(session);
      if (session!==this.session) return;
      this.apply(snapshot);this.state.phase='ready';this.state.message='设备实际模式已确认';this.emit();
    } catch(error) { if(session===this.session)this.fail(error); }
  }
  validateA0(p) { if (p.type!==0xa0 || p.payload.length<18 || !(p.payload[3]&1)) throw new Error('A0 运行证明无效，尚未进入 Restore 查询'); }
  async readSnapshot(session=this.session) {
    for(let attempt=0;attempt<3;attempt++) {
      this.ensure(session);
      const p=await this.transport.request(0xd1,[82,83,84,68],[0xd1,0xa8]);
      this.ensure(session);
      if(p.type===0xa8)throw new ProtocolError('password','D1 被密码认证门拒绝，请验证密码');
      try{return decode(p.payload);}catch(e){if(e.code!=='torn'||attempt===2)throw e;}
    }
  }
  apply(snapshot) { this.state.mode=snapshot.mode;this.state.snapshot=snapshot;this.log('有效快照',snapshot); }
  fail(error) {
    this.log('操作失败',{code:error.code || 'transport',message:error.message});
    this.state.mode=null;this.state.pending=null;this.state.phase=error.code==='password'?'password':'failed';this.state.message=error.message;this.emit();
  }
  async select(mode) {
    if (![0,1,2].includes(mode) || this.state.phase!=='ready' || this.state.pending!==null) return false;
    if (this.state.mode===mode) return true;
    const session=this.session;this.state.pending=mode;this.state.message='等待设备确认 '+names[mode];this.emit();
    try {
      const response=await this.transport.request(0xd2,[mode,mode^255],[0xd2,0xa8]);
      this.ensure(session);
      if(response.type===0xa8)throw new ProtocolError('password','D2 被密码认证门拒绝；模式待确认，不自动重发');
      try{const ack=decode(response.payload);if(ack.mode!==mode)throw new ProtocolError('mismatch','设备回报的模式与请求不一致');}
      catch(e){if(e.code!=='torn')throw e;}
      // Never resend D2: a torn write ACK may follow an applied switch. Read D1.
      const actual=await this.readSnapshot(session);
      if (session!==this.session) return false;
      this.apply(actual);this.state.pending=null;
      this.state.message=actual.mode===mode?'设备已确认 '+names[mode]:'设备当前为 '+names[actual.mode]+'，未确认目标';
      this.emit();return actual.mode===mode;
    } catch(error) { if(session===this.session)this.fail(error);return false; }
  }
  async refresh() {
    if(this.state.phase!=='ready'||this.state.pending!==null)return;
    const session=this.session;this.state.pending='query';this.emit();
    try{const value=await this.readSnapshot(session);if(session!==this.session)return;this.apply(value);this.state.pending=null;this.state.message='已重新读取实际模式';this.emit();}
    catch(error){if(session===this.session)this.fail(error);}
  }
}
