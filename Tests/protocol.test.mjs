import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {encode,Parser,decode,ModeController,firmwareSHA,BLETransport} from '../web/core.mjs';
const evidence=JSON.parse(fs.readFileSync(new URL('./fixtures/firmware_wire.json',import.meta.url),'utf8'));
const bytes=hex=>Uint8Array.from(Buffer.from(hex,'hex'));
const fixture=name=>bytes(evidence.fixtures[name].payload_hex);

test('exact requests match the firmware schema',()=>{
 assert.equal(firmwareSHA,evidence.current_sha256);
 assert.equal(Buffer.from(encode(0xd1,[82,83,84,68])).toString('hex'),'557fd100045253544412');
 for(const [mode,last] of [[0,255],[1,254],[2,253]])
  assert.equal(Buffer.from(encode(0xd2,[mode,last])).toString('hex'),`557fd200020${mode}${last.toString(16)}d3`);
});
test('actual BIN native D1/D2 serialized frames parse at every split point',()=>{
 for(const name of ['current_uninitialized','set_0','set_1','set_2','query_0','query_1','query_2']){
  const wire=bytes(evidence.fixtures[name].wire_hex);
  for(let split=0;split<=wire.length;split++){
   const p=new Parser(),frames=[...p.feed(wire.slice(0,split)),...p.feed(wire.slice(split))];
   assert.equal(frames.length,1);assert.deepEqual(frames[0].payload,fixture(name));decode(frames[0].payload);
  }
 }
});
test('reproduces old uninitialized BIN failure, strict rejection instead of magic searching',()=>{
 assert.throws(()=>decode(fixture('old_uninitialized')),/固件快照不匹配/);
 const raw=fixture('set_2'),nested=encode(0xd1,raw);
 for(const bad of [nested,Uint8Array.from([1,2,...raw]),raw.slice(0,-1)])assert.throws(()=>decode(bad));
 for(const [off,value] of [[4,1],[5,3],[6,1],[7,0]]){const b=raw.slice();b[off]=value;assert.throws(()=>decode(b));}
 assert.equal(decode(fixture('current_uninitialized')).mode,0);
 assert.throws(()=>decode(fixture('torn')),e=>e.code==='torn');
});
test('checksum/noise recovery, notifications in 20 byte chunks',()=>{
 const wire=bytes(evidence.fixtures.set_1.wire_hex),bad=wire.slice();bad[bad.length-1]^=1;
 const parser=new Parser();assert.equal(parser.feed(Uint8Array.from([1,2,...bad,...wire])).length,1);
 assert.equal(parser.badChecksums,1);
 const p=new Parser();let frames=[];for(let i=0;i<wire.length;i+=20)frames.push(...p.feed(wire.slice(i,i+20)));
 assert.equal(decode(frames[0].payload).mode,1);
});
class FirmwareLink {
 constructor(){this.calls=[];this.mode=0;this.generation=0;this.auth=true;this.delay=null;this.ackTorn=false;this.queryTorn=0;this.failWrite=false;}
 async request(type,payload=[]){
  this.calls.push({type,payload:Array.from(payload)});
  if(type===0xa0){if(!this.auth)return {type:0xa8,payload:bytes('fe')};const b=new Uint8Array(76);b[3]=1;return {type,payload:b};}
  if(type===0xa8){assert.equal(Buffer.from(payload).toString(),'1234');this.auth=true;return {type,payload:bytes('01')};}
  if(type===0xd2){
   assert.ok(payload[0]<=2);assert.equal(payload[0]^255,payload[1]);
   if(this.mode!==payload[0])this.generation++;this.mode=payload[0];
   if(this.failWrite)throw new Error('写入后通知丢失');
   if(this.delay)await this.delay;
  }
  if(type===0xd1&&this.queryTorn-->0)return {type,payload:fixture('torn')};
  const b=fixture('query_'+this.mode).slice();new DataView(b.buffer).setUint32(76,this.generation,true);
  if(type===0xd2&&this.ackTorn){b[8]=3;}
  return {type,payload:b};
 }
}
async function ready(){const link=new FirmwareLink(),c=new ModeController(link);await c.authenticate();assert.equal(c.state.phase,'ready');return {link,c};}
test('read before enable; OFF/A/B exclusive; no duplicate writes for same state',async()=>{
 const {link,c}=await ready();assert.equal(c.state.mode,0);
 for(const mode of [1,2,0,2,1]){assert.equal(await c.select(mode),true);assert.equal(c.state.mode,mode);}
 const n=link.calls.length;await c.select(1);assert.equal(link.calls.length,n);
 assert.equal(link.calls.filter(x=>x.type===0xd2).length,5);
 assert.equal(link.calls.filter(x=>x.type===0xd1).length,6);
});
test('torn write acknowledgement reads D1, never resends D2',async()=>{
 const {link,c}=await ready();link.ackTorn=true;link.queryTorn=1;
 assert.equal(await c.select(2),true);assert.equal(link.calls.filter(x=>x.type===0xd2).length,1);
 assert.equal(c.state.mode,2);
});
test('busy switch cannot submit B while A pending; confirmed display stays unchanged',async()=>{
 const {link,c}=await ready();let release;link.delay=new Promise(r=>release=r);
 const first=c.select(1);assert.equal(c.state.mode,0);assert.equal(c.state.pending,1);
 assert.equal(await c.select(2),false);release();await first;assert.equal(c.state.mode,1);
 assert.equal(link.calls.filter(x=>x.type===0xd2).length,1);
});
test('lost write acknowledgement marks state unknown, does not pretend old mode restored',async()=>{
 const {link,c}=await ready();link.failWrite=true;
 assert.equal(await c.select(2),false);assert.equal(link.mode,2);assert.equal(c.state.mode,null);
 assert.equal(c.state.phase,'failed');assert.equal(link.calls.filter(x=>x.type===0xd2).length,1);
});
test('disconnect ignores late reply and cannot reactivate controls',async()=>{
 const {link,c}=await ready();let release;link.delay=new Promise(r=>release=r);
 const first=c.select(1);link.onDisconnect(new Error('断连'));release();await first;
 assert.equal(c.state.mode,null);assert.equal(c.state.phase,'disconnected');
 assert.equal(link.calls.filter(x=>x.type===0xd1).length,1,'late D2 must not issue a new D1');
});
test('password prompt and user provided key; no writes before authentication',async()=>{
 const link=new FirmwareLink();link.auth=false;const c=new ModeController(link);
 await c.authenticate();assert.equal(c.state.phase,'password');assert.equal(c.state.mode,null);
 assert.equal(await c.select(2),false);await c.authenticate('1234');assert.equal(c.state.phase,'ready');
 assert.ok(link.calls.some(x=>x.type===0xa8));assert.ok(!link.calls.some(x=>x.type===0xd2));
});
test('live transport timeout closes connection to prevent stale same-type reply reuse',async()=>{
 const link=new BLETransport();let disconnected=false;
 link.device={gatt:{connected:true,disconnect(){this.connected=false;}},removeEventListener(){}};
 link.write={properties:{write:true},writeValueWithResponse:async()=>{}};
 link.onDisconnect=()=>{disconnected=true;};
 await assert.rejects(link.request(0xd2,[1,254],[0xd2],5),/超时/);
 assert.equal(disconnected,true);assert.equal(link.pending,null);assert.equal(link.device.gatt.connected,false);
});
