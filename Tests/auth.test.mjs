import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {BLETransport,ModeController,Parser,encode} from '../web/core.mjs';
const evidence=JSON.parse(fs.readFileSync(new URL('./fixtures/auth_wire.json',import.meta.url)));
const wire=hex=>Uint8Array.from(Buffer.from(hex,'hex'));
const prelude=wire(evidence.frames[0]),runtime=wire(evidence.frames[1]);
const bin=JSON.parse(fs.readFileSync(new URL('./fixtures/firmware_wire.json',import.meta.url)));
const snapshot=wire(bin.fixtures.current_uninitialized.wire_hex);
function rig(script) {
 const records=[],link=new BLETransport((event,detail)=>records.push({event,...detail}));link.parser=new Parser();const writes=[];
 link.device={gatt:{connected:true,disconnect(){this.connected=false;}},removeEventListener(){}};
 link.write={properties:{write:true},writeValueWithResponse:async raw=>{
  writes.push(raw[2]);for(const frame of script(raw[2],raw))link.receiveChunk(frame);
 }};
 const request=link.request.bind(link);
 link.request=(type,payload=[],types=[type],timeout=6000)=>request(type,payload,types,Math.min(timeout,40));
 return {link,writes,records,c:new ModeController(link)};
}
test('reported A8 FF plus runtime A0 still requires password and sends no D1',async()=>{
 const {link,writes,c}=rig(()=>[prelude,runtime]);await c.authenticate();
 assert.equal(c.state.phase,'password');assert.equal(c.state.mode,null);assert.deepEqual(writes,[0xa0]);
 assert.equal(link.device.gatt.connected,true);link.close();
});
test('same-chunk and all splits cannot let runtime overwrite password challenge',async()=>{
 const sequence=Uint8Array.from([...prelude,...runtime]);
 for(let split=0;split<=sequence.length;split++){
  const {link}=rig(()=>[sequence.slice(0,split),sequence.slice(split)]);
  const p=await link.request(0xa0,[],[0xa0,0xa8]);assert.equal(p.type,0xa8);
  assert.equal(link.passwordChallenge,true);link.close();
 }
});
test('runtime arriving before challenge cannot enable control',async()=>{
 const {link,writes,c}=rig(()=>[runtime,prelude]);await c.authenticate();
 assert.equal(c.state.phase,'password');assert.ok(!writes.includes(0xd1));link.close();
});
test('explicit correct password with A0-only success then queries A0 twice before D1',async()=>{
 let authenticated=false;
 const {link,c,writes}=rig((type,raw)=>{
  if(type===0xa8){authenticated=Buffer.from(raw.slice(5,-1)).toString()==='ABCD';return authenticated?[runtime]:[encode(0xa8,[0])];}
  if(!authenticated)return [prelude,runtime];
  return type===0xa0?[runtime]:[snapshot];
 });
 await c.authenticate();assert.equal(c.state.phase,'password');
 await c.authenticate('ABCD');assert.equal(c.state.phase,'ready');assert.equal(c.state.mode,0);
 assert.deepEqual(writes,[0xa0,0xa8,0xa0,0xa0,0xd1]);link.close();
});
test('A8 success status is followed by active runtime queries',async()=>{
 const {link,c,writes}=rig(type=>type===0xa8?[encode(0xa8,[1])]:type===0xa0?[runtime]:[snapshot]);
 await c.authenticate('ABCD');assert.equal(c.state.phase,'ready');assert.deepEqual(writes,[0xa8,0xa0,0xa0,0xd1]);link.close();
});
test('stale A0 after password write followed by fresh challenge never reaches D1',async()=>{
 const {link,c,writes}=rig(type=>type===0xa8?[runtime]:[prelude,runtime]);
 await c.authenticate('ABCD');assert.equal(c.state.phase,'password');assert.equal(c.state.mode,null);
 assert.ok(!writes.includes(0xd1));link.close();
});
test('wrong password cannot enable D1, correct retry can recover',async()=>{
 let authorized=false;
 const {link,c,writes}=rig((type,raw)=>{
  if(type===0xa8){authorized=Buffer.from(raw.slice(5,-1)).toString()==='ABCD';return authorized?[runtime]:[encode(0xa8,[0])];}
  return authorized?(type===0xa0?[runtime]:[snapshot]):[prelude,runtime];
 });
 await c.authenticate('WXYZ');assert.equal(c.state.phase,'password');assert.ok(!writes.includes(0xd1));
 await c.authenticate('ABCD');assert.equal(c.state.phase,'ready');link.close();
});
test('D1 authentication rejection becomes password prompt without waiting for timeout',async()=>{
 const {link,c}=rig(type=>type===0xa0?[runtime]:[prelude,runtime]);await c.authenticate();
 assert.equal(c.state.phase,'password');assert.equal(c.state.mode,null);assert.equal(link.device.gatt.connected,true);link.close();
});
test('D2 auth rejection leaves unknown mode and never retries a write',async()=>{
 const {link,c,writes}=rig(type=>type===0xa0?[runtime]:type===0xd2?[prelude,runtime]:[snapshot]);
 await c.authenticate();assert.equal(c.state.phase,'ready');await c.select(2);
 assert.equal(c.state.phase,'password');assert.equal(c.state.mode,null);assert.equal(writes.filter(t=>t===0xd2).length,1);link.close();
});
test('runtime without challenge still needs three fresh A0 responses and RTD2',async()=>{
 const {link,c,writes}=rig(type=>type===0xa0?[runtime]:[snapshot]);await c.authenticate();
 assert.equal(c.state.phase,'ready');assert.deepEqual(writes,[0xa0,0xa0,0xa0,0xd1]);link.close();
});
test('auth raw data and password are omitted from transport diagnostic output',async()=>{
 const {link,c,records}=rig(type=>type===0xa0?[runtime]:type===0xa8?[runtime]:[snapshot]);
 await c.authenticate('ABCD');assert.equal(c.state.phase,'ready');
 const text=JSON.stringify(records);assert.ok(!text.includes('41 42 43 44'));assert.ok(records.some(r=>r.event==='认证通知片段'));link.close();
});
test('disconnect during authentication prevents subsequent runtime probes',async()=>{
 const {link,c,writes}=rig(()=>[]);const task=c.authenticate('ABCD');link.close(new Error('disconnect'));
 await task;assert.equal(c.state.phase,'disconnected');assert.equal(c.state.mode,null);assert.deepEqual(writes,[0xa8]);
});
