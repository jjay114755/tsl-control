import {BLETransport,ModeController,names,firmwareSHA} from './core.mjs';
const $=id=>document.getElementById(id),records=[];let truncated=0, connecting=false;
function log(event,detail={}){
  records.push({utc:new Date().toISOString(),event,...detail});
  if(records.length>5000){records.shift();truncated++;}
  $('log').textContent=records.slice(-12).map(v=>`${v.utc.slice(11,19)} ${v.event} ${v.message||v.head||''}`).join('\n');
}
const transport=new BLETransport(log),controller=new ModeController(transport,render,log);
function render(state){
  const busy=state.pending!==null,ready=state.phase==='ready';
  $('notice').textContent=state.message;
  $('notice').classList.toggle('error',state.phase==='failed');
  $('phase').textContent=({disconnected:'未连接',authenticating:'正在认证',password:'等待密码',ready:busy?'正在确认':'模式已同步',failed:'状态待确认'})[state.phase]||state.phase;
  $('current').textContent=state.mode===null?'待确认':names[state.mode];
  for(const [id,mode] of [['mode-a',1],['mode-b',2]]){
    $(id).checked=state.mode===mode;$(id).disabled=!ready||busy;
  }
  for(const id of ['off','refresh'])$(id).disabled=!ready||busy;
  $('auth').hidden=state.phase!=='password';
  $('connect').disabled=connecting||!['disconnected','failed'].includes(state.phase);
  $('disconnect').disabled=!transport.device?.gatt.connected;
  const s=state.snapshot;
  $('metrics').replaceChildren();
  for(const [label,key] of [['候选帧','candidates'],['发送尝试','attempts'],['接口返回 0','zero'],['接口非 0','nonzero'],['队列丢帧','queueDrops'],['模式切换序号','generation']]){
    const box=document.createElement('div');box.className='metric';
    const span=document.createElement('span');span.textContent=label;
    const b=document.createElement('b');b.textContent=s?String(s[key]):'—';box.append(span,b);$('metrics').append(box);
  }
}
$('hash').textContent=firmwareSHA;
$('connect').onclick=async()=>{
  connecting=true;render(controller.state);
  try{$('device').textContent=await transport.connect();await controller.authenticate();}
  catch(error){log('连接失败',{message:error.message});transport.close(error);}
  finally{connecting=false;render(controller.state);}
};
$('disconnect').onclick=()=>transport.close();
$('auth').onsubmit=event=>{event.preventDefault();const value=$('password').value;$('password').value='';controller.authenticate(value);};
$('mode-a').onchange=event=>{const mode=event.target.checked?1:0;render(controller.state);controller.select(mode);};
$('mode-b').onchange=event=>{const mode=event.target.checked?2:0;render(controller.state);controller.select(mode);};
$('off').onclick=()=>controller.select(0);$('refresh').onclick=()=>controller.refresh();
$('export').onclick=()=>{
  const data={app:'TSL8 Restore 1.1.2',expectedFirmwareSHA256:firmwareSHA,exportedUTC:new Date().toISOString(),truncated,records};
  const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='TSL8-Restore-'+Date.now()+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
setInterval(()=>{if($('poll').checked&&!document.hidden)controller.refresh();},2000);
render(controller.state);
