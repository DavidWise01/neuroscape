/* Neuroscape v2.9.15 — isolated, DOM-observed oscilloscope.
 * No access to game state, actions, RAM, internal ledgers or timers.
 * Both source roots retain their own trajectories; x-axis is elapsed time.
 */
(()=>{'use strict';
const root=document.getElementById('pulseOscilloscope');
const canvas=document.getElementById('pulseScopeCanvas');
if(!root||!canvas)return;
const ctx=canvas.getContext('2d');if(!ctx)return;
const channels=[
 {name:'ATTACK',selector:'#plasmaMemoryAttack li',color:'#ffad63'},
 {name:'RECOVERY',selector:'#plasmaMemoryRecovery li',color:'#bd81ff'}
];
const tracks=new Map(),WINDOW=5000,MAX_TRACKS=16;
let match=0;
const now=()=>performance.now();
function gather(){
 const samples=[];
 for(const channel of channels){
  document.querySelectorAll(channel.selector).forEach(node=>{
   const source=node.dataset.source;
   const age=Number(node.dataset.ageMs);
   if(!source||!Number.isFinite(age)||age<0)return;
   const key=channel.name+'|'+source;
   samples.push({key,source,channel:channel.name,age,phase:node.dataset.phase||'quiet'});
  });
 }
 return samples;
}
function sync(){
 const current=gather();
 // A new match clears all owned tracks; no previous-match source can leak.
 const marker=document.getElementById('recoveryTelemetryStatus')?.textContent||'';
 const found=marker.match(/MATCH\s+(\d+)/);
 if(found&&Number(found[1])!==match){match=Number(found[1]);tracks.clear()}
 if(!current.length&&document.querySelectorAll('#plasmaMemoryAttack li,#plasmaMemoryRecovery li').length===0){
   tracks.clear();
 }
 const t=now();
 for(const item of current){
  if(!tracks.has(item.key))tracks.set(item.key,{...item,seen:t,points:[]});
  const track=tracks.get(item.key);
  track.phase=item.phase;track.seen=t;
  const y=item.phase==='launch'?1:item.phase==='travel'?.83:item.phase==='decay'?.46:0;
  const last=track.points[track.points.length-1];
  if(!last||Math.abs(last.age-item.age)>=50||last.value!==y){
   track.points.push({age:Math.min(WINDOW,item.age),value:y});
   if(track.points.length>64)track.points.shift();
  }
 }
 for(const [key,track] of tracks)if(t-track.seen>WINDOW+750)tracks.delete(key);
 while(tracks.size>MAX_TRACKS)tracks.delete(tracks.keys().next().value);
}
function render(){
 const width=canvas.width,height=canvas.height;
 ctx.clearRect(0,0,width,height);
 ctx.fillStyle='#0e0c21';ctx.fillRect(0,0,width,height);
 ctx.lineWidth=1;
 for(let i=0;i<=10;i++){
  const x=36+(width-52)*i/10;
  ctx.strokeStyle='rgba(136,205,255,.13)';
  ctx.beginPath();ctx.moveTo(x,9);ctx.lineTo(x,height-25);ctx.stroke();
 }
 for(let i=0;i<=4;i++){
  const y=16+(height-47)*i/4;
  ctx.beginPath();ctx.moveTo(36,y);ctx.lineTo(width-16,y);ctx.stroke();
 }
 ctx.font='11px ui-monospace,monospace';ctx.fillStyle='#b9b5d6';
 for(let i=0;i<=5;i++){const x=36+(width-52)*i/5;ctx.fillText((i)+'s',x-8,height-8)}
 const items=[...tracks.values()];
 const lower=height-30,space=(height-50)/Math.max(1,items.length);
 items.forEach((track,index)=>{
  const base=lower-index*space,amp=Math.min(13,space*.55);
  const color=track.channel==='ATTACK'?'#ffad63':'#bd81ff';
  ctx.strokeStyle=color;ctx.lineWidth=1.8;ctx.shadowBlur=7;ctx.shadowColor=color;
  ctx.beginPath();
  track.points.forEach((point,i)=>{
   const x=36+(width-52)*point.age/WINDOW;
   const y=base-point.value*amp;
   if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
  });ctx.stroke();ctx.shadowBlur=0;
 });
 const summary=document.getElementById('pulseScopeSummary');
 if(summary){
  const active=items.filter(x=>x.phase!=='quiet').length;
  summary.textContent=items.length+' INDEPENDENT SOURCES · '+active+' ACTIVE · '+(items.length-active)+' QUIET · '+WINDOW/1000+'s SHARED GRID';
 }
 const legend=document.getElementById('pulseScopeLegend');
 if(legend){
  legend.replaceChildren(...items.map(track=>{
   const b=document.createElement('span');b.className=track.channel==='ATTACK'?'scopeAttack':'scopeRecovery';
   b.textContent=track.source+' · '+track.phase.toUpperCase();return b;
  }));
 }
}
function tick(){if(document.hidden)return;sync();render()}
tick();setInterval(tick,180);
window.neuroscapePulseScope=Object.freeze({snapshot:()=>Object.freeze({
 match,tracks:[...tracks.values()].map(t=>Object.freeze({source:t.source,channel:t.channel,
 phase:t.phase,points:t.points.length}))
})});
})();
