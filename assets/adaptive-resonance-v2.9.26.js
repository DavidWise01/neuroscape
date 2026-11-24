/* Neuroscape v2.9.26 — fixed vs adaptive resonance recovery.
 * Independent read-only experiment using snapshot copies. Drift offsets are
 * observational projections, not control signals or source-memory writes.
 * Simulation is deterministic and advances in fixed 100ms steps.
 */
(()=>{'use strict';
const host=document.getElementById('adaptiveResonanceLab');
const canvas=document.getElementById('adaptiveResonanceCanvas');
if(!host||!canvas)return;
const ctx=canvas.getContext('2d');if(!ctx)return;
const output=document.getElementById('adaptiveResonanceStatus');
const run=document.getElementById('adaptiveResonanceRun');
const reset=document.getElementById('adaptiveResonanceReset');
const DT=.1,STEPS=70,INITIAL=Math.PI,EPS=.1;
let running=false,records=[],step=0,source=[],match='none';
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
function coherence(samples,offset){
 let x=0,y=0,w=0;
 for(const item of samples){
  if(!item||!Number.isFinite(item.amplitude)||item.amplitude<=0||!Number.isFinite(item.phase))continue;
  const phase=item.phase+offset*(item.edge-15.5)/15.5;
  x+=item.amplitude*Math.cos(phase);y+=item.amplitude*Math.sin(phase);w+=item.amplitude;
 }
 return w>0?clamp(Math.hypot(x,y)/w,0,1):null;
}
function simulate(samples){
 const result=[];let fixed=INITIAL,adaptive=INITIAL;
 let fixedReached=null,adaptiveReached=null;
 for(let k=0;k<=STEPS;k++){
  const at=+(k*DT).toFixed(3);
  if(fixed<=EPS&&fixedReached===null)fixedReached=at;
  if(adaptive<=EPS&&adaptiveReached===null)adaptiveReached=at;
  result.push(Object.freeze({time:at,fixed,adaptive,
    baseline:coherence(samples,0),
    fixedCoherence:coherence(samples,fixed),
    adaptiveCoherence:coherence(samples,adaptive)}));
  // Both approaches operate only on a copied scalar drift offset.
  fixed=Math.max(0,fixed-.62*DT);
  adaptive=Math.max(0,adaptive-Math.min(2.3,1.55*adaptive)*DT);
 }
 return Object.freeze({rows:Object.freeze(result),fixedReached,adaptiveReached,
  inputCount:samples.filter(v=>v.amplitude>0).length,mutation:false});
}
function draw(){
 const w=canvas.width,h=canvas.height;
 ctx.fillStyle='#101027';ctx.fillRect(0,0,w,h);
 ctx.strokeStyle='#8080bd33';ctx.lineWidth=1;
 for(let i=0;i<=7;i++){
  const x=42+(w-62)*i/7;
  ctx.beginPath();ctx.moveTo(x,14);ctx.lineTo(x,h-28);ctx.stroke();
 }
 for(let i=0;i<=4;i++){
  const y=14+(h-42)*i/4;
  ctx.beginPath();ctx.moveTo(42,y);ctx.lineTo(w-20,y);ctx.stroke();
 }
 for(const [field,color] of [['fixed','#ffa965'],['adaptive','#74ffdb']]){
  ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.5;
  ctx.shadowColor=color;ctx.shadowBlur=7;
  let started=false;
  for(const row of records.slice(0,step+1)){
   const x=42+row.time/7*(w-62),y=h-28-row[field]/Math.PI*(h-47);
   if(!started){ctx.moveTo(x,y);started=true}else ctx.lineTo(x,y);
  }
  ctx.stroke();ctx.shadowBlur=0;
 }
 ctx.fillStyle='#aeb9da';ctx.font='11px ui-monospace,monospace';
 for(let i=0;i<=7;i++)ctx.fillText(i+'s',42+(w-62)*i/7-7,h-8);
}
function render(){
 const cur=records[Math.min(step,records.length-1)];
 draw();
 if(!cur){output.textContent='QUIET · NO EXPERIMENT';return}
 const fmt=n=>n===null?'UNDEFINED':(100*n).toFixed(1)+'%';
 output.textContent=(running?'RUNNING':'HOLD')+' · FIXED '+cur.fixed.toFixed(3)+
  ' RAD · ADAPT '+cur.adaptive.toFixed(3)+' RAD · COHERENCE '+
  fmt(cur.fixedCoherence)+' / '+fmt(cur.adaptiveCoherence);
 host.dataset.readOnly='true';host.dataset.progress=String(step);
}
function start(){
 const data=window.neuroscapeTesseract?.snapshot();
 source=(data?.edgeSamples||[]).map(s=>Object.freeze({...s}));
 match=data?.persistence?.match||'none';
 records=simulate(source).rows;step=0;running=true;render();
}
run?.addEventListener('click',start);
reset?.addEventListener('click',()=>{running=false;step=0;records=[];source=[];render()});
const timer=setInterval(()=>{
 if(!running)return;
 const nextMatch=window.neuroscapeTesseract?.snapshot()?.persistence?.match||'none';
 if(nextMatch!==match){running=false;records=[];source=[];render();return}
 step=Math.min(step+1,STEPS);if(step===STEPS)running=false;render();
},100);
render();
window.neuroscapeAdaptiveResonance=Object.freeze({
 simulate:samples=>simulate(samples.map(s=>({...s}))),
 snapshot:()=>Object.freeze({running,step,count:source.length,
  baseline:records[0]?.baseline??null,
  fixedOffset:records[step]?.fixed??null,
  adaptiveOffset:records[step]?.adaptive??null,
  readOnly:true,sourceMutated:false,gameplayMutation:false})
});
})();
