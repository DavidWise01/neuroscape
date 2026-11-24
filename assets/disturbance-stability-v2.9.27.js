/* Neuroscape v2.9.27 — repeated-disturbance recovery laboratory.
 * Uses copied edge phase/amplitude samples. Four explicit phase injections,
 * all deterministic; no hidden impulse, energy synthesis, or game mutation.
 */
(()=>{'use strict';
const root=document.getElementById('disturbanceStabilityLab');
const canvas=document.getElementById('disturbanceStabilityCanvas');
if(!root||!canvas)return;
const ctx=canvas.getContext('2d');if(!ctx)return;
const status=document.getElementById('disturbanceStabilityStatus');
const run=document.getElementById('disturbanceStabilityRun');
const reset=document.getElementById('disturbanceStabilityReset');
const DT=.1,STEPS=100,LIMIT=Math.PI,QUIET=.1;
const INJECTIONS=Object.freeze([0,20,40,60]);
let records=[],position=0,running=false,match=null,source=[],results=null;
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const eligible=s=>s&&Number.isInteger(s.edge)&&s.edge>=0&&s.edge<32&&
 Number.isFinite(s.phase)&&Number.isFinite(s.amplitude)&&s.amplitude>0;
function coherence(samples,offset){
 let x=0,y=0,w=0;
 for(const sample of samples){
  if(!eligible(sample))continue;
  const theta=sample.phase+offset*(sample.edge-15.5)/15.5;
  x+=sample.amplitude*Math.cos(theta);y+=sample.amplitude*Math.sin(theta);w+=sample.amplitude;
 }
 return w?clamp(Math.hypot(x,y)/w,0,1):null;
}
function simulate(input){
 const samples=input.map(s=>Object.freeze({...s}));
 const rows=[],events=[];
 let fixed=0,adaptive=0,applied=0,firstQuietFixed=null,firstQuietAdaptive=null;
 for(let step=0;step<=STEPS;step++){
  const injected=INJECTIONS.includes(step)?LIMIT:0;
  if(injected){
   fixed=clamp(fixed+injected,0,LIMIT);
   adaptive=clamp(adaptive+injected,0,LIMIT);
   applied++;
   events.push(Object.freeze({step,time:step*DT,radians:injected}));
  }
  if(applied===INJECTIONS.length){
   if(fixed<=QUIET&&firstQuietFixed===null)firstQuietFixed=step*DT;
   if(adaptive<=QUIET&&firstQuietAdaptive===null)firstQuietAdaptive=step*DT;
  }
  rows.push(Object.freeze({
   step,time:+(step*DT).toFixed(2),injected,fixed,adaptive,
   fixedCoherence:coherence(samples,fixed),
   adaptiveCoherence:coherence(samples,adaptive)
  }));
  // Decay is independent for each scalar. No input means strictly nonincreasing.
  fixed=Math.max(0,fixed-.63*DT);
  adaptive=Math.max(0,adaptive-Math.min(2.5,1.8*adaptive)*DT);
 }
 return Object.freeze({rows:Object.freeze(rows),events:Object.freeze(events),
  sourceCount:samples.filter(eligible).length,
  fixedQuiet:firstQuietFixed,adaptiveQuiet:firstQuietAdaptive,
  totalInjections:events.length,writeToGame:false,sourceMutated:false});
}
function draw(){
 const w=canvas.width,h=canvas.height,B=h-30,T=16,L=40,R=w-15;
 ctx.fillStyle='#0c1027';ctx.fillRect(0,0,w,h);
 ctx.strokeStyle='#7172a43b';ctx.lineWidth=1;
 for(let i=0;i<=10;i++){
  const x=L+(R-L)*i/10;
  ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,B);ctx.stroke();
 }
 for(let i=0;i<=4;i++){
  const y=T+(B-T)*i/4;
  ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(R,y);ctx.stroke();
 }
 for(const step of INJECTIONS){
  const x=L+(R-L)*step/STEPS;
  ctx.strokeStyle='#e99ffa55';ctx.setLineDash([4,4]);
  ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,B);ctx.stroke();ctx.setLineDash([]);
 }
 for(const [field,color] of [['fixed','#ffad67'],['adaptive','#72f7dc']]){
  ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.4;
  ctx.shadowColor=color;ctx.shadowBlur=7;
  records.slice(0,position+1).forEach((r,i)=>{
   const x=L+(R-L)*r.step/STEPS,y=B-r[field]/LIMIT*(B-T);
   if(!i)ctx.moveTo(x,y);else ctx.lineTo(x,y);
  });
  ctx.stroke();ctx.shadowBlur=0;
 }
 ctx.fillStyle='#adbad8';ctx.font='11px ui-monospace,monospace';
 for(let i=0;i<=5;i++)ctx.fillText(i*2+'s',L+(R-L)*i/5-5,h-8);
}
function present(){
 draw();
 const current=records[position];
 const fmt=v=>v===null?'UNDEFINED':(v*100).toFixed(1)+'%';
 status.textContent=!current?'QUIET · NO COMPARISON':
  (running?'RUNNING':'FROZEN')+' · DISTURB '+INJECTIONS.filter(x=>x<=current.step).length+'/4'+
  ' · FIXED '+fmt(current.fixedCoherence)+' · ADAPT '+fmt(current.adaptiveCoherence)+
  ' · ORIGINAL MEMORY UNMODIFIED';
 root.dataset.readOnly='true';root.dataset.step=String(position);
}
function begin(){
 const data=window.neuroscapeTesseract?.snapshot();
 source=(data?.edgeSamples||[]).map(s=>Object.freeze({...s}));
 match=data?.persistence?.match||'none';
 results=simulate(source);records=results.rows;position=0;running=true;present();
}
function halt(){running=false;position=0;records=[];source=[];results=null;present()}
run?.addEventListener('click',begin);
reset?.addEventListener('click',halt);
setInterval(()=>{
 if(!running)return;
 if((window.neuroscapeTesseract?.snapshot()?.persistence?.match||'none')!==match){halt();return}
 position=Math.min(position+1,STEPS);if(position===STEPS)running=false;present();
},100);
present();
window.neuroscapeDisturbanceStability=Object.freeze({
 simulate:input=>simulate(input),
 snapshot:()=>Object.freeze({running,step:position,
 injections:results?.totalInjections||0,
 sourceCount:source.length,writeToGame:false,sourceMutated:false,
 fixedOffset:records[position]?.fixed??null,
 adaptiveOffset:records[position]?.adaptive??null,
 fixedQuiet:results?.fixedQuiet??null,adaptiveQuiet:results?.adaptiveQuiet??null})
});
})();
