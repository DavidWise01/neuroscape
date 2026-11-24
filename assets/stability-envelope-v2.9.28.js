/* Neuroscape v2.9.28 — read-only adaptive stability envelope.
 * Fixed-rate and adaptive recovery use inherited v2.9.27 scalar offset laws.
 * Every disturbance is declared. A "stable" policy reaches <=0.1 radians
 * BEFORE the next injection, over three equal-period trials.
 * No engine state access, source writes, replay or invented physical energy.
 */
(()=>{'use strict';
 const host=document.getElementById('stabilityEnvelopeLab');
 const canvas=document.getElementById('stabilityEnvelopeCanvas');
 const status=document.getElementById('stabilityEnvelopeStatus');
 const selector=document.getElementById('stabilityEnvelopePolicy');
 if(!host||!canvas||!status||!selector)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const DT=.1,LIMIT=Math.PI,QUIET=.1,TRIALS=3;
 const PERIODS=Object.freeze(Array.from({length:32},(_,i)=>+(0.5+i*.25).toFixed(2)));
 const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
 const fixedStep=v=>Math.max(0,v-.63*DT);
 const adaptiveStep=v=>Math.max(0,v-Math.min(2.5,1.8*v)*DT);
 function trial(period,policy){
   if(!Number.isFinite(period)||period<DT)throw Error('Invalid disturbance period');
   const durationSteps=Math.round(period/DT);
   let v=0,stable=true,earlyTime=null,peaks=[],preInjection=[],samples=[];
   for(let cycle=0;cycle<TRIALS;cycle++){
     v=clamp(v+LIMIT,0,LIMIT);
     peaks.push(v);
     let reached=null;
     for(let step=1;step<durationSteps;step++){
       v=policy==='adaptive'?adaptiveStep(v):fixedStep(v);
       if(v<=QUIET&&reached===null)reached=step*DT;
       samples.push(Object.freeze({cycle,time:+((cycle*durationSteps+step)*DT).toFixed(3),offset:v}));
     }
     preInjection.push(v);
     if(reached===null)stable=false;
     if(earlyTime===null&&reached!==null)earlyTime=reached;
   }
   return Object.freeze({stable,firstRecoveryTime:earlyTime,lastOffset:v,
     preInjection:Object.freeze(preInjection),peaks:Object.freeze(peaks),samples:Object.freeze(samples)});
 }
 function sweep(){
   const data=PERIODS.map(period=>{
     const fixed=trial(period,'fixed'),adaptive=trial(period,'adaptive');
     return Object.freeze({period,frequency:1/period,fixed,adaptive,
       classification:fixed.stable?'BOTH RECOVER':adaptive.stable?'ADAPTIVE ONLY':'NEITHER RECOVERS'});
   });
   const adaptiveBound=data.find(d=>d.adaptive.stable)?.period??null;
   const fixedBound=data.find(d=>d.fixed.stable)?.period??null;
   return Object.freeze({data:Object.freeze(data),adaptiveBound,fixedBound,
     periodsTested:PERIODS.length,trialsPerPeriod:TRIALS,
     timestepSeconds:DT,thresholdRadians:QUIET,
     sourceMutated:false,gameplayMutation:false});
 }
 const results=sweep();
 function plot(){
   const w=canvas.width,h=canvas.height,L=44,R=w-20,T=14,B=h-30;
   ctx.fillStyle='#0b1025';ctx.fillRect(0,0,w,h);
   ctx.lineWidth=1;ctx.strokeStyle='#6c7aa43e';
   for(let i=0;i<=4;i++){
     const y=T+(B-T)*i/4;ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(R,y);ctx.stroke();
   }
   for(let i=0;i<=8;i++){
     const x=L+(R-L)*i/8;ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,B);ctx.stroke();
   }
   const x=period=>L+(period-.5)/(8.25-.5)*(R-L);
   const shade=(policy,color)=>{
     const points=results.data.filter(d=>d[policy].stable);
     if(!points.length)return;
     const start=x(points[0].period);
     ctx.fillStyle=color;ctx.fillRect(start,T,R-start,B-T);
   };
   shade('adaptive','#24ffa414');shade('fixed','#faad4213');
   for(const [policy,color] of [['fixed','#ffad67'],['adaptive','#71ffe2']]){
     ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.8;
     results.data.forEach((row,i)=>{
       const value=row[policy].preInjection.at(-1);
       const xx=x(row.period),yy=B-value/LIMIT*(B-T);
       if(!i)ctx.moveTo(xx,yy);else ctx.lineTo(xx,yy);
     });
     ctx.stroke();
   }
   const chosen=Number(selector.value);
   ctx.strokeStyle='#d5b3ff';ctx.setLineDash([4,4]);ctx.lineWidth=1.6;
   ctx.beginPath();ctx.moveTo(x(chosen),T);ctx.lineTo(x(chosen),B);ctx.stroke();ctx.setLineDash([]);
   ctx.font='11px ui-monospace,monospace';ctx.fillStyle='#bfc6e4';
   for(let i=0;i<=8;i++){
     const p=.5+(8.25-.5)*i/8;ctx.fillText(p.toFixed(1)+'s',x(p)-10,h-9);
   }
   ctx.fillText('Residual offset before next injection (radians)',L+10,26);
 }
 function render(){
   const selected=results.data.find(d=>String(d.period)===selector.value)||results.data[0];
   plot();
   const fmt=v=>v===null?'OUTSIDE SWEEP':v.toFixed(2)+'s';
   const word=selected.classification;
   status.textContent=word+' · INTERVAL '+selected.period.toFixed(2)+'s · ADAPT MIN '+fmt(results.adaptiveBound)+' · FIXED MIN '+fmt(results.fixedBound);
   host.dataset.classification=word;
   host.dataset.authority='visual-only';
   host.dataset.period=String(selected.period);
 }
 selector.replaceChildren(...PERIODS.map(period=>{
   const option=document.createElement('option');
   option.value=String(period);option.textContent=period.toFixed(2)+'s ('+(1/period).toFixed(2)+' Hz)';
   return option;
 }));
 selector.value='3';
 selector.addEventListener('change',render);
 render();
 window.neuroscapeStabilityEnvelope=Object.freeze({
   snapshot:()=>Object.freeze({
     periodsTested:results.periodsTested,trialsPerPeriod:results.trialsPerPeriod,
     adaptiveBound:results.adaptiveBound,fixedBound:results.fixedBound,
     selectedPeriod:Number(selector.value),classification:host.dataset.classification,
     visualOnly:true,sourceMutated:false,gameplayMutation:false
   }),
   sweep:()=>results,
   trial:(period,policy)=>{
     if(!['fixed','adaptive'].includes(policy))throw Error('Unknown policy');
     return trial(period,policy);
   }
 });
})();