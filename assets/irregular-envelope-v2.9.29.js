/* Neuroscape v2.9.29 · irregular-disturbance stability envelope.
 * Deterministic, bounded visual-only phase-offset simulation. Equal mean
 * intervals across four schedules; no source memory, game/RAM, or DOM input.
 * A policy passes only when each interval reaches <=0.1 radians before
 * its next injection. All scheduled impulses are explicitly reported.
 */
(()=>{'use strict';
 const root=document.getElementById('irregularEnvelopeLab');
 const canvas=document.getElementById('irregularEnvelopeCanvas');
 const status=document.getElementById('irregularEnvelopeStatus');
 const selector=document.getElementById('irregularEnvelopePeriod');
 if(!root||!canvas||!status||!selector)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const DT=.1,THRESHOLD=.1,IMPULSE=Math.PI;
 const BASES=Object.freeze(Array.from({length:32},(_,i)=>.5+i*.25));
 const POLICIES=Object.freeze(['fixed','adaptive']);
 const SCHEDULES=Object.freeze({
  regular:Object.freeze([1,1,1,1]),
  alternating:Object.freeze([.65,1.35,.65,1.35]),
  clustered:Object.freeze([.55,.75,1.15,1.55]),
  deterministic:Object.freeze([1.3,.6,1.4,.7])
 });
 const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
 function evolve(value,policy){
   if(policy==='fixed')return Math.max(0,value-.63*DT);
   if(policy==='adaptive')return Math.max(0,value-Math.min(2.5,1.8*value)*DT);
   throw Error('Unsupported recovery policy');
 }
 function trial(period,policy,schedule){
   if(!Number.isFinite(period)||period<.5)throw Error('Invalid nominal interval');
   if(!POLICIES.includes(policy)||!(schedule in SCHEDULES))throw Error('Invalid policy or schedule');
   const factors=SCHEDULES[schedule],events=[],segments=[];
   let state=0,stable=true,clock=0,unrecovered=0,peakResidual=0;
   for(let index=0;index<factors.length;index++){
     const durationSteps=Math.max(1,Math.round(period*factors[index]/DT));
     const actualDuration=durationSteps*DT;
     const start=clock;
     state=clamp(state+IMPULSE,0,IMPULSE);
     events.push(Object.freeze({cycle:index,atSeconds:+start.toFixed(3),injectedRadians:IMPULSE}));
     let firstQuiet=null;
     // Match the inherited check: recovery at a strict pre-injection step.
     for(let step=1;step<durationSteps;step++){
       state=evolve(state,policy);
       if(firstQuiet===null&&state<=THRESHOLD)firstQuiet=step*DT;
     }
     const passed=firstQuiet!==null;
     if(!passed){stable=false;unrecovered++}
     peakResidual=Math.max(peakResidual,state);
     segments.push(Object.freeze({
       cycle:index,intervalSeconds:actualDuration,
       endSeconds:+(clock+actualDuration).toFixed(3),
       preNextResidual:state,recoveredBeforeNext:passed,
       firstRecoverySeconds:firstQuiet
     }));
     clock+=actualDuration;
   }
   return Object.freeze({period,policy,schedule,stable,unrecovered,peakResidual,
     events:Object.freeze(events),segments:Object.freeze(segments),
     count:events.length,sourceMutated:false,gameplayMutation:false});
 }
 function sweep(){
   const rows=BASES.map(period=>{
     const scenarios=Object.freeze(Object.fromEntries(Object.keys(SCHEDULES).map(schedule=>[
       schedule,Object.freeze({
         fixed:trial(period,'fixed',schedule),
         adaptive:trial(period,'adaptive',schedule)
       })
     ])));
     const fixedAll=Object.values(scenarios).every(x=>x.fixed.stable);
     const adaptiveAll=Object.values(scenarios).every(x=>x.adaptive.stable);
     return Object.freeze({period,scenarios,fixedAll,adaptiveAll,
       classification:fixedAll?'BOTH ROBUST':adaptiveAll?'ADAPTIVE ONLY':'NEITHER ROBUST'});
   });
   const adaptiveBound=rows.find(x=>x.adaptiveAll)?.period??null;
   const fixedBound=rows.find(x=>x.fixedAll)?.period??null;
   return Object.freeze({rows:Object.freeze(rows),adaptiveBound,fixedBound,
     periods:BASES.length,patterns:Object.keys(SCHEDULES).length,
     injectionsPerPattern:4,thresholdRadians:THRESHOLD,
     noGameplayMutation:true});
 }
 const results=sweep();
 selector.replaceChildren(...BASES.map(period=>{
   const item=document.createElement('option');item.value=String(period);
   item.textContent=period.toFixed(2)+' s nominal';return item;
 }));
 selector.value='3';
 const x=p=>44+(p-.5)/(8.25-.5)*(canvas.width-64);
 function draw(){
   const w=canvas.width,h=canvas.height,L=44,R=w-20,T=16,B=h-32;
   ctx.fillStyle='#0c1227';ctx.fillRect(0,0,w,h);
   ctx.lineWidth=1;ctx.strokeStyle='#777fbc33';
   for(let n=0;n<=4;n++){
     const y=T+(B-T)*n/4;ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(R,y);ctx.stroke();
   }
   for(let n=0;n<=8;n++){
     const xx=L+(R-L)*n/8;ctx.beginPath();ctx.moveTo(xx,T);ctx.lineTo(xx,B);ctx.stroke();
   }
   const bound=(value,color)=>{
     if(value===null)return;
     ctx.strokeStyle=color;ctx.setLineDash([5,4]);ctx.lineWidth=1.7;
     ctx.beginPath();ctx.moveTo(x(value),T);ctx.lineTo(x(value),B);ctx.stroke();ctx.setLineDash([]);
   };
   bound(results.adaptiveBound,'#73ffe7');bound(results.fixedBound,'#ffb16f');
   for(const [policy,color] of [['fixed','#ffb16f'],['adaptive','#73ffe7']]){
     ctx.strokeStyle=color;ctx.lineWidth=2.7;ctx.beginPath();
     results.rows.forEach((row,i)=>{
       const highest=Math.max(...Object.values(row.scenarios).map(s=>s[policy].peakResidual));
       const yy=B-(highest/Math.PI)*(B-T);
       if(i===0)ctx.moveTo(x(row.period),yy);else ctx.lineTo(x(row.period),yy);
     });ctx.stroke();
   }
   const selected=Number(selector.value);
   ctx.strokeStyle='#d5b5ff';ctx.setLineDash([3,4]);
   ctx.beginPath();ctx.moveTo(x(selected),T);ctx.lineTo(x(selected),B);ctx.stroke();ctx.setLineDash([]);
   ctx.font='11px ui-monospace,monospace';ctx.fillStyle='#bac3dc';
   for(let n=0;n<=7;n++){
     const p=.5+n*1.1;ctx.fillText(p.toFixed(1)+'s',x(p)-10,h-10);
   }
 }
 function render(){
   draw();
   const selected=results.rows.find(x=>x.period===Number(selector.value))||results.rows[0];
   const fmt=n=>n===null?'NOT OBSERVED':n.toFixed(2)+' s';
   status.textContent=selected.classification+' · ADAPTIVE '+fmt(results.adaptiveBound)+
    ' · FIXED '+fmt(results.fixedBound)+' · '+selected.period.toFixed(2)+' s NOMINAL';
   root.dataset.classification=selected.classification;
   root.dataset.authority='read-only';
 }
 selector.addEventListener('change',render);render();
 window.neuroscapeIrregularEnvelope=Object.freeze({
   snapshot:()=>Object.freeze({
     periods:results.periods,patterns:results.patterns,
     injectionsPerPattern:results.injectionsPerPattern,
     adaptiveBound:results.adaptiveBound,fixedBound:results.fixedBound,
     classification:root.dataset.classification,selectedPeriod:Number(selector.value),
     sourceMutated:false,gameplayMutation:false
   }),
   trial:(period,policy,schedule)=>trial(period,policy,schedule),
   sweep:()=>results
 });
})();