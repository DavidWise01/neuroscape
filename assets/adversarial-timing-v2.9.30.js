/* Neuroscape v2.9.30 — fixed-budget adversarial disturbance schedules.
 * All 24 permutations of the SAME four intervals. Identical total timing
 * budget and total injected phase. The ordering can change recovery outcomes.
 * Read-only scalar-offset model; no combat, RAM or edge memory mutations.
 */
(()=>{'use strict';
 const panel=document.getElementById('adversarialTimingLab'),
 canvas=document.getElementById('adversarialTimingCanvas'),
 status=document.getElementById('adversarialTimingStatus'),
 select=document.getElementById('adversarialTimingPeriod');
 if(!panel||!canvas||!status||!select)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const DT=.1,IMPACT=Math.PI,THRESHOLD=.1;
 const FACTORS=Object.freeze([.4,.7,1.1,1.8]); // sum = 4: equal total budget
 const PERIODS=Object.freeze(Array.from({length:32},(_,i)=>.5+i*.25));
 function permutations(a){
   if(a.length===1)return [[a[0]]];
   const out=[];
   for(let i=0;i<a.length;i++)for(const tail of permutations([...a.slice(0,i),...a.slice(i+1)]))
     out.push([a[i],...tail]);
   return out;
 }
 const schedules=Object.freeze(permutations(FACTORS).map((a,index)=>
   Object.freeze({index,factors:Object.freeze(a),sum:a.reduce((v,n)=>v+n,0)})));
 function evolve(v,policy){
   if(policy==='fixed')return Math.max(0,v-.63*DT);
   if(policy==='adaptive')return Math.max(0,v-Math.min(2.5,1.8*v)*DT);
   throw Error('Policy must be fixed or adaptive');
 }
 function run(period,policy,schedule){
   if(!Number.isFinite(period)||period<.5)throw Error('Invalid period');
   if(!schedule||!Array.isArray(schedule.factors)||schedule.factors.length!==4||
      Math.abs(schedule.factors.reduce((a,b)=>a+b,0)-4)>1e-9)throw Error('Invalid budget');
   let offset=0,failures=0,maxResidual=0,clock=0;
   const events=[],intervals=[];
   for(let n=0;n<4;n++){
     const steps=Math.max(1,Math.round(period*schedule.factors[n]/DT));
     offset=Math.min(IMPACT,offset+IMPACT);
     events.push(Object.freeze({sequence:n,time:+clock.toFixed(3),impulse:IMPACT}));
     let reached=false;
     for(let step=1;step<steps;step++){
       offset=evolve(offset,policy);
       if(offset<=THRESHOLD)reached=true;
     }
     if(!reached)failures++;
     maxResidual=Math.max(maxResidual,offset);
     intervals.push(Object.freeze({sequence:n,steps,seconds:+(steps*DT).toFixed(3),
       recovered:reached,residual:offset}));
     clock+=steps*DT;
   }
   return Object.freeze({policy,stable:failures===0,failures,maxResidual,
      totalSeconds:+clock.toFixed(3),events:Object.freeze(events),
      intervals:Object.freeze(intervals),gameplayMutation:false});
 }
 function sweep(){
   const rows=PERIODS.map(period=>{
     let worstFixed=null,worstAdaptive=null,stableFixed=true,stableAdaptive=true;
     for(const schedule of schedules){
       const f=run(period,'fixed',schedule),a=run(period,'adaptive',schedule);
       const worse=(p,c)=>!p||c.failures>p.result.failures||
           (c.failures===p.result.failures&&c.maxResidual>p.result.maxResidual);
       if(worse(worstFixed,f))worstFixed={schedule:schedule.index,result:f};
       if(worse(worstAdaptive,a))worstAdaptive={schedule:schedule.index,result:a};
       if(!f.stable)stableFixed=false;
       if(!a.stable)stableAdaptive=false;
     }
     return Object.freeze({period,stableFixed,stableAdaptive,
       worstFixed:Object.freeze(worstFixed),worstAdaptive:Object.freeze(worstAdaptive),
       className:stableFixed?'BOTH ROBUST':stableAdaptive?'ADAPTIVE ONLY':'NEITHER ROBUST'});
   });
   return Object.freeze({rows:Object.freeze(rows),scheduleCount:schedules.length,
     periodCount:PERIODS.length,budgetFactors:FACTORS.reduce((a,b)=>a+b,0),
     adaptiveBound:rows.find(x=>x.stableAdaptive)?.period??null,
     fixedBound:rows.find(x=>x.stableFixed)?.period??null});
 }
 const result=sweep();
 select.replaceChildren(...PERIODS.map(p=>{
   const opt=document.createElement('option');opt.value=String(p);
   opt.textContent=p.toFixed(2)+' s nominal';return opt;
 }));
 select.value='3';
 function paint(){
   const width=canvas.width,height=canvas.height,L=46,R=width-23,T=17,B=height-33;
   ctx.fillStyle='#0c1227';ctx.fillRect(0,0,width,height);
   ctx.strokeStyle='#6278ad3a';ctx.lineWidth=1;
   for(let n=0;n<=4;n++){let y=T+n*(B-T)/4;ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(R,y);ctx.stroke()}
   for(let n=0;n<=8;n++){let x=L+n*(R-L)/8;ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,B);ctx.stroke()}
   const toX=p=>L+(p-.5)/(8.25-.5)*(R-L);
   for(const [field,color] of [['worstFixed','#ffae71'],['worstAdaptive','#77ffdd']]){
     ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.8;
     result.rows.forEach((r,i)=>{
       const v=r[field].result.maxResidual,xx=toX(r.period),yy=B-v/Math.PI*(B-T);
       if(i===0)ctx.moveTo(xx,yy);else ctx.lineTo(xx,yy);
     });ctx.stroke();
   }
   const selected=Number(select.value);
   ctx.strokeStyle='#d4abff';ctx.setLineDash([4,5]);
   ctx.beginPath();ctx.moveTo(toX(selected),T);ctx.lineTo(toX(selected),B);ctx.stroke();ctx.setLineDash([]);
   ctx.font='11px ui-monospace,monospace';ctx.fillStyle='#bac4da';
   for(let n=0;n<=7;n++){
     const p=.5+n*1.1;ctx.fillText(p.toFixed(1)+'s',toX(p)-10,height-10);
   }
 }
 function render(){
   const selected=result.rows.find(r=>r.period===Number(select.value))||result.rows[0];
   paint();
   status.textContent=selected.className+' · FIXED ADVERSARY #'+selected.worstFixed.schedule+
     ' · ADAPTIVE ADVERSARY #'+selected.worstAdaptive.schedule+
     ' · '+selected.period.toFixed(2)+' s NOMINAL';
   panel.dataset.classification=selected.className;panel.dataset.authority='visual-only';
 }
 select.addEventListener('change',render);render();
 window.neuroscapeAdversarialTiming=Object.freeze({
   snapshot:()=>Object.freeze({periods:result.periodCount,schedules:result.scheduleCount,
     budgetFactors:result.budgetFactors,adaptiveBound:result.adaptiveBound,
     fixedBound:result.fixedBound,selected:Number(select.value),
     classification:panel.dataset.classification,gameplayMutation:false,sourceMutated:false}),
   sweep:()=>result,
   schedule:i=>schedules[i]||null,
   trial:(period,policy,index)=>run(period,policy,schedules[index])
 });
})();