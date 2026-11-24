/* Neuroscape v2.9.32 — uncertainty-bounded stability margin.
 * Reads v2.9.31 immutable audit results. ±epsilon is an EXPLICIT USER
 * ASSUMPTION, not a measured instrument uncertainty or physical confidence.
 * Conservative classification requires the entire signed margin interval
 * to be on one side of zero. Never mutates edge memory or game state.
 */
(()=>{'use strict';
 const root=document.getElementById('uncertaintyMarginLab');
 const canvas=document.getElementById('uncertaintyMarginCanvas');
 const status=document.getElementById('uncertaintyMarginStatus');
 const periodSelect=document.getElementById('uncertaintyMarginPeriod');
 const widthInput=document.getElementById('uncertaintyMarginWidth');
 const widthRead=document.getElementById('uncertaintyMarginWidthValue');
 const summary=document.getElementById('uncertaintyMarginCounts');
 if(!root||!canvas||!status||!periodSelect||!widthInput||!widthRead||!summary)return;
 const source=window.neuroscapeAdversarialMargin;
 const ctx=canvas.getContext('2d');
 if(!source||!ctx)return;
 const EPSILON_MAX=.3;
 const periods=Object.freeze(source.results().map(r=>r.period));
 const clamp=(v,a,b)=>Math.min(b,Math.max(a,v));
 function evaluateMargin(margin,epsilon){
   if(!Number.isFinite(margin)||!Number.isFinite(epsilon)||epsilon<0||epsilon>EPSILON_MAX)
     throw Error('Invalid margin or assumed uncertainty');
   const lower=margin-epsilon,upper=margin+epsilon;
   const classification=lower>=0?'CONFIRMED STABLE':
     upper<0?'CONFIRMED UNSTABLE':'INDETERMINATE';
   return Object.freeze({margin,epsilon,lower,upper,classification,
     assumption:'symmetric-bounded-offset',gameplayMutation:false});
 }
 function inspect(period,epsilon){
   if(!periods.includes(period))throw Error('Unknown measured period');
   const base=source.audit(period);
   return Object.freeze({
     period,epsilon,
     fixed:evaluateMargin(base.fixed.margin,epsilon),
     adaptive:evaluateMargin(base.adaptive.margin,epsilon),
     fixedWitnessSchedule:base.fixed.schedule,
     adaptiveWitnessSchedule:base.adaptive.schedule,
     sourceMutated:false,gameplayMutation:false
   });
 }
 function sweep(epsilon){
   const rows=Object.freeze(periods.map(period=>inspect(period,epsilon)));
   const counts=Object.freeze(Object.fromEntries(['fixed','adaptive'].map(policy=>[
     policy,Object.freeze({
       stable:rows.filter(r=>r[policy].classification==='CONFIRMED STABLE').length,
       unstable:rows.filter(r=>r[policy].classification==='CONFIRMED UNSTABLE').length,
       indeterminate:rows.filter(r=>r[policy].classification==='INDETERMINATE').length
     })
   ])));
   return Object.freeze({epsilon,rows,counts,periods:rows.length,
     sourceMutated:false,gameplayMutation:false});
 }
 periodSelect.replaceChildren(...periods.map(period=>{
   const o=document.createElement('option');
   o.value=String(period);o.textContent=period.toFixed(2)+' s';return o;
 }));
 periodSelect.value='3';
 const x=p=>42+(p-periods[0])/(periods.at(-1)-periods[0])*(canvas.width-60);
 const y=m=>Math.max(15,Math.min(canvas.height-30,
   15+(Math.PI+.4-m)/(Math.PI+.8)*(canvas.height-48)));
 function plot(rows,epsilon,chosen){
   const w=canvas.width,h=canvas.height,L=42,R=w-18,T=15,B=h-30;
   ctx.fillStyle='#0b1126';ctx.fillRect(0,0,w,h);
   ctx.strokeStyle='#7a75a23b';ctx.lineWidth=1;
   for(let n=0;n<=8;n++){
     let xx=L+(R-L)*n/8;ctx.beginPath();ctx.moveTo(xx,T);ctx.lineTo(xx,B);ctx.stroke();
   }
   for(let n=0;n<=4;n++){
     let yy=T+(B-T)*n/4;ctx.beginPath();ctx.moveTo(L,yy);ctx.lineTo(R,yy);ctx.stroke();
   }
   ctx.strokeStyle='#d9a6ff';ctx.setLineDash([5,4]);
   ctx.beginPath();ctx.moveTo(L,y(0));ctx.lineTo(R,y(0));ctx.stroke();ctx.setLineDash([]);
   for(const [policy,color,fill] of [
     ['fixed','#ffb378','#ffb3782a'],['adaptive','#81ffe0','#81ffe027']
   ]){
     // Uncertainty is a strip around the inherited signed margins.
     ctx.beginPath();
     rows.forEach((r,i)=>{let xx=x(r.period),yy=y(r[policy].upper);
       if(i===0)ctx.moveTo(xx,yy);else ctx.lineTo(xx,yy)});
     [...rows].reverse().forEach(r=>ctx.lineTo(x(r.period),y(r[policy].lower)));
     ctx.closePath();ctx.fillStyle=fill;ctx.fill();
     ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.6;
     rows.forEach((r,i)=>{let xx=x(r.period),yy=y(r[policy].margin);
       if(i===0)ctx.moveTo(xx,yy);else ctx.lineTo(xx,yy)});
     ctx.stroke();
   }
   ctx.strokeStyle='#e4c0ff';ctx.setLineDash([3,5]);
   ctx.beginPath();ctx.moveTo(x(chosen),T);ctx.lineTo(x(chosen),B);ctx.stroke();ctx.setLineDash([]);
   ctx.fillStyle='#c6c7e8';ctx.font='11px ui-monospace,monospace';
   ctx.fillText('SIGNED MARGIN ± '+epsilon.toFixed(3)+' rad',L+8,28);
   for(let n=0;n<=7;n++){
     const p=periods[0]+n*1.1;
     ctx.fillText(p.toFixed(1)+'s',x(p)-9,h-9);
   }
 }
 function render(){
   const epsilon=clamp(Number(widthInput.value),0,EPSILON_MAX);
   const period=Number(periodSelect.value),report=sweep(epsilon);
   const selected=report.rows.find(r=>r.period===period)||report.rows[0];
   widthRead.textContent='±'+epsilon.toFixed(3)+' rad (ASSUMED)';
   plot(report.rows,epsilon,selected.period);
   const f=selected.fixed,a=selected.adaptive;
   status.textContent='FIXED '+f.classification+' · ADAPTIVE '+a.classification+
      ' · '+selected.period.toFixed(2)+'s';
   summary.textContent='32 PERIODS · FIXED '+report.counts.fixed.stable+' STABLE / '+
      report.counts.fixed.indeterminate+' UNCERTAIN · ADAPTIVE '+
      report.counts.adaptive.stable+' STABLE / '+
      report.counts.adaptive.indeterminate+' UNCERTAIN';
   root.dataset.authority='visual-only';root.dataset.epsilon=String(epsilon);
   root.dataset.period=String(selected.period);
   root.dataset.fixedClass=f.classification;
   root.dataset.adaptiveClass=a.classification;
 }
 periodSelect.addEventListener('change',render);
 widthInput.addEventListener('input',render);widthInput.addEventListener('change',render);
 render();
 window.neuroscapeUncertaintyMargin=Object.freeze({
   evaluate:evaluateMargin,inspect,sweep,
   snapshot:()=>Object.freeze({
     periods:periods.length,epsilon:Number(root.dataset.epsilon),
     period:Number(root.dataset.period),
     fixed:root.dataset.fixedClass,adaptive:root.dataset.adaptiveClass,
     measuredUncertainty:false,visualOnly:true,
     sourceMutated:false,gameplayMutation:false
   })
 });
})();