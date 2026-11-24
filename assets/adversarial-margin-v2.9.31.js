/* Neuroscape v2.9.31 — adversarial stability-margin audit.
 * Consumes v2.9.30's existing immutable 24-ordering results.
 * Defines signed margin as the quiet threshold (0.1 rad) minus the
 * largest pre-disturbance residual, taking the minimum across all 24 orders.
 * This is a modeled phase margin, not a physical safety certification.
 * No writes to game, source reservoirs, or predecessor result objects.
 */
(()=>{'use strict';
 const root=document.getElementById('adversarialMarginLab');
 const canvas=document.getElementById('adversarialMarginCanvas');
 const status=document.getElementById('adversarialMarginStatus');
 const selector=document.getElementById('adversarialMarginPeriod');
 if(!root||!canvas||!status||!selector)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const source=window.neuroscapeAdversarialTiming;
 if(!source)return;
 const QUIET=.1,EPS=1e-10;
 function audit(period){
   const schedules=24;
   const byPolicy={fixed:[],adaptive:[]};
   for(let i=0;i<schedules;i++){
     for(const policy of ['fixed','adaptive']){
       const trial=source.trial(period,policy,i);
       const residual=Math.max(...trial.intervals.map(x=>x.residual));
       const margin=QUIET-residual;
       byPolicy[policy].push(Object.freeze({schedule:i,residual,margin,stable:trial.stable,
         unrecovered:trial.failures}));
     }
   }
   const worst=policy=>byPolicy[policy].reduce((w,x)=>
     !w||x.margin<w.margin-EPS?x:w,null);
   const fixed=worst('fixed'),adaptive=worst('adaptive');
   return Object.freeze({period,fixed,adaptive,
     improvement:adaptive.margin-fixed.margin,
     scheduleCount:schedules,
     sourceMutated:false,gameplayMutation:false});
 }
 const periods=source.sweep().rows.map(r=>r.period);
 const results=Object.freeze(periods.map(audit));
 selector.replaceChildren(...periods.map(p=>{
   const item=document.createElement('option');
   item.value=String(p);item.textContent=p.toFixed(2)+' s nominal';
   return item;
 }));
 selector.value='3';
 const left=45,right=canvas.width-18,top=15,bottom=canvas.height-32;
 const px=p=>left+(p-periods[0])/(periods.at(-1)-periods[0])*(right-left);
 const py=margin=>Math.max(top,Math.min(bottom,top+(Math.PI+.1-margin)/(Math.PI+.2)*(bottom-top)));
 function paint(){
   const w=canvas.width,h=canvas.height;
   ctx.fillStyle='#0c1227';ctx.fillRect(0,0,w,h);
   ctx.strokeStyle='#6b80b244';ctx.lineWidth=1;
   for(let n=0;n<=8;n++){
     const x=left+n*(right-left)/8;
     ctx.beginPath();ctx.moveTo(x,top);ctx.lineTo(x,bottom);ctx.stroke();
   }
   for(let n=0;n<=4;n++){
     const y=top+n*(bottom-top)/4;
     ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(right,y);ctx.stroke();
   }
   const zero=py(0);
   ctx.strokeStyle='#cba1f5';ctx.setLineDash([5,5]);
   ctx.beginPath();ctx.moveTo(left,zero);ctx.lineTo(right,zero);ctx.stroke();ctx.setLineDash([]);
   for(const [field,color] of [['fixed','#ffb16c'],['adaptive','#72ffde']]){
     ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.8;
     results.forEach((r,i)=>{
       const x=px(r.period),y=py(r[field].margin);
       if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
     });ctx.stroke();
   }
   const chosen=Number(selector.value);
   ctx.strokeStyle='#d7aeff';ctx.setLineDash([3,4]);
   ctx.beginPath();ctx.moveTo(px(chosen),top);ctx.lineTo(px(chosen),bottom);
   ctx.stroke();ctx.setLineDash([]);
   ctx.fillStyle='#c2c9e5';ctx.font='11px ui-monospace,monospace';
   ctx.fillText('Signed margin (threshold − worst residual)',left+6,28);
   for(let i=0;i<=7;i++){
     const p=periods[0]+i*1.1;
     ctx.fillText(p.toFixed(1)+'s',px(p)-10,h-9);
   }
 }
 function render(){
   const selected=results.find(r=>r.period===Number(selector.value))||results[0];
   paint();
   const f=selected.fixed.margin,a=selected.adaptive.margin;
   const fmt=x=>(x>=0?'+':'')+x.toFixed(4)+'rad';
   status.textContent='FIXED '+fmt(f)+' · ADAPTIVE '+fmt(a)+
    ' · ADVANTAGE '+fmt(selected.improvement)+
    ' · WORST #'+selected.fixed.schedule+' / #'+selected.adaptive.schedule;
   root.dataset.period=String(selected.period);
   root.dataset.fixedMargin=String(f);
   root.dataset.adaptiveMargin=String(a);
   root.dataset.authority='visual-only';
 }
 selector.addEventListener('change',render);render();
 window.neuroscapeAdversarialMargin=Object.freeze({
   snapshot:()=>Object.freeze({
     periods:results.length,schedules:24,threshold:QUIET,
     period:Number(selector.value),
     fixedMargin:Number(root.dataset.fixedMargin),
     adaptiveMargin:Number(root.dataset.adaptiveMargin),
     sourceMutated:false,gameplayMutation:false
   }),
   audit:period=>audit(period),
   results:()=>results
 });
})();