/* v2.9.16 — independent, observation-only phase correlation.
   NEVER reads or mutates game state. A timing overlap is NOT a causal claim.
   Source IDs are retained separately; no synthetic samples are inserted. */
(()=>{'use strict';
 const panel=document.getElementById('phaseCorrelation');
 const canvas=document.getElementById('phaseCorrelationCanvas');
 if(!panel||!canvas)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const WINDOW=5000,STEP=100,PAIR_GATE=750;
 const attackSelector='#plasmaMemoryAttack li[data-source]';
 const recoverySelector='#plasmaMemoryRecovery li[data-source]';
 const phase=(age)=>{
   if(age<0||age>=WINDOW)return 0;
   if(age<350)return age/350;
   if(age<1600)return 1-(age-350)/1250*.25;
   return Math.max(0,.75*(1-(age-1600)/3400));
 };
 function sample(selector,channel){
   return [...document.querySelectorAll(selector)].map(node=>({
     source:node.dataset.source,
     channel,
     age:Number(node.dataset.ageMs),
     phase:node.dataset.phase||'quiet'
   })).filter(e=>e.source&&Number.isFinite(e.age)&&e.age>=0&&e.age<=60000)
     .slice(-8);
 }
 function correlate(attacks,returns){
   const waveform=(events)=>{
     const bins=[];
     for(let offset=WINDOW;offset>=0;offset-=STEP){
       const intensity=events.reduce((value,event)=>
         Math.max(value,phase(event.age-offset)),0);
       bins.push(intensity);
     }
     return bins;
   };
   const a=waveform(attacks),b=waveform(returns);
   const overlapping=a.map((x,i)=>Math.min(x,b[i]));
   const union=a.reduce((v,x,i)=>v+Math.max(x,b[i]),0);
   const sum=overlapping.reduce((v,x)=>v+x,0);
   const percentage=union>0?Math.round(100*sum/union):null;
   // Provenance stays paired, never merged. Matching IDs are not inferred.
   const pairs=[];
   for(const attack of attacks)for(const recovery of returns){
     const lagMs=Math.round(attack.age-recovery.age);
     if(Math.abs(lagMs)>PAIR_GATE)continue;
     pairs.push({attack:attack.source,recovery:recovery.source,lagMs});
   }
   return {a,b,overlapping,percentage,pairs,
     attackSources:attacks.length,recoverySources:returns.length};
 }
 function draw(data){
   const w=canvas.width,h=canvas.height,L=36,R=w-12,T=12,B=h-27;
   ctx.clearRect(0,0,w,h);ctx.fillStyle='#100f21';ctx.fillRect(0,0,w,h);
   ctx.lineWidth=1;ctx.strokeStyle='#62588165';
   for(let i=0;i<=10;i++){const x=L+(R-L)*i/10;ctx.beginPath();ctx.moveTo(x,T);ctx.lineTo(x,B);ctx.stroke()}
   for(let i=0;i<=4;i++){const y=T+(B-T)*i/4;ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(R,y);ctx.stroke()}
   for(const [series,color,width] of [[data.a,'#ffb165',2.4],[data.b,'#c58bff',2.4],[data.overlapping,'#77f3e8',3.2]]){
     ctx.strokeStyle=color;ctx.lineWidth=width;ctx.shadowColor=color;ctx.shadowBlur=6;
     ctx.beginPath();series.forEach((v,i)=>{
       const x=L+(R-L)*i/(series.length-1),y=B-v*(B-T-4);
       if(!i)ctx.moveTo(x,y);else ctx.lineTo(x,y);
     });ctx.stroke();
   }
   ctx.shadowBlur=0;ctx.fillStyle='#bfb3e0';ctx.font='11px ui-monospace,monospace';
   for(let i=0;i<=5;i++){ctx.fillText(i+'s',L+(R-L)*i/5-7,h-8)}
 }
 function paint(){
   const attacks=sample(attackSelector,'attack');
   const returns=sample(recoverySelector,'recovery');
   const data=correlate(attacks,returns);
   draw(data);
   const status=document.getElementById('phaseCorrelationStatus');
   if(status){
     status.textContent=data.percentage===null?'NO COMPARABLE LIVE PULSES':
       'SHARED PHASE OVERLAP '+data.percentage+'% · '+data.pairs.length+' PAIRS WITHIN ±750ms';
     status.dataset.overlap=data.percentage===null?'none':String(data.percentage);
     status.dataset.pairs=String(data.pairs.length);
   }
   const list=document.getElementById('phaseCorrelationPairs');
   if(list){
     const rows=data.pairs.slice(-12).map(pair=>{
       const row=document.createElement('li');
       row.dataset.attackSource=pair.attack;row.dataset.recoverySource=pair.recovery;
       row.dataset.lagMs=String(pair.lagMs);
       // Positive means the recovery began later than the attack.
       row.textContent=pair.attack+' ∥ '+pair.recovery+' · Δt '+(pair.lagMs>=0?'+':'')+pair.lagMs+'ms';
       return row;
     });
     list.replaceChildren(...rows);
   }
   panel.dataset.attackSources=String(data.attackSources);
   panel.dataset.recoverySources=String(data.recoverySources);
   panel.dataset.causality='not-inferred';
 }
 paint();const timer=setInterval(()=>{if(!document.hidden)paint()},180);
 window.neuroscapePhaseCorrelation=Object.freeze({
   snapshot:()=>{const d=correlate(sample(attackSelector,'attack'),sample(recoverySelector,'recovery'));
     return Object.freeze({percentage:d.percentage,
       attackSources:d.attackSources,recoverySources:d.recoverySources,
       pairs:d.pairs.map(p=>Object.freeze({...p})),causality:'not-inferred'});
   }
 });
})();
