/* Neuroscape v2.9.25 · observational phase drift / recovery laboratory.
 * Only reads immutable per-edge amplitudes/phases from the tesseract snapshot.
 * Drift offsets are applied to a COPY for comparative projection; they never
 * modify reservoirs, source ancestry, engine RAM, cards or combat state.
 */
(()=>{'use strict';
 const host=document.getElementById('phaseDriftLab');
 const canvas=document.getElementById('phaseDriftCanvas');
 if(!host||!canvas)return;
 const ctx=canvas.getContext('2d');if(!ctx)return;
 const run=document.getElementById('phaseDriftRun');
 const reset=document.getElementById('phaseDriftReset');
 const readout=document.getElementById('phaseDriftStatus');
 const WINDOW_MS=6500,FRAMES=90,MAX_RAD=Math.PI;
 let started=null,active=false,stage='IDLE',alpha=0,history=[],lastMatch=null;
 const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
 function coherence(samples,drift=0){
   let x=0,y=0,total=0,activeCount=0;
   if(!Array.isArray(samples))return {value:null,active:0};
   for(const s of samples){
     const a=Number(s.amplitude),phase=Number(s.phase);
     if(!Number.isFinite(a)||a<=0||!Number.isFinite(phase))continue;
     const theta=phase+drift*((s.edge-15.5)/15.5);
     x+=a*Math.cos(theta);y+=a*Math.sin(theta);total+=a;activeCount++;
   }
   return {value:total>0?clamp(Math.hypot(x,y)/total,0,1):null,active:activeCount};
 }
 function progression(elapsed){
   if(elapsed<1000)return {stage:'BASELINE',alpha:0};
   if(elapsed<3000)return {stage:'DRIFT',alpha:(elapsed-1000)/2000};
   if(elapsed<5000)return {stage:'RECOVERY',alpha:1-(elapsed-3000)/2000};
   return {stage:'OBSERVE / HOLD',alpha:0};
 }
 function setIdle(){
   active=false;started=null;stage='IDLE';alpha=0;history=[];
   run.textContent='RUN DRIFT / RECOVERY';run.setAttribute('aria-pressed','false');
 }
 function draw(record){
   const w=canvas.width,h=canvas.height;
   ctx.fillStyle='#0b1025';ctx.fillRect(0,0,w,h);
   ctx.strokeStyle='#7995c02a';ctx.lineWidth=1;
   for(let i=0;i<=10;i++){let x=40+(w-60)*i/10;ctx.beginPath();ctx.moveTo(x,12);ctx.lineTo(x,h-28);ctx.stroke()}
   for(let i=0;i<=4;i++){let y=15+(h-47)*i/4;ctx.beginPath();ctx.moveTo(40,y);ctx.lineTo(w-20,y);ctx.stroke()}
   const plot=(key,color)=>{
     let startedLine=false;ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2.5;
     ctx.shadowColor=color;ctx.shadowBlur=7;
     for(const row of history){
       if(row[key]===null){startedLine=false;continue}
       const x=40+row.t/WINDOW_MS*(w-60),y=h-28-row[key]*(h-52);
       if(!startedLine){ctx.moveTo(x,y);startedLine=true}else ctx.lineTo(x,y);
     }
     ctx.stroke();ctx.shadowBlur=0;
   };
   plot('baseline','#ffa96c');plot('projected','#7cf8e6');
   ctx.fillStyle='#adbada';ctx.font='11px ui-monospace,monospace';
   for(let i=0;i<=6;i++)ctx.fillText(i+'s',40+i*(w-60)/6-7,h-8);
   if(record){
     ctx.textAlign='right';ctx.fillStyle='#d6bcff';
     ctx.fillText('DRIFT '+(alpha*180).toFixed(1)+'°',w-24,28);ctx.textAlign='left';
   }
 }
 function tick(now){
   const data=window.neuroscapeTesseract?.snapshot();
   if(!data)return;
   const match=data.persistence?.match||'none';
   if(lastMatch!==null&&lastMatch!==match)setIdle();
   lastMatch=match;
   if(active&&started!==null){
     const elapsed=clamp(now-started,0,WINDOW_MS);
     const progress=progression(elapsed);stage=progress.stage;alpha=progress.alpha;
     if(elapsed>=WINDOW_MS)active=false;
   }
   const raw=coherence(data.edgeSamples),shadow=coherence(data.edgeSamples,alpha*MAX_RAD);
   if(active&&started!==null){
     history.push({t:clamp(now-started,0,WINDOW_MS),baseline:raw.value,projected:shadow.value});
     if(history.length>FRAMES)history.shift();
   }
   draw({baseline:raw.value,projected:shadow.value});
   const fmt=x=>x===null?'UNDEFINED':(x*100).toFixed(2)+'%';
   readout.textContent=stage+' · BASE '+fmt(raw.value)+' · DRIFT '+fmt(shadow.value)+
     ' · '+raw.active+' ACTIVE / 32 · SOURCE MEMORY UNCHANGED';
   host.dataset.stage=stage;host.dataset.activeEdges=String(raw.active);
   host.dataset.authority='visual-only';
   host.dataset.defined=String(raw.value!==null&&shadow.value!==null);
 }
 run.addEventListener('click',()=>{
   active=true;started=performance.now();stage='BASELINE';alpha=0;history=[];
   run.textContent='RESTART DRIFT CYCLE';run.setAttribute('aria-pressed','true');
 });
 reset.addEventListener('click',setIdle);
 const timer=setInterval(()=>{if(!document.hidden)tick(performance.now())},100);
 tick(performance.now());
 window.neuroscapePhaseDrift=Object.freeze({
   snapshot:()=>{
     const src=window.neuroscapeTesseract?.snapshot()?.edgeSamples||[];
     const b=coherence(src),p=coherence(src,alpha*MAX_RAD);
     return Object.freeze({stage,active,driftRadians:alpha*MAX_RAD,
       baseline:b.value,projected:p.value,activeEdges:b.active,
       historyCount:history.length,sourceMutated:false,gameplayMutation:false});
   },
   // Pure deterministic phase comparison, never modifies its argument.
   compare:(samples,radians)=>Object.freeze({
     baseline:coherence(samples).value,
     projected:coherence(samples,clamp(Number(radians)||0,0,Math.PI)).value
   })
 });
})();
