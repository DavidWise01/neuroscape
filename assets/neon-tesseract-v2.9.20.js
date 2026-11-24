/* v2.9.20 — NEON TESSERACT SHADOW.
 * Genuine 16-vertex / 32-edge hypercube with 4D plane rotations (XW,YW,ZW),
 * 4D->3D perspective and 3D->2D camera projection; separate shadow projection.
 * Visual-only: observes existing DOM readouts and never touches engine state.
 */
(()=>{'use strict';
const section=document.getElementById('neonTesseractLab'),canvas=document.getElementById('neonTesseractCanvas');
if(!section||!canvas)return;
const ctx=canvas.getContext('2d');if(!ctx)return;
const info=document.getElementById('neonTesseractStatus');
const pause=document.getElementById('neonTesseractPause');
const motion=window.matchMedia?.('(prefers-reduced-motion: reduce)');
const vertices=[],edges=[];
for(let i=0;i<16;i++){
 const p=[0,1,2,3].map(b=>(i&(1<<b))?1:-1);
 vertices.push(p);
 for(let b=0;b<4;b++){const n=i^(1<<b);if(i<n)edges.push([i,n,b])}
}
const state={pause:false,angle:0,last:0,drag:false,dragX:0,dragY:0,yaw:.4,pitch:-.18,frames:0};
const colors=['#ff943c','#b36aff','#58f9e9','#76baff'];
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const rotate=(p,a,b,t)=>{const c=Math.cos(t),s=Math.sin(t),x=p[a],y=p[b];p[a]=x*c-y*s;p[b]=x*s+y*c};
function project4(point,t){
 const p=[...point];
 rotate(p,0,3,t*.71);rotate(p,1,3,t*.47+.28);rotate(p,2,3,t*.31);
 rotate(p,0,1,.21);rotate(p,1,2,.18);
 const w=3.9/(3.9-p[3]*.55);
 return [p[0]*w,p[1]*w,p[2]*w,p[3]];
}
function view3(p){
 const [x,y,z,w]=p,cy=Math.cos(state.yaw),sy=Math.sin(state.yaw);
 const xp=x*cy-z*sy,zp=x*sy+z*cy;
 const cp=Math.cos(state.pitch),sp=Math.sin(state.pitch),yp=y*cp-zp*sp,zpp=y*sp+zp*cp;
 const zoom=4.4/(4.4-zpp*.43);
 return {x:500+xp*134*zoom,y:245+yp*134*zoom,z:zpp,w};
}
function shadow3(p){
 // Separate orthographic plane image of projected hypercube; it is not another source.
 const [x,y,z]=p;
 const u=x*.68+z*.42,v=y*.32-z*.46+x*.13;
 return {x:500+u*115,y:415+v*49};
}
function observed(){
 const attack=document.querySelectorAll('#plasmaMemoryAttack li[data-phase]:not([data-phase="quiet"])').length;
 const returnCount=document.querySelectorAll('#plasmaMemoryRecovery li[data-phase]:not([data-phase="quiet"])').length;
 const sealed=Number(document.getElementById('temporalProvenanceFreeze')?.dataset.sealed)||0;
 const linked=Number(document.getElementById('causalLineageAudit')?.dataset.linked)||0;
 return {attack,returnCount,sealed,linked};
}
function line(a,b,color,width,glow,opacity=1){
 ctx.globalAlpha=opacity;ctx.strokeStyle=color;ctx.lineWidth=width;
 ctx.shadowColor=color;ctx.shadowBlur=glow;ctx.beginPath();
 ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();ctx.shadowBlur=0;ctx.globalAlpha=1;
}
/* v2.9.21 — deterministic visual plasma on actual 4D hypercube edges.
 * No engine authority. When no attack or recovery evidence is observed, quiet.
 */
const PLASMA_EDGE_LIMIT=32;
/* Dimensionless visual-energy allocation. A normalized source budget is
 * allocated across the 32 actual edges. Edge, shadow, and quiet (dissipated)
 * allocations sum to that budget within floating-point tolerance.
 * This is a rendering-accounting identity, NOT physical energy or game RAM.
 */
let visualEnergy=Object.freeze({input:0,edge:0,shadow:0,quiet:0,residual:0,activeEdges:0,shadowEdges:0});
function visualEnergyFrame(activity,t){
 const input=clamp((activity.attack+activity.returnCount)/6,0,1);
 let edge=0,shadow=0,quiet=0,activeEdges=0,shadowEdges=0;
 if(input>0){
  const allotment=input/edges.length;
  for(let e=0;e<edges.length;e++){
   const axis=edges[e][2];
   const flow=.48+.20*(.5+.5*Math.sin(t*.88+e*.0618));
   const shadowShare=axis===3?.20:.08;
   const edgeShare=flow;
   const quietShare=1-edgeShare-shadowShare;
   edge+=allotment*edgeShare;
   shadow+=allotment*shadowShare;
   quiet+=allotment*quietShare;
   activeEdges++;
   if(axis===3)shadowEdges++;
  }
 }
 const residual=input-edge-shadow-quiet;
 return Object.freeze({input,edge,shadow,quiet,residual,activeEdges,shadowEdges});
}

/* v2.9.23: 32 independent visual edge reservoirs. Input is admitted
 * exclusively while an actual observed attack/recovery source is active.
 * When input disappears, each reservoir decays monotonically; no self-feed.
 * Memory is visual, bounded to [0,1], reset across match boundaries.
 */
const edgeMemory=new Float64Array(PLASMA_EDGE_LIMIT);
const PERSIST_HALF_LIFE=.72,PERSIST_QUIET=.0005;
let persistenceMatch=null,persistenceLast=null;
let persistence=Object.freeze({total:0,max:0,nonzero:0,quiet:true,input:0,halfLifeSeconds:PERSIST_HALF_LIFE,capacity:32,match:'none'});
function advancePersistence(activity,dt){
 const banner=document.getElementById('recoveryTelemetryStatus')?.textContent||'';
 const parsed=/MATCH\\s+(\\d+)/.exec(banner);
 const marker=parsed?.[1]||'none';
 if(persistenceMatch!==null&&marker!==persistenceMatch)edgeMemory.fill(0);
 persistenceMatch=marker;
 const input=clamp((activity.attack+activity.returnCount)/6,0,1);
 const decay=Math.exp(-Math.LN2*clamp(dt,0,.05)/PERSIST_HALF_LIFE);
 let total=0,max=0,nonzero=0;
 for(let i=0;i<edgeMemory.length;i++){
   // Observed input only. No neighboring edge may invent input.
   const drive=input>0?input*(.65+.35*Math.sin(i*.53+state.angle)**2):0;
   const next=clamp(edgeMemory[i]*decay+drive*(1-decay),0,1);
   edgeMemory[i]=next<PERSIST_QUIET?0:next;
   total+=edgeMemory[i];max=Math.max(max,edgeMemory[i]);
   if(edgeMemory[i]>0)nonzero++;
 }
 persistence=Object.freeze({total,max,nonzero,quiet:nonzero===0,input,
   halfLifeSeconds:PERSIST_HALF_LIFE,capacity:32,match:marker});
 return persistence;
}
function plasmaPass(view,shadow,activity,t){
 let bright=0,shadowBright=0;
 if(!motion?.matches){
  for(let e=0;e<edges.length;e++){
   const envelope=edgeMemory[e];if(envelope<=0)continue;
   const [a,b,axis]=edges[e],phase=(t*(axis===3?.62:.88)+e*.0618)%1;
   const color=axis===3?'#83fff3':axis===0?'#ffb26d':'#b98aff';
   const A=view[a],B=view[b],S=shadow[a],T=shadow[b];
   const last=clamp(phase-.16,0,1);
   const at=u=>({x:A.x+(B.x-A.x)*u,y:A.y+(B.y-A.y)*u});
   line(at(last),at(phase),color,axis===3?5:3.5,18+envelope*18,envelope*.85);
   bright++;
   if(axis===3){
     const atShadow=u=>({x:S.x+(T.x-S.x)*u,y:S.y+(T.y-S.y)*u});
     line(atShadow(last),atShadow(phase),'#76fff0',4,20,envelope*.36);
     shadowBright++;
   }
  }
 }
 section.dataset.plasmaEdges=String(bright);
 section.dataset.shadowPlasmaEdges=String(shadowBright);
 section.dataset.plasmaActive=String(bright>0);
 return {bright,shadowBright};
}
function draw(ts){
 const W=canvas.width,H=canvas.height;
 const reduced=!!motion?.matches;
 if(!state.last)state.last=ts;
 const dt=clamp((ts-state.last)/1000,0,.05);state.last=ts;
 if(!state.pause&&!reduced)state.angle+=dt*.36;
 const o=observed(),power=clamp((o.attack*1.4+o.returnCount+o.sealed*.08)/10,0,1);
 ctx.clearRect(0,0,W,H);
 const grad=ctx.createRadialGradient(500,242,25,500,270,565);
 grad.addColorStop(0,'#21163d');grad.addColorStop(.55,'#0c1029');grad.addColorStop(1,'#070a15');
 ctx.fillStyle=grad;ctx.fillRect(0,0,W,H);
 // Neon 3D coordinate field
 ctx.lineWidth=.7;ctx.strokeStyle='#5780cc24';
 for(let n=-8;n<=8;n++){
  const x=500+n*55;
  ctx.beginPath();ctx.moveTo(x,12);ctx.lineTo(x,510);ctx.stroke();
 }
 for(let y=25;y<520;y+=45){ctx.beginPath();ctx.moveTo(25,y);ctx.lineTo(975,y);ctx.stroke()}
 const p4=vertices.map(p=>project4(p,state.angle)),view=p4.map(view3),shadow=p4.map(shadow3);
 ctx.fillStyle='#060b1e88';ctx.fillRect(20,365,960,138);
 for(const [a,b,k] of edges)line(shadow[a],shadow[b],colors[k],1.1,5,.12+power*.09);
 // The 4D shadow appears behind the bright 3D projection.
 const depthOrder=edges.slice().sort((a,b)=>(view[a[0]].z+view[a[1]].z)-(view[b[0]].z+view[b[1]].z));
 for(const [a,b,k] of depthOrder){
  const mid=(view[a].z+view[b].z)/2;
  const alpha=clamp(.46+(mid+2)*.11, .23,1);
  line(view[a],view[b],colors[k],7+power*4,17+power*15,alpha*.25);
  line(view[a],view[b],colors[k],1.8+power*1.1,8+power*7,alpha);
 }
 visualEnergy=visualEnergyFrame(o,state.angle*1.618);
 advancePersistence(o,dt);
 const plasma=plasmaPass(view,shadow,o,state.angle*1.618);
 section.dataset.visualEnergyInput=String(visualEnergy.input);
 section.dataset.visualEnergyResidual=String(visualEnergy.residual);
 for(let i=0;i<view.length;i++){
  const p=view[i],radius=2.1+power*1.2;
  ctx.fillStyle=i%2?'#fff2ff':'#cffffb';ctx.shadowColor=colors[i%4];ctx.shadowBlur=14;
  ctx.beginPath();ctx.arc(p.x,p.y,radius,0,Math.PI*2);ctx.fill();
 }
 ctx.shadowBlur=0;
 // Core and measured readouts; zero input remains quiet, no fabricated pulses.
 ctx.fillStyle='#89eaff';ctx.textAlign='left';ctx.font='12px ui-monospace,monospace';
 ctx.fillText('16 VERTICES   /   32 EDGES   /   4D ROTATION',24,29);
 ctx.fillStyle='#b5b3d4';ctx.fillText('XY · XW · YW · ZW  →  3D  →  2D',24,48);
 ctx.fillText('SHADOW PROJECTION · SEPARATE GEOMETRY',24,500);
 ctx.textAlign='right';ctx.fillStyle='#ffe0a0';
 ctx.fillText('ATTACK '+o.attack+'  ·  RECOVERY '+o.returnCount,973,29);
 ctx.fillStyle='#8ffff0';ctx.fillText('SEALED '+o.sealed+'  ·  ID-LINKED '+o.linked,973,48);
 info.textContent='4D→3D SHADOW · '+o.attack+' ATTACK · '+o.returnCount+' RECOVERY · '+plasma.bright+' PLASMA EDGES · '+o.sealed+' SEALED · READ ONLY';
 section.dataset.vertices=String(vertices.length);section.dataset.edges=String(edges.length);
 section.dataset.causality='not-proven';section.dataset.gameplayMutation='none';
 state.frames++;
}
let raf=0;
function frame(t){draw(t);raf=requestAnimationFrame(frame)}
pause?.addEventListener('click',()=>{
 state.pause=!state.pause;pause.textContent=state.pause?'RESUME 4D ROTATION':'PAUSE 4D ROTATION';
 pause.setAttribute('aria-pressed',String(state.pause));
});
canvas.addEventListener('pointerdown',e=>{state.drag=true;state.dragX=e.clientX;state.dragY=e.clientY;canvas.setPointerCapture?.(e.pointerId)});
canvas.addEventListener('pointermove',e=>{
 if(!state.drag)return;
 state.yaw+=clamp((e.clientX-state.dragX)*.006,-.3,.3);
 state.pitch=clamp(state.pitch+clamp((e.clientY-state.dragY)*.005,-.3,.3),-1.25,1.25);
 state.dragX=e.clientX;state.dragY=e.clientY;
});
canvas.addEventListener('pointerup',()=>{state.drag=false});
canvas.addEventListener('pointercancel',()=>{state.drag=false});
window.addEventListener('pagehide',()=>cancelAnimationFrame(raf),{once:true});
draw(0);raf=requestAnimationFrame(frame);
window.neuroscapeTesseract=Object.freeze({snapshot:()=>Object.freeze({
 vertices:vertices.length,edges:edges.length,rotation4D:true,shadow3D:true,
 frames:state.frames,visualEnergy,persistence,plasmaEdgeLimit:PLASMA_EDGE_LIMIT,plasmaEdges:Number(section.dataset.plasmaEdges)||0,shadowPlasmaEdges:Number(section.dataset.shadowPlasmaEdges)||0,plasmaActive:section.dataset.plasmaActive==='true',causality:'not-proven',gameplayMutation:false
})});
})();
