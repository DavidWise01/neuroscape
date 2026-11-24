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
 info.textContent='4D→3D SHADOW · '+o.attack+' ATTACK · '+o.returnCount+' RECOVERY · '+o.sealed+' SEALED · READ ONLY';
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
 frames:state.frames,causality:'not-proven',gameplayMutation:false
})});
})();
