/* v2.9.24 · independent phase-coherence display.
 * Reads frozen tesseract snapshots only, no engine state or memory mutation.
 */
(()=>{'use strict';
 const host=document.getElementById('plasmaResonancePanel');
 const status=document.getElementById('plasmaResonanceStatus');
 const rings=document.getElementById('plasmaResonanceRings');
 if(!host||!status||!rings)return;
 const NS='http://www.w3.org/2000/svg';
 const palette=['#ffae72','#bc83ff','#72f8e8','#85bfff'];
 const circles=[];
 for(let axis=0;axis<4;axis++){
   const ring=document.createElementNS(NS,'circle');
   ring.setAttribute('cx',String(75+axis*108));
   ring.setAttribute('cy','76');ring.setAttribute('r','37');
   ring.setAttribute('fill','none');ring.setAttribute('stroke',palette[axis]);
   ring.setAttribute('stroke-width','7');ring.setAttribute('pathLength','100');
   ring.setAttribute('stroke-dasharray','0 100');
   ring.setAttribute('transform',`rotate(-90 ${75+axis*108} 76)`);
   rings.append(ring);circles.push(ring);
   const label=document.createElementNS(NS,'text');
   label.setAttribute('x',String(75+axis*108));label.setAttribute('y','80');
   label.setAttribute('text-anchor','middle');label.setAttribute('font-size','11');
   label.setAttribute('fill','#eafaff');label.textContent=['X','Y','Z','W'][axis];
   rings.append(label);
 }
 function paint(){
   const r=window.neuroscapeTesseract?.snapshot()?.resonance;
   if(!r)return;
   for(let axis=0;axis<4;axis++){
     const group=r.groups[axis],value=group.coherence;
     circles[axis].setAttribute('stroke-dasharray',value===null?'0 100':(value*100).toFixed(2)+' 100');
     circles[axis].setAttribute('opacity',value===null?'.3':'1');
     circles[axis].dataset.active=String(group.active);
   }
   status.textContent=r.defined?
     'COHERENCE '+(r.coherence*100).toFixed(2)+'% · '+r.active+' INDEPENDENT EDGES':
     'QUIET · COHERENCE UNDEFINED · NO OBSERVED EDGE ENERGY';
   host.dataset.defined=String(r.defined);host.dataset.active=String(r.active);
   host.dataset.coherence=r.coherence===null?'undefined':String(r.coherence);
 }
 paint();setInterval(()=>{if(!document.hidden)paint()},200);
 window.neuroscapeResonanceDisplay=Object.freeze({snapshot:()=>{
   const r=window.neuroscapeTesseract?.snapshot()?.resonance;
   return Object.freeze({defined:r?.defined||false,coherence:r?.coherence??null,
     active:r?.active||0,groupCount:r?.groups?.length||0,visualOnly:true,
     gameplayMutation:false});
 }});
})();
