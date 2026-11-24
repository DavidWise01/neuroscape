/* v2.9.22 · visual-only plasma conservation display.
 * Reads the tesseract's dimensionless snapshot; it has no gameplay references.
 */
(()=>{'use strict';
const root=document.getElementById('plasmaConservation'),status=document.getElementById('plasmaConservationStatus');
if(!root||!status)return;
const fields=['input','edge','shadow','quiet'];
const number=value=>Number.isFinite(value)?value.toFixed(6):'INVALID';
function paint(){
 const model=window.neuroscapeTesseract?.snapshot();
 const v=model?.visualEnergy;
 if(!v)return;
 const correct=Number.isFinite(v.residual)&&Math.abs(v.residual)<=1e-10;
 for(const name of fields){
  const el=document.getElementById('plasmaEnergy'+name[0].toUpperCase()+name.slice(1));
  const bar=document.getElementById('plasmaEnergyBar'+name[0].toUpperCase()+name.slice(1));
  if(el)el.textContent=number(v[name]);
  if(bar)bar.style.width=(Math.max(0,Math.min(1,v[name]))*100).toFixed(3)+'%';
 }
 status.textContent=(correct?'BALANCED':'ALLOCATION ERROR')+' · Δ '+number(v.residual)+
  ' · '+v.activeEdges+' EDGE ALLOCATIONS · '+v.shadowEdges+' 4D SHADOW EDGES';
 root.dataset.balanced=String(correct);
 root.dataset.authority='visual-only';
}
paint();setInterval(()=>{if(!document.hidden)paint()},200);
window.neuroscapeVisualConservation=Object.freeze({snapshot:()=>{
 const v=window.neuroscapeTesseract?.snapshot()?.visualEnergy;
 return Object.freeze({...(v||{}),balanced:!!v&&Math.abs(v.residual)<=1e-10,
   authority:'visual-only',writesToGameplay:false});
}});
})();
