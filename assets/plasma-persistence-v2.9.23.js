/* v2.9.23 — read-only edge persistence panel. */
(()=>{'use strict';
const host=document.getElementById('plasmaPersistencePanel'),bars=document.getElementById('plasmaPersistenceBars'),status=document.getElementById('plasmaPersistenceStatus');
if(!host||!bars||!status)return;
for(let i=0;i<32;i++){
 const cell=document.createElement('i');cell.dataset.edge=String(i);cell.title='4D tesseract edge '+i;
 cell.setAttribute('aria-hidden','true');bars.append(cell);
}
function paint(){
 const p=window.neuroscapeTesseract?.snapshot()?.persistence;
 if(!p)return;
 // Aggregate persistence determines bar intensity; this readout does not
 // reconstruct unknown per-edge evidence or claim independent witnesses.
 const intensity=p.max;
 const entries=bars.children;
 for(let i=0;i<entries.length;i++){
  const modulation=.65+.35*Math.sin(i*.53)**2;
  entries[i].style.opacity=String(.14+Math.min(1,intensity*modulation)*.86);
 }
 status.textContent=p.quiet?'QUIET · ZERO STORED PLASMA':
  'MEMORY '+p.total.toFixed(4)+' / 32 · '+p.nonzero+' ACTIVE EDGES · t½ '+p.halfLifeSeconds+'s';
 host.dataset.quiet=String(p.quiet);host.dataset.activeEdges=String(p.nonzero);
}
paint();setInterval(()=>{if(!document.hidden)paint()},200);
window.neuroscapePlasmaPersistence=Object.freeze({snapshot:()=>Object.freeze({
 ...(window.neuroscapeTesseract?.snapshot()?.persistence||{}),
 gameplayMutation:false,visualOnly:true
})});
})();
