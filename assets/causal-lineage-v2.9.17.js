/* Neuroscape v2.9.17 · read-only event-lineage adjudicator.
 * Observes existing DOM telemetry only. Event-ID linkage is evidence of
 * engine-reported ancestry, never an independent witness or causal proof.
 * No game-state reads, replay, synthetic records, or writable hooks. */
(()=>{'use strict';
 const root=document.getElementById('causalLineageAudit');
 if(!root)return;
 const attackSel='#plasmaMemoryAttack li[data-source]';
 const recoverySel='#recoveryTelemetryP ol li,#recoveryTelemetryE ol li';
 const rows=document.getElementById('causalLineageRows');
 const summary=document.getElementById('causalLineageStatus');
 const safeCount=16;
 let currentMatch='', lastSignature='';
 const asAttack=key=>/^attack:(\d+):([pe])$/.exec(key||'');
 const asRecovery=key=>/^attack:(\d+):flow:(\d+):([pe])$/.exec(key||'');
 function collect(){
  const attacks=[...document.querySelectorAll(attackSel)].map(node=>({
    id:node.dataset.source||'',phase:node.dataset.phase||'unknown',
    age:Number(node.dataset.ageMs)
  })).filter(x=>asAttack(x.id)&&Number.isFinite(x.age)).slice(-8);
  const returns=[...document.querySelectorAll(recoverySel)].map(node=>{
    const value=node.textContent||'';
    const match=value.match(/(?:attack:\d+:flow:\d+:[pe])|(?:release:\d+:flow:\d+:[pe])/);
    return {id:match?.[0]||'',status:node.querySelector('.recoveryState')?.textContent||'unknown',
     amount:Number(value.match(/\+([\d.]+) RAM/)?.[1])};
  }).filter(x=>x.id).slice(-safeCount);
  return {attacks,returns};
 }
 function classify(data){
  const links=[];
  for(const release of data.returns){
   const match=asRecovery(release.id);
   if(!match){
    links.push({release:release.id,attack:null,classification:'UNLINKED',
      rationale:'No explicit attack identifier'});
    continue;
   }
   const seq=match[1],side=match[3];
   const attack=data.attacks.find(a=>{
     const parsed=asAttack(a.id);return parsed&&parsed[1]===seq;
   });
   if(!attack){
    links.push({release:release.id,attack:null,classification:'UNVERIFIED ROOT',
      rationale:'Attack root not present in bounded observation window'});
   }else{
    // An exact matching attack seq supports asserted event lineage only.
    // A matching source side would be coincidental: impact may release either side.
    links.push({release:release.id,attack:attack.id,classification:'ID-LINKED',
      rationale:'Matching recorded attack sequence; not independent corroboration'});
   }
  }
  // Only a bounded subset is observable, so lack of a link is not disproof.
  return links;
 }
 function draw(){
  const stamp=document.getElementById('recoveryTelemetryStatus')?.textContent||'';
  const m=/MATCH\s+(\d+)/.exec(stamp);
  const marker=m?.[1]||'none';
  if(marker!==currentMatch){currentMatch=marker;lastSignature=''}
  const d=collect(),result=classify(d);
  const signature=JSON.stringify({match:currentMatch,attacks:d.attacks,returns:d.returns,links:result});
  if(signature===lastSignature)return;
  lastSignature=signature;
  rows.replaceChildren(...result.map(link=>{
   const li=document.createElement('li');li.dataset.classification=link.classification;
   li.dataset.releaseSource=link.release;
   if(link.attack)li.dataset.attackSource=link.attack;
   const label=document.createElement('strong');label.textContent=link.classification;
   const detail=document.createElement('span');
   detail.textContent=(link.attack||'NO VISIBLE ATTACK ROOT')+' ∥ '+link.release;
   const note=document.createElement('small');note.textContent=link.rationale;
   li.append(label,detail,note);return li;
  }));
  const linked=result.filter(x=>x.classification==='ID-LINKED').length;
  const unverified=result.filter(x=>x.classification==='UNVERIFIED ROOT').length;
  summary.textContent=linked+' ID-LINKED · '+unverified+' UNVERIFIED ROOT · '+
    (result.length-linked-unverified)+' UNLINKED · '+d.attacks.length+' ATTACK ROOTS VISIBLE';
  root.dataset.causality='not-proven';root.dataset.independentWitnesses='0';
  root.dataset.linked=String(linked);root.dataset.unverified=String(unverified);
 }
 function snapshot(){
  const d=collect(),links=classify(d);
  return Object.freeze({match:currentMatch,attacks:d.attacks.length,returns:d.returns.length,
    linked:links.filter(x=>x.classification==='ID-LINKED').length,
    unverified:links.filter(x=>x.classification==='UNVERIFIED ROOT').length,
    lineage:links.map(x=>Object.freeze({...x})),causality:'not-proven',
    independentWitnesses:0});
 }
 draw();setInterval(()=>{if(!document.hidden)draw()},220);
 window.neuroscapeCausalAudit=Object.freeze({snapshot});
})();
