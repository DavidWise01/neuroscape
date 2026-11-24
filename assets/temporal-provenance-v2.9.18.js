/* v2.9.18 — Temporal provenance freeze.
   Observation-only and match-scoped. The 32-entry sealed window is append-only
   until eviction; eviction is reported. No claim of durable persistence.
   Existing attack, recovery, and lineage displays remain authoritative for
   their own observed UI state. This module does NOT read or write game state. */
(()=>{'use strict';
 const root=document.getElementById('temporalProvenanceFreeze');
 if(!root)return;
 const list=document.getElementById('provenanceFreezeRows');
 const status=document.getElementById('provenanceFreezeStatus');
 const MAX_SEALED=32, MAX_LIVE=16, INTERVAL=200, QUIET_MS=5000;
 let match='unobserved', previousMatchSeen=false, serial=0, evicted=0;
 const live=new Map(),sealed=[];
 const freeze=record=>Object.freeze({...record,phases:Object.freeze(record.phases.map(p=>Object.freeze({...p})))});
 function phaseFromNode(node,kind){
   const age=Number(node.dataset.ageMs);
   if(!Number.isFinite(age)||age<0)return null;
   return {id:node.dataset.source,kind,phase:node.dataset.phase||'unknown',age};
 }
 function observe(){
   const rows=[];
   for(const [selector,kind] of [
     ['#plasmaMemoryAttack li[data-source]','attack'],
     ['#plasmaMemoryRecovery li[data-source]','recovery']]){
     document.querySelectorAll(selector).forEach(node=>{
       const row=phaseFromNode(node,kind);
       if(row?.id)rows.push(row);
     });
   }
   return rows.slice(-MAX_LIVE);
 }
 function sourceClassification(id,kind){
   if(kind==='attack')return 'ATTACK ROOT · ENGINE-OBSERVED';
   // Use only current existing audit DOM rows; no guessed linkage.
   const linked=[...document.querySelectorAll('#causalLineageRows li[data-release-source]')]
      .find(node=>node.dataset.releaseSource===id);
   return linked?.dataset.classification||'NOT CLASSIFIED IN VISIBLE AUDIT';
 }
 function snapshotRecord(item,reason){
   if(!item||item.sealed)return;
   const record=freeze({
     sequence:++serial,match,kind:item.kind,source:item.source,
     firstSeenMs:item.firstSeen,quietSeenMs:performance.now(),
     finalPhase:item.phase,classification:sourceClassification(item.source,item.kind),
     sealReason:reason,phases:item.phases
   });
   sealed.push(record);
   item.sealed=true;live.delete(item.key);
   if(sealed.length>MAX_SEALED){sealed.shift();evicted++}
 }
 function matchMarker(){
   const element=document.getElementById('recoveryTelemetryStatus');
   const text=element?.textContent||'';
   const found=/MATCH\s+(\d+)/.exec(text);
   return found?.[1]||null;
 }
 function sync(){
   const marker=matchMarker();
   if(marker&&marker!==match){
     // New match boundary. Do not allow last match's roots to be joined here.
     live.clear();sealed.length=0;serial=0;evicted=0;match=marker;previousMatchSeen=true;
   }else if(!marker&&previousMatchSeen){
     // Explicit zero-event match readout after restart.
     live.clear();sealed.length=0;serial=0;evicted=0;
     match='unobserved';previousMatchSeen=false;
   }
   const observed=observe(),at=performance.now(),seen=new Set();
   for(const sample of observed){
     const key=sample.kind+'|'+sample.id;
     seen.add(key);
     if(sealed.some(s=>s.kind===sample.kind&&s.source===sample.id))continue;
     let item=live.get(key);
     if(!item){
       item={key,kind:sample.kind,source:sample.id,phase:sample.phase,
         firstSeen:at,lastSeen:at,age:sample.age,phases:[],sealed:false};
       live.set(key,item);
     }
     item.lastSeen=at;item.age=sample.age;
     if(item.phase!==sample.phase||!item.phases.length){
       item.phase=sample.phase;
       item.phases.push({phase:sample.phase,observedAgeMs:sample.age});
       if(item.phases.length>16)item.phases.shift();
     }
     if(sample.phase==='quiet'||sample.age>=QUIET_MS)
       snapshotRecord(item,'QUIET OBSERVED');
   }
   for(const item of [...live.values()]){
     if(seen.has(item.key))continue;
     // Disappearance alone cannot establish quiet. Preserve as unsettled,
     // and never falsely promote to a completed record.
     if(at-item.lastSeen>1000){
       snapshotRecord(item,'OBSERVATION LOST · QUIET UNVERIFIED');
     }
   }
   while(live.size>MAX_LIVE){
     const oldest=live.values().next().value;
     snapshotRecord(oldest,'CAPACITY EXIT · QUIET UNVERIFIED');
   }
   render();
 }
 function render(){
   status.textContent=sealed.length+' SEALED · '+live.size+' OBSERVED LIVE · '+evicted+' EVICTED · MATCH '+match;
   root.dataset.sealed=String(sealed.length);
   root.dataset.evicted=String(evicted);
   list.replaceChildren(...sealed.slice(-10).reverse().map(item=>{
     const row=document.createElement('li');
     row.dataset.source=item.source;
     row.dataset.sealReason=item.sealReason;
     const source=document.createElement('strong');source.textContent='#'+item.sequence+' · '+item.kind.toUpperCase()+' · '+item.source;
     const meta=document.createElement('span');meta.textContent=item.classification+' · '+item.sealReason;
     const phases=document.createElement('small');phases.textContent=item.phases.map(p=>p.phase).join(' → ')||'NO PHASE OBSERVED';
     row.append(source,meta,phases);return row;
   }));
 }
 function snapshot(){
   return Object.freeze({match,sealedCount:sealed.length,liveCount:live.size,
    evicted,retention:MAX_SEALED,appendOnlyWithinWindow:true,durable:false,
    records:Object.freeze(sealed.slice()),causality:'not-proven'});
 }
 const download=document.getElementById('provenanceFreezeExport');
 download?.addEventListener('click',()=>{
   const payload=JSON.stringify({schema:'neuroscape-temporal-provenance-1',...snapshot()},null,2);
   const blob=new Blob([payload],{type:'application/json'});
   const url=URL.createObjectURL(blob);
   const a=document.createElement('a');
   a.href=url;a.download='neuroscape-v2.9.18-provenance.json';
   document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),1000);
 });
 sync();setInterval(()=>{if(!document.hidden)sync()},INTERVAL);
 window.neuroscapeProvenanceFreeze=Object.freeze({snapshot});
})();
