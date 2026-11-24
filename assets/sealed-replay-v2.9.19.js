/* Neuroscape v2.9.19 — isolated sealed-memory integrity and replay inspector.
 * Only reads exported JSON and the v2.9.18 public snapshot. Never touches
 * engine controls, RAM, event capture, or live telemetry.
 * Hashes prove byte-equivalent canonical payloads against an available
 * trustworthy baseline, NOT historical truth or independent witnesses. */
(()=>{'use strict';
 const root=document.getElementById('sealedReplayAudit');
 if(!root)return;
 const $=id=>document.getElementById(id);
 const status=$('sealedReplayStatus'),list=$('sealedReplayRows'),file=$('sealedReplayFile');
 const MAX=32,MAX_BYTES=250000;
 let baseline=null,loaded=null,report=null;
 const plain=(o)=>Object.getPrototypeOf(o)===Object.prototype||Object.getPrototypeOf(o)===null;
 function validate(input){
   if(!input||!plain(input))throw Error('Expected JSON object');
   if(input.schema!=='neuroscape-temporal-provenance-1')throw Error('Unsupported provenance schema');
   if(typeof input.match!=='string'||!/^\d+$/.test(input.match))throw Error('Missing numeric match boundary');
   if(!Array.isArray(input.records)||input.records.length>MAX)throw Error('Invalid bounded records');
   if(!Number.isSafeInteger(input.evicted)||input.evicted<0)throw Error('Invalid evictions');
   if(!Number.isSafeInteger(input.sealedCount)||input.sealedCount!==input.records.length)throw Error('Sealed count mismatch');
   const seen=new Set();let previous=0;
   for(const r of input.records){
     if(!r||!plain(r)||!Number.isSafeInteger(r.sequence)||r.sequence<=previous)
       throw Error('Non-monotonic sealed sequence');
     previous=r.sequence;
     if(r.match!==input.match)throw Error('CROSS-MATCH BOUNDARY VIOLATION');
     if(!['attack','recovery'].includes(r.kind)||typeof r.source!=='string'||r.source.length>180)
       throw Error('Invalid source identity');
     if(r.kind==='attack'&&!/^attack:\d+:[pe]$/.test(r.source))throw Error('Invalid attack identity');
     if(r.kind==='recovery'&&!/^(?:attack:\d+|release:\d+):flow:\d+:[pe]$/.test(r.source))
       throw Error('Invalid recovery identity');
     const key=r.kind+'|'+r.source;if(seen.has(key))throw Error('Duplicate source root');seen.add(key);
     if(typeof r.sealReason!=='string'||!r.sealReason)throw Error('Missing sealing evidence');
     if(!Array.isArray(r.phases)||r.phases.length>16)throw Error('Invalid phase window');
     let last=-1;
     for(const p of r.phases){
       if(!p||!plain(p)||typeof p.phase!=='string'||!Number.isFinite(p.observedAgeMs)||p.observedAgeMs<last)
         throw Error('Nonmonotonic phase observations');
       last=p.observedAgeMs;
     }
   }
   if(input.causality!=='not-proven'||input.durable!==false)
     throw Error('Provenance authority escalation');
   return input;
 }
 function canonical(value){
   if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
   if(value&&typeof value==='object')
     return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
   return JSON.stringify(value);
 }
 async function digest(value){
   const bytes=new TextEncoder().encode(canonical(value));
   const result=await crypto.subtle.digest('SHA-256',bytes);
   return [...new Uint8Array(result)].map(v=>v.toString(16).padStart(2,'0')).join('');
 }
 function render(text,records=[]){
   status.textContent=text;
   list.replaceChildren(...records.slice(-10).map(r=>{
     const row=document.createElement('li');row.dataset.source=r.source;
     const head=document.createElement('strong');head.textContent=r.kind.toUpperCase()+' · '+r.source;
     const detail=document.createElement('small');detail.textContent='MATCH '+r.match+' · #'+r.sequence+' · '+r.sealReason+' · '+r.classification;
     row.append(head,detail);return row;
   }));
 }
 async function inspect(input){
   const record=validate(input),hash=await digest(record);
   const same=baseline!==null&&baseline.hash===hash;
   const state=same?'BASELINE MATCH':baseline===null?'UNANCHORED · NO TRUSTED HASH':'HASH MISMATCH';
   loaded=structuredClone(record);
   report=Object.freeze({status:state,hash,match:record.match,count:record.records.length,
     baselineHash:baseline?.hash||null,causality:'not-proven',replayedToEngine:false});
   render(state+' · SHA-256 '+hash.slice(0,16)+'… · '+record.records.length+' SEALED',record.records);
   return report;
 }
 $('sealedReplayCapture')?.addEventListener('click',async()=>{
   try{
     if(!window.neuroscapeProvenanceFreeze)throw Error('No local provenance snapshot');
     const snap=window.neuroscapeProvenanceFreeze.snapshot();
     if(snap.match==='unobserved')throw Error('No observed match identity');
     const record={schema:'neuroscape-temporal-provenance-1',...snap};
     baseline={hash:await digest(validate(record)),match:record.match};
     await inspect(record);
   }catch(e){render('CAPTURE REJECTED · '+e.message)}
 });
 file?.addEventListener('change',async()=>{
   try{
     const picked=file.files?.[0];if(!picked)return;
     if(picked.size>MAX_BYTES)throw Error('File exceeds 250 KB limit');
     const value=JSON.parse(await picked.text());
     await inspect(value);
   }catch(e){report=null;loaded=null;render('REPLAY REJECTED · '+e.message)}
   finally{file.value=''}
 });
 $('sealedReplayDownload')?.addEventListener('click',()=>{
   if(!loaded||!report)return;
   const payload=JSON.stringify({schema:'neuroscape-replay-audit-1',report,records:loaded.records},null,2);
   const url=URL.createObjectURL(new Blob([payload],{type:'application/json'}));
   const a=document.createElement('a');a.href=url;a.download='neuroscape-v2.9.19-audit.json';
   document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
 });
 window.neuroscapeSealedReplay=Object.freeze({
   snapshot:()=>Object.freeze({loaded:!!loaded,status:report?.status||'NO EVIDENCE',baseline:!!baseline,
     replayedToEngine:false,records:loaded?.records.length||0}),
   verify:async input=>inspect(structuredClone(input))
 });
 render('NO EVIDENCE · NO ENGINE REPLAY');
})();
