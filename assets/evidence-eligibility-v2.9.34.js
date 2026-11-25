/* Neuroscape v2.9.34 — metadata evidence eligibility (append-only).
 * Metadata completeness does not authenticate calibration.
 * Only a separate, independently verified acquisition process could grant
 * empirical authority; this UI deliberately cannot issue that credential.
 * Does not read or write gameplay or visual edge-reservoir states.
 */
(()=>{'use strict';
const host=document.getElementById('componentEvidenceLab');
const rowsHost=document.getElementById('componentEvidenceRows');
const status=document.getElementById('componentEvidenceStatus');
const reset=document.getElementById('componentEvidenceReset');
if(!host||!rowsHost||!status||!reset)return;
const IDS=Object.freeze(['sampling','clock','model']);
const FIELDS=Object.freeze(['method','calibrationRef','timestamp','provenance']);
const values=new Map();
const initial=Object.freeze(Object.fromEntries(IDS.map(id=>[id,Object.freeze({
 method:'',calibrationRef:'',timestamp:'',provenance:''
})])));
const trim=v=>typeof v==='string'?v.trim():'';
function auditRecord(entry){
 const missing=FIELDS.filter(field=>!trim(entry?.[field]));
 const timestamp=trim(entry?.timestamp);
 const parsed=Date.parse(timestamp);
 const validTimestamp=/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?(?:Z|[+-]\d\d:\d\d)$/.test(timestamp)&&
   Number.isFinite(parsed)&&new Date(parsed).getTime()===parsed;
 const errors=[];
 if(timestamp&&!validTimestamp)errors.push('INVALID TIMESTAMP');
 if(trim(entry?.method).length>0&&trim(entry?.method).length<5)errors.push('METHOD TOO SHORT');
 if(trim(entry?.provenance).length>0&&trim(entry?.provenance).length<5)errors.push('PROVENANCE TOO SHORT');
 const complete=missing.length===0&&errors.length===0;
 return Object.freeze({
   complete,missing:Object.freeze(missing),errors:Object.freeze(errors),
   status:complete?'READY FOR INDEPENDENT REVIEW':'INCOMPLETE / DECLARED',
   empiricalVerified:false,authority:'none',provenanceAuthenticated:false,
   independentEvidenceConfirmed:false
 });
}
function auditAll(records){
 const audits=IDS.map(id=>Object.freeze({id,...auditRecord(records[id])}));
 return Object.freeze({components:Object.freeze(audits),
  completeCount:audits.filter(v=>v.complete).length,
  empiricalVerifiedCount:0,gameplayMutation:false});
}
function build(){
 for(const id of IDS){
   const section=document.createElement('fieldset');section.className='evidenceItem';
   const legend=document.createElement('legend');legend.textContent=id.toUpperCase()+' · CALIBRATION DOSSIER';
   section.append(legend);
   const fields={};
   for(const field of FIELDS){
     const wrap=document.createElement('label');wrap.className='evidenceField';
     const name=document.createElement('span');name.textContent=field==='calibrationRef'?'CALIBRATION REFERENCE':field.toUpperCase();
     const input=document.createElement('input');
     input.type='text';input.autocomplete='off';input.spellcheck=false;
     input.id='evidence_'+id+'_'+field;
     input.placeholder=field==='timestamp'?'2026-11-24T19:00:00-06:00':
       field==='provenance'?'Issuer + source ancestry':
       field==='calibrationRef'?'Calibration record ID or URI':'Measurement procedure';
     input.maxLength=256;
     input.setAttribute('aria-label',id+' '+field);
     wrap.append(name,input);section.append(wrap);fields[field]=input;
     input.addEventListener('input',render);
   }
   const verdict=document.createElement('output');verdict.className='evidenceVerdict';
   verdict.id='evidenceVerdict_'+id;verdict.textContent='INCOMPLETE / DECLARED';
   section.append(verdict);rowsHost.append(section);
   values.set(id,{fields,verdict});
 }
}
function current(){
 return Object.fromEntries(IDS.map(id=>[id,Object.fromEntries(FIELDS.map(field=>[
   field,values.get(id).fields[field].value
 ]))]));
}
function render(){
 const result=auditAll(current());
 for(const row of result.components){
   const v=values.get(row.id).verdict;
   v.textContent=row.status+(row.errors.length?' · '+row.errors.join(', '):'')+
     (row.missing.length?' · MISSING '+row.missing.join(', '):'');
   v.dataset.complete=String(row.complete);
 }
 status.textContent=result.completeCount+'/3 METADATA-COMPLETE · '+result.empiricalVerifiedCount+
  ' EMPIRICALLY VERIFIED · NO OPERATIONAL AUTHORITY';
 host.dataset.complete=String(result.completeCount);
 host.dataset.empiricalVerified='0';
 host.dataset.authority='read-only';
}
build();render();
reset.addEventListener('click',()=>{
 for(const {fields} of values.values())for(const item of Object.values(fields))item.value='';
 render();
});
window.neuroscapeEvidenceEligibility=Object.freeze({
 auditRecord,auditAll,
 snapshot:()=>Object.freeze({
   ...auditAll(current()),metadataOnly:true,independentVerificationAvailable:false,
   sourceMutated:false,gameplayMutation:false
 })
});
})();