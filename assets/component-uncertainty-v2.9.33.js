/* Neuroscape v2.9.33 — componentized uncertainty provenance.
 * No empirical calibration is claimed. Components are DECLARED assumptions
 * until separately measured and independently sourced.
 * Additive worst-case propagation assumes no cancellation and no independence.
 * Each sensitivity result removes one assumption solely for WHAT-IF audit;
 * no what-if result changes the authoritative conservative classification.
 */
(()=>{'use strict';
const root=document.getElementById('componentUncertaintyLab'),
      period=document.getElementById('componentUncertaintyPeriod'),
      bars=document.getElementById('componentUncertaintyBars'),
      table=document.getElementById('componentUncertaintySensitivity'),
      status=document.getElementById('componentUncertaintyStatus'),
      totalEl=document.getElementById('componentUncertaintyTotal');
if(!root||!period||!bars||!table||!status||!totalEl)return;
const margins=window.neuroscapeAdversarialMargin;
if(!margins)return;
const defaults=Object.freeze([
 {id:'sampling',name:'Sampling resolution',value:.025,provenance:'DECLARED / NO CALIBRATION'},
 {id:'clock',name:'Clock / scheduling',value:.050,provenance:'DECLARED / NO CALIBRATION'},
 {id:'model',name:'Model mismatch',value:.075,provenance:'DECLARED / NO CALIBRATION'}
]);
const COMPONENT_MAX=.3,COMBINED_MAX=.9,rows=new Map();
const periods=Object.freeze(margins.results().map(row=>row.period));
function classify(margin,epsilon){
 if(!Number.isFinite(margin)||!Number.isFinite(epsilon)||epsilon<0)throw Error('Invalid margin or uncertainty');
 const lower=margin-epsilon,upper=margin+epsilon;
 return Object.freeze({margin,epsilon,lower,upper,
   classification:lower>=0?'CONFIRMED STABLE':upper<0?'CONFIRMED UNSTABLE':'INDETERMINATE'});
}
function calculate(base,components){
 if(!Array.isArray(components)||components.length!==3)throw Error('Three declared components required');
 const ids=new Set(),clean=components.map(c=>{
  if(!c||!['sampling','clock','model'].includes(c.id)||ids.has(c.id)||
     !Number.isFinite(c.value)||c.value<0||c.value>COMPONENT_MAX)
    throw Error('Invalid or duplicate component');
  ids.add(c.id);
  return Object.freeze({id:c.id,value:c.value,source:c.source||'declared-only'});
 });
 if(ids.size!==3)throw Error('Missing uncertainty component');
 const epsilon=clean.reduce((a,c)=>a+c.value,0);
 const policies=Object.freeze(Object.fromEntries(['fixed','adaptive'].map(policy=>[
   policy,classify(base[policy].margin,epsilon)
 ])));
 const sensitivity=Object.freeze(clean.map(comp=>{
   const reduced=epsilon-comp.value;
   return Object.freeze({id:comp.id,removedWidth:comp.value,
     fixed:classify(base.fixed.margin,reduced),
     adaptive:classify(base.adaptive.margin,reduced),
     mayChangeDecision:policies.fixed.classification!==classify(base.fixed.margin,reduced).classification||
       policies.adaptive.classification!==classify(base.adaptive.margin,reduced).classification});
 }));
 return Object.freeze({epsilon,components:Object.freeze(clean),
   policies,sensitivity,
   evidenceLevel:'DECLARED ASSUMPTIONS — NOT EMPIRICALLY CALIBRATED',
   independenceAssumed:false,
   sourceMutated:false,gameplayMutation:false});
}
period.replaceChildren(...periods.map(p=>{
 const option=document.createElement('option');
 option.value=String(p);option.textContent=p.toFixed(2)+' s';return option;
}));
period.value='3';
for(const comp of defaults){
 const wrap=document.createElement('div');wrap.className='componentRow';
 const name=document.createElement('label');name.htmlFor='componentUncertainty_'+comp.id;
 name.textContent=comp.name+' · '+comp.provenance;
 const input=document.createElement('input');
 input.id='componentUncertainty_'+comp.id;input.type='range';
 input.min='0';input.max=String(COMPONENT_MAX);input.step='.005';input.value=String(comp.value);
 const value=document.createElement('output');value.textContent='±'+comp.value.toFixed(3)+'rad';
 wrap.append(name,input,value);bars.append(wrap);
 rows.set(comp.id,{input,value});
 input.addEventListener('input',render);
}
function assumptions(){
 return defaults.map(c=>({id:c.id,value:Number(rows.get(c.id).input.value),source:'declared-only'}));
}
function inspect(p,components){
 if(!periods.includes(p))throw Error('Unknown period');
 return calculate(margins.audit(p),components);
}
function render(){
 const p=Number(period.value),report=inspect(p,assumptions());
 for(const c of report.components){
   rows.get(c.id).value.textContent='±'+c.value.toFixed(3)+'rad';
 }
 totalEl.textContent='Σ ε = ±'+report.epsilon.toFixed(3)+'rad · ADDITIVE WORST CASE';
 const fmt=v=>v.classification+' ['+v.lower.toFixed(3)+', '+v.upper.toFixed(3)+']';
 status.textContent='FIXED '+fmt(report.policies.fixed)+' · ADAPTIVE '+fmt(report.policies.adaptive);
 table.replaceChildren();
 for(const item of report.sensitivity){
   const tr=document.createElement('div');tr.className='componentSensitivityRow';
   tr.textContent='REMOVE '+item.id.toUpperCase()+' → '+(item.mayChangeDecision?'DECISION-SENSITIVE':'NO DECISION CHANGE')+
     ' · ε = ±'+(report.epsilon-item.removedWidth).toFixed(3)+'rad';
   tr.dataset.sensitive=String(item.mayChangeDecision);
   table.append(tr);
 }
 root.dataset.authority='visual-only';
 root.dataset.calibrated='false';
 root.dataset.epsilon=String(report.epsilon);
 root.dataset.period=String(p);
 root.dataset.fixed=report.policies.fixed.classification;
 root.dataset.adaptive=report.policies.adaptive.classification;
}
period.addEventListener('change',render);
render();
window.neuroscapeComponentUncertainty=Object.freeze({
 classify,calculate,inspect,
 snapshot:()=>Object.freeze({
   components:3,period:Number(root.dataset.period),
   epsilon:Number(root.dataset.epsilon),
   fixed:root.dataset.fixed,adaptive:root.dataset.adaptive,
   evidenceCalibrated:false,independenceAssumed:false,
   sourceMutated:false,gameplayMutation:false
 })
});
})();