/* RUST-003: compiled Rust gameplay shadow parity, observation-only.
 * Samples cards and deterministic cloned combat boards through the actual
 * JavaScript cost(), free(), legalActions() and predictedTarget() engine.
 * Rust never receives arena ownership; no state is mutated.
 */
(()=>{'use strict';
const root=document.getElementById('neuroscapeRustShadowLab');
const status=document.getElementById('neuroscapeRustShadowStatus');
const detail=document.getElementById('neuroscapeRustShadowDetail');
if(!root||!status||!detail)return;
let phase='LOADING',checks=0,passed=0,reason='';
function paint(){
 root.dataset.phase=phase;
 status.textContent='RUST SHADOW '+phase+' · '+passed+'/'+checks+' GAMEPLAY CHECKS';
 detail.textContent=reason||'DEPLOYMENT + ATTACK SHADOW · NO GAMEPLAY AUTHORITY · .dlw';
}
const ready=(async()=>{
 try{
   const b64=window.NEUROSCAPE_RUST_WASM_BASE64;
   if(typeof b64!=='string'||b64.length<50)throw Error('Missing compiled Rust WASM binary');
   const bin=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
   const {instance}=await WebAssembly.instantiate(bin,{});
   const w=instance.exports;
   for(const name of ['ns_shadow_free_ram','ns_shadow_deploy_legal','ns_shadow_attacker_after',
     'ns_shadow_defender_after','ns_shadow_meter_after',
     'ns_shadow_attacker_destroyed','ns_shadow_defender_destroyed']){
      if(typeof w[name]!=='function')throw Error('Missing Rust shadow ABI export: '+name);
   }
   const validate=ok=>{checks++;if(ok)passed++};
   // Native catalog cards; card costs are computed by the REAL JavaScript engine.
   const cards=CATALOG.cards.filter(c=>Number.isInteger(c.num)&&Number.isFinite(c.a)&&Number.isFinite(c.d));
   if(cards.length<200)throw Error('Expected complete native card catalog');
   for(const c of cards){
     const ownCost=cost(card(c.num));
     for(const ram of [0,1,3,5,8,13,21,25]){
       validate(w.ns_shadow_free_ram(ram,ownCost)===ram-ownCost);
       for(const occupied of [0,1,4,5]){
         const expected=occupied<5&&ownCost<=ram;
         validate(Boolean(w.ns_shadow_deploy_legal(ram,ownCost,occupied))===expected);
       }
     }
   }
   // Use copied real card data and the actual engine predictedTarget() logic.
   const attackers=cards.filter(c=>c.a>0).slice(0,32);
   const defenders=cards.slice(0,32);
   let boards=0;
   for(const a of attackers){
     for(const d of defenders){
       for(const blocked of [false,true]){
         const attackerHp=Math.max(1,Number(a.d));
         const defenderHp=Math.max(1,Number(d.d));
         const simulated={...state,done:false,active:'p',phase:2,
           p:{...state.p,units:[{n:a.num,hp:attackerHp,used:false,uid:'rust-shadow-p'}]},
           e:{...state.e,bf:17,mf:19,units:blocked?
             [{n:d.num,hp:defenderHp,used:false,uid:'rust-shadow-e'}]:[]}};
         const target=predictedTarget(simulated,'p',0);
         if(!target)throw Error('Native JS predictedTarget rejected a valid shadow board');
         const isBlocked=Number(target.kind==='blocked');
         const before=target.kind==='direct'?target.meterHp:0;
         validate(w.ns_shadow_attacker_after(attackerHp,target.damage,target.retaliation,isBlocked)===target.attackerAfter);
         validate(!blocked||w.ns_shadow_defender_after(defenderHp,target.damage,isBlocked)===target.defenderAfter);
         validate(blocked||w.ns_shadow_meter_after(before,target.damage,isBlocked)===target.meterAfter);
         validate(Boolean(w.ns_shadow_attacker_destroyed(attackerHp,target.retaliation,isBlocked))===target.attackerDestroyed);
         validate(Boolean(w.ns_shadow_defender_destroyed(defenderHp,target.damage,isBlocked))===target.defenderDestroyed);
         boards++;
       }
     }
   }
   // Capture actual live board snapshot; never change active side or turn.
   const snapshot={turn:state.turn,phase:state.phase,active:state.active,done:state.done,
     ram:state.p.ram,units:state.p.units.length,hand:state.p.hand.length};
   validate(w.ns_shadow_free_ram(state.p.ram,committed(state.p))===free(state.p));
   if(snapshot.turn!==state.turn||snapshot.phase!==state.phase||
     snapshot.active!==state.active||snapshot.ram!==state.p.ram||
     snapshot.units!==state.p.units.length||snapshot.hand!==state.p.hand.length)
     throw Error('Gameplay state changed during shadow parity execution');
   if(passed!==checks)throw Error('Gameplay parity diverged: '+passed+'/'+checks);
   phase='PASS';reason=boards+' CLONED REAL-CARD COMBAT BOARDS · '+cards.length+
     ' CATALOG CARDS · JS ENGINE REMAINS AUTHORITATIVE';
   paint();
   return Object.freeze({pass:true,checked:checks,passed,boards,cards:cards.length,
     originalStatePreserved:true,sourceMutated:false,gameplayMutation:false});
 }catch(error){
   phase='FAIL';reason=String(error?.message||error);paint();
   return Object.freeze({pass:false,checked:checks,passed,reason,gameplayMutation:false});
 }
})();
paint();
window.neuroscapeRustShadow=Object.freeze({
 ready,
 snapshot:()=>Object.freeze({phase,checked:checks,passed,reason,gameplayMutation:false})
});
})();