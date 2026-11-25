/* RUST-002 · Rust/WASM parity witness, read-only.
 * Compiled from rust/neuroscape-core in GitHub Actions and published on Pages.
 * Uses data generated from the actual Rust binary. Fails closed: no fallback
 * may be labeled WASM-parity PASS. Does not control or mutate gameplay.
 */
(()=>{'use strict';
const root=document.getElementById('neuroscapeRustParityLab'),
      status=document.getElementById('neuroscapeRustParityStatus'),
      detail=document.getElementById('neuroscapeRustParityDetail');
if(!root||!status||!detail)return;
let phase='LOADING',passed=0,total=0,hash=null,reason='';
const labels=['CONFIRMED STABLE','INDETERMINATE','CONFIRMED UNSTABLE'];
const approx=(a,b)=>Number.isFinite(a)&&Number.isFinite(b)&&Math.abs(a-b)<1e-10;
function render(){
 root.dataset.phase=phase;
 status.textContent='RUST/WASM '+phase+' · '+passed+'/'+total+' PARITY CHECKS';
 detail.textContent=(hash?'SHA-256 '+hash+' · ':'')+
  (reason||'OBSERVATION ONLY · HTML GAME UNCHANGED');
}
const ready=(async()=>{
 try{
   const encoded=window.NEUROSCAPE_RUST_WASM_BASE64;
   hash=window.NEUROSCAPE_RUST_WASM_SHA256||null;
   if(!encoded||typeof encoded!=='string')throw Error('WASM binary not built; CI artifact missing');
   const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
   if(bytes.length<8||bytes[0]!==0||bytes[1]!==97||bytes[2]!==115||bytes[3]!==109)
     throw Error('Invalid WebAssembly binary header');
   if(hash&&globalThis.crypto?.subtle){
     // Cryptographic hash is a build-provenance consistency check, not evidence ancestry.
     const digest=await crypto.subtle.digest('SHA-256',bytes);
     const actual=[...new Uint8Array(digest)].map(n=>n.toString(16).padStart(2,'0')).join('');
     if(actual!==hash)throw Error('WASM asset hash mismatch');
   }
   const {instance}=await WebAssembly.instantiate(bytes,{});
   const w=instance.exports;
   if(w.ns_version()!==2)throw Error('Unexpected Rust ABI version');
   const margin=window.neuroscapeAdversarialMargin;
   const compare=window.neuroscapeUncertaintyMargin;
   if(!margin||!compare)throw Error('Inherited JS observation modules unavailable');
   let successful=0,checked=0;
   const assertion=ok=>{checked++;if(ok)successful++};
   for(const row of margin.results()){
     for(const policy of ['fixed','adaptive']){
       for(const epsilon of [0,.05,.15,.3]){
         const m=row[policy].margin,js=compare.evaluate(m,epsilon);
         assertion(labels[w.ns_margin_classification(m,epsilon)]===js.classification);
         assertion(approx(w.ns_margin_lower(m,epsilon),js.lower));
         assertion(approx(w.ns_margin_upper(m,epsilon),js.upper));
       }
     }
   }
   for(const [a,b,c] of [[.025,.05,.075],[0,0,0],[.3,.3,.3]]){
     assertion(approx(w.ns_uncertainty_sum(a,b,c),a+b+c));
   }
   assertion(approx(w.ns_worst_margin4(.01,.07,.03,.02),.03));
   assertion(w.ns_margin_classification(0,-.1)===-1);
   assertion(Number.isNaN(w.ns_uncertainty_sum(-1,0,0)));
   passed=successful;total=checked;
   if(passed!==total)throw Error('Rust/JavaScript parity mismatch: '+passed+'/'+total);
   phase='PASS';reason='COMPARED AGAINST JS OBSERVATION MODELS · NO GAMEPLAY AUTHORITY';
   render();
   return Object.freeze({pass:true,checked,passed,sha256:hash,sourceMutated:false,gameplayMutation:false});
 }catch(err){
   phase='FAIL';reason=String(err?.message||err);
   render();
   return Object.freeze({pass:false,checked:total,passed,reason,sourceMutated:false,gameplayMutation:false});
 }
})();
render();
window.neuroscapeRustParity=Object.freeze({
 ready,
 snapshot:()=>Object.freeze({phase,passed,total,sha256:hash,reason,
  sourceMutated:false,gameplayMutation:false})
});
})();