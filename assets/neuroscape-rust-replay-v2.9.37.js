/* RUST-004 · immutable-identity bounded combat replay against REAL JS engine.
 * Executes Rust on disposable WASM memory, and JavaScript on disposable
 * clones via simulateSequenceAttack(). Never calls act(), writes to state,
 * modifies card catalog, or mutates live card/RAM/mural fields.
 */
(()=>{'use strict';
const panel=document.getElementById('neuroscapeRustReplayLab');
const status=document.getElementById('neuroscapeRustReplayStatus');
const detail=document.getElementById('neuroscapeRustReplayDetail');
if(!panel||!status||!detail)return;
let phase='LOADING',checked=0,passed=0,scenarios=0,steps=0,reason='';
const paint=()=>{
 panel.dataset.phase=phase;
 status.textContent='RUST REPLAY '+phase+' · '+passed+'/'+checked+' PARITY CHECKS';
 detail.textContent=reason||'BOUND TO REAL JS COMBAT · NO GAMEPLAY AUTHORITY · .dlw';
};
const ready=(async()=>{
 try{
  const encoded=window.NEUROSCAPE_RUST_WASM_BASE64;
  if(typeof encoded!=='string'||encoded.length<100)throw Error('Compiled WASM unavailable');
  const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
  const {instance}=await WebAssembly.instantiate(bytes,{});
  const w=instance.exports;
  for(const key of ['memory','ns_replay_alloc','ns_replay_apply','ns_replay_free']){
    if(!w[key])throw Error('Missing Rust replay export: '+key);
  }
  const assert=(condition,context)=>{
   checked++;
   if(condition)passed++;
   else throw Error('Rust/JS combat divergence at '+context);
  };
  const chars=CATALOG.cards.filter(c=>Number.isFinite(c.a)&&c.a>0&&Number.isFinite(c.d)&&c.d>0);
  const defenders=CATALOG.cards.filter(c=>Number.isFinite(c.a)&&Number.isFinite(c.d)&&c.d>0);
  if(chars.length<50||defenders.length<50)throw Error('Incomplete real combat fixture pool');
  const encodeUnit=(arr,offset,unit)=>{
   arr[offset]=unit.origin;arr[offset+1]=unit.hp;
   arr[offset+2]=cost(card(unit.n));arr[offset+3]=card(unit.n).a||0;
   arr[offset+4]=Number(unit.used);
  };
  const playerSnapshot=()=>JSON.stringify({
   turn:state.turn,phase:state.phase,active:state.active,done:state.done,actions:state.actions,
   p:state.p,e:state.e
  });
  const frozen=playerSnapshot();
  for(let seed=0;seed<96;seed++){
   const pc=1+seed%5,ec=seed%6;
   const units=(pool,count,shift)=>Array.from({length:count},(_,i)=>{
    const c=pool[(seed*13+i*7+shift)%pool.length];
    return {n:c.num,hp:Number(c.d),used:false,origin:shift*10+i+1};
   });
   const sim={...state,active:'p',phase:2,done:false,
     p:{...state.p,ram:25,bf:25,mf:25,units:units(chars,pc,1),bin:[]},
     e:{...state.e,ram:25,bf:7+seed%11,mf:8+seed%13,units:units(defenders,ec,2),bin:[]}};
   let applied=0;
   while(!sim.done){
    const active=sim.p.units.find(u=>!u.used&&card(u.n).a>0);
    if(!active)break;
    const old={
     p:sim.p.units.map(u=>({...u})),e:sim.e.units.map(u=>({...u})),
     pRam:sim.p.ram,eRam:sim.e.ram,pBF:sim.p.bf,pMF:sim.p.mf,
     eBF:sim.e.bf,eMF:sim.e.mf
    };
    const attacker=card(active.n),meter=attacker.hit==='MAINFRAME'?1:0;
    const beforeFree=[free(sim.p),free(sim.e)];
    const ptr=w.ns_replay_alloc();
    if(!ptr)throw Error('Rust WASM buffer allocation failed');
    let out;
    try{
     let buf=new Int32Array(w.memory.buffer,ptr,160);
     buf.fill(0);buf[0]=0;buf[1]=active.origin;buf[2]=meter;
     buf[3]=sim.p.ram;buf[4]=sim.e.ram;
     buf[5]=sim.p.bf;buf[6]=sim.p.mf;buf[7]=sim.e.bf;buf[8]=sim.e.mf;
     buf[9]=old.p.length;buf[10]=old.e.length;
     old.p.forEach((u,i)=>encodeUnit(buf,11+i*5,u));
     old.e.forEach((u,i)=>encodeUnit(buf,36+i*5,u));
     assert(w.ns_replay_apply(ptr)===0,'Rust valid attack / '+seed+'/'+applied);
     out=Array.from(new Int32Array(w.memory.buffer,ptr,160));
    }finally{w.ns_replay_free(ptr)}
    // The authoritative JS reference is the game's actual, existing
    // simulateSequenceAttack() function, operating only on our cloned state.
    const forecast=simulateSequenceAttack(sim,'p',active.origin);
    if(!forecast)throw Error('JS reference rejected copied valid attack');
    const id=seed+'/'+applied;
    assert(out[111]===sim.p.units.length&&out[112]===sim.e.units.length,'survivor counts '+id);
    const compare=(offset,actual,label)=>{
      for(let i=0;i<actual.length;i++){
       const u=actual[i],b=offset+i*5;
       assert(out[b]===u.origin&&out[b+1]===u.hp&&
         out[b+2]===cost(card(u.n))&&out[b+3]===(card(u.n).a||0)&&
         out[b+4]===Number(u.used),'identity/hp/used '+label+' '+id+'/'+i);
      }
    };
    compare(61,sim.p.units,'p');compare(86,sim.e.units,'e');
    const afterFree=[free(sim.p),free(sim.e)];
    const removed=[old.p.length-sim.p.units.length,old.e.length-sim.e.units.length];
    assert(out[113]===removed[0]&&out[114]===removed[1],'destroyed count '+id);
    assert(out[115]===afterFree[0]-beforeFree[0]&&
           out[116]===afterFree[1]-beforeFree[1],'RAM released '+id);
    assert(out[117]===beforeFree[0]&&out[118]===beforeFree[1]&&
           out[119]===afterFree[0]&&out[120]===afterFree[1],'RAM free '+id);
    assert(out[121]===sim.p.bf&&out[122]===sim.p.mf&&
           out[123]===sim.e.bf&&out[124]===sim.e.mf,'meters '+id);
    assert(Boolean(out[125])===Boolean(sim.done),'terminal '+id);
    const expectedWinner=!sim.done?-1:sim.e.bf<=0||sim.e.mf<=0?0:1;
    assert(out[126]===expectedWinner,'winner '+id);
    assert(Boolean(out[127])===(forecast.kind==='blocked'),'block '+id);
    assert(out[128]===(forecast.kind==='blocked'?old.e[forecast.target].origin:-1),'defender identity '+id);
    assert(out[129]===forecast.attackerAfter,'attacker health '+id);
    if(forecast.kind==='blocked')assert(out[130]===forecast.defenderAfter,'defender health '+id);
    applied++;steps++;
    if(applied>=5)break;
   }
   scenarios++;
  }
  assert(playerSnapshot()===frozen,'live-game frozen across shadow replay');
  if(steps<100||checked<1500)throw Error('Insufficient replay coverage');
  phase='PASS';
  reason=scenarios+' REAL-CATALOG BOARDS · '+steps+
    ' ID-SAFE ATTACKS · RAM/RECYCLE/TERMINAL PARITY · ZERO GAME WRITES';
  paint();
  return Object.freeze({pass:true,checked,passed,scenarios,steps,
    sourceMutated:false,gameplayMutation:false});
 }catch(error){
  phase='FAIL';reason=String(error?.message||error);paint();
  return Object.freeze({pass:false,checked,passed,scenarios,steps,reason,
    sourceMutated:false,gameplayMutation:false});
 }
})();
paint();
window.neuroscapeRustReplay=Object.freeze({
 ready,
 snapshot:()=>Object.freeze({phase,checked,passed,scenarios,steps,reason,
  sourceMutated:false,gameplayMutation:false})
});
})();