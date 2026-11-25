/* RUST-005 · 4-phase turn-control shadow. JS keeps gameplay authority.
 * Real catalog cards, independent cloned transition fixtures, Rust WASM
 * owned buffer. Combat remains under independently tested RUST-004 replay.
 */
(()=>{'use strict';
const panel=document.getElementById('neuroscapeRustTurnLab'),
status=document.getElementById('neuroscapeRustTurnStatus'),
detail=document.getElementById('neuroscapeRustTurnDetail');
if(!panel||!status||!detail)return;
let phase='LOADING',checked=0,passed=0,fixtures=0,reason='';
const paint=()=>{panel.dataset.phase=phase;
 status.textContent='RUST TURN '+phase+' · '+passed+'/'+checked+' PARITY CHECKS';
 detail.textContent=reason||'RAM/DRAW → DEPLOY → COMBAT (RUST-004) → END TURN · READ-ONLY · .dlw';};
const ready=(async()=>{
 try{
  const b64=window.NEUROSCAPE_RUST_WASM_BASE64;
  if(typeof b64!=='string'||b64.length<100)throw Error('No compiled Rust WASM');
  const {instance}=await WebAssembly.instantiate(Uint8Array.from(atob(b64),c=>c.charCodeAt(0)),{});
  const w=instance.exports;
  for(const fn of ['ns_turn_alloc','ns_turn_step','ns_turn_free','memory'])
   if(!w[fn])throw Error('Missing Rust turn ABI '+fn);
  const cards=CATALOG.cards.filter(c=>Number.isInteger(Number(c.num))&&c.d!==null&&c.a!==null&&cost(c)===1);
  if(cards.length<2)throw Error('Not enough real affordable character cards');
  const check=(actual,expected,where)=>{checked++;if(actual===expected)passed++;
    else throw Error('Mismatch '+where+' expected '+expected+' got '+actual)};
  const realSnapshot=()=>JSON.stringify({turn:state.turn,active:state.active,phase:state.phase,
    actions:state.actions,done:state.done,p:state.p,e:state.e});
  const before=realSnapshot();
  const writeCard=(b,o,c)=>{b[o]=Number(c.num);b[o+1]=cost(c);b[o+2]=c.d;b[o+3]=c.a;};
  function compare(b,x,tag){
   check(b[0],x.active,tag+'/active');check(b[1],x.phase,tag+'/phase');
   check(b[2],x.actions,tag+'/actions');check(b[3],x.turn,tag+'/turn');
   check(b[4],Number(x.done),tag+'/done');check(b[5],x.nextUid,tag+'/nextUid');
   for(let p=0;p<2;p++){
    const q=x.players[p];
    check(b[10+p],q.ram,tag+'/ram');
    check(b[12+p],q.units.length,tag+'/unit-count');
    check(b[14+p],q.hand.length,tag+'/hand-count');
    check(b[16+p],q.deck.length,tag+'/deck-count');
    for(let i=0;i<q.units.length;i++){
     const u=q.units[i],off=(p?54:24)+i*6;
     for(const [v,expected] of [[b[off],Number(u.card.num)],[b[off+1],u.uid],
       [b[off+2],cost(u.card)],[b[off+3],u.card.d],[b[off+4],u.card.a],
       [b[off+5],u.hp],[b[212+p*5+i],Number(u.used)]])
        check(v,expected,tag+'/unit-'+i);
    }
    for(const [arr,start,name] of [[q.hand,p?116:84,'hand'],[q.deck,p?180:148,'deck']]){
     for(let i=0;i<arr.length;i++){
      const off=start+i*4,c=arr[i];
      for(const [v,expected] of [[b[off],Number(c.num)],[b[off+1],cost(c)],
          [b[off+2],c.d],[b[off+3],c.a]])
       check(v,expected,tag+'/'+name+'-'+i);
     }
    }
   }
  }
  function reference(x,kind,index=0){
   const p=x.players[x.active];
   if(kind===0){p.ram++;x.actions--;}
   else if(kind===1){p.hand.push(p.deck.shift());x.actions--;}
   else if(kind===2){
    const card=p.hand.splice(index,1)[0];
    p.units.push({card,uid:x.nextUid++,hp:card.d,used:false});
   }else if(x.phase<3){x.phase++;}
   else{
    for(const side of x.players)for(const u of side.units)u.hp=u.card.d;
    x.active=1-x.active;x.phase=0;x.actions=2;x.turn++;
    for(const u of x.players[x.active].units)u.used=false;
    if(x.turn>250)x.done=true;
   }
  }
  for(let seed=0;seed<48;seed++){
   const c1=cards[(seed*7)%cards.length],c2=cards[(seed*11+1)%cards.length];
   const x={active:0,phase:0,actions:2,turn:seed%2?250:1,done:false,nextUid:100+seed,
    players:[{ram:0,units:[],hand:[],deck:[c1,c2]},
      {ram:2,units:[],hand:[c2],deck:[]}]};
   const ptr=w.ns_turn_alloc();
   if(!ptr)throw Error('Rust turn allocation failed');
   try{
    let b=new Int32Array(w.memory.buffer,ptr,256);b.fill(0);
    b[0]=x.active;b[1]=x.phase;b[2]=x.actions;b[3]=x.turn;b[5]=x.nextUid;
    b[10]=0;b[11]=2;b[16]=2;b[15]=1;
    writeCard(b,148,c1);writeCard(b,152,c2);writeCard(b,116,c2);
    compare(b,x,'initial '+seed);
    const sequence=[0,1,3,2,3,3,3]; // RAM/DRAW → deploy → combat phase → end
    for(let step=0;step<sequence.length;step++){
     const kind=sequence[step];b[6]=kind;b[7]=0;
     const result=w.ns_turn_step(ptr);
     check(result,0,'Rust transition '+seed+'/'+step);
     // Reacquire the WASM view if Rust Vec allocations grew linear memory.
     b=new Int32Array(w.memory.buffer,ptr,256);
     reference(x,kind);
     compare(b,x,'turn '+seed+'/'+step);
    }
    fixtures++;
   }finally{w.ns_turn_free(ptr)}
  }
  check(realSnapshot(),before,'live game unchanged');
  if(checked<3000||fixtures!==48)throw Error('Insufficient transition coverage');
  phase='PASS';reason=fixtures+' CLONED REAL-CATALOG TURN CYCLES · 7 STEPS EACH · GAMEPLAY UNCHANGED';
  paint();return Object.freeze({pass:true,checked,passed,fixtures,gameplayMutation:false});
 }catch(error){
  phase='FAIL';reason=String(error?.message||error);paint();
  return Object.freeze({pass:false,checked,passed,fixtures,reason,gameplayMutation:false});
 }
})();
paint();
window.neuroscapeRustTurn=Object.freeze({
 ready,snapshot:()=>Object.freeze({phase,checked,passed,fixtures,reason,gameplayMutation:false})
});
})();