/* RUST-006 · unified match-state WASM replay.
 * Read-only: all actions execute in Rust-owned copied memory and in cloned
 * JavaScript reference state, never the live browser game.
 */
(()=>{'use strict';
 const panel=document.getElementById('neuroscapeRustMatchLab');
 const status=document.getElementById('neuroscapeRustMatchStatus');
 const detail=document.getElementById('neuroscapeRustMatchDetail');
 if(!panel||!status||!detail)return;
 let phase='LOADING',checked=0,passed=0,histories=0,events=0,terminal=0,blocked=0,reason='';
 function render(){
  panel.dataset.phase=phase;
  status.textContent='RUST MATCH '+phase+' · '+passed+'/'+checked+' STATE CHECKS';
  detail.textContent=reason||'TURN → COMBAT → RAM RECOVERY → TERMINAL · JS STILL AUTHORITATIVE · .dlw';
 }
 const ready=(async()=>{
  try{
   const encoded=window.NEUROSCAPE_RUST_WASM_BASE64;
   if(typeof encoded!=='string'||encoded.length<100)throw Error('Missing compiled Rust WASM');
   const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
   const {instance}=await WebAssembly.instantiate(bytes,{});
   const wasm=instance.exports;
   for(const fn of ['memory','ns_match_alloc','ns_match_step','ns_match_free']){
    if(!wasm[fn])throw Error('Missing Rust unified match export: '+fn);
   }
   const pool=CATALOG.cards.filter(c=>c.a>0&&Number.isFinite(c.d)&&c.d>0&&cost(c)===1);
   if(pool.length<8)throw Error('Missing real combat catalog fixtures');
   const live=JSON.stringify({turn:state.turn,phase:state.phase,active:state.active,done:state.done,
    actions:state.actions,p:state.p,e:state.e});
   function same(a,b,why){checked++;if(a===b)passed++;else throw Error('Match parity '+why+': '+a+' != '+b);}
   function encodeCard(buf,start,c){
     buf[start]=Number(c.num);buf[start+1]=cost(c);
     buf[start+2]=c.d;buf[start+3]=c.a;
   }
   function encodeUnit(buf,start,u){
     buf[start]=Number(u.n);buf[start+1]=u.uid;
     buf[start+2]=cost(card(u.n));buf[start+3]=card(u.n).d;
     buf[start+4]=card(u.n).a;buf[start+5]=u.hp;
   }
   function compare(buf,sim,tag){
    same(buf[0],sim.active==='p'?0:1,tag+' active');
    same(buf[1],sim.phase,tag+' phase');
    same(buf[2],sim.actions,tag+' actions');
    same(buf[3],sim.turn,tag+' turn');
    same(buf[4],Number(sim.done),tag+' done');
    same(buf[5],sim.nextUid,tag+' nextUID');
    same(buf[230],sim.winner,tag+' winner');
    for(const [i,k] of ['p','e'].entries()){
     const q=sim[k],base=i?54:24;
     same(buf[10+i],q.ram,tag+' ram '+k);
     same(buf[12+i],q.units.length,tag+' unitCount '+k);
     same(buf[14+i],q.hand.length,tag+' handCount '+k);
     same(buf[16+i],q.deck.length,tag+' deckCount '+k);
     same(buf[224+i*2],q.bf,tag+' BF '+k);
     same(buf[225+i*2],q.mf,tag+' MF '+k);
     same(buf[228+i],q.bin.length,tag+' bin '+k);
     same(buf[231+i],sim.released[i],tag+' recycled RAM '+k);
     for(let n=0;n<q.units.length;n++){
      const u=q.units[n],off=base+n*6,c=card(u.n);
      for(const [a,b] of [[buf[off],Number(u.n)],[buf[off+1],u.uid],
       [buf[off+2],cost(c)],[buf[off+3],c.d],[buf[off+4],c.a],
       [buf[off+5],u.hp],[buf[212+i*5+n],Number(u.used)]])
        same(a,b,tag+' unit '+k+'/'+n);
     }
     for(const [list,offset] of [[q.hand,i?116:84],[q.deck,i?180:148]]){
      for(let n=0;n<list.length;n++){
       const c=card(list[n]),off=offset+n*4;
       for(const [a,b] of [[buf[off],Number(c.num)],[buf[off+1],cost(c)],
         [buf[off+2],c.d],[buf[off+3],c.a]])
          same(a,b,tag+' card '+k+'/'+n);
      }
     }
    }
    same(buf[233],sim.attacks,tag+' attack count');
   }
   function reference(sim,kind,index,whichMeter){
    const k=sim.active,p=sim[k],e=sim[k==='p'?'e':'p'];
    if(kind===0){p.ram++;sim.actions--;}
    else if(kind===1){p.hand.push(p.deck.shift());sim.actions--;}
    else if(kind===2){
     const n=p.hand.splice(index,1)[0],c=card(n);
     p.units.push({n,hp:c.d,used:false,uid:sim.nextUid,origin:sim.nextUid++});
    }else if(kind===3){
     if(sim.phase<3)sim.phase++;
     else{
      for(const q of [p,e])for(const u of q.units)u.hp=card(u.n).d;
      sim.active=k==='p'?'e':'p';sim.phase=0;sim.actions=2;sim.turn++;
      for(const u of sim[sim.active].units)u.used=false;
      if(sim.turn>250){sim.done=true;sim.winner=2;}
     }
    }else if(kind===4){
     const before=[free(sim.p),free(sim.e)];
     const counts=[sim.p.units.length,sim.e.units.length];
     const forecast=simulateSequenceAttack(sim,k,index);
     if(!forecast)throw Error('JavaScript native replay rejected attack');
     const after=[free(sim.p),free(sim.e)];
     for(const [i,key] of ['p','e'].entries()){
      const gone=counts[i]-sim[key].units.length;
      for(let n=0;n<gone;n++)sim[key].bin.push(-1);
      sim.released[i]+=after[i]-before[i];
     }
     sim.attacks++;
     if(forecast.kind==='blocked')blocked++;
     if(sim.done){
      sim.winner=(e.bf<=0||e.mf<=0)?(k==='p'?0:1):(k==='p'?1:0);
     }
    }
   }
   for(let seed=0;seed<48;seed++){
    const c1=pool[(seed*3)%pool.length],c2=pool[(seed*7+1)%pool.length],
      blocker=pool[(seed*11+2)%pool.length];
    const withBlock=seed%3===0;
    const player=(deck,ram,units)=>({
     ram,bf:28,mf:28,deck:deck.map(c=>c.num),hand:[],bin:[],units
    });
    const unit=withBlock?[{n:blocker.num,uid:500+seed,hp:blocker.d,used:false,origin:500+seed}]:[];
    const sim={
     active:'p',phase:0,actions:2,turn:seed%11===0?250:1,done:false,
     winner:-1,nextUid:1000+seed*10,attacks:0,released:[0,0],
     p:player([c1,c2],0,[]),
     e:player([c2,c1],withBlock?4:0,unit)
    };
    if(seed%9===1&&!withBlock){sim.e.bf=1;sim.e.mf=1;}
    const initialTurn=sim.turn;
    const ptr=wasm.ns_match_alloc();
    if(!ptr)throw Error('Rust match buffer unavailable');
    try{
     let buf=new Int32Array(wasm.memory.buffer,ptr,256);buf.fill(0);
     buf[0]=0;buf[1]=0;buf[2]=2;buf[3]=sim.turn;buf[5]=sim.nextUid;
     buf[10]=0;buf[11]=sim.e.ram;buf[16]=2;buf[17]=2;
     buf[13]=unit.length;buf[230]=-1;
     buf[224]=sim.p.bf;buf[225]=sim.p.mf;
     buf[226]=sim.e.bf;buf[227]=sim.e.mf;
     for(const [side,cards] of [[0,[c1,c2]],[1,[c2,c1]]]){
      cards.forEach((c,i)=>encodeCard(buf,(side?180:148)+i*4,c));
     }
     unit.forEach((u,i)=>encodeUnit(buf,54+i*6,u));
     compare(buf,sim,seed+'/start');
     for(let step=0;step<28&&!sim.done&&sim.turn<initialTurn+2;step++){
      let action,index=0,meter=0;
      const p=sim[sim.active];
      if(sim.phase===0&&sim.actions>0){
       action=sim.actions===2?0:1;
       if(action===1&&!p.deck.length)action=0;
      }else if(sim.phase===1&&p.hand.length&&p.units.length<5&&
          cost(card(p.hand[0]))<=free(p)){action=2;}
      else if(sim.phase===2){
       const unit=p.units.find(u=>!u.used&&card(u.n).a>0);
       if(unit){
        action=4;index=unit.uid;
        meter=card(unit.n).hit==='MAINFRAME'?1:0;
       }else action=3;
      }else action=3;
      buf[6]=action;buf[7]=index;buf[8]=meter;
      const code=wasm.ns_match_step(ptr);
      same(code,0,seed+'/'+step+' status');
      buf=new Int32Array(wasm.memory.buffer,ptr,256);
      reference(sim,action,index,meter);
      compare(buf,sim,seed+'/'+step);
      events++;
     }
     if(sim.done)terminal++;
     histories++;
    }finally{wasm.ns_match_free(ptr);}
   }
   same(JSON.stringify({turn:state.turn,phase:state.phase,active:state.active,done:state.done,
    actions:state.actions,p:state.p,e:state.e}),live,'unchanged live game');
   if(events<400||checked<6000||blocked<5||terminal<4)
    throw Error('Replay coverage insufficient: '+JSON.stringify({events,checked,blocked,terminal}));
   phase='PASS';
   reason=histories+' HISTORIES · '+events+' EVENTS · '+blocked+
    ' BLOCKED ATTACKS · '+terminal+' TERMINAL MATCHES · NO LIVE WRITES';
   render();
   return Object.freeze({pass:true,histories,events,checked,passed,blocked,terminal,
      sourceMutated:false,gameplayMutation:false});
  }catch(error){
   phase='FAIL';reason=String(error?.message||error);render();
   return Object.freeze({pass:false,histories,events,checked,passed,blocked,terminal,
      reason,sourceMutated:false,gameplayMutation:false});
  }
 })();
 render();
 window.neuroscapeRustMatch=Object.freeze({ready,
  snapshot:()=>Object.freeze({phase,histories,events,checked,passed,blocked,terminal,reason,
   sourceMutated:false,gameplayMutation:false})
 });
})();