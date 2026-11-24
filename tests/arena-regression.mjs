import { chromium } from 'playwright';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const browser = await chromium.launch({headless:true,args:['--no-sandbox']});
const page = await browser.newPage({viewport:{width:1600,height:1000}});
const errors=[];
page.on('pageerror',error=>errors.push(error.message));
const url=pathToFileURL(resolve('index.html')).href;
await page.goto(url,{waitUntil:'domcontentloaded'});
await page.waitForTimeout(750);
const initial=await page.evaluate(()=>{
 const rect=id=>{const r=document.getElementById(id)?.getBoundingClientRect();return r&&{width:r.width,height:r.height}};
 const slots=id=>[...document.querySelectorAll('#'+id+' > .slot')].map(e=>{const r=e.getBoundingClientRect();return {width:r.width,height:r.height,visible:getComputedStyle(e).visibility,display:getComputedStyle(e).display}});
 return {title:document.title,turn:document.getElementById('turnText')?.textContent,
  player:slots('pLanes'),bot:slots('eLanes'),hand:document.querySelectorAll('#hand .sqcard').length,
  installDisabled:document.getElementById('install')?.disabled,playerRect:rect('pLanes'),botRect:rect('eLanes')};
});
const fail=message=>{throw new Error(message+'\n'+JSON.stringify({initial,errors},null,2))};
try{
 if(errors.length)fail('Uncaught browser error');
 if(!initial.turn?.startsWith('TURN '))fail('Engine failed first render');
 for(const [side,list] of [['player',initial.player],['bot',initial.bot]]){
  if(list.length!==5)fail(side+' does not have five slots');
  if(list.some(x=>x.width<70||x.height<70||x.visible!=='visible'||x.display==='none'))fail(side+' card squares have collapsed');
 }
 if(initial.hand<5)fail('Player hand not rendered');
 // v2.8.71: the neon attack overlay must use the same measured endpoints
 // and curve as the existing attack route; no synthetic combat state edits.
 const routed=await page.evaluate(()=>{
   if(typeof drawCombatPathways!=='function')return {error:'combat route missing'};
   drawCombatPathways({from:'p',to:'e',source:0,target:0,kind:'blocked',seq:987654});
   const overlay=document.querySelector('#combatPathways .neonAttackTrail');
   const base=document.querySelector('#combatPathways .energyRoute.combatBlock');
   const core=document.querySelector('#combatPathways .neonAttackCore');
   const corona=document.querySelector('#combatPathways .neonImpactCorona');
   const sparks=document.querySelector('#combatPathways .neonImpactSpark');
   const target=document.querySelector('#eLanes > .slot');
   const board=document.getElementById('gameBoard').getBoundingClientRect();
   const rect=target.getBoundingClientRect();
   const expectedX=rect.left+rect.width/2-board.left;
   const expectedY=rect.top+rect.height/2-board.top;
   return {
     count:document.querySelectorAll('#combatPathways .neonAttackTrail').length,
     from:overlay?.dataset.attackSource,to:overlay?.dataset.attackTarget,seq:overlay?.dataset.attackSeq,
     sameCurve:overlay?.getAttribute('d')===base?.getAttribute('d')&&
       overlay?.getAttribute('d')===core?.getAttribute('d'),
     pointer:overlay?getComputedStyle(overlay).pointerEvents:null,
     animation:overlay?getComputedStyle(overlay).animationName:null,
     impact:{
       target:corona?.dataset.attackTarget,
       x:corona?Number(corona.getAttribute('cx')):null,
       y:corona?Number(corona.getAttribute('cy')):null,
       geometryMatches:corona?Math.abs(Number(corona.getAttribute('cx'))-expectedX)<2&&
         Math.abs(Number(corona.getAttribute('cy'))-expectedY)<2:false,
       rayCount:sparks?(sparks.getAttribute('d')?.match(/ M |^M /g)||[]).length:0,
       pointer:corona?getComputedStyle(corona).pointerEvents:null,
       animation:corona?getComputedStyle(corona).animationName:null,
       delay:corona?getComputedStyle(corona).animationDelay:null
     }
   };
 });
 if(routed.count!==1||routed.from!=='p:0'||routed.to!=='e:0'||
    routed.seq!=='987654'||!routed.sameCurve||routed.pointer!=='none'||
    !routed.animation?.includes('neonAttackTravel'))
   fail('Neon photons diverge from real combat route: '+JSON.stringify(routed));
 if(routed.impact.target!=='e:0'||!routed.impact.geometryMatches||
    routed.impact.rayCount!==6||routed.impact.pointer!=='none'||
    !routed.impact.animation?.includes('neonCoronaDischarge')||
    routed.impact.delay!=='0.77s')
   fail('Impact discharge not aligned to real target: '+JSON.stringify(routed.impact));
 // Defender shield ripple: actual blocked target receives exactly three rings.
 // Direct health attacks must never manufacture a defending card's shield.
 const ripples=await page.evaluate(()=>{
  const rings=[...document.querySelectorAll('#combatPathways .neonDefenderRipple')];
  const report=rings.map(x=>({
    seq:x.dataset.attackSeq,target:x.dataset.attackTarget,
    cx:Number(x.getAttribute('cx')),cy:Number(x.getAttribute('cy')),
    delay:getComputedStyle(x).animationDelay,
    animation:getComputedStyle(x).animationName,
    pointer:getComputedStyle(x).pointerEvents
  }));
  drawCombatPathways({from:'p',to:'e',source:0,target:-1,kind:'direct',seq:987655});
  const directRings=[...document.querySelectorAll('#combatPathways .neonDefenderRipple')]
    .filter(x=>x.dataset.attackSeq==='987655').length;
  return {report,directRings};
 });
 if(ripples.report.length!==3||ripples.report.some(x=>
    x.seq!=='987654'||x.target!=='e:0'||x.pointer!=='none'||
    !x.animation.includes('neonDefenderRipple')||
    Math.abs(x.cx-routed.impact.x)>2||Math.abs(x.cy-routed.impact.y)>2)||
    ripples.directRings!==0)
   fail('Defender ripple must follow blocked card target only: '+JSON.stringify(ripples));
 if(ripples.report.map(x=>x.delay).join(',')!=='0.805s,0.875s,0.945s')
   fail('Defender ripples need staggered impact timing: '+JSON.stringify(ripples.report));

 // v2.8.75: real defender gets two tilted 3D shield rings and one
 // specular arc, but direct hits never impersonate an occupied card.
 const shimmer=await page.evaluate(()=>{
   const svg=document.getElementById('combatPathways');
   const rings=[...svg.querySelectorAll('.neonShieldRim')].filter(x=>x.dataset.attackSeq==='987654');
   const glint=[...svg.querySelectorAll('.neonShieldGlint')].find(x=>x.dataset.attackSeq==='987654');
   const board=document.getElementById('gameBoard').getBoundingClientRect();
   const defender=document.querySelector('#eLanes > .slot').getBoundingClientRect();
   const center=[defender.left+defender.width/2-board.left,defender.top+defender.height/2-board.top];
   const result={
     rings:rings.length,glint:!!glint,
     aligned:rings.every(x=>Math.abs(+x.getAttribute('cx')-center[0])<2&&
       Math.abs(+x.getAttribute('cy')-center[1])<2),
     tilted:rings.every(x=>(x.getAttribute('transform')||'').startsWith('rotate(-17 ')),
     target:rings.map(x=>x.dataset.attackTarget),
     sequence:rings.map(x=>x.dataset.attackSeq),
     delays:rings.map(x=>getComputedStyle(x).animationDelay),
     glintAnimation:glint?getComputedStyle(glint).animationName:null,
     pointer:rings.map(x=>getComputedStyle(x).pointerEvents),
     directShimmer:[...svg.querySelectorAll('.neonShieldRim,.neonShieldGlint')]
       .filter(x=>x.dataset.attackSeq==='987655').length
   };
   return result;
 });
 if(shimmer.rings!==2||!shimmer.glint||!shimmer.aligned||!shimmer.tilted||
    shimmer.target.some(x=>x!=='e:0')||shimmer.sequence.some(x=>x!=='987654')||
    shimmer.pointer.some(x=>x!=='none')||shimmer.delays.join(',')!=='0.79s,0.87s'||
    !shimmer.glintAnimation?.includes('neonShieldSpecular')||shimmer.directShimmer!==0)
   fail('3D shield shimmer missing or attached to wrong combat target: '+JSON.stringify(shimmer));

 // v2.8.76: three rings and a central flash at each observed destroyed
 // slot, strictly derived from the already-resolved destruction ledger.
 const destruction=await page.evaluate(()=>{
   const svg=document.getElementById('combatPathways');
   const seq='987659';
   drawCombatPathways({from:'p',to:'e',source:0,target:1,kind:'blocked',
     retaliation:0,seq:987659,destroyed:[{side:'e',slot:1,name:'Test Defender',ram:2},
                                  {side:'p',slot:0,name:'Test Attacker',ram:1}]});
   const rings=[...svg.querySelectorAll('.neonDestructionRing')]
     .filter(x=>x.dataset.attackSeq===seq);
   const flashes=[...svg.querySelectorAll('.neonDestructionFlash')]
     .filter(x=>x.dataset.attackSeq===seq);
   const board=document.getElementById('gameBoard').getBoundingClientRect();
   const center=(side,slot)=>{
     const el=document.getElementById(side+'Lanes').children[slot];
     const rect=el.getBoundingClientRect();
     return [rect.left+rect.width/2-board.left,rect.top+rect.height/2-board.top];
   };
   const matches=(el,point)=>Math.abs(Number(el.getAttribute('cx'))-point[0])<2&&
     Math.abs(Number(el.getAttribute('cy'))-point[1])<2;
   const expected={'e:1':center('e',1),'p:0':center('p',0)};
   const result={
     rings:rings.length,flashes:flashes.length,
     locations:Object.keys(expected),
     allAligned:[...rings,...flashes].every(x=>expected[x.dataset.destroyedSlot]&&
       matches(x,expected[x.dataset.destroyedSlot])),
     pointerSafe:[...rings,...flashes].every(x=>getComputedStyle(x).pointerEvents==='none'),
     delays:[...rings].filter(x=>x.dataset.destroyedSlot==='e:1').map(x=>getComputedStyle(x).animationDelay),
     flashAnimation:flashes[0]?getComputedStyle(flashes[0]).animationName:null
   };
   drawCombatPathways({from:'p',to:'e',source:0,target:1,kind:'blocked',
     retaliation:0,seq:987660,destroyed:[]});
   result.noFalseDestruction=[...svg.querySelectorAll('.neonDestructionRing,.neonDestructionFlash')]
     .every(x=>x.dataset.attackSeq!=='987660');
   return result;
 });
 if(destruction.rings!==6||destruction.flashes!==2||!destruction.allAligned||
    !destruction.pointerSafe||!destruction.noFalseDestruction||
    destruction.delays.join(',')!=='0.79s,0.86s,0.93s'||
    !destruction.flashAnimation?.includes('neonDestructionFlash'))
   fail('Destruction shockwave must follow real destroyed slot records: '+JSON.stringify(destruction));
 console.log('DESTRUCTION SHOCKWAVE PASS: six rings, two flashes, two recorded slots, zero false destruction');
 // v2.8.77: the exact positive-RAM release event drives the bright
 // recovery photon. Zero release and commits must never masquerade as recovery.
 const recoveryPhoton=await page.evaluate(()=>{
   const svg=document.getElementById('pPathways');
   drawEnergyPathways({seq:987661,events:[
     {side:'p',type:'release',amount:2,slots:[{slot:1,amount:2}]}]});
   const ray=[...svg.querySelectorAll('.neonRecoveryReturn')]
     .find(x=>x.dataset.flowSeq==='987661');
   const core=[...svg.querySelectorAll('.neonRecoveryCore')]
     .find(x=>x.dataset.flowSeq==='987661');
   const arrival=[...svg.querySelectorAll('.neonRecoveryArrival')]
     .find(x=>x.dataset.flowSeq==='987661');
   const side=document.querySelector('#gameBoard .side.you').getBoundingClientRect();
   const station=document.getElementById('pLanes').children[1].getBoundingClientRect();
   const meter=document.getElementById('pRamAvailable').getBoundingClientRect();
   const src=[station.left+station.width/2-side.left,station.top+station.height/2-side.top];
   const dst=[meter.left+meter.width/2-side.left,meter.top+meter.height/2-side.top];
   const curve=typeof routeBetween==='function'?routeBetween(src,dst):'';
   const report={
     side:ray?.dataset.recoverySide,slot:ray?.dataset.recoverySlot,
     amount:ray?.dataset.returnedRam,seq:ray?.dataset.flowSeq,
     matched:ray?.getAttribute('d')===curve&&core?.getAttribute('d')===curve,
     arrival:arrival?Math.abs(+arrival.getAttribute('cx')-dst[0])<2&&
       Math.abs(+arrival.getAttribute('cy')-dst[1])<2:false,
     pointer:ray?getComputedStyle(ray).pointerEvents:null,
     animation:ray?getComputedStyle(ray).animationName:null,
     delay:ray?getComputedStyle(ray).animationDelay:null
   };
   drawEnergyPathways({seq:987662,events:[{side:'p',type:'release',amount:0,slots:[{slot:1,amount:0}]}]});
   drawEnergyPathways({seq:987663,events:[{side:'p',type:'commit',amount:2,slot:1}]});
   report.noFalseReturn=['987662','987663'].every(seq=>!
     [...svg.querySelectorAll('.neonRecoveryReturn')].some(x=>x.dataset.flowSeq===seq));
   return report;
 });
 if(recoveryPhoton.side!=='p'||recoveryPhoton.slot!=='1'||recoveryPhoton.amount!=='2'||
   recoveryPhoton.seq!=='987661'||!recoveryPhoton.matched||!recoveryPhoton.arrival||
   recoveryPhoton.pointer!=='none'||!recoveryPhoton.animation?.includes('neonRecoveryTravel')||
   recoveryPhoton.delay!=='1.37s'||!recoveryPhoton.noFalseReturn)
   fail('RAM recovery photon diverged from positive release ledger: '+JSON.stringify(recoveryPhoton));
 console.log('RAM RECOVERY PASS: original square → actual available RAM meter, positive release only');
 // v2.8.78 — destruction and RAM return share a single attack-origin
 // lineage when the observed release flow records the attack sequence.
 const lifecycle=await page.evaluate(()=>{
   const attack={from:'p',to:'e',source:0,target:1,kind:'blocked',
     retaliation:0,seq:987664,
     destroyed:[{side:'e',slot:1,name:'Observed fallen card',ram:3}]};
   drawCombatPathways(attack);
   drawEnergyPathways({seq:987665,impactSeq:987664,events:[
     {side:'e',type:'release',amount:3,slots:[{slot:1,amount:3}]}]});
   const shock=[...document.querySelectorAll('#combatPathways .neonDestructionRing')]
      .find(x=>x.dataset.attackSeq==='987664');
   const returnPath=[...document.querySelectorAll('#ePathways .neonRecoveryReturn')]
      .find(x=>x.dataset.flowSeq==='987665');
   const arrive=[...document.querySelectorAll('#ePathways .neonRecoveryArrival')]
      .find(x=>x.dataset.flowSeq==='987665');
   const s=shock&&getComputedStyle(shock),r=returnPath&&getComputedStyle(returnPath),
      a=arrive&&getComputedStyle(arrive);
   return {
     shockId:shock?.dataset.lifecycleId,recoveryId:returnPath?.dataset.lifecycleId,
     arrivalId:arrive?.dataset.lifecycleId,
     side:returnPath?.dataset.recoverySide,slot:returnPath?.dataset.recoverySlot,
     amount:returnPath?.dataset.returnedRam,
     shockStart:s?.animationDelay,shockDuration:s?.animationDuration,
     returnStart:r?.animationDelay,returnDuration:r?.animationDuration,
     arrivalStart:a?.animationDelay,
     pointerSafe:[shock,returnPath,arrive].every(x=>x&&getComputedStyle(x).pointerEvents==='none')
   };
 });
 if(lifecycle.shockId!=='attack:987664'||
   lifecycle.recoveryId!==lifecycle.shockId||
   lifecycle.arrivalId!==lifecycle.shockId||
   lifecycle.side!=='e'||lifecycle.slot!=='1'||lifecycle.amount!=='3'||
   lifecycle.shockStart!=='0.79s'||lifecycle.returnStart!=='1.37s'||
   lifecycle.arrivalStart!=='2.05s'||!lifecycle.pointerSafe)
    fail('Unified lifecycle not temporally/provenance aligned: '+JSON.stringify(lifecycle));
 const meterCharge=await page.evaluate(()=>{
   const track=document.getElementById('eRamAvailable').parentElement;
   const charge=[...track.querySelectorAll('.neonRamCharge')].find(x=>x.dataset.flowSeq==='987665');
   const before=charge&&{amount:charge.dataset.returnedRam,id:charge.dataset.lifecycleId,
     delay:getComputedStyle(charge).animationDelay,
     strength:Number(charge.style.getPropertyValue('--charge-strength')),
     pointer:getComputedStyle(charge).pointerEvents};
   drawEnergyPathways({seq:987666,impactSeq:987664,events:[{side:'e',type:'release',amount:8,slots:[{slot:1,amount:8}]}]});
   const strong=[...track.querySelectorAll('.neonRamCharge')].find(x=>x.dataset.flowSeq==='987666');
   return {before,strongAmount:strong?.dataset.returnedRam,
      strongStrength:strong?Number(strong.style.getPropertyValue('--charge-strength')):null,
      currentWidth:document.getElementById('eRamAvailable').style.width};
 });
 if(meterCharge.before?.amount!=='3'||meterCharge.before.id!=='attack:987664'||
    meterCharge.before.delay!=='2.05s'||meterCharge.before.pointer!=='none'||
    !(meterCharge.strongStrength>meterCharge.before.strength)||
    meterCharge.strongAmount!=='8')
   fail('Amount-scaled RAM meter charging not attached to release: '+JSON.stringify(meterCharge));
 // v2.8.80: simultaneous independent card releases preserve per-slot
 // lineage on both sides, without synthesizing a RAM amount or altering fills.
 const simultaneous=await page.evaluate(()=>{
   const seq=987680,impactSeq=987679;
   const read=(side,cls)=>[...document.querySelectorAll('#'+side+'Pathways .'+cls)]
      .filter(x=>x.dataset.flowSeq===String(seq));
   const before=['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width);
   drawEnergyPathways({seq,impactSeq,events:[
     {side:'p',type:'release',amount:5,slots:[{slot:0,amount:2},{slot:3,amount:3},{slot:4,amount:0}]},
     {side:'e',type:'release',amount:4,slots:[{slot:1,amount:4}]}]});
   const records=['p','e'].map(side=>{
     const photons=read(side,'neonRecoveryReturn');
     const cores=read(side,'neonRecoveryCore');
     const arrivals=read(side,'neonRecoveryArrival');
     const charges=[...document.querySelectorAll('#'+side+'RamAvailable')]
       .flatMap(x=>[...x.parentElement.querySelectorAll('.neonRamCharge')])
       .filter(x=>x.dataset.flowSeq===String(seq));
     const row=els=>els.map(x=>({
       transfer:x.dataset.transferId,side:x.dataset.recoverySide,slot:x.dataset.recoverySlot,
       amount:x.dataset.returnedRam,lifecycle:x.dataset.lifecycleId,
       delay:getComputedStyle(x).animationDelay,pointer:getComputedStyle(x).pointerEvents
     }));
     return {side,photons:row(photons),cores:row(cores),
       arrivals:row(arrivals),charges:row(charges),
       chargeStrength:charges.map(x=>Number(x.style.getPropertyValue('--charge-strength'))),
       slotCount:document.getElementById(side+'Lanes').children.length};
   });
   const after=['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width);
   return {records,before,after};
 });
 const expected={p:['0:2','3:3'],e:['1:4']};
 if(simultaneous.before.join(',')!==simultaneous.after.join(','))
   fail('Visual recovery changed actual meter fill width: '+JSON.stringify(simultaneous));
 for(const record of simultaneous.records){
   const expectedPairs=expected[record.side];
   for(const group of ['photons','cores','arrivals','charges']){
     const seen=record[group].map(x=>x.slot+':'+x.amount).sort();
     if(seen.join(',')!==expectedPairs.join(',')||
       record[group].some(x=>x.lifecycle!=='attack:987679'||
        x.transfer!=='attack:987679:'+record.side+':'+x.slot||
        x.side!==record.side||x.pointer!=='none'))
       fail('Simultaneous recovery lost per-slot lineage: '+JSON.stringify({record,group}));
   }
   if(record.slotCount!==5||record.charges.some(x=>x.delay!=='2.05s'))
     fail('Simultaneous recovery changed arena or charge timing: '+JSON.stringify(record));
 }
 const reservoirs=await page.evaluate(()=>{
   const result=['p','e'].map(side=>{
     const track=document.getElementById(side+'RamAvailable').parentElement;
     const reservoir=[...track.querySelectorAll('.neonRamReservoir')].find(x=>x.dataset.flowSeq==='987680');
     return reservoir?{
       side,id:reservoir.dataset.lifecycleId,total:reservoir.dataset.returnedRam,
       count:reservoir.dataset.transferCount,
       transfers:reservoir.dataset.transferIds.split(',').sort(),
       delay:getComputedStyle(reservoir).animationDelay,
       pointer:getComputedStyle(reservoir).pointerEvents,
       strength:Number(reservoir.style.getPropertyValue('--reservoir-strength'))
     }:null;
   });
   const widths=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   drawEnergyPathways({seq:987681,impactSeq:987679,events:[
     {side:'p',type:'release',amount:0,slots:[{slot:2,amount:0}]}]});
   return {result,widths,zeroReservoir:!!document.querySelector('.neonRamReservoir[data-flow-seq="987681"]')};
 });
 if(reservoirs.zeroReservoir||reservoirs.widths.join(',')!==simultaneous.after.join(','))
   fail('Reservoir changed authoritative meter or emitted zero-flow charge: '+JSON.stringify(reservoirs));
 for(const [index,side] of ['p','e'].entries()){
   const row=reservoirs.result[index];
   const amount=side==='p'?'5':'4';
   const ids=side==='p'?['attack:987679:p:0','attack:987679:p:3']:['attack:987679:e:1'];
   if(!row||row.side!==side||row.id!=='attack:987679'||row.total!==amount||
      row.count!==String(ids.length)||row.transfers.join(',')!==ids.join(',')||
      row.delay!=='2.05s'||row.pointer!=='none'||row.strength<=0)
     fail('Pooled reservoir lost observed transfer evidence: '+JSON.stringify(reservoirs));
 }
 const discharge=await page.evaluate(()=>{
   const items=['p','e'].map(side=>{
     const fill=document.getElementById(side+'RamAvailable');
     const el=[...fill.querySelectorAll('.neonRamDischarge')].find(x=>x.dataset.flowSeq==='987680');
     const computed=el?getComputedStyle(el):null;
     return el?{
       side,amount:el.dataset.returnedRam,lifecycle:el.dataset.lifecycleId,
       transfers:el.dataset.transferIds.split(',').sort(),count:el.dataset.transferCount,
       strength:Number(el.style.getPropertyValue('--discharge-strength')),
       delay:computed.animationDelay,duration:computed.animationDuration,
       animation:computed.animationName,pointer:computed.pointerEvents,
       parentIsFill:el.parentElement===fill
     }:null;
   });
   const zero=!!document.querySelector('.neonRamDischarge[data-flow-seq="987681"]');
   return {items,zero,widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width)};
 });
 if(discharge.zero||discharge.widths.join(',')!==simultaneous.after.join(','))
   fail('Final discharge invented return or changed RAM width: '+JSON.stringify(discharge));
 for(const [index,side] of ['p','e'].entries()){
   const item=discharge.items[index];
   const expectedIds=side==='p'?['attack:987679:p:0','attack:987679:p:3']:['attack:987679:e:1'];
   if(!item||item.side!==side||item.amount!==(side==='p'?'5':'4')||
      item.lifecycle!=='attack:987679'||item.count!==String(expectedIds.length)||
      item.transfers.join(',')!==expectedIds.join(',')||item.strength<=0||
      item.delay!=='3.15s'||item.duration!=='0.65s'||
      !item.animation.includes('neonRamDischargeSweep')||
      item.pointer!=='none'||!item.parentIsFill)
     fail('Final neon discharge diverges from observed recovery: '+JSON.stringify(discharge));
 }
 const afterglows=await page.evaluate(()=>{
   const items=['p','e'].map(side=>{
     const fill=document.getElementById(side+'RamAvailable');
     const el=[...fill.querySelectorAll('.neonRamAfterglow')].find(x=>x.dataset.flowSeq==='987680');
     const css=el?getComputedStyle(el):null;
     return el?{side,amount:el.dataset.returnedRam,lifecycle:el.dataset.lifecycleId,
       transfers:el.dataset.transferIds.split(',').sort(),count:el.dataset.transferCount,
       strength:Number(el.style.getPropertyValue('--afterglow-strength')),
       delay:css.animationDelay,duration:css.animationDuration,name:css.animationName,
       pointer:css.pointerEvents,parentIsFill:el.parentElement===fill}:null;
   });
   return {items,zero:!!document.querySelector('.neonRamAfterglow[data-flow-seq="987681"]'),
     widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width)};
 });
 if(afterglows.zero||afterglows.widths.join(',')!==simultaneous.after.join(','))
   fail('Afterglow fabricated zero-RAM return or changed actual RAM fill: '+JSON.stringify(afterglows));
 for(const [index,side] of ['p','e'].entries()){
   const item=afterglows.items[index];
   const ids=side==='p'?['attack:987679:p:0','attack:987679:p:3']:['attack:987679:e:1'];
   if(!item||item.side!==side||item.amount!==(side==='p'?'5':'4')||
      item.lifecycle!=='attack:987679'||item.count!==String(ids.length)||
      item.transfers.join(',')!==ids.join(',')||item.strength<=0||
      item.delay!=='3.8s'||item.duration!=='1.05s'||
      !item.name.includes('neonRamAfterglowFade')||
      item.pointer!=='none'||!item.parentIsFill)
      fail('Afterglow does not preserve recovery evidence or delay: '+JSON.stringify(afterglows));
 }
 // v2.8.84: inject two observed releases on the same player meter before
 // either animation expires. Each event must remain independently removable.
 const overlaps=await page.evaluate(()=>{
   const fill=document.getElementById('pRamAvailable');
   const track=fill.parentElement;
   const before=fill.style.width;
   const first=988401,second=988402;
   drawEnergyPathways({seq:first,impactSeq:988400,events:[
     {side:'p',type:'release',amount:2,slots:[{slot:0,amount:2}]}]});
   drawEnergyPathways({seq:second,impactSeq:988401,events:[
     {side:'p',type:'release',amount:7,slots:[{slot:2,amount:3},{slot:4,amount:4}]}]});
   const elements=selector=>[...document.querySelectorAll(selector)];
   const groups=[
     {name:'reservoir',nodes:elements('#pRamAvailable ~ .neonRamReservoir')},
     {name:'discharge',nodes:elements('#pRamAvailable > .neonRamDischarge')},
     {name:'afterglow',nodes:elements('#pRamAvailable > .neonRamAfterglow')},
     {name:'photon',nodes:elements('#pPathways > .neonRecoveryReturn')},
     {name:'arrival',nodes:elements('#pPathways > .neonRecoveryArrival')}
   ];
   const report=groups.map(g=>{
     const list=g.nodes.filter(x=>[String(first),String(second)].includes(x.dataset.flowSeq));
     return {name:g.name,entries:list.map(x=>({
       seq:x.dataset.flowSeq,cycle:x.dataset.cycleId,
       lifecycle:x.dataset.lifecycleId,amount:x.dataset.returnedRam,
       pointer:getComputedStyle(x).pointerEvents
     }))};
   });
   // Simulate completion only of the FIRST reservoir; it must not remove
   // the second reservoir or the second event's afterglow.
   const old=[...track.querySelectorAll('.neonRamReservoir')]
     .find(x=>x.dataset.flowSeq===String(first));
   const newer=[...track.querySelectorAll('.neonRamReservoir')]
     .find(x=>x.dataset.flowSeq===String(second));
   old?.dispatchEvent(new Event('animationend'));
   const independent=!!newer?.isConnected&&!old?.isConnected;
   const newerAfterglow=!!fill.querySelector('.neonRamAfterglow[data-flow-seq="988402"]');
   return {report,independent,newerAfterglow,before,after:fill.style.width,
     fiveSlots:document.querySelectorAll('#pLanes>.slot').length};
 });
 if(!overlaps.independent||!overlaps.newerAfterglow||
    overlaps.before!==overlaps.after||overlaps.fiveSlots!==5)
   fail('Overlapping cycle altered game meter, destroyed other glow or collapsed cards: '+JSON.stringify(overlaps));
 for(const g of overlaps.report){
   const expected=g.name==='photon'||g.name==='arrival'?
     [['988401','2'],['988402','3'],['988402','4']]:
     [['988401','2'],['988402','7']];
   const actual=g.entries.map(x=>[x.seq,x.amount]).sort((a,b)=>a[0].localeCompare(b[0])||Number(a[1])-Number(b[1]));
   if(JSON.stringify(actual)!==JSON.stringify(expected)||
      g.entries.some(x=>x.pointer!=='none'||x.cycle!==x.lifecycle+':flow:'+x.seq+':p'))
     fail('Overlapping '+g.name+' events lost independent lineage: '+JSON.stringify(overlaps));
 }
 // v2.8.85: high-frequency release bursts must keep newest twelve visual
 // cycle groups per side, without ever touching the underlying RAM width.
 const rapid=await page.evaluate(()=>{
   const fill=document.getElementById('pRamAvailable');
   const before=fill.style.width;
   for(let n=0;n<30;n++)drawEnergyPathways({seq:989000+n,impactSeq:989500+n,
     events:[{side:'p',type:'release',amount:1,slots:[{slot:n%5,amount:1}]}]});
   const parent=document.querySelector('#gameBoard .side.you');
   const nodes=[...parent.querySelectorAll('[data-cycle-id]')];
   const ids=[...new Set(nodes.map(el=>el.dataset.cycleId))];
   const newest='attack:989529:flow:989029:p';
   const oldest='attack:989500:flow:989000:p';
   const latestNodes=nodes.filter(x=>x.dataset.cycleId===newest);
   const firstOlder=nodes.filter(x=>x.dataset.cycleId===oldest);
   // An individual animationend is allowed to remove only its own element.
   const oldGlow=parent.querySelector('.neonRamAfterglow[data-flow-seq="989018"]');
   const newestGlow=parent.querySelector('.neonRamAfterglow[data-flow-seq="989029"]');
   oldGlow?.dispatchEvent(new Event('animationend'));
   return {limit:MAX_VISIBLE_RECOVERY_CYCLES,cycleCount:ids.length,latestNodes:latestNodes.length,
     firstOlder:firstOlder.length,oldGlowGone:!oldGlow?.isConnected,
     newestGlowIntact:!!newestGlow?.isConnected,
     widthBefore:before,widthAfter:fill.style.width,
     cardSlots:document.querySelectorAll('#pLanes > .slot').length,
     latestCycle:ids.includes(newest),invalidPointer:nodes.some(x=>x.isConnected&&getComputedStyle(x).pointerEvents!=='none'),
     pointerOffenders:nodes.filter(x=>x.isConnected&&getComputedStyle(x).pointerEvents!=='none')
       .slice(0,6).map(x=>({tag:x.tagName,cls:x.getAttribute('class'),pointer:getComputedStyle(x).pointerEvents}))};
 });
 if(rapid.cycleCount>rapid.limit||rapid.cycleCount!==12||rapid.latestNodes<5||
    rapid.firstOlder!==0||!rapid.oldGlowGone||!rapid.newestGlowIntact||
    rapid.widthBefore!==rapid.widthAfter||rapid.cardSlots!==5||
    !rapid.latestCycle||rapid.invalidPointer)
   fail('Rapid recovery cleanup did not bound visual cycles independently: '+JSON.stringify(rapid));
 // v2.8.86 — every recorded ephemeral recovery overlay must disappear
 // at the end of its OWN animation; no retained ghost overlay on either side.
 const quiescent=await page.evaluate(()=>{
   const selector='#gameBoard .neonRamReservoir,#gameBoard .neonRamDischarge,'+
     '#gameBoard .neonRamAfterglow,#gameBoard .neonRamCharge,'+
     '#gameBoard .neonRecoveryReturn,#gameBoard .neonRecoveryCore,'+
     '#gameBoard .neonRecoveryArrival';
   const before=[...document.querySelectorAll(selector)];
   const blocked=before.filter(node=>getComputedStyle(node).pointerEvents!=='none').length;
   const ramBefore=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   for(const node of before)node.dispatchEvent(new Event('animationend'));
   const still=document.querySelectorAll(selector).length;
   const ramAfter=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   return {total:before.length,blocked,remaining:still,
     ramUnchanged:JSON.stringify(ramBefore)===JSON.stringify(ramAfter),
     playerSlots:document.querySelectorAll('#pLanes>.slot').length,
     botSlots:document.querySelectorAll('#eLanes>.slot').length};
 });
 if(quiescent.blocked||quiescent.remaining||!quiescent.ramUnchanged||
    quiescent.playerSlots!==5||quiescent.botSlots!==5)
   fail('Recovery visuals failed full quiescence: '+JSON.stringify(quiescent));
 // v2.8.87: real elapsed Chromium animation playback, not simulated
 // animationend. The new recovery must persist initially, then self-expire.
 const timed=await page.evaluate(()=>{
   const before=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   const start=performance.now();
   drawEnergyPathways({seq:989870,impactSeq:989869,events:[
     {side:'p',type:'release',amount:3,slots:[{slot:2,amount:3}]}]});
   const ids=['neonRecoveryReturn','neonRecoveryCore','neonRecoveryArrival',
     'neonRamReservoir','neonRamCharge','neonRamDischarge','neonRamAfterglow'];
   const nodes=ids.map(cls=>document.querySelector('.'+cls+'[data-flow-seq="989870"]'));
   const metadata=nodes.map((x,i)=>({cls:ids[i],exists:!!x,
     delay:x?getComputedStyle(x).animationDelay:null,
     duration:x?getComputedStyle(x).animationDuration:null,
     pointer:x?getComputedStyle(x).pointerEvents:null,
     id:x?.dataset.lifecycleId,cycle:x?.dataset.cycleId}));
   return {start,metadata,before};
 });
 if(timed.metadata.some(x=>!x.exists||x.pointer!=='none'||x.id!=='attack:989869'||
      x.cycle!=='attack:989869:flow:989870:p'))
    fail('Real-time cycle failed to instantiate safely: '+JSON.stringify(timed));
 await page.waitForTimeout(1100);
 const mid=await page.evaluate(()=>({
   elapsed:performance.now(),
   active:document.querySelectorAll('[data-flow-seq="989870"]').length,
   afterglow:!!document.querySelector('.neonRamAfterglow[data-flow-seq="989870"]')
 }));
 if(!mid.active||!mid.afterglow)
   fail('Real-time recovery disappeared before its delayed afterglow: '+JSON.stringify(mid));
 await page.waitForTimeout(4200);
 const completed=await page.evaluate(()=>({
   now:performance.now(),
   remaining:document.querySelectorAll('[data-flow-seq="989870"]').length,
   widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width),
   slots:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)
 }));
 // The normal returnRoute path lacks the flow metadata; verify here only
 // the provenance-linked recovery visual sequence and its completion.
 if(completed.remaining||completed.widths.join(',')!==timed.before.join(',')||
    completed.slots.some(x=>x!==5)||completed.now-timed.start<4800)
   fail('Real elapsed animation did not reach quiescence: '+JSON.stringify({timed,mid,completed}));
 // v2.8.88 — two more real elapsed animation cycles, including a
 // repeat on the same meter. No forced animationend events, only Chromium
 // playback, event-scoped DOM cleanup, and a stable card/RAM snapshot.
 const repeated=[];
 for(const [seq,impact,side,slot,amount] of [
   [989880,989879,'p',0,2],[989881,989880,'e',3,4]
 ]){
   const result=await page.evaluate(({seq,impact,side,slot,amount})=>{
     const start=performance.now();
     const widths=['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width);
     drawEnergyPathways({seq,impactSeq:impact,events:[
       {side,type:'release',amount,slots:[{slot,amount}]}]});
     const nodes=[...document.querySelectorAll('[data-flow-seq="'+seq+'"]')];
     return {start,widths,count:nodes.length,
       cycles:[...new Set(nodes.map(x=>x.dataset.cycleId).filter(Boolean))],
       pointerSafe:nodes.every(x=>getComputedStyle(x).pointerEvents==='none')};
   },{seq,impact,side,slot,amount});
   if(result.count<7||!result.pointerSafe||
      result.cycles.join(',')!=='attack:'+impact+':flow:'+seq+':'+side)
     fail('Repeated recovery did not start safely: '+JSON.stringify({seq,result}));
   await page.waitForTimeout(5100);
   const finished=await page.evaluate(seq=>({
     now:performance.now(),
     remaining:document.querySelectorAll('[data-flow-seq="'+seq+'"]').length,
     widths:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width),
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
   }),seq);
   if(finished.remaining||finished.widths.join(',')!==result.widths.join(',')||
      finished.slots.some(x=>x!==5)||finished.now-result.start<4800)
     fail('Repeated real-time recovery left stale visuals: '+JSON.stringify({seq,result,finished}));
   repeated.push({seq,side,amount,elapsedMs:Math.round(finished.now-result.start),
     remaining:finished.remaining});
 }
 // v2.8.89 — two same-time positive releases, then a third alternating
 // arrival before expiration. Read only DOM animation and actual gauge style.
 const alternating=await page.evaluate(()=>{
   const widths=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   const seqs=[989890,989891,989892];
   drawEnergyPathways({seq:seqs[0],impactSeq:989889,events:[
     {side:'p',type:'release',amount:2,slots:[{slot:0,amount:2}]}]});
   drawEnergyPathways({seq:seqs[1],impactSeq:989890,events:[
     {side:'e',type:'release',amount:4,slots:[{slot:3,amount:4}]}]});
   drawEnergyPathways({seq:seqs[2],impactSeq:989891,events:[
     {side:'p',type:'release',amount:3,slots:[{slot:1,amount:3}]}]});
   const rows=seqs.map((seq,i)=>{
     const side=i===1?'e':'p';
     const selector='[data-flow-seq="'+seq+'"]';
     const nodes=[...document.querySelectorAll(selector)];
     const charge=document.querySelector('#'+side+'RamAvailable .neonRamAfterglow'+selector);
     const track=document.getElementById(side+'RamAvailable').parentElement;
     const reservoir=[...track.querySelectorAll('.neonRamReservoir')]
       .find(el=>el.dataset.flowSeq===String(seq));
     return {seq,side,nodeCount:nodes.length,
       cycleIds:[...new Set(nodes.map(x=>x.dataset.cycleId).filter(Boolean))],
       pointerSafe:nodes.every(x=>getComputedStyle(x).pointerEvents==='none'),
       amount:reservoir?.dataset.returnedRam,
       hue:charge?getComputedStyle(charge).backgroundImage:'',
       reservoir:!!reservoir,afterglow:!!charge};
   });
   return {widths,rows};
 });
 const expectedAlt=[['p','2','989889'],['e','4','989890'],['p','3','989891']];
 for(let i=0;i<alternating.rows.length;i++){
   const x=alternating.rows[i],e=expectedAlt[i];
   const colorGood=x.side==='p'?x.hue.includes('255, 210, 142'):x.hue.includes('248, 215, 255');
   if(x.side!==e[0]||x.amount!==e[1]||!x.reservoir||!x.afterglow||
     x.nodeCount<7||!x.pointerSafe||!colorGood||
     x.cycleIds.join(',')!=='attack:'+e[2]+':flow:'+x.seq+':'+x.side)
     fail('Alternating player neon paths or ancestry differ: '+JSON.stringify(alternating));
 }
 await page.waitForTimeout(5300);
 const alternatingEnd=await page.evaluate(()=>({
   remain:[989890,989891,989892].map(seq=>
     document.querySelectorAll('[data-flow-seq="'+seq+'"]').length),
   widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width),
   slots:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)
 }));
 if(alternatingEnd.remain.some(Boolean)||
    alternatingEnd.widths.join(',')!==alternating.widths.join(',')||
    alternatingEnd.slots.some(n=>n!==5))
   fail('Alternating side recoveries failed independent cleanup: '+JSON.stringify(alternatingEnd));
 console.log('ALTERNATING RECOVERY PASS: player orange, bot purple, three overlapping cycles, natural cleanup');
 console.log('REPEATED LIFECYCLE PASS: '+JSON.stringify(repeated));
 console.log('REAL-TIME LIFECYCLE PASS: positive RAM transfer, delayed visual stages, natural cleanup after 5.3s');
 console.log('QUIESCENCE PASS: all recovery effects expired independently, meters and ten squares retained');
 console.log('RAPID CLEANUP PASS: 30 releases bounded to 12 visual cycles, newest kept, RAM unchanged');
 console.log('OVERLAP PASS: two independent recovery cycles, old cleanup cannot erase new cycle');
 console.log('AFTERGLOW PASS: delayed bounded fading overlay, both sides, zero RAM mutation');
 console.log('RESERVOIR DISCHARGE PASS: delayed sweep over available RAM fill, both sides, provenance intact');
 console.log('NEON RESERVOIR PASS: pooled positive releases, both sides, no RAM mutation');
 console.log('SIMULTANEOUS RECOVERY PASS: three positive card transfers, both RAM meters, zero false releases, unchanged fill widths');
 console.log('METER CHARGE PASS: amount-scaled intensity and original lifecycle lineage');
 console.log('ENERGY LIFECYCLE PASS: attack evidence ties shockwave, RAM packet and arrival to one source');


 console.log('SHIELD SHIMMER PASS: two tilted elliptical rims and specular glint at real defender');
 console.log('DEFENDER RIPPLE PASS: three staggered shield rings at real defender; zero on direct hit');
 // v2.8.74: return photon is derived only from recorded positive retaliation.
 // Exercise read-only rendering with real slot coordinates; game engine untouched.
 const rebound=await page.evaluate(()=>{
   const svg=document.getElementById('combatPathways');
   drawCombatPathways({from:'p',to:'e',source:0,target:0,kind:'blocked',retaliation:3,seq:987656});
   const ray=[...svg.querySelectorAll('.neonRetaliationRebound')]
     .find(x=>x.dataset.attackSeq==='987656');
   const core=[...svg.querySelectorAll('.neonRetaliationCore')]
     .find(x=>x.dataset.attackSeq==='987656');
   const ring=[...svg.querySelectorAll('.neonRetaliationLanding')]
     .find(x=>x.dataset.attackSeq==='987656');
   const board=document.getElementById('gameBoard').getBoundingClientRect();
   const source=document.querySelector('#pLanes > .slot').getBoundingClientRect();
   const target=document.querySelector('#eLanes > .slot').getBoundingClientRect();
   const pos=r=>[r.left+r.width/2-board.left,r.top+r.height/2-board.top];
   const [px,py]=pos(source),[ex,ey]=pos(target);
   const shape=ray?.getAttribute('d')||'';
   const expected=typeof routeBetween==='function'?routeBetween([ex,ey],[px,py]):null;
   const result={
    from:ray?.dataset.from,to:ray?.dataset.to,retaliation:ray?.dataset.retaliation,
    reverse:shape===expected,paired:core?.getAttribute('d')===shape,
    pointer:ray?getComputedStyle(ray).pointerEvents:null,
    animation:ray?getComputedStyle(ray).animationName:null,
    delay:ray?getComputedStyle(ray).animationDelay:null,
    landing:ring?Math.abs(Number(ring.getAttribute('cx'))-px)<2&&
      Math.abs(Number(ring.getAttribute('cy'))-py)<2:false,
    landingDelay:ring?getComputedStyle(ring).animationDelay:null
   };
   drawCombatPathways({from:'p',to:'e',source:0,target:0,kind:'blocked',retaliation:0,seq:987657});
   drawCombatPathways({from:'p',to:'e',source:0,target:-1,kind:'direct',retaliation:9,seq:987658});
   result.noFalseReturn=!['987657','987658'].some(seq=>
     [...svg.querySelectorAll('.neonRetaliationRebound')].some(x=>x.dataset.attackSeq===seq));
   return result;
 });
 if(rebound.from!=='e:0'||rebound.to!=='p:0'||rebound.retaliation!=='3'||
    !rebound.reverse||!rebound.paired||rebound.pointer!=='none'||
    !rebound.animation?.includes('neonRetaliationTravel')||rebound.delay!=='1.1s'||
    !rebound.landing||rebound.landingDelay!=='1.66s'||!rebound.noFalseReturn)
   fail('Retaliation photon must reverse actual positive return damage: '+JSON.stringify(rebound));
 console.log('RETALIATION PASS: real reverse slot route, 3 damage, return core, delayed landing; no false rebounds');

 console.log('IMPACT DISCHARGE PASS: real target, six rays, delayed corona, noninteractive');
 console.log('ATTACK NEON PASS: matched real route, noninteractive, animated and keyed to target');

 // v2.8.70 live neon tubes/trails must be rendered as pure decoration.
 const neonTubes=await page.evaluate(()=>{
  const board=document.getElementById('gameBoard');
  const opposing=document.querySelector('#gameBoard .side.opponent');
  const player=document.querySelector('#gameBoard .side.you');
  const first=board?.getBoundingClientRect();
  const tube=getComputedStyle(board,'::after'),purple=getComputedStyle(opposing,'::after'),orange=getComputedStyle(player,'::after');
  return {
   tubeAnimation:tube.animationName,purpleAnimation:purple.animationName,orangeAnimation:orange.animationName,
   pointer:tube.pointerEvents,boardWidth:first?.width,
   mural1:getComputedStyle(document.getElementById('neuroscapeArt'),'::after').animationName,
   mural2:getComputedStyle(document.getElementById('signalFoundry'),'::after').animationName
  };
 });
 if(!neonTubes.tubeAnimation.includes('neonTubeCircuit')||
    !neonTubes.purpleAnimation.includes('neonLaneTravel')||
    !neonTubes.orangeAnimation.includes('neonLaneTravel')||
    !neonTubes.mural1.includes('neonLaneTravel')||
    !neonTubes.mural2.includes('neonLaneTravel')||
    neonTubes.pointer!=='none')
   fail('Neon tubes/trails missing or intercepting gameplay: '+JSON.stringify(neonTubes));
 console.log('NEON TUBES PASS: animated chrome perimeter, orange/purple lanes, both murals; pointer safe');

 // Active-neon skin uses the original live game turn metadata, without replacing the board.
 const turnNeon=await page.evaluate(()=>({
  active:document.getElementById('gameBoard')?.dataset.activeSide,
  phase:document.getElementById('gameBoard')?.dataset.rhythm,
  neon:document.getElementById('gameBoard')?.dataset.neonIntensity,
  animation:getComputedStyle(document.querySelector('#turnbar strong')).animationName,
  divider:getComputedStyle(document.querySelector('#gameBoard .divider'),'::after').animationName
 }));
 if(turnNeon.active!=='p'||!turnNeon.animation.includes('neonPlayerTurn')||
    !turnNeon.divider.includes('neonDividerSweep')||turnNeon.neon!=='normal')
   fail('Active neon initialization failed: '+JSON.stringify(turnNeon));

 if(initial.installDisabled)fail('Install RAM button disabled at match start');
 await page.getByRole('button',{name:/Install RAM/i}).click();
 const ram=await page.locator('#pInstalled').textContent();
 if(ram!=='1')fail('Install RAM did not execute');
 // The optional art engines observe the visible game log, never game state.
 await page.waitForFunction(()=>document.querySelector('#coresSignal')?.textContent?.includes('CHARGE'),{timeout:3000});
 const reactive=await page.evaluate(()=>({
  cores:document.getElementById('coresSignal')?.textContent,
  foundry:document.getElementById('foundrySignal')?.textContent,
  coresKind:document.getElementById('neuroscapeArt')?.dataset.artSignal,
  foundryKind:document.getElementById('signalFoundry')?.dataset.artSignal
 }));
 if(!reactive.cores?.includes('CHARGE')||!reactive.foundry?.includes('CHARGE')||
    reactive.coresKind!=='charge'||reactive.foundryKind!=='charge')
   fail('Artwork did not observe RAM installation: '+JSON.stringify(reactive));

 await page.getByRole('button',{name:'Restart match'}).click();
 if((await page.locator('#pInstalled').textContent())!=='0')fail('Restart did not reset RAM');
 await page.getByRole('button',{name:'Bot vs Bot'}).click();
 await page.waitForTimeout(900);
 if(errors.length)fail('Browser error after bot start');
 const artCount=await page.locator('#neuroscapeArt, #signalFoundry').count();
 if(artCount!==2)fail('Generative gallery must contain exactly two murals');
 for(const [label,layer,button] of [
   ['Two Cores','generativeCores','regenerateCores'],
   ['Signal Foundry','generativeFoundry','regenerateFoundry']
 ]){
   const before=await page.locator('#'+layer+' circle').first().getAttribute('r');
   const particles=await page.locator('#'+layer+' circle').count();
   if(particles<25)fail(label+' does not have a populated procedural particle field');
   await page.locator('#'+button).click();
   const after=await page.locator('#'+layer+' circle').first().getAttribute('r');
   if(before===after)fail(label+' regenerate did not produce a new procedural seed');
 }
 // v2.8.64: different generators, both based on observed game events.
 const signatures=await page.evaluate(()=>({
  cores:document.getElementById('generativeCores')?.dataset.pattern,
  foundry:document.getElementById('generativeFoundry')?.dataset.pattern,
  coresEvents:Number(document.getElementById('generativeCores')?.dataset.observedEvents),
  foundryEvents:Number(document.getElementById('generativeFoundry')?.dataset.observedEvents),
  labelCores:document.getElementById('coresSignature')?.textContent,
  labelFoundry:document.getElementById('foundrySignature')?.textContent
 }));
 if(signatures.cores!=='dual-helix'||signatures.foundry!=='crystal-lattice')
   fail('Art panels lack distinct bounded generative signatures: '+JSON.stringify(signatures));
 if(signatures.coresEvents<1||signatures.coresEvents>12||signatures.foundryEvents!==signatures.coresEvents)
   fail('Art observation window absent or unbounded: '+JSON.stringify(signatures));
 if(!signatures.labelCores?.startsWith('HELIX')||!signatures.labelFoundry?.startsWith('LATTICE'))
   fail('Generative signatures not displayed');
 // Actual SVG primitives must be distinct: helix uses cubic C, lattice uses L.
 await page.waitForFunction(()=>['generativeCores','generativeFoundry'].every(id=>document.getElementById(id)?.dataset.geometryReady==='yes'),null,{timeout:4500});
 const actualPaths=await page.evaluate(()=>({
   cores:[...document.querySelectorAll('#generativeCores > path')].map(e=>e.getAttribute('d')),
   foundry:[...document.querySelectorAll('#generativeFoundry > path')].map(e=>e.getAttribute('d'))
 }));
 if(!actualPaths.cores.some(d=>/ C /.test(d||''))||!actualPaths.foundry.some(d=>/ L /.test(d||'')))
   fail('Generated path geometries must differ and initialize before scrolling: '+JSON.stringify(actualPaths));
 // Sustained combat must derive from observed events and fade over time.
 // Inject synthetic display-log entries ONLY; no engine actions or state edits.
 for(let i=0;i<4;i++){
   await page.evaluate(i=>{
     const el=document.createElement('li');
     el.textContent='VISUAL TEST '+i+' attacked defender for 1 damage';
     document.getElementById('events').prepend(el);
   },i);
   await page.waitForTimeout(30);
 }
 await page.waitForFunction(()=>document.getElementById('generativeCores')?.dataset.patternPhase==='sustained',null,{timeout:3000});
 const pressure=await page.evaluate(()=>({
   a:document.getElementById('generativeCores').dataset.combatPressure,
   b:document.getElementById('generativeFoundry').dataset.combatPressure,
   aPhase:document.getElementById('generativeCores').dataset.patternPhase,
   bPhase:document.getElementById('generativeFoundry').dataset.patternPhase
 }));
 if(pressure.aPhase!=='sustained'||pressure.bPhase!=='sustained'||
    Number(pressure.a)<.67||pressure.a!==pressure.b)
   fail('Sustained pattern not synchronized: '+JSON.stringify(pressure));
 // Read-only virtual-horizon verification: no 12-second real wait, no game edits.
 const recovery=await page.evaluate(()=>({
   current:window.neuroscapeArtRecovery.snapshot(0),
   afterSix:window.neuroscapeArtRecovery.snapshot(6000),
   afterThirteen:window.neuroscapeArtRecovery.snapshot(13000)
 }));
 if(recovery.current.level!=='SUSTAINED'||
    recovery.afterSix.pressure>=recovery.current.pressure||
    recovery.afterThirteen.level!=='QUIET'||recovery.afterThirteen.pressure!==0)
   fail('Combat pressure must cool monotonically to quiet: '+JSON.stringify(recovery));
 if(recovery.current.samples>12||recovery.current.panels!==2)
   fail('Visual recovery exceeded history/panel limits: '+JSON.stringify(recovery));
 console.log('RECOVERY PASS: sustained → cooling → quiet, observation only, no gameplay acceleration');
 // A new real bot-vs-bot cycle exercises actual legal actions and log updates.
 await page.getByRole('button',{name:'Bot vs Bot'}).click();
 const beforeCycle=await page.evaluate(()=>({
   event:document.getElementById('coresSignal')?.textContent,
   turn:document.getElementById('turnText')?.textContent
 }));
 await page.waitForTimeout(4200);
 const live=await page.evaluate(()=>({
   turn:document.getElementById('turnText')?.textContent,
   log:[...document.querySelectorAll('#events > li')].map(e=>e.textContent),
   a:document.getElementById('coresSignal')?.textContent,
   b:document.getElementById('foundrySignal')?.textContent,
   visual:window.neuroscapeArtRecovery?.snapshot(0),
   lanes:['pLanes','eLanes'].map(id=>[...document.querySelectorAll('#'+id+' > .slot')].map(e=>{
     const box=e.getBoundingClientRect();return [box.width,box.height];
   }))
 }));
 if(live.turn===beforeCycle.turn||!live.a||live.a===beforeCycle.event||live.a!==live.b)
   fail('Real bot actions did not produce synchronized observed-art events: '+JSON.stringify(live));
 if(!live.log.some(x=>/installed RAM|drew a card|deployed|attacked|damage/i.test(x)))
   fail('Real bot-vs-bot legal gameplay did not progress: '+JSON.stringify(live.log));
 if(live.visual?.panels!==2||live.visual?.samples>12||
    live.lanes.some(l=>l.length!==5||l.some(([w,h])=>w<70||h<70)))
   fail('Real gameplay disturbed murals or card-space invariant: '+JSON.stringify(live));
 // v2.8.90 — inspect actual legal bot combat without calling visual
 // renderers or injecting a synthetic release. Observe the engine's rendered
 // flow markers and verify any naturally emitted recovery's provenance.
 await page.evaluate(()=>{
   const samples=[],observed=new Map();
   const start=performance.now();
   const read=()=>{
     const values=['p','e'].map(side=>({
       side,turn:document.getElementById('turnText')?.textContent||'',
       flow:document.getElementById(side+'Flow')?.textContent||'',
       ram:document.getElementById(side+'Ram')?.textContent||'',
       cycleCount:[...new Set([...document.querySelectorAll('#'+side+'Pathways [data-cycle-id], #'+side+'RamAvailable [data-cycle-id], #'+side+'RamAvailable ~ [data-cycle-id]')].map(x=>x.dataset.cycleId))].length
     }));
     if(samples.length<80)samples.push({at:performance.now()-start,values});
     for(const value of values)if(/RETURNED \d+ RAM/.test(value.flow))observed.set(value.side+':'+value.flow,value);
   };
   read();
   const timer=setInterval(read,160);
   window.__liveMatchAuditFinish=()=>{clearInterval(timer);read();return {
     samples,positiveFlows:[...observed.values()],
     endTurn:document.getElementById('turnText')?.textContent,
     widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width),
     lanes:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length),
     errors:document.querySelectorAll('.neonRamAfterglow:not([data-cycle-id])').length
   }};
 });
 await page.waitForTimeout(9500);
 const matchAudit=await page.evaluate(()=>{
   const result=window.__liveMatchAuditFinish();
   delete window.__liveMatchAuditFinish;
   return result;
 });
 if(matchAudit.samples.length<20||matchAudit.lanes.some(n=>n!==5)||
    matchAudit.errors||matchAudit.samples.some(sample=>
      sample.values.some(value=>value.cycleCount>12)))
   fail('Live match recovery audit changed board or exceeded visual bound: '+JSON.stringify(matchAudit));
 if(!matchAudit.samples.some(sample=>
    sample.values[0].turn!==matchAudit.samples[0].values[0].turn))
   fail('Live match did not advance while auditing recovery: '+JSON.stringify(matchAudit));
 console.log('LIVE MATCH AUDIT: '+JSON.stringify({
   samples:matchAudit.samples.length,positiveReleases:matchAudit.positiveFlows.length,
   endTurn:matchAudit.endTurn,
   limitation:matchAudit.positiveFlows.length?'Natural recovery observed':'No positive recovery observed in fixed observation window'
 }));
 console.log('LIVE COMBAT PASS: real bot actions, matching mural telemetry, 10 protected card stations');


 // Restore engine-owned log on next legitimate gameplay render.
 await page.getByRole('button',{name:'Play vs Bot'}).click();
 if(errors.length)fail('Browser error after simulated visual-only combat pressure');
 console.log('SUSTAINED RESPONSE PASS: bounded combat pressure drives both murals');
 console.log('GENERATIVE SIGNATURES PASS: dual helix, faceted lattice, bounded observed-event history');
 const still=await page.evaluate(()=>['pLanes','eLanes'].every(id=>{
   const a=[...document.querySelectorAll('#'+id+' > .slot')];
   return a.length===5&&a.every(e=>e.getBoundingClientRect().height>=70);
 }));
 if(!still)fail('Artwork regenerate changed protected card-space dimensions');
 // Rendered-health-only test: simulate readout changes without altering combat state.
 const originalHealth=await page.evaluate(()=>({
  p:document.getElementById('pHealth').textContent,
  e:document.getElementById('eHealth').textContent
 }));
 const assertMomentum=async(p,e,want)=>{
  await page.evaluate(({p,e})=>{
   document.getElementById('pHealth').textContent=p;
   document.getElementById('eHealth').textContent=e;
  },{p,e});
  await page.waitForFunction(label=>document.getElementById('coresMomentumText')?.textContent===label,want);
  const both=await page.locator('#foundryMomentumText').textContent();
  if(both!==want)fail('Foundry and Two Cores momentum diverged: '+both);
 };
 await assertMomentum('BF 20 / MF 20','BF 20 / MF 20','BALANCED');
 const geometry=async layer=>page.locator('#'+layer).evaluate(e=>({
  shift:Number(e.dataset.geometryShift),bend:Number(e.dataset.geometryBend),tilt:Number(e.dataset.geometryTilt)
 }));
 const balanceCores=await geometry('generativeCores'),balanceFoundry=await geometry('generativeFoundry');
 if(balanceCores.shift!==0||balanceCores.bend!==0||balanceFoundry.shift!==0||balanceFoundry.bend!==0)
   fail('Balanced board must have symmetrical procedural geometry');

 await assertMomentum('BF 20 / MF 20','BF 12 / MF 8','PLAYER ADVANTAGE');
 const orangePosition=await page.locator('#coresMomentumNeedle').evaluate(e=>parseFloat(e.style.left));
 if(orangePosition<=50)fail('Player advantage must move momentum needle orange/right');
 const orangeCores=await geometry('generativeCores'),orangeFoundry=await geometry('generativeFoundry');
 if(orangeCores.shift<=0||orangeCores.bend<=0||orangeFoundry.shift!==orangeCores.shift||
    orangeFoundry.bend!==orangeCores.bend)
   fail('Player lead must bend both art geometries right/orange');

 await assertMomentum('BF 8 / MF 12','BF 20 / MF 20','BOT ADVANTAGE');
 const purplePosition=await page.locator('#coresMomentumNeedle').evaluate(e=>parseFloat(e.style.left));
 if(purplePosition>=50)fail('Bot advantage must move momentum needle violet/left');
 const purpleCores=await geometry('generativeCores'),purpleFoundry=await geometry('generativeFoundry');
 if(purpleCores.shift>=0||purpleCores.bend>=0||purpleFoundry.shift!==purpleCores.shift||
    purpleFoundry.bend!==purpleCores.bend)
   fail('Bot lead must bend both art geometries left/violet');

 await page.evaluate(({p,e})=>{
   document.getElementById('pHealth').textContent=p;
   document.getElementById('eHealth').textContent=e;
 },originalHealth);
 if(errors.length)fail('Browser errors during momentum response');
 console.log('GEOMETRY PASS: symmetric at zero; rightward for player and leftward for bot on both murals');
 console.log('MOMENTUM PASS: both murals follow only displayed health, balanced/player/bot, without changing game state');

 if(errors.length)fail('Browser error after artwork regeneration');
 console.log('ART GENERATION PASS: exactly two active procedural scenes, both regenerate, card space unchanged');
 console.log('ARENA PASS: five large squares per side, hand, controls, RAM install/restart and bot start',JSON.stringify(initial));
}finally{
 await page.screenshot({path:'arena-regression.png',fullPage:true});
 await browser.close();
}
