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
 console.log('DEFENDER RIPPLE PASS: three staggered shield rings at real defender; zero on direct hit');
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
