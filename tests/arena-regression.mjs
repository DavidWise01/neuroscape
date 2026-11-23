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
 await page.locator('#neuroscapeArt').scrollIntoViewIfNeeded();
 await page.waitForTimeout(175);
 const coresPath=await page.locator('#generativeCores > path').first().getAttribute('d');
 await page.locator('#signalFoundry').scrollIntoViewIfNeeded();
 await page.waitForTimeout(175);
 const foundryPath=await page.locator('#generativeFoundry > path').first().getAttribute('d');
 if(!/ C /.test(coresPath||'')||!/ L /.test(foundryPath||''))
   fail('Generated paths must actually differ between helix and crystal lattice');
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
