import { chromium } from 'playwright';
import { writeFileSync } from 'node:fs';
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
 // v2.9.30 — equal declared timing budget under 24 adversarial orderings.
 const adversarialCheck=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapeAdversarialTiming;
   const snap=api?.snapshot(),sweep=api?.sweep();
   const schedules=Array.from({length:24},(_,i)=>api?.schedule(i));
   const fixed=Array.from({length:24},(_,i)=>api?.trial(3,'fixed',i));
   const adapt=Array.from({length:24},(_,i)=>api?.trial(3,'adaptive',i));
   const declarations=schedules.every(s=>s&&s.factors.length===4&&
     Math.abs(s.sum-4)<1e-9)&&
     [...fixed,...adapt].every(t=>t&&t.events.length===4&&
       t.events.every(e=>e.impulse===Math.PI)&&
       t.intervals.every(x=>x.residual>=0&&x.residual<=Math.PI));
   const repeat=JSON.stringify(api?.trial(3,'adaptive',7))===
     JSON.stringify(api?.trial(3,'adaptive',7));
   const monotonic=sweep?.rows.every((r,i,all)=>i===0||
     (!all[i-1].stableFixed||r.stableFixed)&&
     (!all[i-1].stableAdaptive||r.stableAdaptive));
   const select=document.getElementById('adversarialTimingPeriod');
   if(select)select.value='1';
   select?.dispatchEvent(new Event('change',{bubbles:true}));
   const short=api?.snapshot().classification;
   if(select)select.value='8';
   select?.dispatchEvent(new Event('change',{bubbles:true}));
   const long=api?.snapshot().classification;
   return {before,after:game(),snap,declarations,repeat,monotonic,
     count:sweep?.rows.length,schedules:schedules.length,
     short,long,selectCount:select?.options.length,
     mounted:!!document.getElementById('adversarialTimingCanvas')};
 });
 if(!adversarialCheck.mounted||!adversarialCheck.snap||
    adversarialCheck.snap.periods!==32||adversarialCheck.snap.schedules!==24||
    adversarialCheck.snap.budgetFactors!==4||
    adversarialCheck.snap.sourceMutated||adversarialCheck.snap.gameplayMutation||
    adversarialCheck.count!==32||adversarialCheck.schedules!==24||
    adversarialCheck.selectCount!==32||
    !adversarialCheck.declarations||!adversarialCheck.repeat||
    !adversarialCheck.monotonic||
    adversarialCheck.short!=='NEITHER ROBUST'||
    JSON.stringify(adversarialCheck.before)!==JSON.stringify(adversarialCheck.after))
   fail('v2.9.30 adversarial timing budget or engine isolation violation: '+JSON.stringify(adversarialCheck));

 // v2.9.29: four fully declared deterministic schedules; recovery before each next injection.
 const irregularCheck=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapeIrregularEnvelope;
   const snap=api?.snapshot(),sweep=api?.sweep();
   const schedules=['regular','alternating','clustered','deterministic'];
   const trials=schedules.map(name=>api?.trial(3,'adaptive',name));
   const short=api?.trial(.5,'adaptive','clustered');
   const long=api?.trial(8.25,'fixed','clustered');
   const selector=document.getElementById('irregularEnvelopePeriod');
   if(selector)selector.value='1';
   selector?.dispatchEvent(new Event('change',{bubbles:true}));
   const selectedShort=api?.snapshot();
   if(selector)selector.value='8';
   selector?.dispatchEvent(new Event('change',{bubbles:true}));
   const selectedLong=api?.snapshot();
   const declared=trials.every(t=>t&&t.count===4&&t.events.length===4&&
     t.events.every(e=>e.injectedRadians===Math.PI)&&
     t.segments.every(s=>s.intervalSeconds>=.1&&s.preNextResidual>=0&&s.preNextResidual<=Math.PI));
   const deterministic=trials.every((t,i)=>JSON.stringify(t)===JSON.stringify(api?.trial(3,'adaptive',schedules[i])));
   const monotonic=sweep?.rows.every((row,i,all)=>i===0||
     (!all[i-1].adaptiveAll||row.adaptiveAll)&&(!all[i-1].fixedAll||row.fixedAll));
   return {before,after:game(),snap,declared,deterministic,monotonic,
     count:sweep?.rows.length,patterns:sweep?.patterns,
     shortStable:short?.stable,longStable:long?.stable,
     selectedShort:selectedShort?.classification,selectedLong:selectedLong?.classification,
     selectCount:selector?.options.length,mounted:!!document.getElementById('irregularEnvelopeCanvas')};
 });
 if(!irregularCheck.mounted||!irregularCheck.snap||
    irregularCheck.snap.periods!==32||irregularCheck.snap.patterns!==4||
    irregularCheck.snap.injectionsPerPattern!==4||
    irregularCheck.snap.sourceMutated||irregularCheck.snap.gameplayMutation||
    irregularCheck.count!==32||irregularCheck.patterns!==4||
    irregularCheck.selectCount!==32||
    !irregularCheck.declared||!irregularCheck.deterministic||
    !irregularCheck.monotonic||
    irregularCheck.shortStable!==false||irregularCheck.longStable!==false||
    irregularCheck.selectedShort!=='NEITHER ROBUST'||
    irregularCheck.selectedLong!=='ADAPTIVE ONLY'||
    JSON.stringify(irregularCheck.before)!==JSON.stringify(irregularCheck.after))
   fail('v2.9.29 irregular envelope or engine isolation violated: '+JSON.stringify(irregularCheck));

 // v2.9.28: swept stability envelope distinguishes recovery regimes without any gameplay mutation.
 const envelopeCheck=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapeStabilityEnvelope;
   const snap=api?.snapshot(),data=api?.sweep();
   const short=api?.trial(.5,'adaptive'),longFixed=api?.trial(8.25,'fixed'),
     longAdaptive=api?.trial(8.25,'adaptive');
   const selector=document.getElementById('stabilityEnvelopePolicy');
   if(selector)selector.value='1';
   selector?.dispatchEvent(new Event('change',{bubbles:true}));
   const shortSnapshot=api?.snapshot();
   if(selector)selector.value='8';
   selector?.dispatchEvent(new Event('change',{bubbles:true}));
   const longSnapshot=api?.snapshot();
   return {before,after:game(),snap,
     count:data?.data.length,events:data?.data.map(x=>x.classification),
     monotonic:data?.data.every((r,i,a)=>i===0||
       (!a[i-1].adaptive.stable||r.adaptive.stable)&&
       (!a[i-1].fixed.stable||r.fixed.stable)),
     shortest:data?.data[0].classification,
     longest:data?.data.at(-1).classification,
     shortTrials:short?.preInjection.length,
     shortStable:short?.stable,
     longFixed:longFixed?.stable,longAdaptive:longAdaptive?.stable,
     shortSnapshot,longSnapshot,
     selectCount:selector?.options.length,
     mounted:!!document.getElementById('stabilityEnvelopeCanvas')};
 });
 if(!envelopeCheck.mounted||!envelopeCheck.snap||
    envelopeCheck.snap.periodsTested!==32||envelopeCheck.snap.trialsPerPeriod!==3||
    !envelopeCheck.snap.visualOnly||envelopeCheck.snap.sourceMutated||
    envelopeCheck.snap.gameplayMutation||
    !envelopeCheck.snap.adaptiveBound||!envelopeCheck.snap.fixedBound||
    !(envelopeCheck.snap.adaptiveBound<envelopeCheck.snap.fixedBound)||
    envelopeCheck.count!==32||envelopeCheck.selectCount!==32||
    envelopeCheck.shortest!=='NEITHER RECOVERS'||
    envelopeCheck.longest!=='BOTH RECOVER'||
    envelopeCheck.shortTrials!==3||envelopeCheck.shortStable!==false||
    envelopeCheck.longFixed!==true||envelopeCheck.longAdaptive!==true||
    envelopeCheck.monotonic!==true||
    envelopeCheck.shortSnapshot?.classification!=='NEITHER RECOVERS'||
    envelopeCheck.longSnapshot?.classification!=='BOTH RECOVER'||
    JSON.stringify(envelopeCheck.before)!==JSON.stringify(envelopeCheck.after))
   fail('v2.9.28 stability envelope or immutable gameplay violated: '+JSON.stringify(envelopeCheck));

 // v2.9.27: all phase injections declared, no autonomous amplification or source mutation.
 const repeatedDisturbance=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapeDisturbanceStability;
   const fixture=Object.freeze([
     Object.freeze({edge:0,axis:0,amplitude:1,phase:0}),
     Object.freeze({edge:31,axis:3,amplitude:1,phase:0})
   ]);
   const sim=api?.simulate(fixture);
   let bounded=true,nonIncreasing=true,knownInjections=true;
   if(sim){
     for(let i=0;i<sim.rows.length;i++){
       const row=sim.rows[i];
       bounded&&=row.fixed>=0&&row.fixed<=Math.PI&&row.adaptive>=0&&row.adaptive<=Math.PI;
       knownInjections&&=(row.injected>0)===[0,20,40,60].includes(i);
       if(i&&row.injected===0){
         nonIncreasing&&=row.fixed<=sim.rows[i-1].fixed+1e-12;
         nonIncreasing&&=row.adaptive<=sim.rows[i-1].adaptive+1e-12;
       }
     }
   }
   const start=document.getElementById('disturbanceStabilityRun');
   const reset=document.getElementById('disturbanceStabilityReset');
   start?.click();const started=api?.snapshot();
   reset?.click();const stopped=api?.snapshot();
   return {before,after:game(),bounded,nonIncreasing,knownInjections,
      simSummary:sim?{length:sim.rows.length,events:sim.events.length,
        injections:sim.totalInjections,mutation:sim.sourceMutated,
        game:sim.writeToGame,last:sim.rows.at(-1),
        injectionSteps:sim.events.map(e=>e.step)}:null,
      started,stopped,fixtureUnchanged:fixture.every(x=>x.amplitude===1&&x.phase===0),
      mounted:!!document.getElementById('disturbanceStabilityCanvas')};
 });
 if(!repeatedDisturbance.mounted||!repeatedDisturbance.simSummary||
    repeatedDisturbance.simSummary.length!==101||
    repeatedDisturbance.simSummary.events!==4||
    repeatedDisturbance.simSummary.injections!==4||
    repeatedDisturbance.simSummary.mutation||repeatedDisturbance.simSummary.game||
    repeatedDisturbance.simSummary.injectionSteps.join(',')!=='0,20,40,60'||
    !repeatedDisturbance.bounded||!repeatedDisturbance.nonIncreasing||
    !repeatedDisturbance.knownInjections||!repeatedDisturbance.fixtureUnchanged||
    !(repeatedDisturbance.simSummary.last.adaptive<repeatedDisturbance.simSummary.last.fixed)||
    !repeatedDisturbance.started?.running||repeatedDisturbance.started.sourceMutated||
    repeatedDisturbance.stopped?.running||repeatedDisturbance.stopped?.sourceCount!==0||
    JSON.stringify(repeatedDisturbance.before)!==JSON.stringify(repeatedDisturbance.after))
   fail('Repeated disturbance stability or source/game isolation violation: '+JSON.stringify(repeatedDisturbance));

 // v2.9.26 — copies recover deterministically; no source or engine mutation.
 const adaptiveBaseline=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapeAdaptiveResonance,initial=api?.snapshot();
   const fixture=Object.freeze([
     Object.freeze({edge:0,axis:0,amplitude:1,phase:0}),
     Object.freeze({edge:31,axis:3,amplitude:1,phase:0})
   ]);
   const result=api?.simulate(fixture);
   const begin=document.getElementById('adaptiveResonanceRun');
   const reset=document.getElementById('adaptiveResonanceReset');
   begin?.click();const started=api?.snapshot();
   reset?.click();const stopped=api?.snapshot();
   return {before,after:game(),initial,result,started,stopped,
     fixtureUnchanged:fixture.every(e=>e.amplitude===1&&e.phase===0),
     panel:!!document.getElementById('adaptiveResonanceCanvas')};
 });
 if(!adaptiveBaseline.panel||!adaptiveBaseline.initial||
    adaptiveBaseline.initial.running||adaptiveBaseline.initial.gameplayMutation||
    adaptiveBaseline.initial.baseline!==null||
    !adaptiveBaseline.result||adaptiveBaseline.result.rows.length!==71||
    adaptiveBaseline.result.mutation||adaptiveBaseline.result.inputCount!==2||
    !(adaptiveBaseline.result.adaptiveReached<adaptiveBaseline.result.fixedReached)||
    !adaptiveBaseline.started.running||adaptiveBaseline.started.count!==32||
    adaptiveBaseline.stopped.running||adaptiveBaseline.stopped.count!==0||
    !adaptiveBaseline.fixtureUnchanged||
    JSON.stringify(adaptiveBaseline.before)!==JSON.stringify(adaptiveBaseline.after))
   fail('Adaptive phase recovery comparison violated source isolation: '+JSON.stringify(adaptiveBaseline));

 // v2.9.25: synthetic phase comparison is isolated from engine and sources.
 const driftCheck=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),api=window.neuroscapePhaseDrift;
   const empty=api?.snapshot();
   const fixtures=Object.freeze([
     Object.freeze({edge:0,axis:0,amplitude:1,phase:0}),
     Object.freeze({edge:31,axis:3,amplitude:1,phase:0})
   ]);
   const baseline=api?.compare(fixtures,0);
   const drifted=api?.compare(fixtures,Math.PI/2);
   const run=document.getElementById('phaseDriftRun');
   const reset=document.getElementById('phaseDriftReset');
   run?.click();
   const pressed=run?.getAttribute('aria-pressed');
   reset?.click();
   return {before,after:game(),empty,baseline,drifted,pressed,
     resetStage:api?.snapshot().stage,
     fixtureIntact:fixtures.every(e=>e.amplitude===1&&e.phase===0)};
 });
 if(!driftCheck.empty||driftCheck.empty.baseline!==null||
    driftCheck.empty.projected!==null||driftCheck.empty.activeEdges!==0||
    driftCheck.empty.sourceMutated||driftCheck.empty.gameplayMutation||
    !driftCheck.baseline||Math.abs(driftCheck.baseline.baseline-1)>1e-10||
    Math.abs(driftCheck.baseline.projected-1)>1e-10||
    !driftCheck.drifted||!(driftCheck.drifted.projected<driftCheck.drifted.baseline)||
    driftCheck.pressed!=='true'||driftCheck.resetStage!=='IDLE'||
    !driftCheck.fixtureIntact||JSON.stringify(driftCheck.before)!==JSON.stringify(driftCheck.after))
   fail('Phase drift projection violated quiet, independence or game invariant: '+JSON.stringify(driftCheck));

 // v2.9.24: coherence undefined at zero energy; all four axis groups present.
 const resonanceBaseline=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),r=window.neuroscapeResonanceDisplay?.snapshot();
   return {before,after:game(),r,axisRings:document.querySelectorAll('#plasmaResonanceRings circle').length};
 });
 if(!resonanceBaseline.r||resonanceBaseline.axisRings!==4||
    resonanceBaseline.r.defined!==false||
    resonanceBaseline.r.coherence!==null||
    resonanceBaseline.r.active!==0||
    resonanceBaseline.r.groupCount!==4||
    resonanceBaseline.r.visualOnly!==true||
    resonanceBaseline.r.gameplayMutation!==false||
    JSON.stringify(resonanceBaseline.before)!==JSON.stringify(resonanceBaseline.after))
   fail('Neon resonance invented quiet-phase alignment or mutated gameplay: '+JSON.stringify(resonanceBaseline));

 // v2.9.23 — independently bounded edge reservoirs cannot create input.
 const memoryInitial=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),p=window.neuroscapePlasmaPersistence?.snapshot();
   return {before,after:game(),p,bars:document.querySelectorAll('#plasmaPersistenceBars > i').length};
 });
 if(!memoryInitial.p||memoryInitial.bars!==32||
    memoryInitial.p.capacity!==32||
    memoryInitial.p.quiet!==true||
    memoryInitial.p.input!==0||
    memoryInitial.p.nonzero!==0||
    memoryInitial.p.total!==0||
    memoryInitial.p.visualOnly!==true||
    memoryInitial.p.gameplayMutation!==false||
    JSON.stringify(memoryInitial.before)!==JSON.stringify(memoryInitial.after))
   fail('Edge-memory fabricated input or touched gameplay: '+JSON.stringify(memoryInitial));

 // v2.9.22: normalized visual energy must conserve its source budget.
 const visualConservation=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),ledger=window.neuroscapeVisualConservation?.snapshot();
   const after=game();
   return {before,after,ledger,mounted:!!document.getElementById('plasmaConservation')};
 });
 if(!visualConservation.mounted||!visualConservation.ledger||
    visualConservation.ledger.authority!=='visual-only'||
    visualConservation.ledger.writesToGameplay!==false||
    !visualConservation.ledger.balanced||
    Math.abs(visualConservation.ledger.input-
      visualConservation.ledger.edge-visualConservation.ledger.shadow-
      visualConservation.ledger.quiet)>1e-10||
    visualConservation.ledger.input!==0||
    JSON.stringify(visualConservation.before)!==JSON.stringify(visualConservation.after))
   fail('Visual plasma energy ledger broke isolation or conservation: '+JSON.stringify(visualConservation));

 // v2.9.21 — no plasma without observed source activity; 32-edge bound.
 const plasmaStart=await page.evaluate(()=>{
   const before={ram:[state.p.ram,state.e.ram],turn:state.turn,actions:state.actions,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)};
   const t=window.neuroscapeTesseract?.snapshot();
   const after={ram:[state.p.ram,state.e.ram],turn:state.turn,actions:state.actions,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)};
   return {before,after,t};
 });
 if(!plasmaStart.t||plasmaStart.t.plasmaEdgeLimit!==32||
    plasmaStart.t.plasmaEdges!==0||plasmaStart.t.shadowPlasmaEdges!==0||
    plasmaStart.t.plasmaActive!==false||plasmaStart.t.gameplayMutation||
    JSON.stringify(plasmaStart.before)!==JSON.stringify(plasmaStart.after))
   fail('Plasma failed quiet baseline or altered game state: '+JSON.stringify(plasmaStart));

 // v2.9.20 — genuine 4D hypercube topology, visual-only integration.
 const tesseractInitial=await page.evaluate(()=>{
   const game=()=>({turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=game(),visual=window.neuroscapeTesseract?.snapshot();
   const pause=document.getElementById('neonTesseractPause');
   const canvas=document.getElementById('neonTesseractCanvas');
   pause?.click();const pressed=pause?.getAttribute('aria-pressed');
   pause?.click();
   return {before,after:game(),visual,pressed,canvas:!!canvas,
     style:canvas?getComputedStyle(canvas).display:''};
 });
 if(!tesseractInitial.visual||tesseractInitial.visual.vertices!==16||
    tesseractInitial.visual.edges!==32||
    !tesseractInitial.visual.rotation4D||!tesseractInitial.visual.shadow3D||
    tesseractInitial.visual.gameplayMutation||tesseractInitial.visual.causality!=='not-proven'||
    tesseractInitial.pressed!=='true'||!tesseractInitial.canvas||
    tesseractInitial.style==='none'||
    JSON.stringify(tesseractInitial.before)!==JSON.stringify(tesseractInitial.after))
   fail('4D tesseract geometry or gameplay non-regression failed: '+JSON.stringify(tesseractInitial));

 // v2.9.19 — read-only replay may reject bad lineage, never mutate gameplay.
 const replayInitial=await page.evaluate(async()=>{
   const view=()=>({turn:state.turn,actions:state.actions,
     ram:[state.p.ram,state.e.ram],slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)});
   const before=view(),monitor=window.neuroscapeSealedReplay?.snapshot();
   let rejected=false,reason='';
   try{
     await window.neuroscapeSealedReplay.verify({
       schema:'neuroscape-temporal-provenance-1',match:'1',sealedCount:1,
       evicted:0,durable:false,causality:'not-proven',records:[{
         sequence:1,match:'2',kind:'attack',source:'attack:100:p',
         sealReason:'QUIET OBSERVED',phases:[]}]
     });
   }catch(e){rejected=true;reason=e.message}
   return {before,after:view(),monitor,rejected,reason,
     panel:!!document.getElementById('sealedReplayAudit')};
 });
 if(!replayInitial.panel||!replayInitial.monitor||
    replayInitial.monitor.loaded||replayInitial.monitor.replayedToEngine||
    !replayInitial.rejected||!replayInitial.reason.includes('CROSS-MATCH')||
    JSON.stringify(replayInitial.before)!==JSON.stringify(replayInitial.after))
   fail('Replay integrity or gameplay isolation violated: '+JSON.stringify(replayInitial));

 // v2.9.18 — empty observation cannot generate any sealed historical record.
 const provenanceInitial=await page.evaluate(()=>{
   const before={turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes > .slot').length)};
   const archive=window.neuroscapeProvenanceFreeze?.snapshot();
   const after={turn:state.turn,actions:state.actions,ram:[state.p.ram,state.e.ram],
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes > .slot').length)};
   return {before,after,archive,export:!!document.getElementById('provenanceFreezeExport')};
 });
 if(!provenanceInitial.export||!provenanceInitial.archive||
    provenanceInitial.archive.sealedCount!==0||provenanceInitial.archive.liveCount!==0||
    provenanceInitial.archive.evicted!==0||
    provenanceInitial.archive.causality!=='not-proven'||
    provenanceInitial.archive.durable!==false||
    JSON.stringify(provenanceInitial.before)!==JSON.stringify(provenanceInitial.after))
   fail('Provenance freeze invented initial history or mutated engine: '+JSON.stringify(provenanceInitial));

 // v2.9.17: audit reads only existing telemetry, cannot mutate game.
 const lineageInitial=await page.evaluate(()=>{
   const before={ram:[state.p.ram,state.e.ram],turn:state.turn,actions:state.actions,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes > .slot').length)};
   const audit=window.neuroscapeCausalAudit?.snapshot();
   const after={ram:[state.p.ram,state.e.ram],turn:state.turn,actions:state.actions,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes > .slot').length)};
   return {before,audit,after,panel:!!document.getElementById('causalLineageAudit')};
 });
 if(!lineageInitial.panel||!lineageInitial.audit||
    lineageInitial.audit.causality!=='not-proven'||
    lineageInitial.audit.independentWitnesses!==0||
    lineageInitial.audit.linked!==0||lineageInitial.audit.returns!==0||
    JSON.stringify(lineageInitial.before)!==JSON.stringify(lineageInitial.after))
    fail('Causal lineage observer invented evidence or mutated arena: '+JSON.stringify(lineageInitial));

 // v2.9.16 — purely observational correlation; no gameplay state mutation.
 const phaseScope=await page.evaluate(()=>{
   const before={ram:[state.p.ram,state.e.ram],actions:state.actions,turn:state.turn,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)};
   const scope=window.neuroscapePhaseCorrelation?.snapshot();
   return {before,after:{ram:[state.p.ram,state.e.ram],actions:state.actions,turn:state.turn,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)},
     scope,canvas:!!document.getElementById('phaseCorrelationCanvas'),
     status:document.getElementById('phaseCorrelationStatus')?.textContent,
     causality:document.getElementById('phaseCorrelation')?.dataset.causality};
 });
 if(!phaseScope.canvas||!phaseScope.scope||phaseScope.scope.causality!=='not-inferred'||
   phaseScope.causality!=='not-inferred'||phaseScope.scope.percentage!==null||
   phaseScope.scope.attackSources!==0||phaseScope.scope.recoverySources!==0||
   JSON.stringify(phaseScope.before)!==JSON.stringify(phaseScope.after))
   fail('Independent correlation mutated gameplay or synthesized empty evidence: '+JSON.stringify(phaseScope));

 if(!initial.turn?.startsWith('TURN '))fail('Engine failed first render');
 for(const [side,list] of [['player',initial.player],['bot',initial.bot]]){
  if(list.length!==5)fail(side+' does not have five slots');
  if(list.some(x=>x.width<70||x.height<70||x.visible!=='visible'||x.display==='none'))fail(side+' card squares have collapsed');
 }
 if(initial.hand<5)fail('Player hand not rendered');
 // v2.9.03 — only the engine's scheduled render may create telemetry.
 // Direct test renderer calls are visual-only, not historical evidence.
 const telemetry=await page.evaluate(()=>{
   const initial={
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
     ram:[state.p.ram,state.e.ram],actions:state.actions,
     count:document.querySelectorAll('#recoveryTelemetryP ol li, #recoveryTelemetryE ol li').length
   };
   drawEnergyPathways({seq:989902,impactSeq:989901,
     events:[{side:'p',type:'release',amount:2,slots:[{slot:1,amount:2}]}]});
   const visualOnlyCount=document.querySelectorAll('#recoveryTelemetryP ol li, #recoveryTelemetryE ol li').length;
   lastRamFlow={seq:989903,impactSeq:989900,events:[
     {side:'p',type:'release',amount:3,slots:[{slot:2,amount:3}]},
     {side:'e',type:'release',amount:0,slots:[]}
   ]};
   schedulePathways();
   return {initial,visualOnlyCount};
 });
 await page.waitForTimeout(135);
 const telemetryActive=await page.evaluate(()=>({
   player:document.getElementById('recoveryTelemetryP')?.textContent||'',
   bot:document.getElementById('recoveryTelemetryE')?.textContent||'',
   rows:document.querySelectorAll('#recoveryTelemetryP ol li, #recoveryTelemetryE ol li').length,
   ledger:recoveryMonitorEntries.map(x=>({source:x.source,amount:x.amount,
     side:x.side,status:x.status})),
   ram:[state.p.ram,state.e.ram],actions:state.actions,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(telemetry.initial.count!==0||telemetry.visualOnlyCount!==0||
   telemetryActive.rows!==2||
   !telemetryActive.player.includes('attack:989900:flow:989903:p')||
   !telemetryActive.bot.includes('ZERO · NO ENERGY')||
   telemetryActive.ledger.some(x=>x.source.includes('989901'))||
   !telemetryActive.ledger.some(x=>x.side==='p'&&x.amount===3)||
   !telemetryActive.ledger.some(x=>x.side==='e'&&x.amount===0)||
   telemetryActive.ram.some(n=>n!==0)||telemetryActive.actions!==1||
   telemetryActive.slots.some(n=>n!==5))
   fail('Recovery monitor changed gameplay or claimed fixture as live: '+
     JSON.stringify({telemetry,telemetryActive}));
 // v2.9.04 — waveform must derive only from current-match source data.
 const waveLive=await page.evaluate(()=>({
   svg:['recoveryWaveP','recoveryWaveE'].map(id=>{
     const el=document.getElementById(id);
     return {id,trace:el?.querySelector('.recoveryWaveTrace')?.getAttribute('points'),
       text:el?.querySelector('.recoveryWaveLevel')?.textContent};
   }),
   widths:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width)
 }));
 const [playerWave,botWave]=waveLive.svg;
 if(!playerWave?.trace||playerWave.trace==='0,44 240,44'||
    !playerWave.text.includes('3 RAM ACTIVE')||
    botWave?.trace!=='0,44 240,44'||botWave.text!=='0 RAM'||
    waveLive.widths.some(x=>x!=='0%'))
   fail('Recovery waveform is fabricated or mutated real RAM: '+JSON.stringify(waveLive));
 await page.waitForTimeout(5450);
 const telemetryExpired=await page.evaluate(()=>({
   statuses:recoveryMonitorEntries.map(x=>({side:x.side,status:x.status})),
   timer:recoveryMonitorTimer!==null,
   activeNodes:document.querySelectorAll('[data-cycle-id="attack:989900:flow:989903:p"]').length,
   rows:document.querySelectorAll('#recoveryTelemetryP ol li, #recoveryTelemetryE ol li').length
 }));
 const waveQuiet=await page.evaluate(()=>['recoveryWaveP','recoveryWaveE'].map(id=>({
   trace:document.getElementById(id)?.querySelector('.recoveryWaveTrace')?.getAttribute('points'),
   text:document.getElementById(id)?.querySelector('.recoveryWaveLevel')?.textContent
 })));
 if(waveQuiet.some(x=>x.trace!=='0,44 240,44'||x.text!=='0 RAM'))
   fail('Recovery oscilloscope did not settle to zero: '+JSON.stringify(waveQuiet));
 if(telemetryExpired.activeNodes!==0||telemetryExpired.timer||
   telemetryExpired.rows!==2||
   telemetryExpired.statuses.some(x=>x.side==='p'?x.status!=='QUIET':x.status!=='ZERO · NO ENERGY'))
   fail('Recovery monitor failed natural expiration: '+JSON.stringify(telemetryExpired));
 await page.getByRole('button',{name:'Restart match'}).click();
 const telemetryReset=await page.evaluate(()=>({
   rows:document.querySelectorAll('#recoveryTelemetryP ol li, #recoveryTelemetryE ol li').length,
   count:recoveryMonitorEntries.length,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(telemetryReset.rows||telemetryReset.count||telemetryReset.slots.some(n=>n!==5))
   fail('Recovery telemetry leaked into new match: '+JSON.stringify(telemetryReset));
 // v2.9.05 — damage and refund have separate source-bound channels.
 // Direct visual-only combat drawing must never assert a real attack.
 const attackBefore=await page.evaluate(()=>{
   drawCombatPathways({from:'p',to:'e',source:0,target:0,kind:'blocked',
     damage:4,seq:989951});
   return {count:attackMonitorEntries.length,
     trace:document.querySelector('#attackWaveP .attackWaveTrace')?.getAttribute('points')};
 });
 if(attackBefore.count!==0||attackBefore.trace!=='0,44 240,44')
   fail('Visual-only combat drew an authoritative attack trace: '+JSON.stringify(attackBefore));
 await page.evaluate(()=>{
   lastImpact={from:'p',to:'e',source:0,target:0,kind:'blocked',
     damage:4,retaliation:1,seq:989952};
   schedulePathways();
 });
 await page.waitForTimeout(190);
 const attackActive=await page.evaluate(()=>({
   p:document.querySelector('#attackWaveP .attackWaveTrace')?.getAttribute('points'),
   e:document.querySelector('#attackWaveE .attackWaveTrace')?.getAttribute('points'),
   pLabel:document.querySelector('#attackWaveP .attackWaveLevel')?.textContent,
   eLabel:document.querySelector('#attackWaveE .attackWaveLevel')?.textContent,
   ramP:document.querySelector('#recoveryWaveP .recoveryWaveTrace')?.getAttribute('points'),
   ramE:document.querySelector('#recoveryWaveE .recoveryWaveTrace')?.getAttribute('points'),
   damageEvents:attackMonitorEntries.map(x=>({key:x.key,damage:x.damage,side:x.side})),
   ramEvents:recoveryMonitorEntries.length,
   playerRam:state.p.ram,botRam:state.e.ram,actions:state.actions,
   cards:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(attackActive.p==='0,44 240,44'||attackActive.e!=='0,44 240,44'||
    attackActive.pLabel!=='4 DMG'||attackActive.eLabel!=='0 DMG'||
    attackActive.ramP!=='0,44 240,44'||attackActive.ramE!=='0,44 240,44'||
    attackActive.damageEvents.length!==1||
    attackActive.damageEvents[0].key!=='attack:989952:p'||
    attackActive.ramEvents!==0||attackActive.playerRam!==0||
    attackActive.botRam!==0||attackActive.actions!==1||
    attackActive.cards.some(n=>n!==5))
   fail('Attack and recovery channels crossed or changed game state: '+JSON.stringify(attackActive));
 await page.waitForTimeout(1720);
 const attackQuiet=await page.evaluate(()=>({
   p:document.querySelector('#attackWaveP .attackWaveTrace')?.getAttribute('points'),
   e:document.querySelector('#attackWaveE .attackWaveTrace')?.getAttribute('points'),
   pLabel:document.querySelector('#attackWaveP .attackWaveLevel')?.textContent,
   timer:recoveryMonitorTimer!==null
 }));
 if(attackQuiet.p!=='0,44 240,44'||attackQuiet.e!=='0,44 240,44'||
    attackQuiet.pLabel!=='0 DMG'||!attackQuiet.timer)
   fail('Attack waveform did not decay to quiet: '+JSON.stringify(attackQuiet));
 await page.getByRole('button',{name:'Restart match'}).click();
 const attackReset=await page.evaluate(()=>({
   damageEntries:attackMonitorEntries.length,ramEntries:recoveryMonitorEntries.length,
   p:document.querySelector('#attackWaveP .attackWaveTrace')?.getAttribute('points'),
   playerSlots:document.querySelectorAll('#pLanes>.slot').length,
   botSlots:document.querySelectorAll('#eLanes>.slot').length
 }));
 if(attackReset.damageEntries||attackReset.ramEntries||
    attackReset.p!=='0,44 240,44'||attackReset.playerSlots!==5||attackReset.botSlots!==5)
   fail('Attack channel leaked across match reset: '+JSON.stringify(attackReset));
 // v2.9.06 — same observed attack has independent damage and RAM sides.
 // A joined display must not alter either authoritative meter or board.
 await page.evaluate(()=>{
   lastImpact={from:'p',to:'e',source:0,target:1,kind:'blocked',
     damage:6,retaliation:2,seq:989964};
   lastRamFlow={seq:989965,impactSeq:989964,events:[
     {side:'p',type:'release',amount:3,slots:[{slot:0,amount:3}]},
     {side:'e',type:'release',amount:0,slots:[]}
   ]};
   schedulePathways();
 });
 await page.waitForTimeout(220);
 const joined=await page.evaluate(()=>({
   rows:[...document.querySelectorAll('#combatTimelineEvents li')].map(x=>x.textContent),
   damage:attackMonitorEntries.map(x=>({key:x.key,amount:x.damage})),
   recovery:recoveryMonitorEntries.map(x=>({source:x.source,amount:x.amount})),
   playerAttack:document.querySelector('#attackWaveP .attackWaveLevel')?.textContent,
   playerRecovery:document.querySelector('#recoveryWaveP .recoveryWaveLevel')?.textContent,
   botRecovery:document.querySelector('#recoveryWaveE .recoveryWaveLevel')?.textContent,
   ram:[state.p.ram,state.e.ram],actions:state.actions,
   slots:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)
 }));
 if(joined.rows.length!==1||!joined.rows[0].includes('ATTACK 989964')||
    !joined.rows[0].includes('6 DMG')||!joined.rows[0].includes('+3 RAM')||
    !joined.rows[0].includes('E:ZERO · NO ENERGY')||
    !/Δ\d+ms/.test(joined.rows[0])||
    joined.damage.length!==1||joined.recovery.length!==2||
    joined.playerAttack!=='6 DMG'||joined.playerRecovery!=='3 RAM ACTIVE'||
    joined.botRecovery!=='0 RAM'||joined.ram.some(n=>n!==0)||
    joined.actions!==1||joined.slots.some(n=>n!==5))
   fail('Linked combat timeline crossed independent source channels: '+JSON.stringify(joined));
 // v2.9.07 — both event families must share a single, measured clock.
 const ruler=await page.evaluate(()=>{
   const svg=document.querySelector('#combatTimelineEvents .temporalRuler');
   const attack=svg?.querySelector('.rulerAttack');
   const recoveries=[...(svg?.querySelectorAll('.rulerRecovery')||[])];
   const ticks=[...(svg?.querySelectorAll('.rulerTick')||[])].map(el=>el.textContent);
   return {attackId:svg?.dataset.attackId,damage:svg?.dataset.damage,
     ram:svg?.dataset.returnedRam,source:attack?.dataset.source,
     recoveryCount:svg?.dataset.recoveryCount,
     recoverySources:recoveries.map(node=>node.dataset.source),
     offsets:svg?.dataset.recoveryOffsets,
     attackX:Number(attack?.getAttribute('cx')),
     recoveryX:recoveries.map(node=>Number(node.getAttribute('cx'))),
     ticks,cardCounts:['p','e'].map(side=>
       document.querySelectorAll('#'+side+'Lanes>.slot').length),
     realRam:[state.p.ram,state.e.ram]};
 });
 const offsets=(ruler.offsets||'').split(',').map(Number);
 const expectedX=ms=>20+300*(Math.max(-250,Math.min(5200,ms))+250)/5450;
 if(ruler.attackId!=='989964'||ruler.damage!=='6'||ruler.ram!=='3'||
    ruler.source!=='attack:989964:p'||ruler.recoveryCount!=='2'||
    ruler.recoverySources.length!==2||
    ruler.recoverySources.some(x=>!x.startsWith('attack:989964:flow:989965:'))||
    !ruler.ticks.includes('0')||!ruler.ticks.includes('5s')||
    Math.abs(ruler.attackX-expectedX(0))>.001||
    ruler.recoveryX.some((x,i)=>Math.abs(x-expectedX(offsets[i]))>.001)||
    ruler.cardCounts.some(n=>n!==5)||ruler.realRam.some(n=>n!==0))
   fail('Shared temporal ruler fabricated timing or changed gameplay: '+JSON.stringify(ruler));
 console.log('SHARED TEMPORAL RULER PASS: attack and both recovery origins aligned to measured relative timestamps');
 await page.waitForTimeout(5450);
 const settledJoin=await page.evaluate(()=>({
   rows:[...document.querySelectorAll('#combatTimelineEvents li')].map(x=>x.textContent),
   attack:document.querySelector('#attackWaveP .attackWaveLevel')?.textContent,
   recovery:document.querySelector('#recoveryWaveP .recoveryWaveLevel')?.textContent
 }));
 if(settledJoin.rows.length!==1||!settledJoin.rows[0].includes('P:QUIET')||
    settledJoin.attack!=='0 DMG'||settledJoin.recovery!=='0 RAM')
   fail('Linked combat timeline did not settle independently: '+JSON.stringify(settledJoin));
 await page.getByRole('button',{name:'Restart match'}).click();
 const joinedReset=await page.evaluate(()=>({
   rows:document.querySelectorAll('#combatTimelineEvents li').length,
   attacks:attackMonitorEntries.length,recoveries:recoveryMonitorEntries.length,
   cards:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)
 }));
 if(joinedReset.rows||joinedReset.attacks||joinedReset.recoveries||
    joinedReset.cards.some(n=>n!==5))
   fail('Linked combat timeline leaked across match boundary: '+JSON.stringify(joinedReset));
 // v2.9.08 — two consecutive events retain separate expiry provenance.
 for(const c of [
   {seq:989976,flow:989977,side:'p',opposite:'e',damage:5,returned:2,slot:1},
   {seq:989978,flow:989979,side:'e',opposite:'p',damage:7,returned:4,slot:3}
 ]){
   await page.evaluate(item=>{
     lastImpact={seq:item.seq,from:item.side,to:item.opposite,
       source:0,target:1,kind:'blocked',damage:item.damage,retaliation:1};
     lastRamFlow={seq:item.flow,impactSeq:item.seq,events:[
       {side:item.side,type:'release',amount:item.returned,
         slots:[{slot:item.slot,amount:item.returned}]},
       {side:item.opposite,type:'release',amount:0,slots:[]}
     ]};
     schedulePathways();
   },c);
   await page.waitForTimeout(90);
 }
 const timelinePairs=await page.evaluate(()=>[...document.querySelectorAll(
   '#combatTimelineEvents .temporalRuler')].map(svg=>({
   attack:svg.dataset.attackId,damage:svg.dataset.damage,
   ram:svg.dataset.returnedRam,returns:svg.dataset.recoveryCount,
   attackSource:svg.querySelector('.rulerAttack')?.dataset.source,
   returnSources:[...svg.querySelectorAll('.rulerRecovery')].map(x=>x.dataset.source)
 })));
 if(timelinePairs.length!==2||
    !timelinePairs.some(x=>x.attack==='989976'&&x.damage==='5'&&x.ram==='2'&&
      x.returns==='2'&&x.attackSource==='attack:989976:p'&&
      x.returnSources.every(v=>v.startsWith('attack:989976:flow:989977:')))||
    !timelinePairs.some(x=>x.attack==='989978'&&x.damage==='7'&&x.ram==='4'&&
      x.returns==='2'&&x.attackSource==='attack:989978:e'&&
      x.returnSources.every(v=>v.startsWith('attack:989978:flow:989979:'))))
   fail('Consecutive timeline events cross-linked provenance: '+JSON.stringify(timelinePairs));
 await page.waitForTimeout(5550);
 const expiredPairs=await page.evaluate(()=>({
   rulers:[...document.querySelectorAll('#combatTimelineEvents .temporalRuler')].map(svg=>({
     attack:svg.dataset.attackId,expired:svg.dataset.attackExpired,
     settled:svg.dataset.expiredRecoveries,
     attackMarks:[...svg.querySelectorAll('.rulerAttackExpiry')].map(x=>x.dataset.source),
     returnMarks:[...svg.querySelectorAll('.rulerRecoveryExpiry')].map(x=>x.dataset.source),
     activeReturns:svg.querySelectorAll('.rulerRecovery').length
   })),
   liveMeter:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width),
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(expiredPairs.rulers.length!==2||expiredPairs.rulers.some(row=>
      row.expired!=='true'||row.settled!=='1'||
      row.attackMarks.length!==1||row.attackMarks[0]!=='attack:'+row.attack+
        ':'+(row.attack==='989976'?'p':'e')||
      row.returnMarks.length!==1||!row.returnMarks[0].startsWith(
        'attack:'+row.attack+':flow:'+(row.attack==='989976'?'989977':'989979')+':')||
      row.activeReturns!==2)||
    expiredPairs.slots.some(n=>n!==5)||expiredPairs.liveMeter.some(w=>w!=='0%'))
   fail('Multi-event expiry leaked or changed arena: '+JSON.stringify(expiredPairs));
 await page.getByRole('button',{name:'Restart match'}).click();
 const expiresReset=await page.evaluate(()=>({
   rows:document.querySelectorAll('#combatTimelineEvents li').length,
   attackHistory:attackMonitorEntries.length,recoveryHistory:recoveryMonitorEntries.length,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(expiresReset.rows||expiresReset.attackHistory||expiresReset.recoveryHistory||
    expiresReset.slots.some(n=>n!==5))
   fail('Expired timeline events crossed match reset: '+JSON.stringify(expiresReset));
 // v2.9.09 — ten independent scheduled combat observations show only
 // the most recent eight in the neon history strip.
 for(let i=0;i<10;i++){
   await page.evaluate(i=>{
     const seq=990100+i,side=i%2?'e':'p',opposite=side==='p'?'e':'p';
     lastImpact={seq,from:side,to:opposite,source:0,target:0,
       kind:'blocked',damage:i+1,retaliation:1};
     lastRamFlow={seq:991100+i,impactSeq:seq,events:[
       {side,type:'release',amount:i%3===0?0:i+1,
        slots:i%3===0?[]:[{slot:i%5,amount:i+1}]},
       {side:opposite,type:'release',amount:0,slots:[]}
     ]};
     schedulePathways();
   },i);
   await page.waitForTimeout(35);
 }
 // Wait for the actual scheduled frame, rather than assuming a 35ms
 // wall-clock delay on a loaded CI browser was enough.
 await page.waitForFunction(()=>
   attackMonitorEntries.some(x=>x.key==='attack:990109:e')&&
   recoveryMonitorEntries.some(x=>x.source.startsWith('attack:990109:flow:991109:'))&&
   document.querySelector('#combatHistoryEvents li')?.dataset.attackId==='990109',
   null,{timeout:8000,polling:50});
 const historyStrip=await page.evaluate(()=>({
   entries:[...document.querySelectorAll('#combatHistoryEvents li')].map(li=>({
     id:li.dataset.attackId,count:li.dataset.recoveryCount,
     damage:li.querySelector('span')?.textContent,
     text:li.textContent
   })),
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
   ram:[state.p.ram,state.e.ram],actions:state.actions,
   murals:document.querySelectorAll('#neuroscapeArt,#signalFoundry').length
 }));
 const expectedIds=Array.from({length:8},(_,i)=>String(990109-i));
 if(historyStrip.entries.length!==8||
    historyStrip.entries.some((entry,i)=>entry.id!==expectedIds[i]||
      entry.count!=='2'||entry.damage!==(10-i)+' DAMAGE'||
      !entry.text.includes('RAM')||
      !entry.text.includes('#'+expectedIds[i]))||
    historyStrip.slots.some(n=>n!==5)||historyStrip.ram.some(n=>n!==0)||
    historyStrip.actions!==1||historyStrip.murals!==2)
   fail('Bounded neon history lost event ownership or changed gameplay: '+
     JSON.stringify(historyStrip));
 // v2.9.14 — overlapping source records keep distinct age/phase and
 // read-only memory does not collapse newer and older attacks together.
 const phaseMemory=await page.evaluate(()=>({
   attack:[...document.querySelectorAll('#plasmaMemoryAttack li')].map(x=>({
     source:x.dataset.source,phase:x.dataset.phase,age:+x.dataset.ageMs})),
   recovery:[...document.querySelectorAll('#plasmaMemoryRecovery li')].map(x=>({
     source:x.dataset.source,phase:x.dataset.phase,age:+x.dataset.ageMs})),
   arena:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(phaseMemory.attack.length!==8||phaseMemory.recovery.length!==5||
   phaseMemory.attack[0].source!=='attack:990109:e'||
   phaseMemory.attack[7].source!=='attack:990102:p'||
   new Set(phaseMemory.attack.map(x=>x.source)).size!==8||
   new Set(phaseMemory.recovery.map(x=>x.source)).size!==5||
   phaseMemory.recovery.some(x=>!x.source.startsWith('attack:'))||
   phaseMemory.attack.some(x=>x.phase==='quiet'||x.age<0)||
   phaseMemory.arena.some(x=>x!==5))
   fail('Plasma memory merged or lost overlapping sources: '+JSON.stringify(phaseMemory));
 console.log('ISOLATED PHASE MEMORY PASS: eight attack sources and five retained positive RAM sources');
 // v2.9.10 — ten independently sourced observations generate ten
 // attack bins over five seconds; only positive RAM releases count.
 const density=await page.evaluate(()=>({
   attackBins:[...document.querySelectorAll('#combatDensityAttack i')].map(x=>+x.dataset.count),
   recoveryBins:[...document.querySelectorAll('#combatDensityRecovery i')].map(x=>+x.dataset.count),
   summary:document.getElementById('combatDensitySummary')?.textContent,
   actualAttacks:attackMonitorEntries.filter(x=>performance.now()-x.born<5000).length,
   actualReturns:recoveryMonitorEntries.filter(x=>x.amount>0&&performance.now()-x.born<5000).length,
   ram:[state.p.ram,state.e.ram],
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 const attackTotal=density.attackBins.reduce((a,b)=>a+b,0);
 const returnTotal=density.recoveryBins.reduce((a,b)=>a+b,0);
 if(density.attackBins.length!==10||density.recoveryBins.length!==10||
    attackTotal!==10||returnTotal!==5||
    attackTotal!==density.actualAttacks||returnTotal!==density.actualReturns||
    density.summary!=='10 ATTACKS · 5 RETURNS'||
    density.ram.some(n=>n!==0)||density.slots.some(n=>n!==5))
   fail('Activity density invented RAM or lost event timestamps: '+JSON.stringify(density));
 // v2.9.11 — glowing envelopes reflect only the retained source events.
 // They must decay to zero after five seconds even when no new combat occurs.
 const plasmaActive=await page.evaluate(()=>({
   levels:[document.getElementById('attackEnvelopeLevel')?.textContent,
     document.getElementById('recoveryEnvelopeLevel')?.textContent],
   widths:[document.getElementById('attackEnvelopeFill')?.style.width,
     document.getElementById('recoveryEnvelopeFill')?.style.width],
   cardCounts:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
   ram:[state.p.ram,state.e.ram]
 }));
 if(plasmaActive.levels.some(x=>!(parseInt(x,10)>0))||
    plasmaActive.widths.some(x=>!(parseInt(x,10)>0))||
    plasmaActive.cardCounts.some(n=>n!==5)||plasmaActive.ram.some(n=>n!==0))
   fail('Reactive activity envelope did not reflect recorded events: '+JSON.stringify(plasmaActive));
 // v2.9.12 — both lightning channels are visual-only and source-driven.
 const lightningActive=await page.evaluate(()=>({
   nodes:['attackLightning','recoveryLightning'].map(id=>{
     const svg=document.getElementById(id),bolt=svg?.querySelector('.plasmaBolt');
     return {active:svg?.dataset.active,level:Number(bolt?.dataset.level),
       path:bolt?.getAttribute('points'),height:svg?.getBoundingClientRect().height};
   }),
   cards:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length),
   ram:[state.p.ram,state.e.ram],
   murals:document.querySelectorAll('#neuroscapeArt,#signalFoundry').length
 }));
 if(lightningActive.nodes.some(x=>x.active!=='true'||x.level<=0||
      !x.path||x.path.split(' ').length!==17||x.height<=0)||
    lightningActive.cards.some(n=>n!==5)||lightningActive.ram.some(n=>n!==0)||
    lightningActive.murals!==2)
   fail('Plasma lightning absent or changed arena: '+JSON.stringify(lightningActive));
 // v2.9.13: distinct phases are sourced from each channel's
 // newest eligible observation; they do not mutate gameplay.
 const phaseLaunch=await page.evaluate(()=>['attackLightning','recoveryLightning'].map(id=>{
   const svg=document.getElementById(id);
   return {phase:svg?.dataset.phase,source:svg?.dataset.source,
     age:Number(svg?.dataset.ageMs),head:Number(svg?.querySelector('.plasmaTravelHead')?.getAttribute('cx')),
     opacity:svg?.querySelector('.plasmaTravelHead')?.getAttribute('opacity')};
 }));
 if(phaseLaunch.some(x=>x.phase!=='launch'&&x.phase!=='travel')||
    !phaseLaunch[0].source.startsWith('attack:')||
    !phaseLaunch[1].source.startsWith('attack:')||
    phaseLaunch.some(x=>x.age<0||x.age>=1600||x.opacity!=='1'))
   fail('Lightning phase lacks independent source provenance: '+JSON.stringify(phaseLaunch));
 await page.waitForTimeout(550);
 const phaseTravel=await page.evaluate(()=>({
   channels:['attackLightning','recoveryLightning'].map(id=>{
     const svg=document.getElementById(id),head=svg?.querySelector('.plasmaTravelHead');
     return {phase:svg?.dataset.phase,source:svg?.dataset.source,
       age:Number(svg?.dataset.ageMs),cx:Number(head?.getAttribute('cx')),
       opacity:head?.getAttribute('opacity')};
   }),
   cards:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
   realRam:[state.p.ram,state.e.ram]
 }));
 if(phaseTravel.channels.some(x=>x.phase!=='travel'||x.cx<=0||x.cx>=320||
      !x.source||x.opacity!=='1')||
    phaseTravel.cards.some(x=>x!==5)||phaseTravel.realRam.some(x=>x!==0))
   fail('Lightning travel phase failed or altered gameplay: '+JSON.stringify(phaseTravel));
 await page.waitForTimeout(1300);
 const phaseDecay=await page.evaluate(()=>['attackLightning','recoveryLightning'].map(id=>{
   const svg=document.getElementById(id);
   return {phase:svg?.dataset.phase,opacity:svg?.querySelector('.plasmaTravelHead')?.getAttribute('opacity'),
     cx:Number(svg?.querySelector('.plasmaTravelHead')?.getAttribute('cx'))};
 }));
 if(phaseDecay.some(x=>x.phase!=='decay'||x.opacity!=='0.28'||x.cx!==320))
   fail('Lightning decay phase failed: '+JSON.stringify(phaseDecay));
 await page.waitForTimeout(3800);
 const plasmaQuiet=await page.evaluate(()=>({
   levels:[document.getElementById('attackEnvelopeLevel')?.textContent,
     document.getElementById('recoveryEnvelopeLevel')?.textContent],
   widths:[document.getElementById('attackEnvelopeFill')?.style.width,
     document.getElementById('recoveryEnvelopeFill')?.style.width],
   count:[...document.querySelectorAll('#combatDensityAttack i,#combatDensityRecovery i')].reduce(
     (sum,x)=>sum+Number(x.dataset.count),0),
   timer:recoveryMonitorTimer!==null,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 const phaseQuiet=await page.evaluate(()=>['attackLightning','recoveryLightning'].map(id=>{
   const svg=document.getElementById(id);
   return {phase:svg?.dataset.phase,source:svg?.dataset.source,
     headOpacity:svg?.querySelector('.plasmaTravelHead')?.getAttribute('opacity')};
 }));
 if(phaseQuiet.some(x=>x.phase!=='quiet'||x.source!==''||x.headOpacity!=='0'))
   fail('Plasma phase did not become quiet: '+JSON.stringify(phaseQuiet));
 const lightningQuiet=await page.evaluate(()=>['attackLightning','recoveryLightning'].map(id=>{
   const svg=document.getElementById(id),bolt=svg?.querySelector('.plasmaBolt');
   return {active:svg?.dataset.active,level:bolt?.dataset.level,
      path:bolt?.getAttribute('points')};
 }));
 if(lightningQuiet.some(x=>x.active!=='false'||x.level!=='0'||x.path!==''))
   fail('Lightning remained after five-second source silence: '+JSON.stringify(lightningQuiet));
 if(plasmaQuiet.levels.some(x=>x!=='0%')||plasmaQuiet.widths.some(x=>x!=='0%')||
    plasmaQuiet.count!==0||plasmaQuiet.timer||plasmaQuiet.slots.some(n=>n!==5))
   fail('Neon activity envelope failed to decay naturally: '+JSON.stringify(plasmaQuiet));
 await page.getByRole('button',{name:'Restart match'}).click();
 const historyReset=await page.evaluate(()=>({
   entries:document.querySelectorAll('#combatHistoryEvents li').length,
   attacks:attackMonitorEntries.length,recoveries:recoveryMonitorEntries.length,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 const densityReset=await page.evaluate(()=>({
   attack:[...document.querySelectorAll('#combatDensityAttack i')].map(x=>+x.dataset.count),
   recovery:[...document.querySelectorAll('#combatDensityRecovery i')].map(x=>+x.dataset.count),
   summary:document.getElementById('combatDensitySummary')?.textContent,
   shields:document.querySelectorAll('#combatPathways .neonDefenderRipple').length
 }));
 if(densityReset.attack.some(Boolean)||densityReset.recovery.some(Boolean)||
    densityReset.summary!=='0 ATTACKS · 0 RETURNS'||densityReset.shields)
   fail('Activity density or combat ripples leaked through restart: '+JSON.stringify(densityReset));
 const memoryReset=await page.evaluate(()=>({
   attacks:document.querySelectorAll('#plasmaMemoryAttack li').length,
   recoveries:document.querySelectorAll('#plasmaMemoryRecovery li').length,
   headCounts:['attackLightning','recoveryLightning'].map(id=>
     document.querySelectorAll('#'+id+' .plasmaTravelHead').length)
 }));
 if(memoryReset.attacks||memoryReset.recoveries||
    memoryReset.headCounts.some(n=>n!==1))
   fail('Plasma memory failed to reset or photon markup is duplicated: '+
     JSON.stringify(memoryReset));
 if(historyReset.entries!==0||historyReset.attacks!==0||
    historyReset.recoveries!==0||historyReset.slots.some(n=>n!==5))
   fail('Combat history persisted across match reset: '+JSON.stringify(historyReset));
 console.log('PHASE-SYNCHRONIZED PLASMA PASS: source-bound launch, travel, decay, quiet on both channels');
 console.log('PLASMA LIGHTNING PASS: independent source-driven bolts, natural extinguish and protected arena');
 console.log('ACTIVITY DENSITY PASS: 10 attack events, five retained positive recovery sources, five-second window, clean reset');
 console.log('BOUNDED COMBAT HISTORY PASS: latest eight of ten attacks, independent release identity, reset clean');
 console.log('MULTI-EVENT EXPIRY PASS: two independent attack sources, positive-return quiet markers, zero phantom expiry, reset clean');
 console.log('LINKED COMBAT TIMELINE PASS: attack 989964, 6 DMG, +3 RAM, zero bot, exact shared ID, settled/reset');
 console.log('DUAL WAVEFORM PASS: source-bound attack damage independent of RAM refund, decay and reset clean');
 console.log('RECOVERY WAVEFORM PASS: player active orange trace, zero-cost bot quiet, both settle to zero');
 console.log('LIVE RECOVERY TELEMETRY PASS: engine-sourced source/amount/expiration, zero-return and reset isolation');
 // v2.8.98: interrupt a visible recovery on restart, then again on
 // mode change. The old match cannot reintroduce effects on queued frames.
 const boundary=await page.evaluate(()=>{
   const cls='.neonRamReservoir,.neonRamDischarge,.neonRamAfterglow,'+
     '.neonRecoveryReturn,.neonRecoveryCore,.neonRecoveryArrival,.neonRamCharge';
   const play=seq=>drawEnergyPathways({seq,impactSeq:seq-1,events:[
     {side:'p',type:'release',amount:2,slots:[{slot:1,amount:2}]},
     {side:'e',type:'release',amount:3,slots:[{slot:2,amount:3}]}]});
   const measure=()=>({
     transient:document.querySelectorAll('#gameBoard '+cls).length,
     player:document.querySelectorAll('#pLanes>.slot').length,
     bot:document.querySelectorAll('#eLanes>.slot').length,
     widths:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width),
     mode:document.getElementById('modeHuman').classList.contains('active')?'human':'auto',
     gameTurn:document.getElementById('turnText').textContent,
     murals:document.querySelectorAll('#neuroscapeArt,#signalFoundry').length
   });
   play(989980);
   const old=measure();
   restart('human');const reset=measure();
   play(989981);const active=measure();
   restart('auto');const switched=measure();
   return {old,reset,active,switched};
 });
 if(boundary.old.transient<12||boundary.active.transient<12||
    boundary.reset.transient!==0||boundary.switched.transient!==0||
    boundary.reset.mode!=='human'||boundary.switched.mode!=='auto'||
    [boundary.reset,boundary.switched].some(v=>v.player!==5||v.bot!==5||
      v.murals!==2||v.widths.some(w=>w!=='0%')))
   fail('Restart/mode boundary leaked old recovery energy: '+JSON.stringify(boundary));
 await page.waitForTimeout(90);
 const afterBoundary=await page.evaluate(()=>({
   old:document.querySelectorAll('[data-flow-seq="989980"],[data-flow-seq="989981"]').length,
   cardCounts:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)
 }));
 if(afterBoundary.old||afterBoundary.cardCounts.some(n=>n!==5))
   fail('Delayed old-match frame crossed restart boundary: '+JSON.stringify(afterBoundary));
 await page.getByRole('button',{name:'Play vs Bot'}).click();
 // v2.8.99 — repeatedly schedule bot actions and visual draws, then
 // cancel them by switching modes. Only the final human match may act.
 const resetStorm=await page.evaluate(()=>{
   const counts=[],modes=['auto','human','auto','auto','human','auto','human','auto','human','human'];
   const transient='.neonRamReservoir,.neonRamDischarge,.neonRamAfterglow,'+
      '.neonRecoveryReturn,.neonRecoveryCore,.neonRecoveryArrival,.neonRamCharge';
   const read=()=>({
     turn:state.turn,phase:state.phase,ram:[state.p.ram,state.e.ram],
     active:state.active,actions:state.actions,mode,
     visual:document.querySelectorAll('#gameBoard '+transient).length,
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
     murals:document.querySelectorAll('#neuroscapeArt,#signalFoundry').length,
     epoch:temporalEvidence.match
   });
   const startingEpoch=temporalEvidence.match;
   for(let i=0;i<modes.length;i++){
     drawEnergyPathways({seq:989990+i,impactSeq:989989+i,events:[
       {side:'p',type:'release',amount:2,slots:[{slot:i%5,amount:2}]},
       {side:'e',type:'release',amount:1,slots:[{slot:(i+2)%5,amount:1}]}]});
     // Exercise a pending browser animation frame originating in this match.
     lastRamFlow={seq:999000+i,impactSeq:998000+i,events:[
       {side:'p',type:'release',amount:1,slots:[{slot:0,amount:1}]}]};
     schedulePathways();
     restart(modes[i]);
     counts.push(read());
   }
   return {startingEpoch,counts,final:read()};
 });
 if(resetStorm.counts.length!==10||resetStorm.final.epoch!==resetStorm.startingEpoch+10||
    resetStorm.counts.some((row,i)=>row.mode!==(i===0||i===2||i===3||i===5||i===7?'auto':'human')||
      row.visual!==0||row.turn!==1||row.phase!==0||row.actions!==1||
      row.ram.some(n=>n!==0)||row.slots.some(n=>n!==5)||row.murals!==2||
      row.epoch!==resetStorm.startingEpoch+i+1))
   fail('Repeated restarts leaked neon, RAM or game actions: '+JSON.stringify(resetStorm));
 await page.waitForTimeout(650);
 const settledReset=await page.evaluate(()=>({
   mode,turn:state.turn,phase:state.phase,actions:state.actions,
   ram:[state.p.ram,state.e.ram],epoch:temporalEvidence.match,
   lingering:document.querySelectorAll('[data-flow-seq^="98999"],[data-flow-seq^="99900"]').length,
   slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length),
   murals:document.querySelectorAll('#neuroscapeArt,#signalFoundry').length
 }));
 if(settledReset.epoch!==resetStorm.final.epoch||
    settledReset.mode!=='human'||settledReset.turn!==1||
    settledReset.phase!==0||settledReset.actions!==1||
    settledReset.ram.some(n=>n!==0)||settledReset.lingering!==0||
    settledReset.slots.some(n=>n!==5)||settledReset.murals!==2)
   fail('Queued old-match bot action or visual frame crossed reset storm: '+JSON.stringify(settledReset));
 console.log('REPEATED RESET PASS: ten alternating mode/restart boundaries, old bot timers and animation frames excluded');
 console.log('MATCH BOUNDARY PASS: active recovery cleared across restart and mode change; queued frames isolated');
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
 // v2.8.94 — one attack can destroy several cards. Independently
 // conserve each destroyed slot BEFORE pooling the positive RAM totals.
 // A zero-RAM destruction contributes neither a photon nor its own pool.
 const multiCard=await page.evaluate(()=>{
   const before=['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width);
   const seq=989940,impact=989939;
   const destroyed=[
     {side:'p',slot:0,ram:2},{side:'p',slot:2,ram:3},
     {side:'p',slot:4,ram:0},{side:'e',slot:1,ram:4},
     {side:'e',slot:3,ram:1}
   ];
   const releases=['p','e'].map(side=>{
     const slots=destroyed.filter(d=>d.side===side&&d.ram>0)
       .map(d=>({slot:d.slot,amount:d.ram}));
     return {side,type:'release',amount:slots.reduce((n,x)=>n+x.amount,0),slots};
   });
   drawEnergyPathways({seq,impactSeq:impact,events:releases});
   const report=['p','e'].map(side=>{
     const from=destroyed.filter(x=>x.side===side&&x.ram>0);
     const amount=from.reduce((n,x)=>n+x.ram,0);
     const match=selector=>[...document.querySelectorAll(selector)]
       .filter(x=>x.dataset.flowSeq===String(seq));
     const rays=match('#'+side+'Pathways .neonRecoveryReturn');
     const arrivals=match('#'+side+'Pathways .neonRecoveryArrival');
     const charges=match('#'+side+'RamAvailable ~ .neonRamCharge');
     const reservoir=match('#'+side+'RamAvailable ~ .neonRamReservoir');
     const discharge=match('#'+side+'RamAvailable > .neonRamDischarge');
     const afterglow=match('#'+side+'RamAvailable > .neonRamAfterglow');
     const transferIds=from.map(x=>'attack:'+impact+':'+side+':'+x.slot).sort();
     const details=x=>({
       transfer:x.dataset.transferId,slot:x.dataset.recoverySlot,ram:x.dataset.returnedRam,
       lifecycle:x.dataset.lifecycleId,cycle:x.dataset.cycleId
     });
     const cycle='attack:'+impact+':flow:'+seq+':'+side;
     return {side,amount,expected:from.map(x=>x.slot+':'+x.ram).sort(),transferIds,cycle,
       rays:rays.map(details),arrivals:arrivals.map(details),charges:charges.map(details),
       pools:[...reservoir,...discharge,...afterglow].map(x=>({
         cls:x.className,amount:x.dataset.returnedRam,
         count:x.dataset.transferCount,transfers:x.dataset.transferIds.split(',').sort(),
         cycle:x.dataset.cycleId
       }))};
   });
   return {report,before,after:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width),
     slots:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)};
 });
 if(multiCard.before.join(',')!==multiCard.after.join(',')||
    multiCard.slots.some(x=>x!==5))
   fail('Multi-card visual conservation changed game meters or playfield: '+JSON.stringify(multiCard));
 for(const item of multiCard.report){
   for(const group of ['rays','arrivals','charges']){
     const actual=item[group].map(x=>x.slot+':'+x.ram).sort();
     if(actual.join(',')!==item.expected.join(',')||
       item[group].some(x=>x.cycle!==item.cycle||
         x.lifecycle!=='attack:989939'||!item.transferIds.includes(x.transfer)))
       fail('Multi-card recovery transfer duplicated or missing: '+JSON.stringify({item,group}));
   }
   if(item.pools.length!==3||item.pools.some(x=>
      +x.amount!==item.amount||+x.count!==item.expected.length||
      x.transfers.join(',')!==item.transferIds.join(',')||x.cycle!==item.cycle))
     fail('Multi-card recovery reservoir does not conserve sum: '+JSON.stringify(item));
 }
 // v2.8.95 — one blocked attack with reciprocal lethal retaliation.
 // The authoritative consequence is two separate release accounts, both
 // retaining the same attack origin but never pooling RAM across players.
 const retaliationConservation=await page.evaluate(()=>{
   const seq=989950,impact=989949;
   const widths=['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width);
   const impacts=[
     {side:'p',slot:0,amount:2,role:'attacker'},
     {side:'e',slot:3,amount:4,role:'defender'}
   ];
   drawEnergyPathways({seq,impactSeq:impact,events:[
     {side:'p',type:'release',amount:2,slots:[{slot:0,amount:2}]},
     {side:'e',type:'release',amount:4,slots:[{slot:3,amount:4}]}
   ]});
   const observed=impacts.map(x=>{
     const cycle='attack:'+impact+':flow:'+seq+':'+x.side;
     const nodes=[...document.querySelectorAll('[data-cycle-id="'+cycle+'"]')];
     const selected=cls=>nodes.filter(n=>n.classList.contains(cls));
     const reservoir=selected('neonRamReservoir');
     const photon=selected('neonRecoveryReturn');
     const afterglow=selected('neonRamAfterglow');
     const charge=selected('neonRamCharge');
     const sample=nodes.map(node=>({
       cls:node.getAttribute('class'),side:node.dataset.recoverySide,
       amount:node.dataset.returnedRam,cycle:node.dataset.cycleId,
       id:node.dataset.lifecycleId,
       transfer:node.dataset.transferId||null
     }));
     return {...x,cycle,nodeCount:nodes.length,
       reservoirCount:reservoir.length,photonCount:photon.length,
       afterglowCount:afterglow.length,chargeCount:charge.length,
       reservoirAmount:reservoir[0]?.dataset.returnedRam,
       photonAmount:photon[0]?.dataset.returnedRam,
       transfers:reservoir[0]?.dataset.transferIds,
       colors:afterglow[0]?getComputedStyle(afterglow[0]).backgroundImage:'',
       pointerSafe:nodes.every(n=>getComputedStyle(n).pointerEvents==='none'),sample};
   });
   return {observed,widths,after:['p','e'].map(k=>document.getElementById(k+'RamAvailable').style.width),
     lanes:['p','e'].map(k=>document.querySelectorAll('#'+k+'Lanes>.slot').length)};
 });
 const attackSide=retaliationConservation.observed.find(x=>x.side==='p');
 const defenseSide=retaliationConservation.observed.find(x=>x.side==='e');
 for(const row of retaliationConservation.observed){
   const id='attack:989949:'+row.side+':'+row.slot;
   const expectedColor=row.side==='p'?'255, 210, 142':'248, 215, 255';
   if(row.nodeCount<7||row.reservoirCount!==1||row.photonCount!==1||
      row.afterglowCount!==1||row.chargeCount!==1||
      +row.reservoirAmount!==row.amount||+row.photonAmount!==row.amount||
      row.transfers!==id||!row.colors.includes(expectedColor)||!row.pointerSafe||
      row.sample.some(x=>x.side!==row.side||x.id!=='attack:989949'))
     fail('Reciprocal knockout crossed player recovery account: '+JSON.stringify(retaliationConservation));
 }
 if(!attackSide||!defenseSide||attackSide.cycle===defenseSide.cycle||
    retaliationConservation.widths.join(',')!==retaliationConservation.after.join(',')||
    retaliationConservation.lanes.some(x=>x!==5))
   fail('Reciprocal knockout disrupted RAM ownership or cards: '+JSON.stringify(retaliationConservation));
 // v2.8.96 — a reciprocal knockout can contain one zero-cost card.
 // Both directions are tested; zero-side releases must emit no recovered
 // photon, reservoir, charge, discharge or afterglow.
 const mixedRetaliation=await page.evaluate(()=>{
   const before=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   const scenarios=[
     {seq:989960,impact:989959,positive:'p',zero:'e',slot:0,amount:2},
     {seq:989961,impact:989960,positive:'e',zero:'p',slot:3,amount:4}
   ];
   const results=scenarios.map(test=>{
     const release=side=>side===test.positive?
       {side,type:'release',amount:test.amount,slots:[{slot:test.slot,amount:test.amount}]}:
       {side,type:'release',amount:0,slots:[]};
     drawEnergyPathways({seq:test.seq,impactSeq:test.impact,
       events:[release('p'),release('e')]});
     const sides=['p','e'].map(side=>{
       const cycle='attack:'+test.impact+':flow:'+test.seq+':'+side;
       const nodes=[...document.querySelectorAll('[data-cycle-id="'+cycle+'"]')];
       const types=['neonRecoveryReturn','neonRecoveryCore','neonRecoveryArrival',
         'neonRamCharge','neonRamReservoir','neonRamDischarge','neonRamAfterglow'];
       const counts=Object.fromEntries(types.map(cls=>[cls,
         nodes.filter(node=>node.classList.contains(cls)).length]));
       const reservoir=nodes.find(node=>node.classList.contains('neonRamReservoir'));
       return {side,cycle,counts,total:reservoir?.dataset.returnedRam||null,
         transfers:reservoir?.dataset.transferIds||null,
         pointerSafe:nodes.every(node=>getComputedStyle(node).pointerEvents==='none')};
     });
     return {...test,sides};
   });
   return {results,before,
     after:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width),
     lanes:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)};
 });
 for(const scenario of mixedRetaliation.results){
   const pos=scenario.sides.find(row=>row.side===scenario.positive);
   const zero=scenario.sides.find(row=>row.side===scenario.zero);
   if(!pos||!zero||!pos.pointerSafe||!zero.pointerSafe||
      pos.total!==String(scenario.amount)||
      pos.transfers!=='attack:'+scenario.impact+':'+scenario.positive+':'+scenario.slot||
      Object.values(pos.counts).some(n=>n!==1)||
      Object.values(zero.counts).some(n=>n!==0))
     fail('Zero-cost reciprocal retaliation generated phantom energy: '+JSON.stringify(mixedRetaliation));
 }
 if(mixedRetaliation.before.join(',')!==mixedRetaliation.after.join(',')||
    mixedRetaliation.lanes.some(n=>n!==5))
   fail('Zero-cost retaliation modified RAM meter or card space: '+JSON.stringify(mixedRetaliation));
 // v2.8.97 — zero-cost return must stay dark even when an earlier
 // positive release on the SAME side is still actively glowing.
 const isolated=await page.evaluate(()=>{
   const initial=['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width);
   const cases=[
     {seq:989970,impact:989969,side:'p',amount:3,slot:1},
     {seq:989971,impact:989970,side:'p',amount:0,slot:2},
     {seq:989972,impact:989971,side:'e',amount:2,slot:4},
     {seq:989973,impact:989972,side:'e',amount:0,slot:0},
     {seq:989974,impact:989973,side:'p',amount:1,slot:3}
   ];
   const records=[];
   const types=['neonRecoveryReturn','neonRecoveryCore','neonRecoveryArrival',
      'neonRamCharge','neonRamReservoir','neonRamDischarge','neonRamAfterglow'];
   const read=c=>{
     const cycle='attack:'+c.impact+':flow:'+c.seq+':'+c.side;
     const nodes=[...document.querySelectorAll('[data-cycle-id="'+cycle+'"]')];
     const classes=Object.fromEntries(types.map(type=>[type,
       nodes.filter(n=>n.classList.contains(type)).length]));
     const reservoir=nodes.find(n=>n.classList.contains('neonRamReservoir'));
     return {cycle,classes,total:reservoir?.dataset.returnedRam||null,
       transferIds:reservoir?.dataset.transferIds||null,
       pointerSafe:nodes.every(n=>getComputedStyle(n).pointerEvents==='none')};
   };
   for(const c of cases){
     drawEnergyPathways({seq:c.seq,impactSeq:c.impact,events:[
       {side:c.side,type:'release',amount:c.amount,
        slots:c.amount>0?[{slot:c.slot,amount:c.amount}]:[]}
     ]});
     records.push({case:c,observed:read(c)});
   }
   const oldStillPresent=[cases[0],cases[2],cases[4]].map(c=>
     document.querySelectorAll('[data-cycle-id="attack:'+c.impact+
       ':flow:'+c.seq+':'+c.side+'"]').length);
   return {cases,records,oldStillPresent,initial,
     final:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width),
     lanes:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)};
 });
 for(const row of isolated.records){
   const {seq,impact,side,amount,slot}=row.case;
   const {classes,total,transferIds,pointerSafe}=row.observed;
   if(!pointerSafe||
      (amount===0&&Object.values(classes).some(n=>n!==0))||
      (amount>0&&(Object.values(classes).some(n=>n!==1)||
        total!==String(amount)||transferIds!=='attack:'+impact+':'+side+':'+slot)))
     fail('Cross-cycle recovery borrowed RAM from earlier attack: '+JSON.stringify(row));
 }
 if(isolated.oldStillPresent.some(n=>n<7)||
    isolated.initial.join(',')!==isolated.final.join(',')||
    isolated.lanes.some(n=>n!==5))
   fail('Cross-cycle isolation modified earlier recovery or card geometry: '+JSON.stringify(isolated));
 await page.waitForTimeout(5300);
 const isolatedExpired=await page.evaluate(()=>({
   remaining:[989970,989971,989972,989973,989974].map(seq=>
     document.querySelectorAll('[data-flow-seq="'+seq+'"]').length),
   lanes:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length),
   widths:['p','e'].map(side=>document.getElementById(side+'RamAvailable').style.width)
 }));
 if(isolatedExpired.remaining.some(Boolean)||
    isolatedExpired.lanes.some(n=>n!==5)||
    isolatedExpired.widths.join(',')!==isolated.initial.join(','))
   fail('Cross-cycle return did not expire independently: '+JSON.stringify(isolatedExpired));
 console.log('CROSS-CYCLE ISOLATION PASS: five alternating events, two zero returns, three independent positive recoveries, no ghosts');
 console.log('ZERO-COST RETALIATION PASS: reciprocal +2/0 and 0/+4, no invented photons');
 console.log('RETALIATION CONSERVATION PASS: attacker +2, defender +4, independent neon cycles and no meter mutation');
 console.log('MULTI-CARD CONSERVATION PASS: five destroyed slots, four positive packets, two pooled reservoirs, zero phantom RAM');
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
   const destructions=[],seenAttacks=new Set();
   const capture=()=>{
     const impact=typeof lastImpact!=='undefined'?lastImpact:null;
     const flow=typeof lastRamFlow!=='undefined'?lastRamFlow:null;
     if(!impact?.destroyed?.length||seenAttacks.has(impact.seq))return;
     seenAttacks.add(impact.seq);
     const destroyed=impact.destroyed.map(x=>({
       side:x.side,slot:x.slot,ram:x.ram,name:x.name
     }));
     const releases=flow?.impactSeq===impact.seq?
       flow.events.filter(x=>x.type==='release').map(x=>({
         side:x.side,amount:x.amount,slots:x.slots?.map(slot=>({...slot}))||[]
       })):[];
     const entry={seq:impact.seq,flowSeq:flow?.seq??null,
       destruction:destroyed,releases,visuals:[]};
     destructions.push(entry);
     requestAnimationFrame(()=>requestAnimationFrame(()=>{
       entry.visuals=[...document.querySelectorAll(
         '.neonRecoveryReturn[data-lifecycle-id="attack:'+entry.seq+'"],'+
         '.neonRamReservoir[data-lifecycle-id="attack:'+entry.seq+'"]'
       )].map(el=>({cls:el.getAttribute('class'),side:el.dataset.recoverySide,
         amount:el.dataset.returnedRam,slot:el.dataset.recoverySlot||null,
         cycle:el.dataset.cycleId,flowSeq:el.dataset.flowSeq}));
     }));
   };
   const events=document.getElementById('events');
   const observer=new MutationObserver(capture);
   if(events)observer.observe(events,{childList:true});
   window.__liveMatchAuditFinish=()=>{clearInterval(timer);observer.disconnect();read();return {
     samples,positiveFlows:[...observed.values()],destructions,
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
 // v2.8.91 — only real engine destruction/release records can qualify.
 // An observation interval without destruction remains explicitly inconclusive.
 for(const result of matchAudit.destructions){
   const expected=new Map();
   for(const d of result.destruction){
     if(d.ram>0)expected.set(d.side,(expected.get(d.side)||0)+d.ram);
   }
   /* Destruction of a zero-cost card remains a legitimate zero-RAM
      release in the engine. It must NOT create any energy photon. */
   const expectedReleaseSides=new Set(result.destruction.map(x=>x.side));
   if(result.releases.length!==expectedReleaseSides.size)
     fail('Real destruction missing its authoritative release record: '+JSON.stringify(result));
   for(const release of result.releases){
     const expectedSlots=result.destruction.filter(x=>x.side===release.side&&x.ram>0)
       .map(x=>x.slot+':'+x.ram).sort();
     const actualSlots=release.slots.map(x=>x.slot+':'+x.amount).sort();
     if(release.amount!==(expected.get(release.side)||0)||
        expectedSlots.join(',')!==actualSlots.join(','))
       fail('Live RAM recovery diverged from destroyed card costs: '+JSON.stringify(result));
     const ray=result.visuals.filter(x=>x.cls?.includes('neonRecoveryReturn')&&x.side===release.side);
     const reservoir=result.visuals.find(x=>x.cls?.includes('neonRamReservoir')&&x.side===release.side);
     if(release.amount===0){
       if(ray.length||reservoir)
         fail('Zero-cost destruction invented energy recovery: '+JSON.stringify(result));
       continue;
     }
     if(ray.length!==release.slots.length||!reservoir||
        +reservoir.amount!==release.amount||
        ray.some(x=>!release.slots.some(slot=>
          String(slot.slot)===x.slot&&String(slot.amount)===x.amount)))
       fail('Live recovery neon has missing or fabricated transfer: '+JSON.stringify(result));
   }
 }
 // v2.8.93 — conserve observed live return value across successive
 // attack events. Distinguish card destructions (including zero-cost) from
 // positive recoveries; count ledger amounts once per attack/flow/side.
 const seenAttack=new Set(),seenFlowSide=new Set(),seenVisual=new Set();
 const totals={destroyed:0,released:0,visualized:0,attacks:0,positive:0,zero:0};
 for(const entry of matchAudit.destructions){
   if(seenAttack.has(entry.seq))
     fail('Real attack was recorded twice: '+JSON.stringify(entry));
   seenAttack.add(entry.seq);totals.attacks++;
   const positiveDestroyed=entry.destruction.filter(d=>d.ram>0);
   totals.destroyed+=positiveDestroyed.reduce((n,d)=>n+d.ram,0);
   totals.zero+=entry.destruction.filter(d=>d.ram===0).length;
   for(const release of entry.releases){
     const flowKey=entry.flowSeq+':'+release.side;
     if(seenFlowSide.has(flowKey))
       fail('Recovery ledger counted a side twice: '+JSON.stringify(entry));
     seenFlowSide.add(flowKey);
     totals.released+=release.amount;
     if(release.amount<=0)continue;
     totals.positive++;
     const sources=positiveDestroyed.filter(d=>d.side===release.side);
     if(sources.reduce((n,d)=>n+d.ram,0)!==release.amount)
       fail('Observed recovery violates conservation: '+JSON.stringify(entry));
     const reservoir=entry.visuals.filter(v=>v.cls?.includes('neonRamReservoir')&&
       v.side===release.side);
     if(reservoir.length!==1)
       fail('Positive recovery must have exactly one visual reservoir: '+JSON.stringify(entry));
     const evidence=reservoir[0],visualKey=evidence.cycle;
     if(seenVisual.has(visualKey)||evidence.flowSeq!==String(entry.flowSeq)||
        visualKey!=='attack:'+entry.seq+':flow:'+entry.flowSeq+':'+release.side)
       fail('Recovery reservoir is duplicated or orphaned: '+JSON.stringify(entry));
     seenVisual.add(visualKey);
     totals.visualized+=Number(evidence.amount);
     const rays=entry.visuals.filter(v=>v.cls?.includes('neonRecoveryReturn')&&
       v.side===release.side);
     const expectedSlots=sources.map(d=>d.slot+':'+d.ram).sort();
     const actualSlots=rays.map(v=>v.slot+':'+v.amount).sort();
     if(expectedSlots.join(',')!==actualSlots.join(','))
       fail('Visual photon transfer repeated or omitted destroyed slot: '+JSON.stringify(entry));
   }
 }
 if(totals.destroyed!==totals.released||totals.released!==totals.visualized||
    totals.positive!==seenVisual.size)
   fail('Conservation totals differ across source, ledger and neon: '+JSON.stringify(totals));
 console.log('LIVE RAM CONSERVATION: '+JSON.stringify({
   ...totals,status:totals.positive?'POSITIVE_RETURNS_RECONCILED':'NO_POSITIVE_RETURN_OBSERVED'
 }));
 // Multi-card live observation is conditional: a bounded match may not
 // naturally destroy two units in the same attack. Never claim that it did.
 const liveMulti=matchAudit.destructions.filter(x=>x.destruction.length>=2);
 for(const entry of liveMulti){
   for(const release of entry.releases){
     const expected=entry.destruction.filter(x=>x.side===release.side&&x.ram>0)
       .map(x=>x.slot+':'+x.ram).sort();
     const actual=release.slots.map(x=>x.slot+':'+x.amount).sort();
     if(expected.join(',')!==actual.join(',')||
       release.amount!==release.slots.reduce((n,x)=>n+x.amount,0))
       fail('Live multi-card attack lost independent slot accounting: '+JSON.stringify(entry));
   }
 }
 console.log('LIVE MULTI-CARD STATUS: '+JSON.stringify({
   observed:liveMulti.length,
   status:liveMulti.length?'RECONCILED':'NOT_OBSERVED_IN_BOUNDED_MATCH'
 }));
 // v2.8.95 — distinguish actual reciprocal casualties from test fixture.
 // Do not claim a real double knockout if bot combat does not produce one.
 const reciprocal=matchAudit.destructions.filter(entry=>
   new Set(entry.destruction.map(x=>x.side)).size===2);
 for(const entry of reciprocal){
   const bySide=new Map(entry.releases.map(x=>[x.side,x]));
   for(const side of ['p','e']){
     const cards=entry.destruction.filter(x=>x.side===side);
     const amount=cards.reduce((sum,x)=>sum+x.ram,0);
     const observed=bySide.get(side);
     if(!observed||observed.amount!==amount)
       fail('Actual reciprocal combat failed independent side accounting: '+JSON.stringify(entry));
   }
 }
 console.log('LIVE RECIPROCAL DESTRUCTION: '+JSON.stringify({
   attacks:reciprocal.length,
   status:reciprocal.length?'OBSERVED_AND_RECONCILED':'NOT_OBSERVED_IN_BOUNDED_MATCH'
 }));
 // Report live zero-cost reciprocal attacks separately from synthetic
 // scenarios. If not encountered, do not claim live zero-cost coverage.
 const liveMixed=reciprocal.filter(entry=>
   entry.destruction.some(x=>x.ram===0)&&entry.destruction.some(x=>x.ram>0));
 for(const entry of liveMixed){
   for(const side of ['p','e']){
     const expected=entry.destruction.filter(x=>x.side===side).reduce((n,x)=>n+x.ram,0);
     const release=entry.releases.find(x=>x.side===side);
     const reservoirs=entry.visuals.filter(x=>x.side===side&&
       x.cls?.includes('neonRamReservoir'));
     if(!release||release.amount!==expected||
        (expected===0&&reservoirs.length!==0)||
        (expected>0&&(reservoirs.length!==1||+reservoirs[0].amount!==expected)))
       fail('Live zero-cost retaliation violated independent recovery: '+JSON.stringify(entry));
   }
 }
 console.log('LIVE ZERO-COST RECIPROCAL: '+JSON.stringify({
   attacks:liveMixed.length,status:liveMixed.length?'OBSERVED':'NOT_OBSERVED_IN_BOUNDED_MATCH'
 }));
 // v2.8.92 — close the real evidence chain at final expiration.
 // Stop producing new actions; inspect only recovered visual cycles captured
 // by the immutable attack/flow tuple. An older animation must self-expire.
 const documented=matchAudit.destructions.flatMap(d=>d.releases.filter(r=>r.amount>0)
   .map(r=>({attack:d.seq,flow:d.flowSeq,side:r.side,amount:r.amount,
     slots:r.slots.map(x=>x.slot+':'+x.amount).sort()})));
 // A bounded observation that sees no positive release is not considered
 // proof of completed recovery.
 if(documented.length){
   const beforeExpire=await page.evaluate(cycles=>cycles.map(c=>({
     attack:c.attack,flow:c.flow,side:c.side,
     still:[...document.querySelectorAll('[data-cycle-id="attack:'+c.attack+
       ':flow:'+c.flow+':'+c.side+'"]')].length
   })),documented);
   await page.waitForTimeout(5400);
   const afterExpire=await page.evaluate(cycles=>({
     remaining:cycles.map(c=>({
       attack:c.attack,flow:c.flow,side:c.side,
       nodes:document.querySelectorAll('[data-cycle-id="attack:'+c.attack+
         ':flow:'+c.flow+':'+c.side+'"]').length
     })),
     slots:['p','e'].map(side=>document.querySelectorAll('#'+side+'Lanes>.slot').length)
   }),documented);
   if(afterExpire.remaining.some(x=>x.nodes!==0)||
      afterExpire.slots.some(n=>n!==5))
     fail('Real recovery lineage retained orphaned visual nodes: '+JSON.stringify({documented,beforeExpire,afterExpire}));
   console.log('LIVE RECOVERY EXPIRATION PASS: '+JSON.stringify({
     recoveredCycles:documented.length,retainedNodes:0,waitMs:5400
   }));
 }else{
   console.log('LIVE RECOVERY EXPIRATION NOT OBSERVED: bounded match had no positive recovery');
 }
 console.log('LIVE DESTRUCTION RECONCILIATION: '+JSON.stringify({
   count:matchAudit.destructions.length,
   status:matchAudit.destructions.length?'OBSERVED_AND_RECONCILED':'NOT_OBSERVED_IN_WINDOW'
 }));
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

 // v2.9.00 — formal, reviewable acceptance gate. Freeze the observed
 // pass/fail evidence before reporting success; never infer that a live
 // destruction case occurred if the bounded bot match did not produce it.
 const baselineGates=[
   {id:'ARENA_LOCK',pass:initial.player.length===5&&initial.bot.length===5&&
      still&&resetStorm.counts.every(x=>x.slots.every(n=>n===5))},
   {id:'RAM_CONSERVATION',pass:totals.destroyed===totals.released&&
      totals.released===totals.visualized&&multiCard.report.length===2},
   {id:'ZERO_RETURN',pass:mixedRetaliation.results.length===2&&
      isolated.records.filter(x=>x.case.amount===0).length===2},
   {id:'RECIPROCAL_OWNERSHIP',pass:retaliationConservation.observed.length===2&&
      retaliationConservation.observed.every(x=>x.reservoirCount===1)},
   {id:'VISUAL_EXPIRATION',pass:alternatingEnd.remain.every(x=>x===0)&&
      isolatedExpired.remaining.every(x=>x===0)&&completed.remaining===0},
   {id:'MATCH_BOUNDARY',pass:resetStorm.counts.length===10&&
      settledReset.mode==='human'&&settledReset.lingering===0},
   {id:'GENERATIVE_MURALS',pass:initial.player.length===5&&
      await page.locator('#neuroscapeArt,#signalFoundry').count()===2},
   {id:'BROWSER_ERRORS',pass:errors.length===0}
 ];
 const baselineReport={
   version:'2.9.00',name:'Neuroscape recovery acceptance baseline',
   policy:'Any failed gate blocks acceptance; live unobserved conditions stay unverified',
   gates:baselineGates,passed:baselineGates.every(x=>x.pass),
   liveEvidence:{
     attacks:totals.attacks,positiveReturns:totals.positive,
     reciprocalAttacks:reciprocal.length,
     realMultiCardAttacks:liveMulti.length,
     zeroCostReciprocalAttacks:liveMixed.length,
     coverage:totals.positive?'POSITIVE_RECOVERY_OBSERVED':'NO_POSITIVE_RECOVERY_OBSERVED'
   },
   fixedConstraints:{arenaSlotsPerSide:5,catalogCards:256,visualCycleLimit:12},
   browserErrorCount:errors.length
 };
 writeFileSync('recovery-baseline.json',JSON.stringify(baselineReport,null,2)+String.fromCharCode(10));
 if(!baselineReport.passed)
   fail('v2.9.00 RECOVERY ACCEPTANCE GATE FAILED: '+JSON.stringify(baselineReport));
 console.log('RECOVERY ACCEPTANCE GATE PASS: '+JSON.stringify(baselineReport));
 if(errors.length)fail('Browser error after artwork regeneration');
 console.log('ART GENERATION PASS: exactly two active procedural scenes, both regenerate, card space unchanged');
 console.log('ARENA PASS: five large squares per side, hand, controls, RAM install/restart and bot start',JSON.stringify(initial));
}finally{
 await page.screenshot({path:'arena-regression.png',fullPage:true});
 await browser.close();
}
