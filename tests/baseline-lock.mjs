import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
/* Baseline is a separate branch; modifications to main are additive only.
   This test enforces protected card-space markup and CSS byte-for-byte
   against the accepted frozen snapshot. Browser CI verifies visual size. */
const baseline=execFileSync('git',['show','refs/remotes/origin/baseline/v2.8.57-locked-arena:index.html'],{encoding:'utf8'});
const current=readFileSync('index.html','utf8');
const fixed=(source)=>{
 const from=source.indexOf('/* PERMANENT PLAYFIELD INVARIANT:');
 const to=source.indexOf('</style>',from);
 assert(from>=0&&to>from,'Missing permanent card geometry lock');
 return source.slice(from,to);
};
assert(current.includes(fixed(baseline)),'Protected minimum-size card-space CSS changed: add new code without modifying baseline');
const arena='<section class="board" id="gameBoard" data-arena-invariant="5x2-visible-square-card-slots"';
assert(current.includes(arena),'Protected arena root changed');
const lane=id=>{
 const pattern=new RegExp('<div class="lanes" id="'+id+'"[^>]*>([\\s\\S]*?)<\\/div><(?:svg|\\/div>)');
 const match=current.match(pattern);
 const original=baseline.match(pattern);
 assert(match&&original,'Missing player/bot square lane: '+id);
 assert.equal(match[1],original[1],'Baseline square markup replaced: '+id);
 assert.equal((match[1].match(/class="slot"/g)||[]).length,5,'Lost card slots: '+id);
};
lane('pLanes');lane('eLanes');
assert(current.includes('lane.replaceChildren(...Array.from({length:5}'),'Five-slot live board rendering removed');
for(const id of ['hand','install','draw','next','modeHuman','modeAuto','restart'])assert(current.includes('id="'+id+'"'),'Protected game control missing: '+id);
assert(current.includes('const phase34Closure=phase34GameplayClosure()'),'Phase 34 gameplay regression removed');
assert(current.includes('ARCADE INITIALIZATION FAILED'),'Missing visible startup error');
console.log('BASELINE LOCK PASS — protected 5×2 arena, geometry, controls and startup evidence match frozen branch');
