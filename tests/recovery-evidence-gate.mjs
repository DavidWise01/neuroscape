import { readFileSync } from 'node:fs';
import { strict as assert } from 'node:assert';

const path=process.argv[2]||'recovery-baseline.json';
let record;
try {
  record=JSON.parse(readFileSync(path,'utf8'));
} catch(error) {
  throw new Error('Acceptance evidence missing or invalid JSON: '+error.message);
}
const required=[
  'ARENA_LOCK','RAM_CONSERVATION','ZERO_RETURN','RECIPROCAL_OWNERSHIP',
  'VISUAL_EXPIRATION','MATCH_BOUNDARY','GENERATIVE_MURALS','BROWSER_ERRORS'
];
assert.equal(record.version,'2.9.00','Baseline version mismatch');
assert.equal(record.passed,true,'Overall acceptance must pass');
assert.ok(Array.isArray(record.gates),'Missing gate array');
assert.equal(record.gates.length,required.length,'Gate count must match frozen baseline');
assert.deepEqual(record.gates.map(g=>g.id),required,'Missing, repeated or reordered baseline gate');
for(const gate of record.gates) assert.equal(gate.pass,true,'Failed gate: '+gate.id);
assert.equal(record.fixedConstraints?.arenaSlotsPerSide,5,'Card layout changed');
assert.equal(record.fixedConstraints?.catalogCards,256,'Catalog contract changed');
assert.equal(record.fixedConstraints?.visualCycleLimit,12,'Recovery bound changed');
assert.equal(record.browserErrorCount,0,'Browser errors recorded');
const observed=record.liveEvidence;
assert.ok(observed&&typeof observed==='object','Live evidence record missing');
for(const field of ['attacks','positiveReturns','reciprocalAttacks','realMultiCardAttacks','zeroCostReciprocalAttacks']) {
  assert.ok(Number.isSafeInteger(observed[field])&&observed[field]>=0,
    'Invalid live observation count: '+field);
}
assert.ok(['POSITIVE_RECOVERY_OBSERVED','NO_POSITIVE_RECOVERY_OBSERVED'].includes(observed.coverage),
  'Live observation coverage must be explicit');
assert.equal(observed.coverage,
  observed.positiveReturns>0?'POSITIVE_RECOVERY_OBSERVED':'NO_POSITIVE_RECOVERY_OBSERVED',
  'Live coverage contradicts observation count');
console.log('RECOVERY EVIDENCE VALIDATED: '+JSON.stringify({
 version:record.version,gates:required.length,allPassed:true,
 liveCoverage:observed.coverage,positiveReturns:observed.positiveReturns
}));
