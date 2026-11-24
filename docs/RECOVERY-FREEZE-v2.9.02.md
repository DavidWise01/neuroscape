# Neuroscape v2.9.02 — Recovery Evidence Freeze

## Verified source freeze

**Frozen reference:** `baseline/v2.9.01-recovery-accepted`

**Exact accepted commit:** `0b547a8cb134874959eb195400cfe6ca388a0445`

**Chromium acceptance:** https://github.com/DavidWise01/neuroscape/actions/runs/45405387939

**GitHub Pages:** https://github.com/DavidWise01/neuroscape/actions/runs/45405385801

**Arcade deployment:** https://github.com/DavidWise01/neuroscape/actions/runs/45405388223

The three runs completed successfully against the same accepted source commit. The Chromium run executed the protected arena baseline, browser regression and independent acceptance JSON validator.

## Artifact identity

| Archived item | Artifact ID | GitHub-reported ZIP SHA-256 |
|---|---|---|
| `recovery-baseline-v2.9.00` | `14924814276` | `c430bace534295287274d561fdd964e47ef74865d45b44b80c61985b888b00d0` |
| `arena-browser-proof` | `14924654905` | `7d5b1fcd32f31f30fb5d407958e9debd252da28a8e6388fb4ce29420ca99f514` |

These hashes are for **GitHub's archived ZIP artifacts**, not the raw JSON or screenshot contents. They are recorded from GitHub's artifact API and are not an independent local hash calculation.

### Acceptance result

Eight of eight checks passed:

1. `ARENA_LOCK`
2. `RAM_CONSERVATION`
3. `ZERO_RETURN`
4. `RECIPROCAL_OWNERSHIP`
5. `VISUAL_EXPIRATION`
6. `MATCH_BOUNDARY`
7. `GENERATIVE_MURALS`
8. `BROWSER_ERRORS`

The report records `passed: true`, zero JavaScript errors, five card slots per side, the 256-card catalog contract, and a maximum of 12 visible recovery cycles per side.

### Evidence limitations

The accepted Chromium run observed two natural attacks and **zero natural positive-RAM recovery events** within its bounded observation window. This does not negate passing deterministic recovery tests, but it does not certify positive-recovery observations in that specific live match. Live reciprocal or multi-card destruction was likewise not observed in the accepted run.

### Governance of the freeze

The frozen reference points to one reviewed source commit. Development continues on `main`, not on the frozen branch. Do not rewrite the frozen reference. Extend future versions additively while preserving the original playfield, combat rules, RAM mechanics, two murals, evidence and acceptance gates. New builds need their own CI confirmation; the historical freeze must not be presented as verification of later code.

`.dlw`

`{ LOCKED PLAYFIELD } ∧ { BOUNDED RECOVERY } ∧ { CONSERVED RAM } ∧ { OBSERVED EVIDENCE }`
