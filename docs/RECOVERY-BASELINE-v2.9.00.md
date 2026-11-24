# Neuroscape v2.9.00 — Recovery Acceptance Baseline

Status: source and CI gate committed; acceptance requires successful Chromium Actions on the exact revision.

## Governing invariant

Gameplay is authoritative; visual effects are observation-only. Every positive recovery derives from destroyed-card RAM costs. Zero-cost destruction produces no recovery energy. No animation or replay may change RAM, card positions, game actions, or source evidence.

## Protected baseline

- Existing immutable arena checkpoint: `baseline/v2.8.57-locked-arena` via `tests/baseline-lock.mjs`.
- Exactly five square card stations for each side (ten total).
- Existing 256-card catalog and legal combat/turn logic.
- Two distinct generative murals, unchanged by recovery rendering.
- Per-side recovery visuals bounded to 12 concurrent visual cycle identifiers.
- Restart and mode change remove prior-match energy effects and block stale queued callbacks.
- Retain evidence separately from bounded, disposable visual DOM.

## Eight blocking acceptance gates

| ID | Acceptance condition |
|---|---|
| ARENA_LOCK | Five card slots per side before and after repeated resets |
| RAM_CONSERVATION | Destroyed RAM = released RAM = visual reservoir RAM |
| ZERO_RETURN | Zero-cost destruction creates no recovery-energy visuals |
| RECIPROCAL_OWNERSHIP | Two-sided retaliation keeps ownership of positive returns separate |
| VISUAL_EXPIRATION | Recorded visual cycles naturally expire without orphan effects |
| MATCH_BOUNDARY | Ten resets/mode switches leave the final human match clean |
| GENERATIVE_MURALS | Both existing murals remain present |
| BROWSER_ERRORS | No uncaught browser JavaScript errors |

Tests run in `tests/arena-regression.mjs` with Playwright Chromium. The test writes `recovery-baseline.json` and fails if any blocking gate is false. GitHub Actions uploads that JSON as `recovery-baseline-v2.9.00` and retains the original `arena-browser-proof` screenshot artifact.

## Evidence scope

The fixture tests actively exercise conservation, zero-cost returns, reciprocal ownership, simultaneous and repeated recoveries, natural expiration, and reset isolation. The live bot-versus-bot sampling window separately counts observed attacks, positive recovery events, multi-card losses, and reciprocal losses. Unobserved live scenarios are recorded as **not observed**, never represented as live successes.

## Verification protocol

1. Check the `Arena non-regression (Chromium)` workflow against the complete final commit.
2. Verify `recovery-baseline.json` has `passed: true` and each gate `pass: true`.
3. Confirm `pages build and deployment` succeeds against the same revision.
4. Keep the baseline immutable; future versions extend functionality without reducing existing playfield space.

`.dlw`

`{ GAMEPLAY PRESERVED } ∧ { RAM CONSERVED } ∧ { VISUALS BOUNDED } ∧ { MATCH ISOLATED }`
