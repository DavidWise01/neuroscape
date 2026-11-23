# NEUROSCAPE — LOCKED PLAYFIELD BASELINE

**Status:** Accepted visual/gameplay baseline. **Policy:** append-only enhancements; never replace or shrink the protected playable arena.

**Frozen reference branch:** `baseline/v2.8.57-locked-arena`

**Exact baseline commit:** `4a43d1178a104cbb80299d097719e73238460e50`

**Live arcade:** https://davidwise01.github.io/neuroscape/

## Protected, non-negotiable baseline

1. Bone-white two-player arena with high-definition orange/purple neon.
2. Exactly five **full-sized, visible square card stations per player**, shown even when empty or before startup; ten total.
3. The player’s playable card hand, deployment, attack selection, RAM/draw, restart, and Bot vs Bot remain functional.
4. Gameplay/card area takes priority over every forecast, log, analytics, witness, new AI module, navigation feature, or decorative effect. Add these *outside* the protected playfield.
5. Keep all 256 catalog entries; retain actual card imagery, card identities, and deterministic authoritative gameplay.
6. Preserve the `data-arena-invariant="5x2-visible-square-card-slots"` marker and geometry protections.
7. Keep the existing base unchanged unless the user **explicitly authorizes a baseline change**. Any future work should be an additive extension, not a replacement or page redesign.
8. Test with real Chromium on every `index.html` change; block regressions, and never report browser success from source-only tests.

## Acceptance proof at freeze

Chromium regression run: https://github.com/DavidWise01/neuroscape/actions/runs/45187848969

That job successfully completed **Verify visible 5x2 arena and real game startup** after correcting a script-initialization error. It checks 10 full-sized card stations, startup, hand cards, RAM install, restart, and bot-mode activation. This is a browser smoke test, not proof of a complete manual human playthrough.

**Rule:** `BASELINE = IMMUTABLE REFERENCE; FUTURE = ADDITIVE ONLY`.

`.dlw · 1×5×2×1 · P0 PLAYFIELD`
