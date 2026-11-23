# Neuroscape / Genesis HD — v0.7 RC1

[Launch browser client](https://davidwise01.github.io/neuroscape/). Independent training client inspired by [Neuroscape Local v0.2.1](https://github.com/nothingalike/deckscape-app/releases/tag/v0.2.1). Original card artwork streams from source URLs; rights and redistribution are not assumed.

## Features
- 256 embedded catalog records and four source starter lists; all starter names resolved.
- High-DPI canvas, projected chrome/glass board and responsive layout.
- Basic character-only training scenario; not full official gameplay.
- Local autosave, validated JSON import, export, and destructive-action confirmation.

## Qualification
JavaScript parses. 28 headless logic assertions passed covering initial state, RAM, deploy, attack, turn transitions, state validation and malformed saves. Browser end-to-end, Pages deployment, card image availability, full rules parity and licensing remain open. Starter lists are reference/export only.

## Permanent non-regression invariant — card arena (v2.8.57)

**P0 / APPEND-ONLY / NO EXCEPTIONS:** The **playable card space is the primary UI**. Never remove, collapse, shrink to a strip, hide, or replace the square-card arena while adding agents, neon, forecasting, witness panels, logs, menus, or other features. Both players must always retain **five visibly rendered square card slots**, even on an empty board, before JavaScript initialization, or if initialization fails. The hand must remain playable and the existing game rules and action buttons must remain functional. Mobile layouts may scale the squares responsively but must not hide them. Keep the bone-white background with high-definition orange/purple neon.

**Acceptance gate for every future iteration:** Inspect the actual GitHub Pages arcade in Chromium after deployment; check both 5-slot lanes, readable square cards, hand and controls, live deployment and attack, and the full game path. Run the startup/geometry assertions and gameplay regression suite. Do not claim browser verification when only JavaScript syntax or headless tests have passed. Do not publish a change that reduces playable card area to accommodate secondary panels. If the game fails to initialize, retain all ten card slots and display a visible startup failure instead of leaving a blank arena.

Canonical arcade: https://davidwise01.github.io/neuroscape/
