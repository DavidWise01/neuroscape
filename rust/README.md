# Neuroscape Rust Core — 0.1.0

The original game remains in `index.html` and its existing browser scripts.
This is an **additive, dependency-free Rust computation crate**, not a claim
that the existing JavaScript arcade has already been rewritten in Rust.

## Scope

- Deterministic conservative stability margins: `0.1 - max(residuals)`
- Component-based uncertainty propagation with separately tracked sampling,
  clock, and model assumptions
- Three-way confirmed-stable / indeterminate / confirmed-unstable classification
- Calibration dossier review eligibility, **never self-issued empirical authority**
- Unit tests, rustfmt, and clippy in GitHub Actions

## Run

```bash
cd rust/neuroscape-core
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Contract

The Rust core has **no network dependencies, no game-state access, and no
mutation of the HTML game**. Input evidence is declared/synthetic unless
independently verified. This first stage establishes the Rust reference
implementation and test gate. A later stage can compile Rust to WebAssembly,
compare it against existing JavaScript fixtures, and wire it into GitHub Pages
only after browser parity is verified.

`.dlw`

## RUST-002 — WebAssembly browser parity

The GitHub Actions workflows now compile `neuroscape-core` for
`wasm32-unknown-unknown` from Rust source. `rust/build-wasm.py` converts
that compiled binary into a JS-embedded, SHA-256-labeled asset solely to
support the existing `file://` Playwright regression harness. **The source
file `assets/neuroscape-rust-wasm.generated.js` in Git is a placeholder**;
the actual binary is compiled and substituted in the GitHub Actions workspace
for browser acceptance and custom Pages deployment.

The browser's read-only `neuroscapeRustParity` monitor executes the genuine
WebAssembly exports and compares numeric bounds and classifications against
all 32 inherited JavaScript adversarial periods. A missing binary, mismatched
ABI version, or disagreement fails the parity check. This is **not** yet a
Rust rewrite of card mechanics, rendering, or the main arcade application.

The compiled browser binary is checked into `assets/neuroscape-rust-wasm.generated.js`,
so both the default GitHub Pages build and `Deploy Ether Arena` have a valid
WASM asset. CI still rebuilds the binary independently from Rust source before
testing and deploying. Verify the live monitor reports `RUST/WASM PASS`
before claiming real browser acceptance.

Run locally:

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path rust/neuroscape-core/Cargo.toml --target wasm32-unknown-unknown --release --locked
python3 rust/build-wasm.py
# Open index.html to inspect the resulting read-only WASM parity monitor.
```

## RUST-003 — Gameplay shadow transition verification

The Rust crate now exports deterministic calculations for RAM availability,
deployment affordability, and a **single observed combat attack** (attacker
health, defender health, meter health and destruction decisions). It matches
the legacy JavaScript `cost`, `free`, `predictedTarget` and legal-deploy
calculations using the actual 256-card catalog. Chromium creates **cloned
combat fixtures** from real character cards; it does not issue player or bot
actions or mutate the live board. The Rust shadow is not yet the authoritative
gameplay engine.

The compiled WebAssembly asset is checked into GitHub as
`assets/neuroscape-rust-wasm.generated.js`, with its SHA-256 digest.
GitHub Actions recompiles from Rust before running parity and deploying.
`window.neuroscapeRustShadow.ready` exposes a fail-closed comparison result.

Next steps are full turn/event state replay, identity-safe card removal,
resource conservation and migration only after browser parity gates pass.

## RUST-004 — Identity-safe bounded combat replay

The Rust replay owns a **temporary, fixed-size 160-word WASM buffer** and can
resolve a copied, five-slot-per-side combat state. The buffer is allocated
and freed within the Rust module; the live HTML engine has no Rust authority.

The `ns_replay_apply` contract uses these zero-based i32 offsets:

| Offsets | Meaning |
| --- | --- |
| 0–2 | Attacker side (0 player / 1 enemy), immutable unit ID, meter selector (0 BF / 1 MF) |
| 3–10 | RAM, BF/MF meters for both sides; count of units for each side |
| 11–35 | Five player units: each [ID, HP, RAM cost, attack damage, used] |
| 36–60 | Five enemy units in the same shape |
| 61–85 | Output player survivors; original identities preserved |
| 86–110 | Output enemy survivors |
| 111–120 | Survivor counts, destroyed counts, recycled RAM, available RAM before/after |
| 121–131 | Post-combat meters, terminal status, winner, defender ID, HP and status |

Rust selects the first unused defender, applies the exchange or direct meter
damage, compacts surviving units, tracks removed card costs, enforces RAM
release consistency, and identifies terminal outcomes. The JS parity harness
replays bounded multi-attack combat on **clones** using the original
`simulateSequenceAttack`, then checks every Rust output against the native
JS state. The full four-phase gameplay loop and bot AI remain JavaScript.
No shadow result is permitted to drive a live game action.

The original locked 5×2 arena, 256 cards and both murals are unaffected.

`.dlw`

## RUST-005 — Four-phase turn control

This stage adds a separate pure Rust `turn` module. It covers legal RAM
installation, deck-to-hand drawing, legal hand-to-five-slot deployment,
immutable unit identity allocation, phase advancement, HP restoration,
active-side rotation, per-turn action reset, and turn-limit detection.
The existing RUST-004 module remains the combat calculation shadow.

The compiled WebAssembly provides a caller-owned 256-word buffer through
`ns_turn_alloc / ns_turn_step / ns_turn_free`. The browser tests 48
deterministic seven-transition cycles against equivalent copied JavaScript
state using real catalog card data, and confirms the live game state is
unchanged. Invalid transitions fail without modifying the WASM input.

This is a bounded reference implementation, **not** an authoritative
replacement of the production gameplay engine or the bot. Hand/deck
capacity in this ABI is limited to eight cards per side; the live game
may hold more and remains JavaScript-owned.

`.dlw`

## RUST-006 — Unified copied match replay

The `match_core` module combines RUST-005 turn phases and RUST-004 combat
into a single atomic, caller-owned 256-word match-state buffer. Action code
`4` attacks by immutable UID (`word[7]`) against the declared BF/MF meter
(`word[8]`). Post-action state includes BF/MF values, recycled bin counts,
released RAM, winner and cumulative attack count in words 224–233.

Chromium runs 48 deterministic real-catalog action histories on copied
JavaScript and Rust states. It checks every transition, card identity, health,
unit compaction, hand/deck state, resource conservation, winner and turn
rotation. Both match histories are **read-only relative to the live game**.

This does not transfer match authority to Rust and is not a full port of
bot decision-making, logging, animation, or unconstrained hand/deck capacity.

`.dlw`

## RUST-007/008 — Ordered evidence and WASM digest parity

The copied-state Rust module `evidence_ledger` records every accepted action,
the pre/post 256-word digests, ordered chain, resource counters and terminal
status. Its FNV-1a digests are deterministic parity checks, **not cryptographic
signatures or proof of source authenticity**. Invalid actions, terminal reuse,
and nonmonotonic cumulative counters fail closed.

RUST-008 exports `ns_evidence_digest_low/high` as the two unsigned halves of
one 64-bit digest. The separate `rust/evidence-parity.js` adapter accepts
only caller-provided copied match fixtures, a compiled WASM instance and a
separately supplied JavaScript transition oracle. It compares state digests
after **every** action and rejects any disagreement.

To qualify this stage: run `cargo test`, `cargo fmt --all -- --check`,
`cargo clippy --all-targets -- -D warnings`, rebuild WASM with
`wasm32-unknown-unknown`, run the adapter in Chromium against the real
JavaScript oracle, and verify the checked-in Pages WASM asset and live
deployment. **These gates are not yet claimed complete.** Merely checking
in the adapter does not execute it, and the previously pinned WASM binary
does not automatically gain the new exports.

The canonical game, artwork, card catalog, 5×2 arena, bot, and turn
authority remain JavaScript-owned.

`.dlw`

## RUST-011 — Browser-visible combat evidence witness

- [RUST-011 interactive neon evidence page](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html)
- [Neuroscape live arcade](https://davidwise01.github.io/neuroscape/)
- [Rust core regression workflow](https://github.com/DavidWise01/neuroscape/actions/workflows/rust-core.yml)

The test page uses a **copied** 256-word state with three attacks. It checks
a simultaneous attacker/blocker destruction, card compaction, two-sided RAM
release, unblocked meter hits, a terminal winner and rejection of subsequent
actions. The WASM digest is checked against independent JavaScript state
serialization on every transition. Replaying the same actions twice must
produce identical evidence. The phase test continues checking 64 transitions.

`rust/tests/run_rust009_browser.py` now requires **both** RUST-009 and
RUST-011 fixtures in Chromium. The established `rust-core.yml` workflow
already invokes that runner after rebuilding WASM, so new pushes under
`rust/**` qualify both.

**Release policy:** GitHub source commits do not certify a Pages deployment.
The browser display deliberately shows HOLD if the checked-in deployed WASM
does not provide RUST-008 digest exports. Before declaring browser PASS,
verify that Actions completed successfully, that the regenerated WASM reached
the Pages deployment, and that the public page displays PASS. The test fixture
is synthetic and does not imply real gameplay authority or independent witness
ancestry. The original arcade is preserved.

`.dlw`

## RUST-013 — Pages release identity and digest readback

The deployment workflow now writes `assets/rust013-release.json` **only after**
its native Rust, fresh WASM build, and Chromium replay checks complete.
The manifest records the source commit, Actions run ID, SHA-256 digest of
the *compiled binary*, and the UTC generation time. The publication witness
at [RUST-013](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html)
fetches that JSON and recalculates SHA-256 from the WASM binary delivered
alongside the public page. A mismatch or missing report means HOLD.

This establishes consistency between the deployed binary and the
self-reported CI manifest. It does **not** independently authenticate the
workflow execution, guarantee the latest deployment completed, prove external
witness independence, or transfer live gameplay authority.

- [Main GitHub Pages arcade](https://davidwise01.github.io/neuroscape/)
- [Combat witness](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html)
- [Publication witness](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html)
- [Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-014 — Public Pages acceptance after deploy

Deployment success is insufficient to freeze a binary. The workflow now invokes
`rust/tests/verify_live_pages.py` **after** `actions/deploy-pages@v4`.

The public probe verifies:

1. The live release manifest matches the exact `GITHUB_SHA` and `GITHUB_RUN_ID`.
2. The public RUST-013 page recalculates the actual shipped WASM SHA-256.
3. The public RUST-011 Chromium fixture passes the copied-state combat
   replay, including blocker destruction, two-sided RAM release, terminal
   outcome, replay reproducibility and post-terminal rejection.

Transient public propagation is allowed up to eight attempts, but a missing,
stale or inconsistent result keeps the job failed. A self-declared CI manifest
is **not** independent evidence of source provenance; the browser probe
establishes delivery and execution consistency only.

[Live arcade](https://davidwise01.github.io/neuroscape/) ·
[Combat parity](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html) ·
[Publication readback](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Pages workflow](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-015 — Dual-fingerprint release receipts

A browser-independent Python SHA-256 is calculated over the canonical,
sorted-key JSON of the **complete** RUST-011 combat replay evidence in the
predeployment Chromium runner. This is separate from both the Rust FNV
per-state checksum and the SHA-256 of the WASM binary.

The Pages build embeds the replay SHA-256 and step count into its
`assets/rust013-release.json` manifest while retaining the existing
`phase: RUST-013` public ABI. After deployment, the public browser runner
retrieves the same combat evidence and independently recomputes the SHA-256.
The gate requires the public digest, CI digest and manifest digest all match,
with the identical source commit and Actions run.

After all checks succeed, the workflow uploads an immutable, run/attempt-
specific GitHub Actions artifact containing the local replay receipt, public
readback receipt, and deployment manifest. Artifact retention is 90 days;
this is **not a permanent external custody service**, and CI/public probes
still share the repository's own ancestry.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Combat witness](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html) ·
[Release dashboard](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Deploy actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

No transfer of gameplay authority. Freeze only after the public acceptance
job finishes successfully.

`.dlw`
