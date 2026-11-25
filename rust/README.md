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
