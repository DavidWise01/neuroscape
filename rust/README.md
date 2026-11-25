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

The repository may have a second, platform-managed Pages build in addition
to `Deploy Ether Arena`. Only the custom workflow includes the generated
binary. Verify the live Pages monitor says `RUST/WASM PASS` before making
a claim that the deployed page is running WebAssembly; if a plain Pages build
wins the deployment race, the monitor will correctly report FAIL rather
than present JavaScript as Rust.

Run locally:

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path rust/neuroscape-core/Cargo.toml --target wasm32-unknown-unknown --release --locked
python3 rust/build-wasm.py
# Open index.html to inspect the resulting read-only WASM parity monitor.
```
