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
