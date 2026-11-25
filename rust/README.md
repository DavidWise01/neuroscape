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

## RUST-016 — Exact-commit clean build reproduction

The Pages workflow now runs `rust/tests/reproduce_wasm.py` after compiling
its primary WASM binary and before publication. The second build extracts
the exact `GITHUB_SHA` with `git archive` into a fresh temporary directory,
uses a separate Cargo target directory, and builds `--release --locked`.
Both generated WebAssembly binaries must have identical SHA-256 and size.

The result is recorded in `assets/rust016-reproduction.json`, bound into
the RUST-013 release manifest and checked again by the public Pages witness
and post-deployment Chromium acceptance. Any missing or mismatching result
fails the publication gate. The run-specific Actions artifact also stores
this reproduction receipt.

Two clean builds of the same GitHub source are useful reproducibility
evidence, **not** two independent source witnesses. This experiment does not
compare different Rust toolchains or operating systems, authenticate the
repository history externally, or grant live gameplay authority.

[Live Neuroscape](https://davidwise01.github.io/neuroscape/) ·
[Neon release dashboard](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Combat replay](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html) ·
[Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-017 — Pinned cross-runner WASM reproduction

The Pages workflow adds a separate `cross-environment` job on Ubuntu 22.04,
using pinned Rust 1.85.1 to rebuild the exact GitHub commit. The deploy job
uses Ubuntu 24.04 and the same pinned toolchain. Both builds record the
compiler version, byte count, source commit and compiled WASM SHA-256.

The Ubuntu 22.04 fingerprint travels as a GitHub Actions artifact, not through
shared workspace state. The deployment compares it against its own compiled
binary and fails closed on missing files, mismatched toolchain metadata, or
different bytes. After the gate, the public RUST-013 dashboard reads
`assets/rust017-cross-environment.json`, and post-deploy Chromium must
confirm the same fingerprint from the served release manifest.

A matching fingerprint is **cross-runner reproducibility evidence**, not
independent source ancestry or proof of external custody: both builds use the
same repository, GitHub infrastructure and compiler toolchain.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Cross-runner neon dashboard](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Combat replay](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html) ·
[Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-018 — Three observation classes, one ancestry

The build manifest, predeployment copied-state replay receipt, and
postdeployment public-browser receipt have different **observed claims**.
`rust/tests/adjudicate_rust018.py` requires agreement on the exact
source commit, GitHub run ID, WASM SHA-256 and replay SHA-256, including
reproduction checks and no transfer of gameplay authority. It fails
closed on missing or contradictory fields. Ten negative mutations
are covered by `test_adjudicate_rust018.py`.

The seal is written **after successful public Pages readback**, to
`rust/tests/.rust018-adjudication.json` with exclusive creation;
the run-scoped Actions artifact archives it alongside RUST-015–017 receipts.
This seal deliberately declares *three observation classes but only
one source ancestry*. It is **not** three independent witnesses, external
custody, or an immutable record beyond the artifact's retention period.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Combat witness](https://davidwise01.github.io/neuroscape/rust/tests/rust011-browser.html) ·
[Neon release dashboard](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Pages evidence workflow](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-019 — Append-only release lineage and anti-rollback boundary

`rust/tests/lineage_rust019.py` validates a complete RUST-018 receipt,
checks its canonical SHA-256, and optionally links to a **previously
anchored** RUST-019 record. A valid continuation requires (a) an intact
predecessor hash, (b) a new source commit that descends from the predecessor
by Git ancestry, (c) a non-reused observation receipt and (d) a strictly
incremented sequence. New records are created using exclusive file creation;
preexisting output is never overwritten.

**No predecessor is fabricated.** Until a genuine retained predecessor
is supplied as `rust/release/predecessor.json`, the CI workflow records
`HOLD_UNANCHORED` and archives it as evidence, not as an accepted freeze.
The anchored path uses a strict exit status; unanchored reporting is
explicitly permitted only for documentation/archiving. Synthetic tests cover
missing ancestry, same-commit replay, tampered receipts, wrong sequence and
non-descendant commits.

The design does not yet prevent rollback of an entire repository, deletion
of retained records, or counterfeit predecessor records if no independently
held and authenticated checkpoint exists. A predecessor record in the same
repository is **not** independent custody, even if it is hash-consistent.

[Live arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon RUST-019 lineage observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust019-lineage.html) ·
[Release dashboard](https://davidwise01.github.io/neuroscape/rust/tests/rust013-release.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-020 — Genesis candidate, external Ed25519 custody gate

`rust/tests/genesis_rust020.py` derives an **immutable candidate** from a
RUST-018 accepted observation receipt. The candidate includes the source
commit, replay and WASM SHA-256 digests, adjudication digest, sequence zero,
and a canonical candidate fingerprint. CI emits
`rust/tests/.rust020-genesis-candidate.json` after the public acceptance
and three-observation steps; the run-specific artifact includes that file.
It is explicitly `GENESIS_CANDIDATE`, not an authenticated checkpoint.

An external custodian must separately retain the candidate hash and use
their own Ed25519 private key to sign the **canonical compact JSON bytes**
of the candidate (sorted keys, no spaces). The verification command
requires the corresponding public key, the raw signature, and
`RUST020_CUSTODIAN_PUBKEY_SHA256` pinned **outside this repository**.
That environment variable is the SHA-256 of the public key's DER SPKI.
For example, an external verifier can compute it with:

```sh
openssl pkey -pubin -in custodian-public.pem -outform DER | sha256sum
```

With the independently held pin and signed candidate available:

```sh
RUST020_CUSTODIAN_PUBKEY_SHA256="<externally-checked 64-hex pin>" \
python3 rust/tests/genesis_rust020.py verify \
  --candidate rust/tests/.rust020-genesis-candidate.json \
  --public-key custodian-public.pem \
  --signature external-custodian.sig \
  --output genesis-verification.json
```

The verifier does **not** generate a custody key, invent an owner,
authenticate the external key-pin process, establish three independent
source ancestries, or automatically authorize a RUST-019 lineage freeze.
A public key stored only alongside the source is insufficient proof
of external custody. The signature acknowledgment must remain held and
checked outside GitHub to resist repository-wide rollback.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon Genesis Observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust020-genesis.html) ·
[Lineage](https://davidwise01.github.io/neuroscape/rust/tests/rust019-lineage.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-021 — Externally signed genesis to first successor

`rust/tests/successor_rust021.py` accepts a fresh RUST-018 adjudication,
a historical RUST-020 genesis candidate, a custodian Ed25519 public key,
and the matching raw signature. It **re-verifies** the candidate using
`genesis_rust020.authenticated` with an independently pinned public-key
SPKI SHA-256 and checks source ancestry using `git merge-base --is-ancestor`.

It denies same-commit reuse, replay of the genesis observation, mismatched
candidate and signature claims, missing key-pin, and non-descendant commits.
Qualified successors receive sequence 1 with a hash of the canonical
previous custody attestation. The output is created exclusively and never
overwrites existing evidence. This is not a general public-authority
or global anti-rollback certificate: protection against full-history
replacement still requires a trusted external checkpoint and retention.

The **automatic GitHub Actions workflow does not possess external custody
material**, and emits an archived `HOLD_EXTERNAL_GENESIS` receipt instead
of constructing fictional signatures. The optional manually supplied
qualified path is:

```sh
RUST020_CUSTODIAN_PUBKEY_SHA256="<independently pinned DER SPKI SHA-256>" \
python3 rust/tests/successor_rust021.py \
  --current rust/tests/.rust018-adjudication.json \
  --candidate /external/genesis-candidate.json \
  --public-key /external/custodian-public.pem \
  --signature /external/genesis.sig \
  --output /external/first-successor.json
```

The genesis candidate must be genuinely from an **earlier** commit,
and the signature and public key must belong to a real off-repository
custodian; a signature on the current run's candidate cannot satisfy
the descendant condition.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon First Successor](https://davidwise01.github.io/neuroscape/rust/tests/rust021-successor.html) ·
[Genesis Observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust020-genesis.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-022 — Custodian continuity and dual-signed key rotation

`rust/tests/rotation_rust022.py` accepts a retained RUST-021 or
RUST-022 predecessor, a newer RUST-018 receipt, an externally pinned old
Ed25519 public key, and a signature on a canonical rotation proposal.
It checks predecessor hash integrity, source descent, non-reuse of source
or evidence, incremented sequence and custodian key pin.

A **key change** additionally requires the new Ed25519 public key, an
independently supplied new-key SPKI SHA-256 pin, and a second signature on
the **same exact proposal**. Without these checks there is no qualified
rotation. The returned `CUSTODIAN_CONTINUITY` record is append-only and
records both signature digests, key fingerprints and predecessor hash.
It explicitly declines external custodian identity certification, global
anti-rollback and gameplay authority.

The automatic Pages workflow has no custodian private keys and emits
`HOLD_CUSTODIAN_CONTINUITY`. It runs synthetic structural negative tests
and includes the HOLD record in its finite-retention Actions artifact.
The source contains **no generated custodian key or forged witness**.

Manual externally controlled verification example:

```sh
RUST022_OLD_KEY_SPKI_SHA256="<external old key pin>" \
RUST022_NEW_KEY_SPKI_SHA256="<external new key pin, only for rotation>" \
python3 rust/tests/rotation_rust022.py \
  --current current-rust018.json \
  --previous retained-rust021-or-rust022.json \
  --old-key old-custodian-public.pem \
  --old-signature signed-proposal.old.sig \
  --new-key new-custodian-public.pem \
  --new-signature signed-proposal.new.sig \
  --output rotation-receipt.json
```

Both signatures must be made over the exact canonical JSON of the
`proposal(...)` result. For unchanged-key continuity, omit all
`--new-*` arguments and the new-key environment variable.

[Live arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon rotation observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust022-rotation.html) ·
[Previous successor](https://davidwise01.github.io/neuroscape/rust/tests/rust021-successor.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-023 — Emergency publication freeze and custodian recovery

New deployments can be stopped with the repository Actions variable
`RUST023_EMERGENCY_FREEZE=true`. The Pages deployment job checks this
variable before checkout, compilation or publication, and exits with an
error rather than publishing. This is a **GitHub operational emergency
switch**, not a global freeze of already deployed pages, repository history
or external copies. Turning the variable off merely permits the normal
release gates to run; it does not authenticate a recovery.

`rust/tests/revocation_rust023.py` defines a canonical, hash-linked
`REVOCATION_PROPOSAL` for a retained RUST-022 custodian checkpoint. A
valid emergency revocation requires a **separate externally pinned**
Ed25519 recovery public key and its signature over that exact proposal.
The compromised custodian key cannot be its own recovery key. The
verified record marks `REVOKED_EMERGENCY_FREEZE`, and the denylist
rejects later use of the revoked fingerprint. A RUST-021 predecessor
without an authenticated current-key pin is insufficient for the
automated revocation path and remains HOLD.

**Trust boundary:** a JSON revocation record's self-consistent hash is
not external authentication. The external recovery signature, pin
provenance and retained predecessor must be checked independently by
the verifier before treating the denylist as authoritative. The
automatic workflow has no external recovery credentials; it runs
negative tests and archives only
`HOLD_REVOCATION_CUSTODY_UNVERIFIED`, without granting custody or
gameplay authority. The archive retains the record for 90 days.

For a real external recovery custodian to produce a verified revocation,
first create the canonical proposal, sign its compact JSON bytes using
the separately controlled recovery Ed25519 key, then supply the pinned
public key SHA-256 (DER SPKI), predecessor and signature:

```sh
RUST023_RECOVERY_KEY_SPKI_SHA256="<externally pinned SHA-256>" \
python3 rust/tests/revocation_rust023.py \
  --previous /external/last-qualified-rust022.json \
  --revoked-key "<current custodian SPKI SHA-256>" \
  --reason COMPROMISE \
  --recovery-key-public /external/recovery.pem \
  --recovery-signature /external/recovery.sig \
  --output /external/revocation-rust023.json
```

The command does not create keys, designate an actual recovery custodian,
or authenticate an off-repository record's storage. The current RUST-022
qualifier does not automatically query a network revocation register; any
qualification workflow claiming active custody must supply and verify
the retained revocation state.

[Live arcade](https://davidwise01.github.io/neuroscape/) ·
[Emergency neon observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust023-revocation.html) ·
[Previous rotation](https://davidwise01.github.io/neuroscape/rust/tests/rust022-rotation.html) ·
[Pages workflow](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-024 — Recovery epochs, permanent quarantine and replay fencing

`rust/tests/recovery_epoch_rust024.py` adds a structured recovery-epoch
proposal. It validates a retained RUST-022 custodian predecessor, a
hash-consistent RUST-023 revocation, a separately retained highwater
checkpoint with its epoch and sequence, and an explicit quarantine
set containing the revoked key. The next epoch and sequence must
advance monotonically. A quarantined key cannot be selected as the
new custodian; the recovery signer cannot silently promote itself.

Qualifying a proposal requires **two** verified Ed25519 signatures on
the exact canonical proposal, from independently pinned recovery and
new-custodian keys. It also requires external verification of the
previous custody checkpoint and highwater; a consistent local JSON
file or a caller-provided assertion is not enough. Even after the
two signatures, the output sets
`custody_resume_authorized: false`; a separate policy and external
authority decision would be required to resume.

The default GitHub workflow has no external checkpoint or custody
signatures. It runs regression tests before deploying and archives
`HOLD_QUARANTINED` as an append-only, finite-retention Actions
artifact. The CLI deliberately declines to self-attest the historical
trust condition. Source-level regression tests do not establish live
Pages deployment or authenticated anti-rollback.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-024 neon epoch observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust024-recovery.html) ·
[Revocation witness](https://davidwise01.github.io/neuroscape/rust/tests/rust023-revocation.html) ·
[Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-025 — External highwater witness and anti-replay boundary

`rust/tests/highwater_rust025.py` defines the canonical signed
`HIGHWATER_CANDIDATE` containing epoch, sequence, source commit,
release entry SHA-256, and predecessor highwater fingerprint.

It requires an Ed25519 signature on the exact candidate JSON and a
public-key SPKI SHA-256 fingerprint **pinned outside the GitHub repository**.
A successor comparison rejects a forked predecessor fingerprint, replayed
or skipped sequences, epoch rollback, duplicated source revision, reused
release entries and altered candidate bytes.

A valid signature proves only that the pinned key signed **that
historical checkpoint**. Without an independently obtained, authenticated
**latest** checkpoint, signed old history could be replayed. Hence
`SIGNED_HIGHWATER_OBSERVED` explicitly keeps
`external_latest_checkpoint_confirmed: false`,
`global_anti_rollback_certified: false`, and
`release_authorized: false`.

CI runs the anti-fork regression tests **before** Pages publication.
Without off-repository witness material it later archives
`HOLD_EXTERNAL_HIGHWATER` as a run-scoped Actions artifact, not as a
qualified release. The arcade and live game state remain unchanged.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon RUST-025 observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust025-highwater.html) ·
[Recovery observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust024-recovery.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-026 — Three external highwater observations and fork retention

`rust/tests/multiwitness_rust026.py` consumes three ordered signed
RUST-025 checkpoints, from the configured `ff`, `cf`, and `rr`
observation positions. For each it verifies the RUST-025 candidate
digest and Ed25519 signature against a public key whose DER SPKI SHA-256
fingerprint must be supplied separately in
`RUST026_PIN_FF`, `RUST026_PIN_CF`, `RUST026_PIN_RR`.
Duplicate key fingerprints, missing witnesses, altered checkpoints and
signature failures stop adjudication.

The JSON evidence receipt retains all three ordered observations,
their candidate fingerprints, keys and signature hashes.
`CONSISTENT_SIGNED_SNAPSHOTS` means only that these three signatures
cover the same candidate and history position; the result still has
`independent_custody_ancestries_verified: false`,
`external_latest_checkpoint_confirmed: false`, and
`release_authorized: false`.

Any disagreement—including a 2:1 split—is retained as
`HOLD_FORK_EVIDENCE` rather than erased by majority voting. Three
different signing keys do not establish independent organizations,
external storage or a globally latest checkpoint. The automated
GitHub Pages job has no external witness material; it runs the
predeployment negative tests and archives only
`HOLD_MISSING_THREE_WITNESSES`.

For a genuine externally sourced witness bundle, each element must
include the position, RUST-025 checkpoint, PEM public-key path and raw
signature path. Public-key pins must come from the externally retained
custody records, **not** from the same bundle itself. The runner can
check the signature and compare the snapshots, but cannot prove who
ultimately controls the keys.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[Three-witness neon observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust026-multiwitness.html) ·
[Highwater laboratory](https://davidwise01.github.io/neuroscape/rust/tests/rust025-highwater.html) ·
[GitHub Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-027 — Fork lineage reconstruction and source ancestry limits

`rust/tests/fork_lineage_rust027.py` accepts a signed three-witness
RUST-026 observation receipt and an explicit list of canonical RUST-025
checkpoint records. It validates the witness receipt hash and each
checkpoint hash, then follows SHA-256 parent pointers backward from
every witnessed head. Every witness branch remains in the resulting
ordered evidence ledger; a 2:1 split does not erase a minority branch.

The verifier rejects missing witness heads, duplicated node IDs,
inconsistent witness/graph fields, malformed hashes, replayed source
or entry digests, non-sequential links and epoch rollback. It can
identify the deepest **observed common ancestor** when all three
paths contain the same checkpoint. If a node is missing, it records
the missing predecessor explicitly and never manufactures a genesis.
A common ancestor in a supplied graph is an observation, not
authentication of that graph's historical custody.

The branch report preserves the `ff`, `cf` and `rr` key and signature
fingerprints, head hashes, paths, and missing predecessors.
`independent_custody_ancestries_verified` remains **false**,
`release_authorized` remains **false**, and every result is HOLD
pending external custody. No majority vote or source duplication can
authorize the next release.

The GitHub Actions workflow runs synthetic reconstruction regression
tests before publication. Since no externally qualified graph is
available in the normal workflow, it archives an append-only
`HOLD_MISSING_FORK_GRAPH` result with the other run-scoped evidence.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon fork ancestry observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust027-fork-lineage.html) ·
[Three-witness page](https://davidwise01.github.io/neuroscape/rust/tests/rust026-multiwitness.html) ·
[Pages Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`
