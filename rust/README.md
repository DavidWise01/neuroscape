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

## RUST-028 — Source-ancestry classification and fork resolution HOLD

`rust/tests/source_ancestry_rust028.py` analyzes the preserved
RUST-027 fork ledger using **three separately signed provenance
assertions**. Each declaration binds one witness role and observed head
fingerprint to its source root, source family, custody-controller
declaration and original capture SHA-256. Signatures require individually
pinned Ed25519 public-key SPKI hashes supplied **outside** the bundle
through `RUST028_PIN_FF`, `RUST028_PIN_CF`, `RUST028_PIN_RR`.

Shared roots, families, controllers or capture hashes are recorded as
explicit ancestry collisions. A mirror of one GitHub repository (including
its public Pages view) is a single source family, not an independent origin.
Even three nonmatching signed declarations cannot prove organizational
or data-acquisition independence: distinct keys may be under common
custody. Reports therefore retain
`independent_source_roots_certified: false`,
`independent_custody_ancestries_verified: false`,
`fork_resolved: false`, and `release_authorized: false`.
No 2:1 fork can be selected by quorum.

The source-verifier checks prior RUST-027 record integrity and role
alignment, preserves its full fork-head set and observed common ancestor,
then appends provenance assertions and collision findings without
altering the earlier ledger. GitHub Actions runs the negative regression
tests before publication. Because no genuinely external provenance
records are provided, the default workflow archives
`HOLD_NO_EXTERNAL_PROVENANCE` only.

This stage audits *assertions* about source ancestry; it does not
authenticate the independent acquisition history, storage location
or organizational control behind an external witness.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon source ancestry display](https://davidwise01.github.io/neuroscape/rust/tests/rust028-source-ancestry.html) ·
[Fork reconstruction](https://davidwise01.github.io/neuroscape/rust/tests/rust027-fork-lineage.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-029 — Custody-root challenge and archive-acquisition independence

`rust/tests/custody_roots_rust029.py` takes the **unaltered, hash-checked
RUST-028 ancestry ledger** and three separately signed custody-root
assertions for `ff`, `cf`, `rr`. Each challenge message binds the
RUST-028 receipt, witness head, source root and family, original capture
SHA-256, archive origin/operator, acquisition path/controller, and
operator registry fingerprint.

Three externally supplied Ed25519 SPKI SHA-256 pins
(`RUST029_PIN_FF/CF/RR`) and distinct challenge nonces
(`RUST029_NONCE_FF/CF/RR`) must be provided outside the assertion
bundle. This detects a reused key/nonce in the supplied set, but the
verifier does **not** establish that a nonce was freshly and independently
issued; the operator must verify that provenance.

Pairwise shared source families, archive operators, operator registry
fingerprints, capture digests, acquisition paths and capture controllers
are retained as collision evidence. A source mirror with a separate
signature is still one acquisition ancestry. Even if no declared fields
collide, signed operator declarations alone cannot authenticate
real-world archive control or organizational independence.

Every result remains either
`HOLD_SHARED_CUSTODY_OR_ACQUISITION`,
`HOLD_CUSTODY_CONTROL_UNPROVEN`, or
`HOLD_MISSING_EXTERNAL_CUSTODY_ROOTS`.
`independent_source_roots_certified`, `fork_resolved` and
`release_authorized` are always **false**.

GitHub Actions adds negative tests **before** Pages deployment and
archives the missing-custody HOLD receipt with the existing run-scoped
artifacts. The core Rust WASM parity and original game are untouched.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-029 neon custody observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust029-custody-roots.html) ·
[Ancestry audit](https://davidwise01.github.io/neuroscape/rust/tests/rust028-source-ancestry.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-030 — Acquisition challenge and archive-byte possession

`rust/tests/acquisition_rust030.py` extends the RUST-029 custody-root
ledger with three byte-level archive challenges. The verifier reads the
complete supplied archive, checks SHA-256 against its inherited original
capture, derives a deterministic 32-byte window offset from a separately
supplied challenge nonce and the archive fingerprint, and hashes that
window. The exact compact challenge payload includes the RUST-029
receipt fingerprint, role, archive digest/size, offset/window hash,
source-custody controller, archive operator, acquisition path/controller
and the nonce. Its Ed25519 signature is verified using an externally
pinned public-key fingerprint. This is a byte-possession check, not
independent verification of the archive's operator.

The three pinned keys are provided through
`RUST030_PIN_FF`, `RUST030_PIN_CF`, `RUST030_PIN_RR`, and the
three challenge nonces through
`RUST030_NONCE_FF`, `RUST030_NONCE_CF`, `RUST030_NONCE_RR`.
The input sample bundle contains ordered `ff/cf/rr` objects with
`archive_path`, `public_key`, and `signature` fields. Keys and nonces
must not be generated from the sample bundle itself. Duplicate keys,
duplicate nonces, original-capture mismatches, altered archive bytes,
and incorrect role bindings are rejected.

Identical archive digests, custody controllers, archive operators,
acquisition controllers or acquisition-path fingerprints are retained
as pairwise collision evidence. An attacker with copies of an archive
can answer these challenges without controlling its true origin.
Therefore `operator_control_independently_verified`,
`nonce_freshness_independently_verified`,
`independent_source_roots_certified`,
`fork_resolved` and `release_authorized` remain **false** even after
successful signatures and byte checks. Verifiable operator-control
requires trusted out-of-band identity and custody evidence.

The normal GitHub Actions workflow has no external archives or keys.
It runs negative acquisition tests before Pages deployment and archives
`HOLD_MISSING_EXTERNAL_ACQUISITION`. No changes are made to card
mechanics, the Rust WASM replay engine or the five-by-two arena.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-030 neon acquisition lab](https://davidwise01.github.io/neuroscape/rust/tests/rust030-acquisition.html) ·
[RUST-029 custody roots](https://davidwise01.github.io/neuroscape/rust/tests/rust029-custody-roots.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-031 — Independent retrieval and operator-control challenge

`rust/tests/operator_control_rust031.py` extends the hash-checked
RUST-030 acquisition record with three retrieval files and three
operator-control challenge responses. For each FF/CF/RR witness it reads
the entire retrieved archive, validates its SHA-256 against the
inherited capture, and binds its digest, size, retrieval session,
retrieval endpoint, operator account, registry fingerprint and
custody/acquisition controllers into a canonical message. An Ed25519
signature is checked against a separately supplied SPKI SHA-256 pin.

The caller must supply externally maintained keys and nonces as
`RUST031_PIN_FF/CF/RR` and `RUST031_NONCE_FF/CF/RR`. Inputs must not
be treated as trustworthy merely because the repository, an agent, or
a signed JSON record declares them independent. Identical retrieval
sessions, endpoints, operator accounts, archive hashes or controller
identifiers are retained as pairwise collision evidence.

Byte agreement and signed challenge response establish a narrower
observation than real-world independence: retrieved files may be
copied from one common source; operator identifiers may be claimed by
the signer; the challenge's independent issuance and latest freshness
have not been authenticated. For this reason every RUST-031 report
is HOLD; `independent_archive_custody_verified`,
`nonce_freshness_independently_verified`, `fork_resolved` and
`release_authorized` remain false.

The workflow runs eight negative/structural regression tests before
Pages deployment and archives the default
`HOLD_MISSING_OPERATOR_CONTROL_EVIDENCE` result in its finite-retention
run artifact. No user-facing gameplay controls, cards, 5×2 arena or
Rust WASM combat behavior were altered.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[Neon RUST-031 observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust031-operator-control.html) ·
[Acquisition observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust030-acquisition.html) ·
[Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-032 — Retrieval-session challenge freshness and replay ledger

`rust/tests/session_freshness_rust032.py` binds three signed issuer
challenges (`ff/cf/rr`) to an intact RUST-031 retrieval receipt. Each
canonical challenge includes epoch, previous ledger SHA-256, source
receipt, session and endpoint SHA-256, retrieved archive SHA-256, and
nonce. The script verifies Ed25519 issuer signatures using separately
supplied `RUST032_ISSUER_PIN_FF/CF/RR` key fingerprints.

Before appending an observation, it rejects reused nonces and
retrieval-session identifiers appearing anywhere in the supplied
historical entries, duplicates within the current batch, shared issuer
keys, changed retrieval endpoints, and tampered ledger hashes.
Entries from old epochs are carried forward in order, with a new
SHA-256 ledger fingerprint. Previous entries are never silently
overwritten or removed from the newly produced receipt.

The `genesis_history()` helper is for local deterministic tests; it is
**not** independently witnessed genesis. A locally self-consistent
ledger can miss prior challenges if earlier history has been withheld,
and an Ed25519 key does not prove an independent issuer or freshness.
Accordingly `external_latest_ledger_confirmed`,
`independent_issuer_custody_verified`,
`global_anti_rollback_certified`, `fork_resolved` and
`release_authorized` remain **false**.

Automatic GitHub Actions runs ten structural and negative regression
tests before Pages publication and archives
`HOLD_MISSING_EXTERNAL_SESSION_LEDGER` without pretending the
repository can authenticate off-repository custody. It does not change
the existing arena, 256 cards, or Rust WASM combat behavior.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-032 neon freshness observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust032-session-freshness.html) ·
[RUST-031 operator-control page](https://davidwise01.github.io/neuroscape/rust/tests/rust031-operator-control.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-033 — Signed session highwater and withheld-history detection

`rust/tests/session_highwater_rust033.py` binds an intact RUST-032
session ledger to an externally signed **exact checkpoint** containing
the ledger SHA-256, epoch, entry count, ordered entries SHA-256 and
last-entry SHA-256. It checks epoch-by-epoch `ff/cf/rr` ordering,
three entries per completed epoch, and the absence of duplicate nonce
or session identifiers across the **supplied** history.

The Ed25519 witness public key must match an externally maintained
DER-SPKI SHA-256 fingerprint supplied through
`RUST033_HIGHWATER_WITNESS_SPKI_SHA256`. A signed checkpoint that
commits to all entries detects a truncated or substituted ledger,
even if an attacker recalculates the shortened ledger's own hash.
An optional `compare_with_retained_floor` function rejects rollback
below an externally maintained epoch or a mismatching ledger at the
same epoch. The caller must authenticate that floor outside this
repository; this function does not authenticate its custody.

**Important boundary:** A valid signature on a historical checkpoint
does not prove it is the latest or that a witness operates an
independent archive. Every resulting observation remains
`HOLD_LATEST_HIGHWATER_UNCONFIRMED`, with
`latest_highwater_independently_verified: false`,
`global_anti_rollback_certified: false` and
`release_authorized: false`.

The deployment workflow runs ten structural/negative tests before
Pages publication and archives
`HOLD_MISSING_SIGNED_SESSION_HIGHWATER` when external witness
material is absent. Existing gameplay, card catalog, arena and Rust
WASM replay behavior are unchanged.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-033 Neon Highwater](https://davidwise01.github.io/neuroscape/rust/tests/rust033-session-highwater.html) ·
[RUST-032 Freshness](https://davidwise01.github.io/neuroscape/rust/tests/rust032-session-freshness.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-034 — Independent highwater retention and equivocation evidence

`rust/tests/highwater_retention_rust034.py` takes three ordered
`ff/cf/rr` retained histories. Each supplied snapshot contains the
complete canonical RUST-033 signed checkpoint, its public key and
signature. Signatures are checked against separately provided SPKI
SHA-256 pins (`RUST034_PIN_FF/CF/RR`), which must come from external
custody rather than the signed-history bundle itself.

The verifier retains every signed observation, epoch, ledger hash,
entry count, signer fingerprint, signature digest and checkpoint
digest. A mismatch of ledger hashes **at the same epoch** is preserved
as `HOLD_SIGNED_EQUIVOCATION`, with all conflicting claims and both
fingerprints. A two-to-one majority does not erase the contradictory
third source. It also rejects duplicate signing keys, reordered or
skipped epochs within a supplied history, replay of an identical
signed checkpoint, malformed checkpoints and failed signatures.

When all supplied signatures and epochs agree, the result is merely
`HOLD_LATEST_CUSTODY_UNVERIFIED`: three signing keys do **not** prove
three independent custodians or that no later epochs have been
withheld. The code cannot authenticate external storage,
organizational control, or the globally latest checkpoint. It never
sets `release_authorized`, `fork_resolved`,
`independent_witness_ownership_verified` or
`global_anti_rollback_certified` to true.

GitHub Actions runs ten structural and negative tests before Pages
deployment. Without real externally retained signed histories, the
normal workflow archives `HOLD_MISSING_RETAINED_HIGHWATER` as a
run-scoped evidence artifact. Existing Rust WASM gameplay and the
Neuroscape 5×2 arena remain unchanged.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-034 neon observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust034-highwater-retention.html) ·
[RUST-033 session highwater](https://davidwise01.github.io/neuroscape/rust/tests/rust033-session-highwater.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-035 — Cross-epoch custodian continuity and rotation evidence

`rust/tests/custodian_continuity_rust035.py` consumes an intact
RUST-034 signed-highwater evidence receipt. For each witness
(`ff`, `cf`, `rr`), it orders observed checkpoints by epoch and
inspects the signing-key fingerprints. When the key changes across
successive epochs, the verifier requires a domain-separated transition
message binding the RUST-034 receipt, old and new checkpoint hashes,
epoch pair, role and both SPKI SHA-256 pins. **Both** predecessor and
successor Ed25519 keys must sign the identical canonical transition
message. Missing, extra, misbound or invalid signatures stop
adjudication.

The engine retains per-role final history heads, every examined
dual-signature transition and cross-epoch contradictions. Existing
RUST-034 signed equivocation is never overridden by a key rotation or
majority vote. Repeated epochs with incompatible ledgers or signer
fingerprints, rollback and epoch gaps are retained as conflicting
evidence. All results remain either
`HOLD_CROSS_EPOCH_CONTRADICTION` or
`HOLD_CUSTODIAN_CONTINUITY_UNPROVEN`.

**Compatibility limitation:** The RUST-034 audit pins one key per
role for its entire supplied history. It therefore cannot by itself
generate a historically verified per-epoch rotated-key chain.
RUST-035 can check supplied transition evidence but cannot elevate
that evidence to independent custody or prove that the operator
controlled either key in an external organization. The assertions
`independent_custody_continuity_verified`, `fork_resolved` and
`release_authorized` always remain false.

GitHub Actions runs ten negative and structural tests before the
Pages publication stage and archives
`HOLD_MISSING_CUSTODIAN_CONTINUITY` when real external evidence is
absent. The Rust WASM replay engine, 256-card catalog and existing
5×2 arena are unchanged.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-035 neon continuity observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust035-custodian-continuity.html) ·
[RUST-034 highwater histories](https://davidwise01.github.io/neuroscape/rust/tests/rust034-highwater-retention.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-036 — Per-epoch witness key registry, dual-signed rotations, revocation

`rust/tests/epoch_key_registry_rust036.py` introduces an explicit
per-epoch registry for the three `ff/cf/rr` witness positions instead
of assuming that one RUST-034 key remains unchanged throughout the
history. Each historical checkpoint is verified with the SPKI SHA-256
fingerprint specified for its exact epoch; adjacent epochs must be
contiguous and an obsolete key cannot reappear after a successor has
been introduced.

Every key change requires two Ed25519 signatures over the same
domain-separated canonical transition record, binding role, old/new
epochs, old/new key pins and both checkpoint fingerprints. Separate
authority-signed revocations bind an evidence SHA-256, key fingerprint,
and effective epoch. Any signature from a revoked key at or after its
effective epoch is rejected. All prior checkpoint signatures, rotation
signatures and revocation claims are retained as observational evidence.
Shared signing keys across witness roles and different ledger hashes
at one epoch are recorded explicitly, not majority-voted away.

**Security boundary:** `registries` is a separately supplied JSON
input but this module does not authenticate its off-repository custody
or prove its pins were independently established. The revocation
authority is also only pinned *by that supplied registry*. Consequently
`external_key_registry_ancestry_verified`,
`independent_custodian_control_verified`,
`external_latest_highwater_verified`, `fork_resolved` and
`release_authorized` remain **false**, including after every successful
cryptographic signature check.

GitHub Actions includes eleven structural and adversarial unit tests
before Pages publication. Without external histories and key registry,
the workflow archives `HOLD_MISSING_EPOCH_KEY_REGISTRY`. The original
Rust WASM combat engine, 5×2 arena and 256-card deck are unchanged.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-036 neon epoch-key observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust036-epoch-key-registry.html) ·
[RUST-035 continuity](https://davidwise01.github.io/neuroscape/rust/tests/rust035-custodian-continuity.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-037 — External registry highwater and revocation retention floor

`rust/tests/registry_highwater_rust037.py` binds an intact,
hash-checked RUST-036 per-epoch registry receipt to a signed
`SIGNED_REGISTRY_HIGHWATER` checkpoint. The exact canonical message
contains the RUST-036 receipt digest, maximum observed epoch, complete
ordered key-claim digest and count, all rotation digests and count,
and the complete revocation history digest and count. It is verified
with an Ed25519 witness key pinned **outside** the bundle using
`RUST037_ANCHOR_WITNESS_SPKI_SHA256`.

A separately supplied retention floor can reject a registry epoch
older than an externally recorded one, an altered registry at the same
epoch, a reduced revocation count, or a different revocation digest
at an unchanged count. A signed checkpoint with missing revocations
cannot match the full RUST-036 evidence from which the original
checkpoint was derived.

**Boundary:** `--floor` imports a declared highwater reference but
does not authenticate who retained it. A newer epoch with an increased
revocation count also does not establish that old revocations are
still present unless separately verified through a retained
append-only history. The key registry and signature witness are not
by themselves independent source ancestries. All receipts remain
`HOLD_EXTERNAL_LATEST_REGISTRY_UNVERIFIED` or
`HOLD_REGISTRY_EQUIVOCATION`; release and fork resolution stay false.

GitHub Actions includes eleven negative/structural tests before
Pages publication and archives
`HOLD_MISSING_EXTERNAL_REGISTRY_HIGHWATER` when no out-of-band
anchor is supplied. No gameplay, 5×2 arena, 256-card catalog, or
Rust WASM combat engine behavior is changed.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-037 neon registry highwater](https://davidwise01.github.io/neuroscape/rust/tests/rust037-registry-highwater.html) ·
[RUST-036 epoch registry](https://davidwise01.github.io/neuroscape/rust/tests/rust036-epoch-key-registry.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-038 — Append-only revocation ancestry and superseded-key fencing

`rust/tests/revocation_ancestry_rust038.py` extends RUST-037's
signed registry highwater with an **ordered, predecessor-linked SHA-256
chain** covering every RUST-036 revocation. Each chain entry binds its
ordinal, previous entry fingerprint, complete source revocation digest,
revoked key pin, effective epoch, role and revocation authority pin.
A domain-separated RUST-038 genesis digest anchors the empty prefix.

The verifier checks the original RUST-036 receipt and exact RUST-037
signed anchor, re-verifies that Ed25519 anchor signature against a
separately provided SPKI fingerprint
(`RUST038_ANCHOR_WITNESS_SPKI_SHA256`), and requires the signature
fingerprint to match the hash recorded in the original RUST-037
receipt. Duplicate revocations of the same role and key are rejected.

For a separately retained prefix floor containing `phase:
RUST-038`, `entry_count` and `head_sha256`, the verifier
requires the computed chain head **at exactly that count** to match
the retained value. Rewriting, deleting, inserting before, or
reordering an earlier revocation causes prefix mismatch even if
new records increase the total count. Successful comparison records
the floor's digest while preserving all upstream RUST-037
equivocation evidence.

**Limit:** A floor supplied through JSON is still a *claim* about
external custody, not proof that it was independently acquired or is
the latest. A malicious provider can withhold both an old floor and
later revocations. The chain protects integrity relative to the
presented independently established reference; it does not solve
real-world acquisition or global anti-rollback. The fields
`external_floor_custody_authenticated`,
`global_anti_rollback_certified`, `fork_resolved` and
`release_authorized` remain false.

GitHub Actions runs eleven negative and structural tests before
Pages deployment, then archives
`HOLD_MISSING_EXTERNAL_REVOCATION_ANCESTRY` when no external chain
materials are supplied. The existing 5×2 arena, 256-card catalog,
neon gameplay and Rust WASM engine remain unchanged.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-038 neon revocation ancestry](https://davidwise01.github.io/neuroscape/rust/tests/rust038-revocation-ancestry.html) ·
[RUST-037 registry highwater](https://davidwise01.github.io/neuroscape/rust/tests/rust037-registry-highwater.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-039 — Revocation persistence across registry epochs

`rust/tests/revocation_persistence_rust039.py` compares two complete
RUST-036 epoch-key registry receipts with the corresponding integrity-
checked RUST-038 revocation-chain receipts. Each chain is rebuilt from
the exact revocation events; the complete retained predecessor chain
head **must equal the successor chain head at the predecessor's event
count**. The earlier revocation objects, epoch-key claim lists and
rotation history must remain exact prefixes of the new histories.
This rejects a reordering, substitution, truncation or deletion even
if the newer record has a valid self-computed hash.

A revoked key's fingerprint is denied at or beyond its revocation's
effective epoch across all successor claims. A registry that reuses
that fingerprint to sign a newer epoch fails closed. An optional
list of key-to-custodian identifiers records potential continuity
between a previously revoked key and a successor key, including across
different witness roles. Identical *claimed* custodian identities are
preserved under `HOLD_SHARED_CUSTODY_LINEAGE`; different identities
do not demonstrate true independence.

The input is five JSON documents: `--previous-registry`,
`--current-registry`, `--previous-chain`, `--current-chain`
and `--controllers`. The ordinary workflow lacks these external
records and archives `HOLD_MISSING_CROSS_EPOCH_CUSTODY`.
GitHub Actions includes eleven adversarial/structural tests before
Pages deployment.

**Custody boundary:** Neither separately supplied controller
descriptions nor digest-valid JSON receipts establish independent
custodian control, globally latest highwater or original external
signature provenance. The verifier leaves
`external_custodian_identity_verified`, `fork_resolved`,
`global_anti_rollback_certified`, and `release_authorized` false
even after complete prefix agreement.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-039 neon persistence observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust039-revocation-persistence.html) ·
[RUST-038 revocation ancestry](https://davidwise01.github.io/neuroscape/rust/tests/rust038-revocation-ancestry.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-040 — Custodian identity ancestry and replacement-key substitution

`rust/tests/custodian_ancestry_rust040.py` consumes a complete
digest-checked RUST-039 receipt and source-root declarations for
every claimed signing-key lineage in that receipt. Every claim
binds its `ff/cf/rr` role, signing-key SPKI fingerprint, source-root
SHA-256, acquisition-path SHA-256, custody-controller SHA-256,
operator-registry SHA-256 and one or more explicitly retained aliases.
A role/key with a missing ancestry claim causes a hard failure.

Pairwise graph comparisons retain shared source roots, acquisition
paths, controller fingerprints, registry fingerprints and overlapping
aliases, including aliases that connect two supposedly separate
source roots. Revoked-key descendants are flagged when a new key
has matching controller ancestry, path, source root or alias. Existing
RUST-039 custody suspicions and upstream equivocation are preserved
without treating a majority of witness labels as proof of independence.

**Critical boundary:** This is a comparison of *declared* identity and
custody fingerprints, not independently authenticated operator
ownership or direct acquisition evidence. A provider can forge
different identifiers for one controlled origin; a clean comparison
cannot establish independence. Consequently the observation always
remains `HOLD_POTENTIAL_COMMON_CONTROL` or
`HOLD_IDENTITY_ANCESTRY_UNPROVEN`, with
`independent_custodian_roots_verified`, `fork_resolved` and
`release_authorized` all false.

The Actions workflow runs eleven structural/adversarial regression
tests before the Pages deployment step and archives the no-external-
material report `HOLD_MISSING_CUSTODIAN_ANCESTRY` in its run artifact.
The Rust WASM engine, 256-card catalog, five-by-two arena and neon
gameplay are unchanged.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-040 neon custodian ancestry](https://davidwise01.github.io/neuroscape/rust/tests/rust040-custodian-ancestry.html) ·
[RUST-039 revoked-key persistence](https://davidwise01.github.io/neuroscape/rust/tests/rust039-revocation-persistence.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-041 — Custodian challenge and attestor ancestry

`rust/tests/custody_challenge_rust041.py` checks the exact SHA-256
receipt from RUST-040, then binds three ordered `ff/cf/rr` claimed
custodian roots to externally supplied challenge nonces, archive
fingerprints, retrieval-session identifiers, acquisition paths and
controller/operator-registry fingerprints. The same canonical
domain-separated challenge is authenticated by the inherited
custodian signing key **and** a separately pinned Ed25519
attestor key (`RUST041_ATTESTOR_PIN_FF/CF/RR`).
Nonce fingerprints are supplied via `RUST041_NONCE_FF/CF/RR`.

The verifier rejects reused attestor keys, custodian self-attestation,
role swaps, changed ancestral fingerprints, reused nonces within the
batch, and replay against the **supplied** previous nonce list.
It compares claimed attestor roots, acquisition paths, source roots,
controller and operator-registry hashes and retrieval sessions
pairwise. Shared claims are retained in
`HOLD_SHARED_ATTESTATION_ANCESTRY`, never majority-voted away.
Inherited RUST-040 conflicts and proposed replacement lineages remain
visible. The extended nonce history is represented by an output
digest; it is not silently stored as an authoritative external ledger.

**Authority limitation:** Two signed responses prove only possession
of the corresponding private keys. They cannot prove that signers
have distinct real-world controlling entities, that a challenge nonce
was freshly issued outside the same operator, or that an external
archive retrieval is genuine. Even a clean three-key observation
retains `HOLD_INDEPENDENT_CONTROL_UNVERIFIED`.
`real_world_operator_control_verified`,
`independent_source_ancestry_verified`, `fork_resolved` and
`release_authorized` are always false.

GitHub Actions runs eleven adversarial/structural tests before Pages
publication and archives
`HOLD_MISSING_EXTERNAL_CONTROL_CHALLENGES` when trusted external
inputs are absent. The 5×2 arena, 256-card catalog and Rust WASM
gameplay have not been modified.

[Arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-041 neon challenge observatory](https://davidwise01.github.io/neuroscape/rust/tests/rust041-custody-challenge.html) ·
[RUST-040 source ancestry](https://davidwise01.github.io/neuroscape/rust/tests/rust040-custodian-ancestry.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-042 — Externally retained challenge ledger and attestor continuity

`rust/tests/challenge_ledger_rust042.py` adds an append-only record of
RUST-041 dual-signed challenge observations. Each `ff/cf/rr` entry
binds its epoch, ordinal, preceding event digest, upstream receipt,
full observation fingerprint, challenge nonce, retrieval session, two
signature fingerprints, attestor key fingerprint and claimed attestor
root. A domain-separated genesis head establishes the local initial
condition. All prior entries and their exact prefix heads are carried
into the next epoch without rewriting.

A digest-checked previous ledger is validated entry by entry:
complete three-role epochs, continuous ordinals, matching predecessor
hashes, exact prefix heads, and unique nonces and retrieval sessions.
A newly supplied RUST-041 receipt must match its own three ordered
nonce references; replay of any retained nonce or retrieval session
is rejected. Changes to a witness's last attestor key or claimed root
remain visible as `HOLD_ATTESTOR_IDENTITY_SUBSTITUTION` and are
preserved through later epochs. The optional `--floor` reference
checks the exact externally declared head at its retained entry
count, exposing withheld or substituted historical entries relative
to that reference.

**Authority limit:** Neither the local challenge ledger nor a
caller-supplied floor proves an external observer retained the
correct or globally latest history. An unverified attestor key
rotation is evidence to preserve, not authority to infer
continuity. No result grants `external_custody_verified`,
`global_anti_rollback_certified`, `fork_resolved` or
`release_authorized`.

GitHub Actions runs eleven structural and negative unit tests before
Pages publication and archives
`HOLD_MISSING_RETAINED_CHALLENGE_LEDGER` if external evidence
is absent. This module does not change the Rust WASM engine,
existing five-by-two arena, 256-card catalog or game mechanics.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-042 neon challenge ledger](https://davidwise01.github.io/neuroscape/rust/tests/rust042-challenge-ledger.html) ·
[RUST-041 custody challenges](https://davidwise01.github.io/neuroscape/rust/tests/rust041-custody-challenge.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-043 — Signed challenge highwater and attestor rotation authorization

`rust/tests/attestor_rotation_rust043.py` compares two adjacent
digest-checked RUST-042 challenge epochs. Every prior entry and prefix
head must be an exact prefix of the newer epoch. The previous,
nonempty ledger is committed to a domain-separated
`SIGNED_CHALLENGE_HIGHWATER` message that includes its epoch, entry
count, complete ordered history digest, last chain head, and RUST-042
receipt SHA-256. An Ed25519 witness signature is verified against
`RUST043_HIGHWATER_WITNESS_SPKI_SHA256`, a separately supplied SPKI
fingerprint.

The supplied retained floor must match the exact historical prefix
head and cover the entire prior epoch. Any change in a witness's
attestor fingerprint or declared source root requires a rotation
record for that role. The rotation message binds both adjacent
challenge receipt hashes, both attestor pins and claimed roots, and
the exact predecessor and successor challenge-entry hashes.
The old and new attestor keys must sign identical canonical bytes.
A source-root change with an unchanged signing pin is not accepted as
a valid rotation.

RUST-043 preserves RUST-042's unresolved substitutions; it does not
discard them because valid signatures or a new epoch have appeared.
The inherited RUST-042 source was also repaired so an earlier
attestor substitution stays marked on later epochs and its JSON
output newline is serialized correctly.

**Evidence limit:** The source of the retained floor and witness
SPKI pin is not independently authenticated by this module.
Correct signatures demonstrate signing-key possession, not
independent organizational custody, globally latest highwater or
real-world control. Every outcome remains
`HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED` or
`HOLD_EXTERNAL_HIGHWATER_UNVERIFIED`, with release, gameplay
authority and fork resolution false. No live attestor rotation is
asserted.

GitHub Actions includes eleven negative/structural tests before
Pages publication, then archives the explicit default
`HOLD_MISSING_SIGNED_CHALLENGE_HIGHWATER` receipt in its run-scoped
artifact when no external evidence is provided. The Rust WASM combat
engine, original 5×2 arena, 256 cards and gameplay are unchanged.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-043 neon rotation highwater](https://davidwise01.github.io/neuroscape/rust/tests/rust043-attestor-rotation.html) ·
[RUST-042 challenge ledger](https://davidwise01.github.io/neuroscape/rust/tests/rust042-challenge-ledger.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

`.dlw`

## RUST-044 — Compromised attestor revocation and historical trust fencing

\`rust/tests/attestor_revocation_rust044.py\` builds on intact,
digest-checked RUST-042 challenge history and an RUST-043 signed
highwater/attestor transition receipt. A separately supplied
revocation authority key pin verifies each canonical RUST-044
revocation payload with Ed25519. The revocation binds a witness role,
old attestor key SPKI fingerprint, claimed controlling source root,
effective epoch, and evidence digest.

Every revocation becomes an append-only SHA-256-linked entry with an
explicit domain-separated genesis. The verifier checks the precise
historical chain prefix against an optionally supplied retained floor
and rejects duplicate revocations or attempts to let a compromised
key self-issue its own revocation.

**Historical fence:** The complete RUST-042 challenge ledger is
examined, not just the newest epoch. Any challenge signed by a
revoked attestor key at or after its revocation's effective epoch is
a hard error. If a distinct successor key at a later epoch claims the
same controlling attestor root, the observation is preserved under
\`HOLD_POTENTIAL_COMPROMISED_CONTROL\`. Matching claimed root hashes
do not independently prove shared organizational control.

**Authority boundary:** A separately supplied revocation key pin
and retention-floor JSON do not establish the real custodian's
identity, independent control, or that every real-world revocation
was made available. A valid signature is necessary cryptographic
evidence, not clearance for independent custody or release. The
fields \`independent_revocation_custody_verified\`,
\`real_world_control_verified\`, \`fork_resolved\` and
\`release_authorized\` remain false.

GitHub Actions runs twelve adversarial/structural tests before Pages
publication and archives a default
\`HOLD_MISSING_ATTESTOR_REVOCATION_CUSTODY\` record when no external
materials are supplied. The existing Rust WASM combat engine,
5×2 arena, 256-card catalog and neon gameplay are unchanged.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-044 neon attestor revocation](https://davidwise01.github.io/neuroscape/rust/tests/rust044-attestor-revocation.html) ·
[RUST-043 signed rotation](https://davidwise01.github.io/neuroscape/rust/tests/rust043-attestor-rotation.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

\`.dlw\`

## RUST-045 — Quarantined compromised-custodian recovery

\`rust/tests/custodian_recovery_rust045.py\` adds a recovery-candidate
mechanism without restoring trust. It consumes an intact, SHA-256
receipt-checked RUST-042 challenge ledger and an exactly matched
RUST-044 revocation receipt. Every revocation-chain entry and
predecessor hash is independently recalculated. Recovery cannot
proceed if a separately supplied retained floor does not cover
**all** known revocations at exactly the current head hash.

A recovery proposal binds its compromised key fingerprint, role,
effective revocation epoch, revocation-entry hash, replacement
attestor fingerprint, successor challenge entry and epoch, declared
old/new controller roots, externally declared recovery authority
root, acquisition fingerprint, challenge nonce and both upstream
receipts. The identical domain-separated recovery message must be
signed by a separately pinned recovery authority **and** the new
successor attestor key. The module denies attempts to recover using
a revoked key, a successor key that is itself revoked, a self-issued
recovery authority, a reused old control root, or a nonce already in
the signed challenge ledger. The new key must have real challenge
evidence within the supplied history at or after the effective epoch.

This proves **structural and cryptographic consistency only**.
Claimed distinct root hashes are not independently authenticated
control identities. No local JSON or GitHub Actions artifact proves
an off-repository witness controls an actual entity. Even after two
valid signatures, the status stays
\`HOLD_QUARANTINED_RECOVERY_CANDIDATES\`; the compromised key remains
revoked, all historical challenges and RUST-044 suspicions are
retained, and \`release_authorized\`, \`fork_resolved\`,
\`real_world_independent_recovery_verified\` and
\`live_gameplay_authority\` remain false.

Thirteen adversarial/structural tests run as a predeployment GitHub
Actions step. Without external recovery material the workflow
archives \`HOLD_MISSING_INDEPENDENT_RECOVERY\` in the run-scoped
artifact. The Rust WASM combat core, existing 5×2 arena, 256-card
catalog and neon gameplay are not modified.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-045 neon custody recovery](https://davidwise01.github.io/neuroscape/rust/tests/rust045-custodian-recovery.html) ·
[RUST-044 attestor revocation](https://davidwise01.github.io/neuroscape/rust/tests/rust044-attestor-revocation.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

\`.dlw\`

## RUST-046 — Recovery quarantine persistence and graduation review

\`rust/tests/recovery_quarantine_rust046.py\` keeps each RUST-045
quarantined recovery candidate under HOLD across later RUST-042
challenge epochs and RUST-044 revocation ancestry. It checks an
unaltered original RUST-045 receipt, authenticates the predecessor
and current receipts for structural integrity, requires the original
challenge ledger to be a byte-for-byte logical prefix of the
successor, and ensures old revocations and chain heads remain an
exact prefix of the new revocation history. The separately supplied
RUST-044 floor must cover **all** known revocations in the current
epoch, not just the predecessor highwater.

Each candidate's old key must remain revoked. The replacement
key must be unrevoked, be the latest signing key in that witness
role's successor challenge history, and not claim a revoked
custodian-control root. For each candidate, three ordered
\`ff/cf/rr\` review witnesses sign the same domain-separated
recovery-review fact with separate externally supplied SPKI key
pins and fresh nonce fingerprints. The review binds the
original RUST-045 recovery-proposal digest, current RUST-044
receipt, latest successor challenge, observer root and acquisition
fingerprints. Claimed root or acquisition collisions, identical
witness keys, nonce replay and self-issued or revoked witness keys
are rejected.

**Graduation is not claimed.** Three structurally distinct signed
review assertions are insufficient to establish independent
real-world source ancestry. The verifier records a
\`HOLD_GRADUATION_NOT_AUTHORIZED\` assessment with
\`graduation_approved: false\` for every candidate. Old
revocations, evidence of root-equivalent replacement, and
unresolved historical conflicts remain visible. No function
promotes \`release_authorized\`, \`fork_resolved\`,
\`independent_operator_custody_verified\`, or
\`live_gameplay_authority\`.

Thirteen structural and adversarial unit tests are committed to
the GitHub Actions predeployment gate. Without complete external
evidence, the workflow archives a default
\`HOLD_MISSING_GRADUATION_CUSTODY\` record. The 5×2 card arena,
256-card catalog, neon gameplay and existing Rust WASM combat
engine have not been changed.

[Neuroscape arcade](https://davidwise01.github.io/neuroscape/) ·
[RUST-046 neon quarantine graduation review](https://davidwise01.github.io/neuroscape/rust/tests/rust046-recovery-quarantine.html) ·
[RUST-045 custodian recovery](https://davidwise01.github.io/neuroscape/rust/tests/rust045-custodian-recovery.html) ·
[GitHub Actions](https://github.com/DavidWise01/neuroscape/actions/workflows/pages.yml)

\`.dlw\`
