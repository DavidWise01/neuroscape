#!/usr/bin/env python3
"""RUST-099: preserve both forks and fence custody adjudication.

Source: RUST-098 append-only HOLD ledger. All decisions remain HOLD; locally
asserted ancestry and witness bytes never establish independent custody.
"""
import argparse
import json
from pathlib import Path
from cross_run_acquisition_ledger_rust091 import digest, require
from highwater_custody_continuity_rust098 import validate, FIELDS

DOMAIN = "NEUROSCAPE_RUST099_FORK_PRESERVATION_V1"
HOLD = "HOLD_FORK_ADJUDICATION_EXTERNAL_CUSTODY_UNVERIFIED"
ZERO = "0" * 64

def sha(v):
    require(isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdef" for c in v),
            "SHA-256 fingerprint required")
    return v

def fork_pairs(history):
    """Return every conflicting-head pair under a shared signed receipt."""
    validate(history)
    pairs = []
    for i, left in enumerate(history):
        a = left["observation"]
        for j in range(i + 1, len(history)):
            b = history[j]["observation"]
            if (a["rust096_receipt_sha256"] == b["rust096_receipt_sha256"]
                    and a["highwater_head_sha256"] != b["highwater_head_sha256"]):
                pairs.append({
                    "left_index": i, "right_index": j,
                    "rust096_receipt_sha256": a["rust096_receipt_sha256"],
                    "left_head_sha256": a["highwater_head_sha256"],
                    "right_head_sha256": b["highwater_head_sha256"],
                    "left_entry_sha256": left["entry_sha256"],
                    "right_entry_sha256": history[j]["entry_sha256"]})
    return pairs

def ancestry_conflicts(witnesses):
    seen_pins, seen_nonces, seen_lineage = set(), set(), set()
    reasons = []
    for witness in witnesses:
        require(isinstance(witness, dict), "witness record required")
        pin = sha(witness.get("signer_pin"))
        nonce = sha(witness.get("nonce_sha256"))
        if pin in seen_pins:
            reasons.append("SHARED_SIGNER")
        if nonce in seen_nonces:
            reasons.append("REPLAYED_NONCE")
        seen_pins.add(pin)
        seen_nonces.add(nonce)
        lineage = witness.get("control_ancestry")
        require(isinstance(lineage, dict) and set(lineage) == set(FIELDS),
                "complete control ancestry required")
        for field in FIELDS:
            value = sha(lineage[field])
            if value in seen_lineage:
                reasons.append("SHARED_" + field.upper() + "_ANCESTRY")
            seen_lineage.add(value)
    return sorted(set(reasons))

def adjudicate(history, claims):
    head = validate(history)
    pairs = fork_pairs(history)
    require(pairs, "no detected RUST-098 fork for adjudication")
    require(isinstance(claims, list) and len(claims) == 2,
            "exactly two claimed external custody witnesses required")
    indexes = set()
    all_witnesses = []
    for claim in claims:
        require(isinstance(claim, dict), "custody claim required")
        idx = claim.get("branch_index")
        require(type(idx) is int and 0 <= idx < len(history),
                "claim branch index outside preserved history")
        indexes.add(idx)
        evidence = sha(claim.get("highwater_head_sha256"))
        require(history[idx]["observation"]["highwater_head_sha256"] == evidence,
                "claimed branch head differs from historical record")
        require(claim.get("independent_external_custody_verified") is False
                and claim.get("release_authorized") is False
                and claim.get("fork_selected") is False,
                "claim falsely promotes authority")
        witness = claim.get("witness")
        require(isinstance(witness, dict), "claim witness missing")
        all_witnesses.append(witness)
    require(any({p["left_index"], p["right_index"]} == indexes for p in pairs),
            "both fork branches must be represented")
    conflicts = ancestry_conflicts(all_witnesses)
    return {"phase": "RUST-099", "domain": DOMAIN, "status": HOLD,
            "source_rust098_head_sha256": head,
            "preserved_fork_pairs": pairs,
            "preserved_fork_pairs_sha256": digest(pairs),
            "claims_sha256": digest(claims),
            "ancestry_conflicts": conflicts,
            "both_branches_retained": True,
            "external_witness_acquisition_authenticated": False,
            "independent_external_custody_verified": False,
            "fork_selected": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-099",
            "status": "HOLD_MISSING_INDEPENDENT_FORK_ADJUDICATION",
            "both_branches_retained": False,
            "independent_external_custody_verified": False,
            "fork_selected": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ledger")
    p.add_argument("--claims")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    require(bool(args.ledger) == bool(args.claims), "partial custody bundle")
    if args.ledger:
        read = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))
        result = adjudicate(read(args.ledger), read(args.claims))
    else:
        result = missing()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-099 HOLD: independent fork custody unverified")
if __name__ == "__main__":
    main()
