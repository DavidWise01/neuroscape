#!/usr/bin/env python3
"""RUST-106: signed RUST-105 operator-continuity highwater and fork retention.

A signed highwater binds the entire observed ledger prefix and its conflict
history. Local signature checks never prove independent external custody,
authenticated global freshness, or release/recovery authority.
"""
import argparse
import json
from pathlib import Path

from operator_continuity_rust105 import validate, digest, need
from rotation_rust022 import canonical, verify_key_and_signature

DOMAIN = "NEUROSCAPE_RUST106_OPERATOR_HIGHWATER_V1"
HOLD = "HOLD_OPERATOR_HIGHWATER_EXTERNAL_CUSTODY_UNVERIFIED"

def sha(value):
    need(isinstance(value, str) and len(value) == 64
         and all(ch in "0123456789abcdef" for ch in value),
         "lowercase SHA-256 required")
    return value

def conflicts_snapshot(history):
    validate(history)
    return [{"index": e["index"],
             "upstream_conflicts": e["observation"]["upstream_conflicts"],
             "cross_epoch_conflicts": e["cross_epoch_conflicts"]}
            for e in history]

def checkpoint(history, pin, nonce):
    head = validate(history)
    need(len(history) > 0, "nonempty RUST-105 ledger required")
    pin, nonce = sha(pin), sha(nonce)
    return {
        "domain": DOMAIN, "phase": "RUST-106",
        "epoch_count": len(history),
        "head_sha256": head,
        "history_sha256": digest(history),
        "retained_conflicts_sha256": digest(conflicts_snapshot(history)),
        "signer_pin": pin, "nonce_sha256": nonce,
        "globally_authenticated_latest": False,
        "independent_external_custody_verified": False,
        "release_authorized": False, "recovery_authorized": False,
        "fork_selected": False,
    }

def verify_signed(history, signed, verifier=verify_key_and_signature):
    need(isinstance(signed, dict), "signed highwater record required")
    pin = sha(signed.get("signer_pin"))
    nonce = sha(signed.get("nonce_sha256"))
    expected = checkpoint(history, pin, nonce)
    need(signed.get("payload") == expected,
         "signed operator highwater payload changed")
    receipt = verifier(signed.get("public_key"),
                       signed.get("signature"), pin, canonical(expected))
    return expected, sha(receipt)

def assess(previous, current, previous_signed, current_signed,
           verifier=verify_key_and_signature):
    old_head, new_head = validate(previous), validate(current)
    need(previous and len(current) > len(previous)
         and current[:len(previous)] == previous,
         "stale highwater, rollback or edited prefix")
    prior, prior_receipt = verify_signed(previous, previous_signed, verifier)
    later, later_receipt = verify_signed(current, current_signed, verifier)
    need(prior["head_sha256"] == old_head
         and later["head_sha256"] == new_head, "signed head mismatch")
    need(prior["epoch_count"] < later["epoch_count"],
         "highwater epoch count must grow")
    need(prior["nonce_sha256"] != later["nonce_sha256"],
         "replayed highwater nonce")
    need(prior["signer_pin"] != later["signer_pin"],
         "same signing pin cannot masquerade as rotated custodian")
    need(current[len(previous)]["previous_sha256"] == old_head,
         "successor not linked to frozen predecessor")
    return {
        "phase": "RUST-106", "domain": DOMAIN, "status": HOLD,
        "previous_head_sha256": old_head, "current_head_sha256": new_head,
        "previous_signed_checkpoint_sha256": digest(prior),
        "current_signed_checkpoint_sha256": digest(later),
        "previous_signature_receipt_sha256": prior_receipt,
        "current_signature_receipt_sha256": later_receipt,
        "current_conflicts_sha256": later["retained_conflicts_sha256"],
        "historic_conflicts_retained": True,
        "locally_verified_signature_rotation": True,
        "independent_operator_rotation_authenticated": False,
        "globally_authenticated_latest": False,
        "independent_external_custody_verified": False,
        "fork_selected": False, "recovery_authorized": False,
        "release_authorized": False, "live_gameplay_authorized": False,
    }

def competing(history, left_signed, right_signed,
              verifier=verify_key_and_signature):
    """Preserve conflicting signed claims for one epoch without adjudication."""
    left, left_receipt = verify_signed(history, left_signed, verifier)
    right, right_receipt = verify_signed(history, right_signed, verifier)
    need(left["signer_pin"] != right["signer_pin"]
         and left["nonce_sha256"] != right["nonce_sha256"],
         "replayed fork-witness identity")
    return {
        "phase": "RUST-106", "status": HOLD,
        "both_claims_preserved": [
            {"checkpoint_sha256": digest(left),
             "signature_receipt_sha256": left_receipt},
            {"checkpoint_sha256": digest(right),
             "signature_receipt_sha256": right_receipt}],
        "same_frozen_head_sha256": left["head_sha256"],
        "independent_external_custody_verified": False,
        "fork_selected": False, "recovery_authorized": False,
        "release_authorized": False,
    }

def missing():
    return {"phase": "RUST-106",
            "status": "HOLD_MISSING_SIGNED_OPERATOR_HIGHWATER",
            "independent_external_custody_verified": False,
            "globally_authenticated_latest": False,
            "fork_selected": False, "recovery_authorized": False,
            "release_authorized": False, "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("previous", "current", "previous-signed", "current-signed"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    bundle = (args.previous, args.current, args.previous_signed,
              args.current_signed)
    need(all(bundle) or not any(bundle), "partial signed highwater bundle")
    if all(bundle):
        read = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))
        record = assess(read(args.previous), read(args.current),
                        read(args.previous_signed), read(args.current_signed))
    else:
        record = missing()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(json.dumps(record, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-106 HOLD: independent highwater custody not established")

if __name__ == "__main__":
    main()
