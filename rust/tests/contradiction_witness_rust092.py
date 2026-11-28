#!/usr/bin/env python3
"""RUST-092: structural contradiction-witness reconciliation; authority HOLD.

Validates exactly two externally *claimed* observations, checks supplied
cryptographic signatures, fences shared ancestry, and binds an immutable
RUST-091 ledger snapshot. It cannot authenticate physical custody.
"""
import argparse
import json
from pathlib import Path
from cross_run_acquisition_ledger_rust091 import verify_ledger, digest, require
from rotation_rust022 import canonical, verify_key_and_signature

DOMAIN = "NEUROSCAPE_RUST092_CONTRADICTION_WITNESS_V1"
HOLD = "HOLD_INDEPENDENT_CONTRADICTION_CUSTODY_UNVERIFIED"
ANCESTRY = ("controller", "root", "source", "acquisition")

def checked_sha(value):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value),
            "missing SHA-256 fingerprint")

def payload(head, contradictions_digest, signer_pin, nonce, ancestry):
    checked_sha(head)
    checked_sha(contradictions_digest)
    checked_sha(signer_pin)
    checked_sha(nonce)
    return {"domain": DOMAIN, "phase": "RUST-092", "ledger_head_sha256": head,
            "contradictions_sha256": contradictions_digest,
            "signer_pin": signer_pin, "nonce_sha256": nonce,
            "control_ancestry": ancestry,
            "independent_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False}

def reconcile(ledger, witnesses, verifier=verify_key_and_signature):
    head = verify_ledger(ledger)
    require(len(ledger) > 0, "RUST-091 ledger required")
    contradictions = [{"index": e["index"], "reasons": e["contradictions"]}
                      for e in ledger if e["contradictions"]]
    require(contradictions, "no historical contradiction to reconcile")
    sealed_digest = digest(contradictions)
    require(isinstance(witnesses, list) and len(witnesses) == 2,
            "exactly two signed witness observations required")
    pins, nonces, ancestry_values = set(), set(), set()
    receipts = []
    for witness in witnesses:
        require(isinstance(witness, dict), "witness object required")
        pin, nonce = witness.get("signer_pin"), witness.get("nonce_sha256")
        checked_sha(pin)
        checked_sha(nonce)
        require(pin not in pins and nonce not in nonces,
                "signer or nonce replay")
        pins.add(pin)
        nonces.add(nonce)
        ancestry = witness.get("control_ancestry")
        require(isinstance(ancestry, dict)
                and set(ancestry) == set(ANCESTRY), "complete ancestry required")
        for k in ANCESTRY:
            checked_sha(ancestry[k])
            require(ancestry[k] not in ancestry_values,
                    "shared controller/root/source/acquisition ancestry")
            ancestry_values.add(ancestry[k])
        expected = payload(head, sealed_digest, pin, nonce, ancestry)
        require(witness.get("payload") == expected,
                "signed witness payload substituted or authority promoted")
        signature_receipt = verifier(witness.get("public_key"),
                                     witness.get("signature"), pin,
                                     canonical(expected))
        checked_sha(signature_receipt)
        receipts.append({"signer_pin": pin, "signed_payload_sha256": digest(expected),
                         "signature_receipt_sha256": signature_receipt})
    return {"phase": "RUST-092", "status": HOLD,
            "ledger_head_sha256": head,
            "retained_contradictions_sha256": sealed_digest,
            "retained_contradictions": contradictions,
            "witness_receipts": receipts,
            "supplied_signature_checks_passed": True,
            "independent_external_custody_verified": False,
            "historical_contradictions_cleared": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def hold():
    return {"phase": "RUST-092",
            "status": "HOLD_MISSING_INDEPENDENT_CONTRADICTION_WITNESSES",
            "independent_external_custody_verified": False,
            "historical_contradictions_cleared": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ledger")
    p.add_argument("--witnesses")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    require(bool(a.ledger) == bool(a.witnesses), "partial witness bundle refused")
    if a.ledger:
        read = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))
        result = reconcile(read(a.ledger), read(a.witnesses))
    else:
        result = hold()
    target = Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-092 HOLD: independent custody unverified")

if __name__ == "__main__":
    main()
