#!/usr/bin/env python3
"""RUST-093 — bounded witness-byte replay against frozen RUST-092 reconciliation.

Validates submitted byte evidence and rejects apparent independent witnesses
sharing acquisition ancestry. It cannot authenticate external physical custody.
Never grants recovery, release or gameplay authority.
"""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path

from cross_run_acquisition_ledger_rust091 import digest, require
from contradiction_witness_rust092 import HOLD as PRIOR_HOLD

DOMAIN = "NEUROSCAPE_RUST093_WITNESS_BYTE_REPLAY_V1"
HOLD = "HOLD_EXTERNAL_WITNESS_CUSTODY_UNVERIFIED"
CAP = 1024 * 1024
FIELDS = ("controller", "root", "source", "acquisition")

def checked_sha(s):
    require(isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s), "invalid SHA-256")
    return s

def check(reconciliation, witnesses):
    require(isinstance(reconciliation, dict)
            and reconciliation.get("phase") == "RUST-092"
            and reconciliation.get("status") == PRIOR_HOLD,
            "frozen RUST-092 HOLD reconciliation required")
    require(reconciliation.get("independent_external_custody_verified") is False
            and reconciliation.get("release_authorized") is False,
            "upstream authority promotion")
    ledger_head = checked_sha(reconciliation.get("ledger_head_sha256"))
    conflicts = checked_sha(reconciliation.get("retained_contradictions_sha256"))
    receipts = reconciliation.get("witness_receipts")
    require(isinstance(receipts, list) and len(receipts) == 2,
            "two frozen RUST-092 receipts required")
    require(isinstance(witnesses, list) and len(witnesses) == 2,
            "two exact byte witness bundles required")
    seen_pins, seen_nonces, seen_ancestry, seen_bytes = set(), set(), set(), set()
    rows = []
    for index, (receipt, item) in enumerate(zip(receipts, witnesses)):
        require(isinstance(receipt, dict) and isinstance(item, dict),
                "invalid witness entry")
        pin = checked_sha(item.get("signer_pin"))
        nonce = checked_sha(item.get("nonce_sha256"))
        require(pin == receipt.get("signer_pin"),
                "witness order or signer substitution")
        require(pin not in seen_pins and nonce not in seen_nonces,
                "replayed witness identity or nonce")
        seen_pins.add(pin)
        seen_nonces.add(nonce)
        require(item.get("domain") == DOMAIN
                and item.get("ledger_head_sha256") == ledger_head
                and item.get("contradictions_sha256") == conflicts,
                "source ledger or reconciliation substituted")
        require(item.get("signed_payload_sha256")
                == checked_sha(receipt.get("signed_payload_sha256")),
                "signed payload ancestry changed")
        ancestry = item.get("control_ancestry")
        require(isinstance(ancestry, dict) and set(ancestry) == set(FIELDS),
                "complete controller/root/source/acquisition ancestry required")
        for field in FIELDS:
            value = checked_sha(ancestry[field])
            require(value not in seen_ancestry,
                    "independent source claim shares ancestry")
            seen_ancestry.add(value)
        declared = checked_sha(item.get("evidence_sha256"))
        encoded = item.get("evidence_base64")
        require(isinstance(encoded, str) and 0 < len(encoded) <= 1400000,
                "missing or oversized evidence encoding")
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("malformed evidence bytes") from None
        require(0 < len(blob) <= CAP, "empty or oversized evidence")
        actual = hashlib.sha256(blob).hexdigest()
        require(actual == declared, "evidence byte digest mismatch")
        require(actual not in seen_bytes, "two mirrors of identical bytes")
        seen_bytes.add(actual)
        require(item.get("independent_external_custody_verified") is False
                and item.get("release_authorized") is False,
                "false external custody or release")
        rows.append({"index": index, "signer_pin": pin,
                     "nonce_sha256": nonce, "evidence_sha256": actual,
                     "evidence_length": len(blob),
                     "ancestry_sha256": digest(ancestry)})
    return {"phase": "RUST-093", "status": HOLD,
            "reconciliation_sha256": digest(reconciliation),
            "ledger_head_sha256": ledger_head,
            "retained_contradictions_sha256": conflicts,
            "witness_byte_receipts": rows,
            "submitted_byte_digests_verified": True,
            "independently_authenticated_acquisition": False,
            "independent_external_custody_verified": False,
            "historical_contradictions_cleared": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-093",
            "status": "HOLD_MISSING_EXTERNAL_WITNESS_BYTES",
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reconciliation")
    p.add_argument("--witnesses")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    require(bool(args.reconciliation) == bool(args.witnesses),
            "partial independent witness byte bundle")
    if args.reconciliation:
        reconciliation = json.loads(Path(args.reconciliation).read_text(encoding="utf-8"))
        witnesses = json.loads(Path(args.witnesses).read_text(encoding="utf-8"))
        result = check(reconciliation, witnesses)
    else:
        result = missing()
    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-093 HOLD: external custody unverified")

if __name__ == "__main__":
    main()
