#!/usr/bin/env python3
"""RUST-026: preserve three signed highwater observations and all forks.

A distinct Ed25519 key is not proof of distinct organizational custody.
The tool never uses majority voting to erase a conflicting history, and
never promotes any checkpoint to globally latest or release-authorized.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from highwater_rust025 import check_checkpoint, verify_witness, check64

ROLES = ("ff", "cf", "rr")

def verify_observations(items):
    """items: three dictionaries with role, checkpoint, key, signature, pin.
    Signature verification occurs before any observation is accepted.
    """
    require(isinstance(items, list) and len(items) == 3, "exactly three observations required")
    preserved = []
    pins = set()
    for role, item in zip(ROLES, items):
        require(isinstance(item, dict) and item.get("role") == role, "witness role mismatch")
        pin = item.get("external_pin")
        require(check64(pin) and pin not in pins, "missing or repeated externally pinned key")
        pins.add(pin)
        cp = check_checkpoint(item.get("checkpoint"))
        signature_sha = verify_witness(cp, item.get("key"), item.get("signature"), pin)
        preserved.append({
            "role": role,
            "key_spki_sha256": pin,
            "signature_sha256": signature_sha,
            "candidate_sha256": cp["candidate_sha256"],
            "source_commit": cp["source_commit"],
            "epoch": cp["epoch"],
            "sequence": cp["sequence"],
            "previous_highwater_sha256": cp["previous_highwater_sha256"],
            "entry_sha256": cp["entry_sha256"],
            "signature_verified": True,
        })
    return preserved

def adjudicate(preserved):
    require(isinstance(preserved, list) and len(preserved) == 3, "three verified witnesses required")
    require([x.get("role") for x in preserved] == list(ROLES), "witness positions disagree")
    require(all(x.get("signature_verified") is True for x in preserved), "unverified witness")
    require(len(set(x["key_spki_sha256"] for x in preserved)) == 3, "shared key ancestry")
    # Every distinct fingerprint and exact predecessor is retained in the
    # receipt. A 2:1 split is a fork, NOT an agreement.
    candidates = {x["candidate_sha256"] for x in preserved}
    ancestry = {(x["previous_highwater_sha256"], x["epoch"], x["sequence"]) for x in preserved}
    status = "CONSISTENT_SIGNED_SNAPSHOTS" if len(candidates) == 1 and len(ancestry) == 1 else "HOLD_FORK_EVIDENCE"
    record = {
        "phase": "RUST-026",
        "status": status,
        "observations": preserved,
        "distinct_signature_keys": 3,
        "independent_custody_ancestries_verified": False,
        "external_latest_checkpoint_confirmed": False,
        "global_anti_rollback_certified": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
        "fork_detected": status == "HOLD_FORK_EVIDENCE",
        "observed_candidate_sha256": sorted(candidates),
    }
    record["receipt_sha256"] = digest(record)
    return record

def hold(reason):
    return {
        "phase": "RUST-026",
        "status": "HOLD_MISSING_THREE_WITNESSES",
        "reason": reason,
        "release_authorized": False,
        "independent_custody_ancestries_verified": False,
        "global_anti_rollback_certified": False,
        "live_gameplay_authority": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness-bundle", help="three ordered witnessed snapshots and signature paths")
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-hold-record", action="store_true")
    args = parser.parse_args()
    if not args.witness_bundle:
        result = hold("No three externally pinned and signed witness snapshots supplied")
    else:
        bundle = json.loads(Path(args.witness_bundle).read_text(encoding="utf-8"))
        require(isinstance(bundle, list), "bundle must be an array")
        # Pins must be supplied separately by the operator, not solely
        # alongside repository-controlled witness claims.
        pins = [os.getenv("RUST026_PIN_" + role.upper()) for role in ROLES]
        require(all(check64(pin) for pin in pins), "external SPKI pin environment incomplete")
        require(len(set(pins)) == 3, "witness key pins reused")
        require(len(bundle) == 3, "exactly three witnesses")
        verified = verify_observations([
            {**x, "external_pin": pin} for x, pin in zip(bundle, pins)
        ])
        result = adjudicate(verified)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record and result["status"] != "CONSISTENT_SIGNED_SNAPSHOTS":
        raise SystemExit("RUST-026 HOLD: missing or forked highwater observations")

if __name__ == "__main__":
    main()
