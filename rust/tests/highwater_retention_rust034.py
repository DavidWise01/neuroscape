#!/usr/bin/env python3
"""RUST-034: retain signed highwater histories and expose epoch equivocation.

Verifies every supplied RUST-033 checkpoint signature against separately
pinned FF/CF/RR keys. Conflicting ledger fingerprints at one epoch are
preserved, never voted away. Reported independent custody and latest-state
authority are ALWAYS false; absent externally held history means HOLD.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from session_highwater_rust033 import check_signed_checkpoint

def audit(histories, pins, verifier=verify_key_and_signature):
    require(isinstance(histories, list) and len(histories) == 3,
            "exactly three retained witness histories required")
    require(isinstance(pins, list) and len(pins) == 3,
            "three externally pinned witness keys required")
    for pin in pins:
        check_sha(pin, "invalid external custodian key pin")
    require(len(set(pins)) == 3, "reused witness signing key")
    observations = []
    per_role = []
    for role, history, pin in zip(ROLES, histories, pins):
        require(isinstance(history, dict) and history.get("role") == role,
                "witness role does not match retained history")
        snapshots = history.get("snapshots")
        require(isinstance(snapshots, list) and len(snapshots) > 0,
                "witness history has no signed snapshots")
        last_epoch = -1
        role_observations = []
        for position, item in enumerate(snapshots):
            require(isinstance(item, dict), "malformed highwater witness entry")
            checkpoint = check_signed_checkpoint(item.get("checkpoint"))
            epoch = checkpoint["epoch"]
            require(epoch >= last_epoch, "witness history reordered or rolled back")
            require(epoch <= last_epoch + 1 or last_epoch == -1,
                    "withheld epoch inside witnessed history")
            last_epoch = epoch
            sig = verifier(item.get("public_key"), item.get("signature"),
                           pin, canonical(checkpoint))
            check_sha(sig, "witness signature digest missing")
            entry = {
                "role": role, "position": position,
                "epoch": epoch,
                "ledger_sha256": checkpoint["ledger_sha256"],
                "entry_count": checkpoint["entry_count"],
                "entries_sha256": checkpoint["entries_sha256"],
                "last_entry_sha256": checkpoint["last_entry_sha256"],
                "witness_key_spki_sha256": pin,
                "witness_signature_sha256": sig,
                "checkpoint_sha256": digest(checkpoint),
                "signed_checkpoint_verified": True,
            }
            observations.append(entry)
            role_observations.append(entry)
        per_role.append({
            "role": role, "signing_key_spki_sha256": pin,
            "signed_snapshot_count": len(role_observations),
            "last_observed_epoch": last_epoch,
            "checkpoint_sha256": [x["checkpoint_sha256"] for x in role_observations],
        })
    collisions = []
    epochs = sorted({x["epoch"] for x in observations})
    for epoch in epochs:
        at_epoch = [x for x in observations if x["epoch"] == epoch]
        variants = sorted({x["ledger_sha256"] for x in at_epoch})
        if len(variants) > 1:
            collisions.append({
                "epoch": epoch,
                "ledger_sha256_variants": variants,
                "claims": [{
                    "role": x["role"], "position": x["position"],
                    "ledger_sha256": x["ledger_sha256"],
                    "checkpoint_sha256": x["checkpoint_sha256"],
                    "signature_sha256": x["witness_signature_sha256"],
                } for x in at_epoch],
            })
    roots = set()
    exact_duplicates = []
    for x in observations:
        key = (x["role"], x["checkpoint_sha256"], x["witness_signature_sha256"])
        if key in roots:
            exact_duplicates.append({
                "role": x["role"], "position": x["position"],
                "checkpoint_sha256": x["checkpoint_sha256"],
            })
        roots.add(key)
    require(not exact_duplicates, "replayed identical signed snapshot within witness history")
    out = {
        "phase": "RUST-034",
        "status": "HOLD_SIGNED_EQUIVOCATION" if collisions else "HOLD_LATEST_CUSTODY_UNVERIFIED",
        "witness_histories": per_role,
        "ordered_signed_observations": observations,
        "epoch_equivocation_evidence": collisions,
        "equivocation_detected": len(collisions) > 0,
        "observed_epochs": epochs,
        "independent_witness_ownership_verified": False,
        "external_latest_highwater_confirmed": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    out["receipt_sha256"] = digest(out)
    return out

def hold():
    return {
        "phase": "RUST-034",
        "status": "HOLD_MISSING_RETAINED_HIGHWATER",
        "ordered_signed_observations": [],
        "epoch_equivocation_evidence": [],
        "independent_witness_ownership_verified": False,
        "external_latest_highwater_confirmed": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "Three independently retained, signed highwater histories not supplied",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--histories", help="JSON ordered FF/CF/RR signed-history bundle")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    if not args.histories:
        result = hold()
    else:
        pins = [os.environ.get("RUST034_PIN_" + role.upper()) for role in ROLES]
        require(all(pins), "externally pinned FF/CF/RR keys required")
        histories = json.loads(Path(args.histories).read_text(encoding="utf-8"))
        result = audit(histories, pins)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-034 HOLD: external custody or equivocation unresolved")

if __name__ == "__main__":
    main()
