#!/usr/bin/env python3
"""RUST-035 — custodian continuity and cross-epoch rotation audit.

Consumes a digest-checked RUST-034 highwater report. Key transitions must
have an old-key signature and new-key signature over the identical
domain-separated payload. This does not demonstrate independent custody.
No rotation or consistency observation can promote release authority.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature


def checked_parent(parent):
    require(isinstance(parent, dict) and parent.get("phase") == "RUST-034",
            "RUST-034 evidence required")
    require(parent.get("status") in (
        "HOLD_SIGNED_EQUIVOCATION", "HOLD_LATEST_CUSTODY_UNVERIFIED"),
        "invalid parent release status")
    require(parent.get("release_authorized") is False and parent.get("fork_resolved") is False,
            "parent attempted authority escalation")
    require(digest({k: v for k, v in parent.items() if k != "receipt_sha256"}) ==
            parent.get("receipt_sha256"), "parent receipt altered")
    observations = parent.get("ordered_signed_observations")
    require(isinstance(observations, list) and len(observations) >= 3,
            "three witnessed histories required")
    require(set(x.get("role") for x in observations) == set(ROLES),
            "witness ancestry roles missing")
    require(all(x.get("signed_checkpoint_verified") is True for x in observations),
            "unverified upstream checkpoint")
    for item in observations:
        for field in ("ledger_sha256", "checkpoint_sha256",
                      "witness_key_spki_sha256", "witness_signature_sha256"):
            check_sha(item.get(field), "upstream observation fingerprint missing")
    return observations


def rotation_payload(parent_hash, role, previous, successor, old_pin, new_pin):
    require(previous.get("role") == role and successor.get("role") == role,
            "cross-role identity substitution")
    require(type(previous.get("epoch")) is int and
            type(successor.get("epoch")) is int,
            "invalid transition epochs")
    require(successor["epoch"] == previous["epoch"] + 1,
            "skipped or replayed transition")
    require(previous["witness_key_spki_sha256"] == old_pin and
            successor["witness_key_spki_sha256"] == new_pin,
            "transition key does not match signed history")
    require(old_pin != new_pin, "same-key transition is not rotation")
    for pin in (old_pin, new_pin):
        check_sha(pin, "untrusted rotation key pin")
    return {
        "phase": "RUST-035",
        "kind": "DUAL_SIGNED_CUSTODIAN_ROTATION",
        "parent_rust034_receipt_sha256": parent_hash,
        "role": role,
        "from_epoch": previous["epoch"], "to_epoch": successor["epoch"],
        "from_checkpoint_sha256": previous["checkpoint_sha256"],
        "to_checkpoint_sha256": successor["checkpoint_sha256"],
        "from_key_spki_sha256": old_pin, "to_key_spki_sha256": new_pin,
        "release_authorized": False,
    }


def audit(parent, transitions, verifier=verify_key_and_signature):
    observed = checked_parent(parent)
    require(isinstance(transitions, list), "transition descriptions missing")
    ordered = []
    for role in ROLES:
        snapshots = [x for x in observed if x["role"] == role]
        snapshots.sort(key=lambda x: (x["epoch"], x.get("position", 0)))
        require(snapshots, "missing custodian history")
        ordered.append((role, snapshots))
    expected = []
    for role, snapshots in ordered:
        for i in range(1, len(snapshots)):
            earlier, later = snapshots[i-1], snapshots[i]
            if later["epoch"] == earlier["epoch"] + 1 and (
                later["witness_key_spki_sha256"] != earlier["witness_key_spki_sha256"]
            ):
                expected.append((role, earlier, later))
    require(len(transitions) == len(expected),
            "missing or extra key rotations")
    verified = []
    for claim, (role, earlier, later) in zip(transitions, expected):
        require(isinstance(claim, dict) and claim.get("role") == role,
                "unexpected custodian key transition")
        old_pin, new_pin = (earlier["witness_key_spki_sha256"],
                            later["witness_key_spki_sha256"])
        payload = rotation_payload(parent["receipt_sha256"], role, earlier, later,
                                   old_pin, new_pin)
        require(claim.get("from_checkpoint_sha256") == payload["from_checkpoint_sha256"] and
                claim.get("to_checkpoint_sha256") == payload["to_checkpoint_sha256"],
                "rotation references wrong checkpoint")
        old_sig = verifier(claim.get("old_public_key"), claim.get("old_signature"),
                           old_pin, canonical(payload))
        new_sig = verifier(claim.get("new_public_key"), claim.get("new_signature"),
                           new_pin, canonical(payload))
        for fingerprint in (old_sig, new_sig):
            check_sha(fingerprint, "invalid signature digest")
        verified.append({
            **payload,
            "old_signature_sha256": old_sig,
            "new_signature_sha256": new_sig,
            "dual_signature_verified": True,
            "independent_custody_continuity_verified": False,
        })
    conflicts = []
    for role, snapshots in ordered:
        for i in range(1, len(snapshots)):
            a, b = snapshots[i-1], snapshots[i]
            if b["epoch"] < a["epoch"] or b["epoch"] > a["epoch"] + 1:
                conflicts.append({"role": role, "reason": "EPOCH_GAP_OR_ROLLBACK",
                                  "earlier": a["checkpoint_sha256"],
                                  "later": b["checkpoint_sha256"]})
            if b["epoch"] == a["epoch"] and (
                b["ledger_sha256"] != a["ledger_sha256"] or
                b["witness_key_spki_sha256"] != a["witness_key_spki_sha256"]
            ):
                conflicts.append({"role": role, "reason": "SAME_EPOCH_CONTRADICTION",
                                  "earlier": a["checkpoint_sha256"],
                                  "later": b["checkpoint_sha256"]})
    # Never demote a RUST-034 conflict merely because rotations look valid.
    fork = bool(parent.get("equivocation_detected")) or bool(conflicts)
    result = {
        "phase": "RUST-035",
        "status": "HOLD_CROSS_EPOCH_CONTRADICTION" if fork else "HOLD_CUSTODIAN_CONTINUITY_UNPROVEN",
        "upstream_rust034_receipt_sha256": parent["receipt_sha256"],
        "preserved_upstream_equivocation": parent.get("epoch_equivocation_evidence", []),
        "custodian_key_transitions": verified,
        "cross_epoch_conflicts": conflicts,
        "custodian_history_heads": [{
            "role": role,
            "last_epoch": snapshots[-1]["epoch"],
            "last_checkpoint_sha256": snapshots[-1]["checkpoint_sha256"],
            "last_key_spki_sha256": snapshots[-1]["witness_key_spki_sha256"],
        } for role, snapshots in ordered],
        "independent_custody_continuity_verified": False,
        "latest_external_highwater_verified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-035", "status": "HOLD_MISSING_CUSTODIAN_CONTINUITY",
        "custodian_key_transitions": [],
        "independent_custody_continuity_verified": False,
        "release_authorized": False, "fork_resolved": False,
        "live_gameplay_authority": False,
        "reason": "No externally authenticated custodian histories or dual-signed rotations",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--parent")
    p.add_argument("--transitions")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    require(bool(args.parent) == bool(args.transitions),
            "partial continuity evidence refused")
    if args.parent:
        result = audit(json.loads(Path(args.parent).read_text(encoding="utf-8")),
                       json.loads(Path(args.transitions).read_text(encoding="utf-8")))
    else:
        result = hold()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-035 HOLD: independent custodian continuity unavailable")


if __name__ == "__main__":
    main()
