#!/usr/bin/env python3
"""RUST-049 — cross-custody signed denial highwater and fork evidence.

Both signed checkpoints and complete RUST-047 branch histories are
verified relative to supplied signing-key pins. Detects divergent
same-count histories and ancestral incompatibility, preserves both
branches without electing a winner or granting custody authority.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from denial_highwater_rust048 import checkpoint_payload
from graduation_denial_rust047 import validate_history


def checked_branch(bundle, expected_pin, verifier):
    require(isinstance(bundle, dict), "custody branch missing")
    ledger = bundle.get("ledger")
    entries, heads = validate_history(ledger)
    checkpoint = bundle.get("checkpoint")
    require(checkpoint == checkpoint_payload(ledger),
            "signed checkpoint differs from denial branch")
    check_sha(expected_pin, "externally pinned custodian key missing")
    require(isinstance(bundle.get("custody_root_sha256"), str),
            "claimed custody root missing")
    check_sha(bundle["custody_root_sha256"], "invalid claimed custody root")
    check_sha(bundle.get("acquisition_sha256"), "invalid acquisition ancestry")
    signature_hash = verifier(bundle.get("public_key"),
                              bundle.get("signature"), expected_pin,
                              canonical(checkpoint))
    check_sha(signature_hash, "invalid checkpoint signature fingerprint")
    return {
        "branch_sha256": digest({
            "checkpoint": checkpoint,
            "custody_root_sha256": bundle["custody_root_sha256"],
            "acquisition_sha256": bundle["acquisition_sha256"],
            "signer_pin": expected_pin,
            "signature_sha256": signature_hash,
        }),
        "denial_count": len(entries),
        "head_sha256": heads[-1],
        "prefix_heads": heads,
        "denial_history_sha256": digest(entries),
        "rust047_receipt_sha256": ledger["receipt_sha256"],
        "custody_root_sha256": bundle["custody_root_sha256"],
        "acquisition_sha256": bundle["acquisition_sha256"],
        "signer_pin": expected_pin,
        "signature_sha256": signature_hash,
        "independent_custody_authenticated": False,
    }


def audit(left, right, pins, retained_floor=None,
          verifier=verify_key_and_signature):
    require(isinstance(pins, list) and len(pins) == 2,
            "two externally supplied signing pins required")
    for pin in pins:
        check_sha(pin, "invalid custodian signing pin")
    require(pins[0] != pins[1], "same signing key is not two custodians")
    a = checked_branch(left, pins[0], verifier)
    b = checked_branch(right, pins[1], verifier)
    shared_signing_ancestry = (
        a["custody_root_sha256"] == b["custody_root_sha256"] or
        a["acquisition_sha256"] == b["acquisition_sha256"])
    count = min(a["denial_count"], b["denial_count"])
    common = 0
    for idx in range(count + 1):
        if a["prefix_heads"][idx] != b["prefix_heads"][idx]:
            break
        common = idx
    conflicting = a["prefix_heads"][count] != b["prefix_heads"][count]
    fork = None
    if conflicting:
        fork = {
            "kind": "INCOMPATIBLE_DENIAL_ANCESTRY",
            "common_prefix_count": common,
            "compared_count": count,
            "left_prefix_sha256": a["prefix_heads"][count],
            "right_prefix_sha256": b["prefix_heads"][count],
            "left_branch_sha256": a["branch_sha256"],
            "right_branch_sha256": b["branch_sha256"],
            "both_branches_preserved": True,
            "winner_selected": False,
        }
    if retained_floor is not None:
        require(isinstance(retained_floor, dict) and
                retained_floor.get("phase") == "RUST-049",
                "external floor invalid")
        floor_count = retained_floor.get("denial_count")
        require(type(floor_count) is int and floor_count >= 1,
                "floor count invalid")
        check_sha(retained_floor.get("head_sha256"), "floor hash invalid")
        # A floor can't be ignored just because one custodian has a
        # newer-looking branch or a higher reported count.
        require(floor_count <= a["denial_count"] and
                floor_count <= b["denial_count"],
                "retained highwater omitted by one custodian")
        matches = [
            item["prefix_heads"][floor_count] == retained_floor["head_sha256"]
            for item in (a, b)
        ]
        require(any(matches), "neither branch matches retained highwater")
    else:
        matches = None
    result = {
        "phase": "RUST-049",
        "status": ("HOLD_CONFLICTING_DENIAL_HIGHWATERS" if conflicting else
                   "HOLD_SHARED_CUSTODY_ANCESTRY" if shared_signing_ancestry else
                   "HOLD_EXTERNAL_CUSTODY_UNVERIFIED"),
        "left_branch": a,
        "right_branch": b,
        "same_count_fork_evidence": fork,
        "shared_claimed_custody_ancestry": shared_signing_ancestry,
        "retained_floor_claim_sha256":
            digest(retained_floor) if retained_floor is not None else None,
        "floor_match_by_branch": matches,
        "highest_observed_denial_count":
            max(a["denial_count"], b["denial_count"]),
        "globally_latest_highwater_verified": False,
        "independent_custodian_control_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-049",
        "status": "HOLD_MISSING_CROSS_CUSTODY_HIGHWATER",
        "independent_custodian_control_verified": False,
        "globally_latest_highwater_verified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "Two signed independently retained denial highwaters unavailable",
    }


def main():
    p = argparse.ArgumentParser()
    for name in ("left", "right", "pins", "floor"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    sources = [args.left, args.right, args.pins]
    require(all(sources) or not any(sources), "partial cross-custody evidence refused")
    require(not args.floor or all(sources), "floor without both branches refused")
    if all(sources):
        left, right, pins = [
            json.loads(Path(path).read_text(encoding="utf-8")) for path in sources]
        floor = (json.loads(Path(args.floor).read_text(encoding="utf-8"))
                 if args.floor else None)
        result = audit(left, right, pins, floor)
    else:
        result = hold()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as writer:
        json.dump(result, writer, indent=2, sort_keys=True)
        writer.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-049 HOLD: independent highwater custody not proven")


if __name__ == "__main__":
    main()
