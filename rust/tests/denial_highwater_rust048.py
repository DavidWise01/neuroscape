#!/usr/bin/env python3
"""RUST-048 — signed denial highwater & exact-prefix anti-rollback.

Verifies an RUST-047 denial ledger, a pinned Ed25519 signature on a
denial highwater, and equality with an independently *supplied* retained
floor. This cannot establish that the floor is actually independently
held or globally latest. All resulting authority remains HOLD.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from graduation_denial_rust047 import validate_history


def checkpoint_payload(ledger):
    entries, heads = validate_history(ledger)
    require(len(entries) >= 1, "highwater must cover a recorded denial")
    return {
        "phase": "RUST-048",
        "kind": "SIGNED_DENIAL_HIGHWATER_V1",
        "denial_count": len(entries),
        "head_sha256": heads[-1],
        "source_rust047_receipt_sha256": ledger["receipt_sha256"],
        "denial_history_sha256": digest(entries),
        "release_authorized": False,
    }


def verify_floor(floor, heads, minimum_count):
    require(isinstance(floor, dict) and floor.get("phase") == "RUST-048",
            "retained denial highwater floor absent")
    count = floor.get("denial_count")
    require(type(count) is int and count >= 1, "retained denial count invalid")
    check_sha(floor.get("head_sha256"), "retained denial head invalid")
    require(count >= minimum_count, "denial rollback below retained highwater")
    require(count < len(heads), "denial history withheld below retained highwater")
    require(heads[count] == floor["head_sha256"],
            "retained denial ancestry replaced or forked")
    return True


def audit(previous, current, checkpoint, public_key, signature, pinned_key,
          retained_floor, verifier=verify_key_and_signature):
    old_entries, old_heads = validate_history(previous)
    new_entries, new_heads = validate_history(current)
    require(len(old_entries) > 0, "signed previous denial history missing")
    require(len(new_entries) > len(old_entries), "no new denial beyond prior highwater")
    require(new_entries[:len(old_entries)] == old_entries and
            new_heads[:len(old_heads)] == old_heads,
            "previous denial history truncated or rewritten")
    expected = checkpoint_payload(previous)
    require(checkpoint == expected, "signed denial checkpoint does not match prior history")
    check_sha(pinned_key, "external highwater signer pin unavailable")
    signature_hash = verifier(public_key, signature, pinned_key, canonical(expected))
    check_sha(signature_hash, "signed denial highwater fingerprint missing")
    verify_floor(retained_floor, new_heads, len(old_entries))
    # A floor newer than the signed predecessor is still allowed only
    # when the complete corresponding prefix is present in the new ledger.
    require(retained_floor["denial_count"] <= len(new_entries),
            "external retained highwater exceeds current history")
    result = {
        "phase": "RUST-048",
        "status": "HOLD_EXTERNAL_DENIAL_HIGHWATER_CUSTODY_UNVERIFIED",
        "previous_rust047_receipt_sha256": previous["receipt_sha256"],
        "current_rust047_receipt_sha256": current["receipt_sha256"],
        "signed_checkpoint": expected,
        "highwater_witness_spki_sha256": pinned_key,
        "highwater_signature_sha256": signature_hash,
        "retained_floor_claim_sha256": digest(retained_floor),
        "retained_denial_count": retained_floor["denial_count"],
        "previous_denial_count": len(old_entries),
        "current_denial_count": len(new_entries),
        "current_denial_head_sha256": new_heads[-1],
        "historical_prefix_preserved": True,
        "all_graduations_denied": all(
            e["graduation_approved"] is False for e in new_entries),
        "preserved_witness_ancestry_conflicts":
            current.get("witness_ancestry_conflicts", []),
        "preserved_attestor_conflicts":
            current.get("preserved_attestor_conflicts", []),
        "preserved_root_equivalent_replacements":
            current.get("preserved_root_equivalent_replacements", []),
        "external_floor_custody_authenticated": False,
        "globally_latest_denial_highwater_verified": False,
        "independent_witness_ancestry_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-048",
        "status": "HOLD_MISSING_SIGNED_DENIAL_HIGHWATER",
        "external_floor_custody_authenticated": False,
        "globally_latest_denial_highwater_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "No signed highwater with an independently retained complete denial history",
    }


def main():
    p = argparse.ArgumentParser()
    for name in ("previous", "current", "checkpoint", "public-key",
                 "signature", "floor"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    inputs = [a.previous, a.current, a.checkpoint,
              a.public_key, a.signature, a.floor]
    require(all(inputs) or not any(inputs), "partial signed highwater evidence refused")
    if all(inputs):
        pin = os.getenv("RUST048_DENIAL_HIGHWATER_SPKI_SHA256")
        require(pin, "independently pinned highwater witness key absent")
        prev = json.loads(Path(a.previous).read_text(encoding="utf-8"))
        curr = json.loads(Path(a.current).read_text(encoding="utf-8"))
        checkpoint = json.loads(Path(a.checkpoint).read_text(encoding="utf-8"))
        floor = json.loads(Path(a.floor).read_text(encoding="utf-8"))
        result = audit(prev, curr, checkpoint, a.public_key, a.signature, pin, floor)
    else:
        result = hold()
    output = Path(a.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as writer:
        json.dump(result, writer, sort_keys=True, indent=2)
        writer.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-048 HOLD: independently retained latest denial highwater unverified")


if __name__ == "__main__":
    main()
