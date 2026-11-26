#!/usr/bin/env python3
"""RUST-046 — append-only recovery quarantine and witness graduation review.

This verifies immutable RUST-045 candidates across later RUST-042/044
histories and checks separately pinned, nonce-bound witness attestations.
No real-world independence is certified: all recoveries stay quarantined,
all operational authority stays HOLD.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from custodian_recovery_rust045 import checked_revocations


def checked_recovery(receipt, old_revocation):
    require(isinstance(receipt, dict) and receipt.get("phase") == "RUST-045"
            and receipt.get("status") == "HOLD_QUARANTINED_RECOVERY_CANDIDATES",
            "quarantined RUST-045 receipt required")
    require(receipt.get("release_authorized") is False and
            receipt.get("fork_resolved") is False and
            receipt.get("real_world_independent_recovery_verified") is False,
            "upstream recovery claimed authority")
    require(digest({k: v for k, v in receipt.items() if k != "receipt_sha256"}) ==
            receipt.get("receipt_sha256"), "RUST-045 receipt altered")
    require(receipt.get("upstream_rust044_receipt_sha256") ==
            old_revocation["receipt_sha256"], "RUST-045 recovery bound to another revocation")
    candidates = receipt.get("recovery_candidates")
    require(isinstance(candidates, list) and candidates, "no quarantined recovery candidates")
    seen = set()
    for c in candidates:
        require(isinstance(c, dict) and c.get("role") in ROLES and
                c.get("authority_quarantined") is True and
                c.get("dual_signature_verified") is True and
                c.get("independent_custody_verified") is False,
                "unqualified recovery candidate")
        for k in ("recovery_proposal_sha256", "revoked_pin", "replacement_pin",
                  "authority_pin", "recovery_authority_signature_sha256",
                  "successor_signature_sha256"):
            check_sha(c.get(k), "invalid recovery evidence " + k)
        key = (c["role"], c["revoked_pin"])
        require(key not in seen, "duplicate recovery candidate")
        seen.add(key)
    return candidates


def graduation_message(previous, current, candidate, entry, witness, nonce):
    check_sha(nonce, "external challenge nonce missing")
    check_sha(witness.get("source_root_sha256"), "witness source root missing")
    check_sha(witness.get("acquisition_sha256"), "witness acquisition missing")
    require(witness.get("role") in ROLES, "unknown witness")
    return {
        "phase": "RUST-046", "kind": "QUARANTINE_GRADUATION_REVIEW_V1",
        "previous_recovery_receipt_sha256": previous["receipt_sha256"],
        "current_revocation_receipt_sha256": current["receipt_sha256"],
        "recovery_proposal_sha256": candidate["recovery_proposal_sha256"],
        "candidate_role": candidate["role"],
        "candidate_replacement_pin": candidate["replacement_pin"],
        "latest_challenge_entry_sha256": entry["entry_sha256"],
        "latest_challenge_epoch": entry["epoch"],
        "witness_role": witness["role"],
        "source_root_sha256": witness["source_root_sha256"],
        "acquisition_sha256": witness["acquisition_sha256"],
        "externally_issued_nonce_sha256": nonce,
        "release_authorized": False,
    }


def audit(recovery, previous_revocation, current_revocation,
          previous_ledger, current_ledger, witnesses, witness_pins, nonces,
          floor, verifier=verify_key_and_signature):
    previous_entries, old_revokes, old_heads = checked_revocations(
        previous_revocation, previous_ledger)
    current_entries, new_revokes, new_heads = checked_revocations(
        current_revocation, current_ledger)
    candidates = checked_recovery(recovery, previous_revocation)
    require(len(current_entries) > len(previous_entries),
            "no successor challenge epoch")
    require(current_ledger["epoch"] > previous_ledger["epoch"],
            "replayed challenge epoch")
    require(current_entries[:len(previous_entries)] == previous_entries,
            "challenge history prefix rewritten or truncated")
    require(len(new_revokes) >= len(old_revokes) and
            new_revokes[:len(old_revokes)] == old_revokes and
            new_heads[:len(old_heads)] == old_heads,
            "revocation history prefix rewritten or truncated")
    require(isinstance(floor, dict) and floor.get("phase") == "RUST-044",
            "retained revocation floor missing")
    require(type(floor.get("entry_count")) is int and
            floor["entry_count"] == len(new_revokes) and
            floor.get("head_sha256") == new_heads[-1],
            "retained revocation floor does not cover current history")
    require(isinstance(witnesses, list) and len(witnesses) == len(candidates),
            "one witness set per recovery candidate required")
    require(isinstance(witness_pins, list) and len(witness_pins) == len(candidates),
            "externally pinned witness sets required")
    require(isinstance(nonces, list) and len(nonces) == len(candidates),
            "nonce sets required")
    all_revoked_pins = {x["revoked_attestor_spki_sha256"] for x in new_revokes}
    all_revoked_roots = {x["revoked_attestor_root_sha256"] for x in new_revokes}
    all_nonce = {x["nonce_sha256"] for x in current_entries}
    used_nonces = set()
    results = []
    all_evidence = []
    for candidate, group, pins, challenges in zip(
            candidates, witnesses, witness_pins, nonces):
        role = candidate["role"]
        key = candidate["replacement_pin"]
        require(key not in all_revoked_pins and candidate["revoked_pin"] in all_revoked_pins,
                "compromised key reinstated or replacement newly revoked")
        role_entries = [x for x in current_entries if x["role"] == role]
        require(role_entries and role_entries[-1]["attestor_key_spki_sha256"] == key,
                "successor key not active in latest challenge epoch")
        require(role_entries[-1]["external_attestor_root_sha256"] not in all_revoked_roots,
                "latest successor shares revoked source root")
        require(isinstance(group, list) and len(group) == 3 and
                [x.get("role") for x in group] == list(ROLES),
                "three ordered ff/cf/rr review witnesses required")
        require(isinstance(pins, list) and len(pins) == 3 and
                isinstance(challenges, list) and len(challenges) == 3,
                "three witness pins and nonce fingerprints required")
        for pin, nonce in zip(pins, challenges):
            check_sha(pin, "review witness pin missing")
            check_sha(nonce, "review challenge nonce missing")
            require(pin not in (candidate["revoked_pin"],
                                candidate["replacement_pin"], candidate["authority_pin"])
                    and pin not in all_revoked_pins,
                    "witness is a compromised or self-issued authority")
            require(nonce not in all_nonce and nonce not in used_nonces,
                    "graduation challenge nonce replay")
            used_nonces.add(nonce)
        require(len(set(pins)) == 3, "duplicated review witness key")
        claims = []
        roots = []
        acquisitions = []
        for witness, pin, nonce in zip(group, pins, challenges):
            message = graduation_message(
                recovery, current_revocation, candidate, role_entries[-1], witness, nonce)
            signature = verifier(witness.get("public_key"), witness.get("signature"),
                                 pin, canonical(message))
            check_sha(signature, "review witness signature invalid")
            roots.append(message["source_root_sha256"])
            acquisitions.append(message["acquisition_sha256"])
            claims.append({
                "role": witness["role"], "pin": pin,
                "source_root_sha256": message["source_root_sha256"],
                "acquisition_sha256": message["acquisition_sha256"],
                "nonce_sha256": nonce,
                "message_sha256": digest(message),
                "signature_sha256": signature,
                "real_world_independence_authenticated": False,
            })
        require(len(set(roots)) == 3 and len(set(acquisitions)) == 3,
                "claimed witness ancestry collision")
        results.append({
            "recovery_proposal_sha256": candidate["recovery_proposal_sha256"],
            "role": role,
            "replacement_pin": key,
            "latest_challenge_entry_sha256": role_entries[-1]["entry_sha256"],
            "latest_challenge_epoch": role_entries[-1]["epoch"],
            "signed_review_claims": claims,
            "quarantine_persists": True,
            "graduation_approved": False,
        })
        all_evidence.extend(claims)
    result = {
        "phase": "RUST-046", "status": "HOLD_GRADUATION_NOT_AUTHORIZED",
        "previous_rust045_receipt_sha256": recovery["receipt_sha256"],
        "previous_rust044_receipt_sha256": previous_revocation["receipt_sha256"],
        "current_rust044_receipt_sha256": current_revocation["receipt_sha256"],
        "previous_challenge_ledger_sha256": previous_ledger["receipt_sha256"],
        "current_challenge_ledger_sha256": current_ledger["receipt_sha256"],
        "retained_revocation_floor_claim_sha256": digest(floor),
        "quarantined_recovery_reviews": results,
        "witness_evidence_sha256": digest(all_evidence),
        "preserved_attestor_conflicts":
            recovery.get("preserved_attestor_conflicts", []) +
            current_revocation.get("preserved_attestor_conflicts", []),
        "preserved_root_equivalent_replacements":
            recovery.get("preserved_root_equivalent_replacements", []) +
            current_revocation.get("suspected_root_equivalent_replacements", []),
        "retained_revocation_count": len(new_revokes),
        "historical_challenge_prefix_preserved": True,
        "revocation_prefix_preserved": True,
        "independent_operator_custody_verified": False,
        "latest_external_highwater_authenticated": False,
        "fork_resolved": False, "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-046", "status": "HOLD_MISSING_GRADUATION_CUSTODY",
        "quarantined_recovery_reviews": [],
        "independent_operator_custody_verified": False,
        "fork_resolved": False, "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "No externally pinned review witnesses and independently retained highwater",
    }


def main():
    parser = argparse.ArgumentParser()
    for field in ("recovery", "previous-revocation", "current-revocation",
                  "previous-ledger", "current-ledger", "witnesses", "pins",
                  "nonces", "floor"):
        parser.add_argument("--" + field)
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-hold-record", action="store_true")
    args = parser.parse_args()
    files = [args.recovery, args.previous_revocation, args.current_revocation,
             args.previous_ledger, args.current_ledger, args.witnesses,
             args.pins, args.nonces, args.floor]
    require(all(files) or not any(files), "partial recovery-graduation evidence refused")
    report = audit(*[json.loads(Path(path).read_text(encoding="utf-8")) for path in files]
                   ) if all(files) else hold()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as writer:
        json.dump(report, writer, indent=2, sort_keys=True)
        writer.write("\n")
    print(json.dumps(report, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-046 HOLD: independently authenticated graduation unavailable")


if __name__ == "__main__":
    main()
