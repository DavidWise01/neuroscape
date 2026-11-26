#!/usr/bin/env python3
"""RUST-047 — append-only recovery graduation-denial ledger.

Preserve each reviewed, quarantined RUST-046 attempt with exact ordered
hash-chain ancestry. Detect reused review evidence, changed signatures,
claimed shared source roots, and rollback against a supplied floor.

No signature count, denial receipt or caller-supplied floor establishes
real-world independent witness custody. All outputs stay HOLD.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import check_sha


GENESIS = digest({"phase": "RUST-047", "kind": "GRADUATION_DENIAL_GENESIS_V1"})
STATUSES = ("HOLD_GRADUATION_NOT_AUTHORIZED",)


def checked_review(review):
    require(isinstance(review, dict) and review.get("phase") == "RUST-046" and
            review.get("status") in STATUSES, "RUST-046 graduation review missing")
    require(review.get("release_authorized") is False and
            review.get("fork_resolved") is False and
            review.get("independent_operator_custody_verified") is False,
            "review promoted authority")
    require(digest({k: v for k, v in review.items()
                    if k != "receipt_sha256"}) == review.get("receipt_sha256"),
            "RUST-046 review receipt altered")
    rows = review.get("quarantined_recovery_reviews")
    require(isinstance(rows, list) and rows, "no quarantined recovery reviews")
    require(review.get("historical_challenge_prefix_preserved") is True and
            review.get("revocation_prefix_preserved") is True,
            "review omitted historical ancestry")
    all_claims = []
    used_proposals = set()
    for row in rows:
        require(isinstance(row, dict) and row.get("role") in ROLES and
                row.get("quarantine_persists") is True and
                row.get("graduation_approved") is False,
                "review did not retain quarantine")
        for field in ("recovery_proposal_sha256", "replacement_pin",
                      "latest_challenge_entry_sha256"):
            check_sha(row.get(field), "invalid review " + field)
        proposal = row["recovery_proposal_sha256"]
        require(proposal not in used_proposals, "duplicate recovery proposal review")
        used_proposals.add(proposal)
        require(type(row.get("latest_challenge_epoch")) is int and
                row["latest_challenge_epoch"] >= 1, "invalid review epoch")
        claims = row.get("signed_review_claims")
        require(isinstance(claims, list) and len(claims) == 3 and
                [c.get("role") for c in claims] == list(ROLES),
                "three ordered witness claims required")
        for claim in claims:
            for field in ("pin", "source_root_sha256", "acquisition_sha256",
                          "nonce_sha256", "message_sha256", "signature_sha256"):
                check_sha(claim.get(field), "invalid witness " + field)
            require(claim.get("real_world_independence_authenticated") is False,
                    "unsupported witness independence claim")
        require(len({c["pin"] for c in claims}) == 3 and
                len({c["source_root_sha256"] for c in claims}) == 3 and
                len({c["acquisition_sha256"] for c in claims}) == 3,
                "review contains duplicated witness source ancestry")
        all_claims.extend(claims)
    require(digest(all_claims) == review.get("witness_evidence_sha256"),
            "signed witness review evidence mismatched")
    return rows


def validate_history(history):
    require(isinstance(history, dict) and history.get("phase") == "RUST-047" and
            history.get("status") == "HOLD_GRADUATION_DENIAL_LEDGER",
            "RUST-047 predecessor denial ledger missing")
    require(history.get("release_authorized") is False and
            history.get("fork_resolved") is False,
            "historical denial promoted authority")
    entries = history.get("entries")
    heads = history.get("prefix_heads")
    require(isinstance(entries, list) and isinstance(heads, list) and
            len(heads) == len(entries)+1 and heads[0] == GENESIS,
            "historical denial ancestry incomplete")
    previous = GENESIS
    seen = set()
    for index, entry in enumerate(entries):
        require(isinstance(entry, dict) and
                entry.get("phase") == "RUST-047" and
                entry.get("kind") == "GRADUATION_DENIAL_ENTRY" and
                entry.get("ordinal") == index+1 and
                entry.get("previous_entry_sha256") == previous,
                "denial ledger predecessor or ordinal changed")
        for field in ("source_rust046_receipt_sha256",
                      "recovery_proposal_sha256", "replacement_pin",
                      "review_fingerprint_sha256", "witness_claims_sha256"):
            check_sha(entry.get(field), "invalid denial entry " + field)
        require(entry.get("role") in ROLES and
                entry.get("quarantine_persists") is True and
                entry.get("graduation_approved") is False,
                "denial ledger lost quarantine")
        key = (entry["source_rust046_receipt_sha256"],
               entry["recovery_proposal_sha256"])
        require(key not in seen, "duplicate denial event in history")
        seen.add(key)
        claims = entry.get("witness_claims")
        require(isinstance(claims, list) and len(claims) == 3 and
                [c.get("role") for c in claims] == list(ROLES),
                "denial witness evidence missing")
        require(digest(claims) == entry["witness_claims_sha256"],
                "denial witness evidence rewritten")
        for claim in claims:
            for field in ("pin", "source_root_sha256", "acquisition_sha256",
                          "nonce_sha256", "message_sha256", "signature_sha256"):
                check_sha(claim.get(field), "historic witness claim invalid")
        require(digest({k: v for k, v in entry.items()
                        if k != "entry_sha256"}) == entry.get("entry_sha256"),
                "historical denial digest altered")
        previous = entry["entry_sha256"]
        require(heads[index+1] == previous, "historical denial prefix changed")
    require(history.get("entry_count") == len(entries) and
            history.get("head_sha256") == previous,
            "denial count or head changed")
    require(digest({k: v for k, v in history.items()
                    if k != "receipt_sha256"}) == history.get("receipt_sha256"),
            "historical denial receipt altered")
    return entries, heads


def genesis():
    result = {
        "phase": "RUST-047", "status": "HOLD_GRADUATION_DENIAL_LEDGER",
        "entries": [], "prefix_heads": [GENESIS], "entry_count": 0,
        "head_sha256": GENESIS,
        "release_authorized": False, "fork_resolved": False,
        "external_custody_verified": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def audit(review, history, floor=None):
    rows = checked_review(review)
    old_entries, old_heads = validate_history(history)
    if floor is not None:
        require(isinstance(floor, dict) and floor.get("phase") == "RUST-047",
                "externally retained denial floor missing")
        count = floor.get("entry_count")
        require(type(count) is int and count >= 0, "invalid retained denial count")
        check_sha(floor.get("head_sha256"), "invalid retained denial head")
        require(count < len(old_heads), "retained denial floor exceeds history")
        require(old_heads[count] == floor["head_sha256"],
                "retained denial history substituted or withheld")

    entries = list(old_entries)
    heads = list(old_heads)
    seen_attempts = {
        (entry["source_rust046_receipt_sha256"], entry["recovery_proposal_sha256"])
        for entry in old_entries
    }
    seen_nonces = {c["nonce_sha256"] for e in entries for c in e["witness_claims"]}
    seen_messages = {c["message_sha256"] for e in entries for c in e["witness_claims"]}
    ancestry = {}
    for entry in entries:
        for claim in entry["witness_claims"]:
            ancestry.setdefault(claim["pin"], set()).add(
                (claim["source_root_sha256"], claim["acquisition_sha256"]))
    collisions = []
    appended = []
    for row in rows:
        key = (review["receipt_sha256"], row["recovery_proposal_sha256"])
        require(key not in seen_attempts, "graduation review replayed")
        seen_attempts.add(key)
        for claim in row["signed_review_claims"]:
            require(claim["nonce_sha256"] not in seen_nonces,
                    "replayed graduation challenge nonce")
            require(claim["message_sha256"] not in seen_messages,
                    "replayed signed review statement")
            seen_nonces.add(claim["nonce_sha256"])
            seen_messages.add(claim["message_sha256"])
            existing = ancestry.get(claim["pin"], set())
            observed = (claim["source_root_sha256"], claim["acquisition_sha256"])
            if existing and observed not in existing:
                collisions.append({
                    "witness_pin": claim["pin"],
                    "historical_claims": sorted([list(x) for x in existing]),
                    "new_claim": list(observed),
                    "reason": "WITNESS_PIN_CLAIMS_CHANGED_SOURCE_ANCESTRY",
                    "real_world_identity_authenticated": False,
                })
            ancestry.setdefault(claim["pin"], set()).add(observed)
        entry = {
            "phase": "RUST-047", "kind": "GRADUATION_DENIAL_ENTRY",
            "ordinal": len(entries)+1,
            "previous_entry_sha256": heads[-1],
            "source_rust046_receipt_sha256": review["receipt_sha256"],
            "recovery_proposal_sha256": row["recovery_proposal_sha256"],
            "replacement_pin": row["replacement_pin"],
            "role": row["role"],
            "latest_challenge_epoch": row["latest_challenge_epoch"],
            "review_fingerprint_sha256": digest(row),
            "witness_claims_sha256": digest(row["signed_review_claims"]),
            "witness_claims": row["signed_review_claims"],
            "quarantine_persists": True,
            "graduation_approved": False,
        }
        entry["entry_sha256"] = digest(entry)
        entries.append(entry)
        heads.append(entry["entry_sha256"])
        appended.append(entry)
    result = {
        "phase": "RUST-047", "status": "HOLD_GRADUATION_DENIAL_LEDGER",
        "entries": entries, "prefix_heads": heads,
        "entry_count": len(entries), "head_sha256": heads[-1],
        "new_denials": appended,
        "witness_ancestry_conflicts": history.get("witness_ancestry_conflicts", []) + collisions,
        "retained_floor_compared": floor is not None,
        "retained_floor_claim_sha256": digest(floor) if floor is not None else None,
        "last_review_receipt_sha256": review["receipt_sha256"],
        "preserved_attestor_conflicts": history.get("preserved_attestor_conflicts", []) +
                                       review.get("preserved_attestor_conflicts", []),
        "preserved_root_equivalent_replacements":
            history.get("preserved_root_equivalent_replacements", []) +
            review.get("preserved_root_equivalent_replacements", []),
        "review_source_ancestry_authenticated": False,
        "independent_external_retention_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-047", "status": "HOLD_MISSING_INDEPENDENT_DENIAL_LEDGER",
        "release_authorized": False, "fork_resolved": False,
        "review_source_ancestry_authenticated": False,
        "independent_external_retention_verified": False,
        "live_gameplay_authority": False,
        "reason": "RUST-046 review and external retained denial history missing",
    }


def main():
    p = argparse.ArgumentParser()
    for field in ("review", "history", "floor"):
        p.add_argument("--" + field)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    require(bool(a.review) == bool(a.history),
            "partial denial-ledger material refused")
    require(not a.floor or (a.review and a.history),
            "retained floor without denial history refused")
    if a.review:
        result = audit(json.loads(Path(a.review).read_text(encoding="utf-8")),
                       json.loads(Path(a.history).read_text(encoding="utf-8")),
                       json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None)
    else:
        result = hold()
    path = Path(a.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as writer:
        json.dump(result, writer, sort_keys=True, indent=2)
        writer.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-047 HOLD: independent graduation custody unavailable")


if __name__ == "__main__":
    main()
