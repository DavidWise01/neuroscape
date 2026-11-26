#!/usr/bin/env python3
"""RUST-044 — attestor revocation ancestry and compromised-key fencing.

Consumes digest-checked RUST-042/043 receipts and an ordered, authority-
signed revocation list. Checks full challenge history against effective
epochs, preventing reuse of revoked attestor signing keys. A replacement
key bearing an already-revoked claimed control root is flagged as suspect.
Actual independent control, freshness and global anti-rollback remain HOLD.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from challenge_ledger_rust042 import checked_history

GENESIS = digest({"phase": "RUST-044", "kind": "ATTESTOR_REVOCATION_GENESIS_V1"})


def checked_inputs(ledger, rotation):
    entries, heads = checked_history(ledger)
    require(isinstance(rotation, dict) and rotation.get("phase") == "RUST-043",
            "RUST-043 transition receipt missing")
    require(rotation.get("status") in (
        "HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED",
        "HOLD_EXTERNAL_HIGHWATER_UNVERIFIED"),
        "unexpected transition predecessor")
    require(rotation.get("release_authorized") is False and
            rotation.get("fork_resolved") is False, "source asserted authority")
    require(digest({k: v for k, v in rotation.items()
                    if k != "receipt_sha256"}) == rotation.get("receipt_sha256"),
            "RUST-043 receipt altered")
    require(rotation.get("current_rust042_receipt_sha256") ==
            ledger["receipt_sha256"], "transition bound to another challenge ledger")
    require(rotation.get("historical_prefix_preserved") is True,
            "unqualified previous history")
    verified = rotation.get("verified_rotation_signatures")
    require(isinstance(verified, list), "missing rotation evidence")
    for item in verified:
        require(item.get("role") in ROLES and
                item.get("dual_signature_verified") is True,
                "unsigned attestor transition")
        for field in ("old_attestor_spki_sha256", "new_attestor_spki_sha256",
                      "transition_sha256", "old_signature_sha256",
                      "new_signature_sha256"):
            check_sha(item.get(field), "invalid rotation evidence " + field)
    return entries, heads, verified


def revocation_payload(role, pin, root, epoch, evidence):
    require(role in ROLES, "invalid revoked attestor role")
    for value in (pin, root, evidence):
        check_sha(value, "invalid revocation fingerprint")
    require(type(epoch) is int and epoch >= 1, "invalid effective epoch")
    return {
        "phase": "RUST-044",
        "kind": "ATTESTOR_REVOCATION_V1",
        "role": role,
        "revoked_attestor_spki_sha256": pin,
        "revoked_attestor_root_sha256": root,
        "effective_epoch": epoch,
        "evidence_sha256": evidence,
        "release_authorized": False,
    }


def audit(ledger, rotation, revocations, authority_pins,
          retained_floor=None, verifier=verify_key_and_signature):
    entries, heads, transitions = checked_inputs(ledger, rotation)
    require(isinstance(revocations, list), "attestor revocations missing")
    require(isinstance(authority_pins, list) and len(authority_pins) == len(revocations),
            "externally supplied revocation authority pins missing")
    appended = []
    chain = [GENESIS]
    seen = set()
    for i, (item, authority_pin) in enumerate(zip(revocations, authority_pins), 1):
        require(isinstance(item, dict), "invalid attestor revocation record")
        msg = revocation_payload(
            item.get("role"), item.get("revoked_attestor_spki_sha256"),
            item.get("revoked_attestor_root_sha256"),
            item.get("effective_epoch"), item.get("evidence_sha256"))
        key = (msg["role"], msg["revoked_attestor_spki_sha256"])
        require(key not in seen, "duplicated attestor revocation")
        seen.add(key)
        check_sha(authority_pin, "missing external revocation authority pin")
        require(authority_pin != msg["revoked_attestor_spki_sha256"],
                "revoked attestor cannot self-authorize revocation")
        signature_sha = verifier(
            item.get("authority_public_key"), item.get("authority_signature"),
            authority_pin, canonical(msg))
        check_sha(signature_sha, "revocation authority signature rejected")
        value = {
            "phase": "RUST-044", "kind": "ATTESTOR_REVOCATION_CHAIN_ENTRY",
            "ordinal": i, "previous_entry_sha256": chain[-1],
            "revocation_payload_sha256": digest(msg),
            "authority_key_spki_sha256": authority_pin,
            "authority_signature_sha256": signature_sha,
            "role": msg["role"],
            "revoked_attestor_spki_sha256": msg["revoked_attestor_spki_sha256"],
            "revoked_attestor_root_sha256": msg["revoked_attestor_root_sha256"],
            "effective_epoch": msg["effective_epoch"],
            "release_authorized": False,
        }
        value["entry_sha256"] = digest(value)
        appended.append(value)
        chain.append(value["entry_sha256"])
    if retained_floor is not None:
        require(isinstance(retained_floor, dict) and
                retained_floor.get("phase") == "RUST-044",
                "external revocation floor absent")
        count = retained_floor.get("entry_count")
        require(type(count) is int and 0 <= count < len(chain),
                "revocation history shorter than retained floor")
        check_sha(retained_floor.get("head_sha256"), "retained head invalid")
        require(chain[count] == retained_floor["head_sha256"],
                "retained revocation history was rewritten or withheld")
    # Even historical challenge records after the effective epoch cannot
    # be retroactively accepted by a late-disclosed revocation.
    violations = []
    suspected_replacements = []
    for revoked in appended:
        for entry in entries:
            if entry["role"] != revoked["role"] or
                    entry["epoch"] < revoked["effective_epoch"]:
                continue
            if entry["attestor_key_spki_sha256"] == revoked["revoked_attestor_spki_sha256"]:
                violations.append({
                    "role": entry["role"], "epoch": entry["epoch"],
                    "revoked_pin": revoked["revoked_attestor_spki_sha256"],
                    "challenge_entry_sha256": entry["entry_sha256"],
                })
            elif entry["external_attestor_root_sha256"] == revoked["revoked_attestor_root_sha256"]:
                suspected_replacements.append({
                    "role": entry["role"], "epoch": entry["epoch"],
                    "revoked_pin": revoked["revoked_attestor_spki_sha256"],
                    "replacement_pin": entry["attestor_key_spki_sha256"],
                    "shared_claimed_root": revoked["revoked_attestor_root_sha256"],
                    "controller_independently_verified": False,
                })
    # Hard reject known reuse, but retain root-equivalent replacement as
    # suspicion because a claimed root does not authenticate ownership.
    require(not violations, "revoked attestor signed at or after effective epoch")
    result = {
        "phase": "RUST-044",
        "status": "HOLD_POTENTIAL_COMPROMISED_CONTROL" if suspected_replacements
            else "HOLD_EXTERNAL_REVOCATION_CUSTODY_UNVERIFIED",
        "upstream_rust042_receipt_sha256": ledger["receipt_sha256"],
        "upstream_rust043_receipt_sha256": rotation["receipt_sha256"],
        "revocation_events": appended,
        "revocation_prefix_heads": chain,
        "revocation_head_sha256": chain[-1],
        "revocation_count": len(appended),
        "suspected_root_equivalent_replacements": suspected_replacements,
        "preserved_attestor_conflicts": rotation.get("preserved_attestor_conflicts", []),
        "verified_rotation_fingerprints": [
            x["transition_sha256"] for x in transitions],
        "retained_floor_compared": retained_floor is not None,
        "retained_floor_claim_sha256": digest(retained_floor) if retained_floor is not None else None,
        "independent_revocation_custody_verified": False,
        "real_world_control_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-044",
        "status": "HOLD_MISSING_ATTESTOR_REVOCATION_CUSTODY",
        "revocation_events": [], "revocation_prefix_heads": [GENESIS],
        "independent_revocation_custody_verified": False,
        "fork_resolved": False, "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "External signed attestor revocations and independently retained floor unavailable",
    }


def main():
    p = argparse.ArgumentParser()
    for name in ("ledger", "rotation", "revocations", "pins", "floor"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    inputs = (args.ledger, args.rotation, args.revocations, args.pins)
    require(all(inputs) or not any(inputs), "partial attestor revocation bundle refused")
    require(not args.floor or all(inputs), "floor without signed evidence refused")
    if all(inputs):
        records = [json.loads(Path(x).read_text(encoding="utf-8")) for x in inputs]
        floor = json.loads(Path(args.floor).read_text(encoding="utf-8")) if args.floor else None
        result = audit(*records, retained_floor=floor)
    else:
        result = hold()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as writer:
        json.dump(result, writer, indent=2, sort_keys=True)
        writer.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-044 HOLD: independent revocation custody not verified")


if __name__ == "__main__":
    main()
