#!/usr/bin/env python3
"""RUST-045 — quarantined custodian recovery candidate, never release.

Requires exact RUST-044 revocation ancestry, surviving challenge evidence,
a separately pinned recovery authority and successor signatures over one
domain-separated recovery payload. Distinct *claimed* roots are necessary,
not proof of independent real-world custody. A recovered key never revives
its compromised predecessor or authorizes gameplay.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from challenge_ledger_rust042 import checked_history
from attestor_revocation_rust044 import GENESIS


def checked_revocations(report, ledger):
    entries, heads = checked_history(ledger)
    require(isinstance(report, dict) and report.get("phase") == "RUST-044",
            "RUST-044 revocation receipt required")
    require(report.get("status") in (
        "HOLD_POTENTIAL_COMPROMISED_CONTROL",
        "HOLD_EXTERNAL_REVOCATION_CUSTODY_UNVERIFIED"),
        "revocation predecessor unqualified")
    require(report.get("release_authorized") is False and
            report.get("fork_resolved") is False,
            "predecessor claimed release authority")
    require(report.get("upstream_rust042_receipt_sha256") ==
            ledger["receipt_sha256"], "RUST-044 bound to different challenge ledger")
    require(digest({k: v for k, v in report.items()
                    if k != "receipt_sha256"}) == report.get("receipt_sha256"),
            "RUST-044 receipt modified")
    events = report.get("revocation_events")
    heads44 = report.get("revocation_prefix_heads")
    require(isinstance(events, list) and isinstance(heads44, list)
            and len(heads44) == len(events) + 1 and heads44[0] == GENESIS,
            "revocation ancestry missing")
    require(report.get("revocation_count") == len(events) and
            report.get("revocation_head_sha256") == heads44[-1],
            "revocation count/head mismatch")
    previous = GENESIS
    seen = set()
    for i, event in enumerate(events, 1):
        require(isinstance(event, dict) and
                event.get("phase") == "RUST-044" and
                event.get("kind") == "ATTESTOR_REVOCATION_CHAIN_ENTRY"
                and event.get("ordinal") == i and
                event.get("previous_entry_sha256") == previous,
                "revocation link or sequence broken")
        require(event.get("role") in ROLES, "unknown revoked role")
        for field in ("revoked_attestor_spki_sha256",
                      "revoked_attestor_root_sha256",
                      "authority_key_spki_sha256",
                      "authority_signature_sha256",
                      "revocation_payload_sha256"):
            check_sha(event.get(field), "invalid revocation " + field)
        require(type(event.get("effective_epoch")) is int and
                event["effective_epoch"] >= 1, "invalid revocation effective epoch")
        require((event["role"], event["revoked_attestor_spki_sha256"])
                not in seen, "duplicate revoked attestor")
        seen.add((event["role"], event["revoked_attestor_spki_sha256"]))
        require(digest({k: v for k, v in event.items()
                        if k != "entry_sha256"}) == event.get("entry_sha256"),
                "revocation entry hash altered")
        previous = event["entry_sha256"]
        require(heads44[i] == previous, "revocation prefix rewritten")
    return entries, events, heads44


def payload(report, ledger, revocation, successor, item):
    role = revocation["role"]
    old_pin = revocation["revoked_attestor_spki_sha256"]
    new_pin = successor["attestor_key_spki_sha256"]
    old_root = revocation["revoked_attestor_root_sha256"]
    new_root = successor["external_attestor_root_sha256"]
    require(old_pin != new_pin, "revoked key cannot self-recover")
    require(old_root != new_root, "claimed compromised root reused")
    require(successor["role"] == role and
            successor["epoch"] >= revocation["effective_epoch"],
            "replacement not from valid later witness epoch")
    require(item.get("role") == role and
            item.get("revoked_attestor_spki_sha256") == old_pin and
            item.get("replacement_attestor_spki_sha256") == new_pin,
            "recovery role/pins not bound")
    recovery_root = item.get("recovery_authority_root_sha256")
    acquisition = item.get("independent_acquisition_sha256")
    nonce = item.get("challenge_nonce_sha256")
    for field in (recovery_root, acquisition, nonce):
        check_sha(field, "recovery authority ancestry/nonce missing")
    require(recovery_root not in (old_root, new_root),
            "recovery authority root matches predecessor or successor")
    return {
        "phase": "RUST-045", "kind": "QUARANTINED_RECOVERY_V1",
        "role": role, "revoked_attestor_spki_sha256": old_pin,
        "revoked_attestor_root_sha256": old_root,
        "revocation_entry_sha256": revocation["entry_sha256"],
        "effective_epoch": revocation["effective_epoch"],
        "replacement_attestor_spki_sha256": new_pin,
        "replacement_attestor_root_sha256": new_root,
        "replacement_epoch": successor["epoch"],
        "replacement_challenge_sha256": successor["entry_sha256"],
        "recovery_authority_root_sha256": recovery_root,
        "independent_acquisition_sha256": acquisition,
        "challenge_nonce_sha256": nonce,
        "upstream_rust044_receipt_sha256": report["receipt_sha256"],
        "upstream_rust042_receipt_sha256": ledger["receipt_sha256"],
        "release_authorized": False,
    }


def audit(report, ledger, proposals, authority_pins,
          floor, verifier=verify_key_and_signature):
    observations, events, heads = checked_revocations(report, ledger)
    require(isinstance(floor, dict) and floor.get("phase") == "RUST-044",
            "separately retained revocation floor required")
    count = floor.get("entry_count")
    require(type(count) is int and count == len(events),
            "recovery floor must cover all known revocations")
    require(floor.get("head_sha256") == heads[-1],
            "external revocation floor contradicts current history")
    require(isinstance(proposals, list) and proposals,
            "explicit recovery proposals required")
    require(isinstance(authority_pins, list) and
            len(authority_pins) == len(proposals),
            "externally pinned recovery authorities required")
    require(len(set(authority_pins)) == len(authority_pins),
            "recovery authority signing key reused across proposals")
    all_revoked_pins = {e["revoked_attestor_spki_sha256"] for e in events}
    all_revoked_roots = {e["revoked_attestor_root_sha256"] for e in events}
    used_nonces = {e["nonce_sha256"] for e in observations}
    used_authorities = set()
    used_proposals = set()
    signed = []
    for item, authority_pin in zip(proposals, authority_pins):
        require(isinstance(item, dict), "malformed recovery proposal")
        role = item.get("role")
        old_pin = item.get("revoked_attestor_spki_sha256")
        revocation = next((e for e in events if
                           e["role"] == role and
                           e["revoked_attestor_spki_sha256"] == old_pin), None)
        require(revocation is not None, "unrevoked attestor cannot invoke recovery")
        require((role, old_pin) not in used_proposals,
                "duplicate recovery for same compromised key")
        used_proposals.add((role, old_pin))
        replacement_pin = item.get("replacement_attestor_spki_sha256")
        successor = next((e for e in observations if
                          e["role"] == role and
                          e["attestor_key_spki_sha256"] == replacement_pin and
                          e["epoch"] >= revocation["effective_epoch"]), None)
        require(successor is not None, "replacement lacks later challenge evidence")
        require(replacement_pin not in all_revoked_pins,
                "replacement signing key already revoked")
        require(successor["external_attestor_root_sha256"] not in all_revoked_roots,
                "replacement shares a revoked controlling root")
        check_sha(authority_pin, "recovery authority signing pin missing")
        require(authority_pin not in all_revoked_pins and
                authority_pin != replacement_pin and authority_pin != old_pin,
                "self-issued or revoked recovery authority")
        msg = payload(report, ledger, revocation, successor, item)
        require(msg["challenge_nonce_sha256"] not in used_nonces,
                "recovery challenge nonce replay")
        used_nonces.add(msg["challenge_nonce_sha256"])
        require(msg["recovery_authority_root_sha256"] not in all_revoked_roots,
                "recovery authority inherits revoked control root")
        require(msg["recovery_authority_root_sha256"] not in used_authorities,
                "recovery root reused across proposals")
        used_authorities.add(msg["recovery_authority_root_sha256"])
        authority_sig = verifier(item.get("recovery_public_key"),
                                 item.get("recovery_signature"),
                                 authority_pin, canonical(msg))
        successor_sig = verifier(item.get("successor_public_key"),
                                 item.get("successor_signature"),
                                 replacement_pin, canonical(msg))
        for value in (authority_sig, successor_sig):
            check_sha(value, "recovery signature fingerprint invalid")
        signed.append({
            "recovery_proposal_sha256": digest(msg),
            "role": role, "revoked_pin": old_pin,
            "replacement_pin": replacement_pin,
            "authority_pin": authority_pin,
            "recovery_authority_signature_sha256": authority_sig,
            "successor_signature_sha256": successor_sig,
            "dual_signature_verified": True,
            "independent_custody_verified": False,
            "authority_quarantined": True,
        })
    result = {
        "phase": "RUST-045",
        "status": "HOLD_QUARANTINED_RECOVERY_CANDIDATES",
        "upstream_rust044_receipt_sha256": report["receipt_sha256"],
        "revocation_head_sha256": heads[-1],
        "retained_floor_claim_sha256": digest(floor),
        "recovery_candidates": signed,
        "preserved_attestor_conflicts": report.get("preserved_attestor_conflicts", []),
        "preserved_root_equivalent_replacements":
            report.get("suspected_root_equivalent_replacements", []),
        "revoked_key_history_retained": True,
        "real_world_independent_recovery_verified": False,
        "latest_external_floor_authenticated": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-045",
        "status": "HOLD_MISSING_INDEPENDENT_RECOVERY",
        "recovery_candidates": [],
        "real_world_independent_recovery_verified": False,
        "release_authorized": False,
        "fork_resolved": False,
        "live_gameplay_authority": False,
        "reason": "No externally held revocation floor and independently authenticated recovery authority",
    }


def main():
    p = argparse.ArgumentParser()
    for field in ("revocation", "ledger", "proposals", "pins", "floor"):
        p.add_argument("--" + field)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    inputs = (args.revocation, args.ledger, args.proposals, args.pins, args.floor)
    require(all(inputs) or not any(inputs),
            "partial recovery material refused")
    if all(inputs):
        values = [json.loads(Path(x).read_text(encoding="utf-8")) for x in inputs]
        result = audit(*values)
    else:
        result = hold()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as writer:
        json.dump(result, writer, indent=2, sort_keys=True)
        writer.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-045 HOLD: recovery remains quarantined")


if __name__ == "__main__":
    main()
