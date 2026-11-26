#!/usr/bin/env python3
"""RUST-053 — signed fork-challenge highwater and session replay fencing.

The signer, external floor, and session statements are caller-supplied.
Checks are cryptographic/structural only; latest external custody,
independent control, global anti-rollback, and release remain HOLD.
"""
import argparse
import json
import os
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from fork_challenge_ledger_rust052 import checked_history


def highwater(ledger):
    entries, heads = checked_history(ledger)
    require(entries, "nonempty RUST-052 challenge history required")
    return {
        "phase": "RUST-053", "kind": "FORK_CHALLENGE_HIGHWATER_V1",
        "challenge_count": len(entries), "head_sha256": heads[-1],
        "entries_sha256": digest(entries),
        "source_rust052_receipt_sha256": ledger["receipt_sha256"],
        "release_authorized": False,
    }


def session_message(old, new, session):
    for field in ("session_nonce_sha256", "acquisition_sha256",
                  "operator_control_sha256", "claimed_source_root_sha256"):
        check_sha(session.get(field), "session evidence missing: " + field)
    require(session.get("phase") == "RUST-053",
            "invalid session domain")
    return {
        "phase": "RUST-053", "kind": "FORK_CHALLENGE_SESSION_V1",
        "prior_rust052_receipt_sha256": old["receipt_sha256"],
        "current_rust052_receipt_sha256": new["receipt_sha256"],
        "prior_head_sha256": old["head_sha256"],
        "current_head_sha256": new["head_sha256"],
        "session_nonce_sha256": session["session_nonce_sha256"],
        "acquisition_sha256": session["acquisition_sha256"],
        "operator_control_sha256": session["operator_control_sha256"],
        "claimed_source_root_sha256": session["claimed_source_root_sha256"],
        "release_authorized": False,
    }


def audit(previous, current, signed_checkpoint, checkpoint_key,
          checkpoint_signature, checkpoint_pin, retained_floor,
          sessions, session_pins, verifier=verify_key_and_signature):
    prior_entries, prior_heads = checked_history(previous)
    new_entries, new_heads = checked_history(current)
    require(prior_entries and len(new_entries) > len(prior_entries),
            "current ledger must extend a nonempty previous history")
    require(new_entries[:len(prior_entries)] == prior_entries and
            new_heads[:len(prior_heads)] == prior_heads,
            "historical fork challenges truncated or rewritten")
    expected = highwater(previous)
    require(signed_checkpoint == expected, "signed checkpoint differs from prior history")
    check_sha(checkpoint_pin, "external checkpoint signing pin missing")
    signed = verifier(checkpoint_key, checkpoint_signature,
                      checkpoint_pin, canonical(expected))
    check_sha(signed, "checkpoint signature digest invalid")
    require(isinstance(retained_floor, dict) and
            retained_floor.get("phase") == "RUST-053",
            "retained highwater floor unavailable")
    n = retained_floor.get("challenge_count")
    require(type(n) is int and n >= len(prior_entries),
            "rollback below previously signed highwater")
    require(n <= len(new_entries), "retained highwater contains withheld entries")
    check_sha(retained_floor.get("head_sha256"), "floor head absent")
    require(new_heads[n] == retained_floor["head_sha256"],
            "retained challenge head conflicts with current prefix")
    require(isinstance(sessions, list) and sessions and
            isinstance(session_pins, list) and
            len(sessions) == len(session_pins),
            "signed session exchange evidence required")
    previous_nonces = {c["nonce_sha256"] for e in prior_entries
                       for c in e["witness_claims"]}
    all_claim_nonces = {c["nonce_sha256"] for e in new_entries
                       for c in e["witness_claims"]}
    all_claim_messages = {c["message_sha256"] for e in new_entries
                          for c in e["witness_claims"]}
    previously_seen = {}
    for e in prior_entries:
        for c in e["witness_claims"]:
            previously_seen.setdefault(c["pin"], set()).add((
                c["source_root_sha256"], c["acquisition_sha256"],
                c["operator_control_sha256"]))
    conflicts = []
    signed_sessions = []
    seen_session_nonces = set()
    seen_message_hashes = set()
    for session, pin in zip(sessions, session_pins):
        require(isinstance(session, dict), "invalid session record")
        check_sha(pin, "session signing key missing")
        require(pin != checkpoint_pin, "checkpoint signer cannot self-witness session")
        msg = session_message(previous, current, session)
        nonce = msg["session_nonce_sha256"]
        require(nonce not in all_claim_nonces and
                nonce not in previous_nonces and
                nonce not in seen_session_nonces,
                "cross-session challenge nonce replay")
        seen_session_nonces.add(nonce)
        message_hash = digest(msg)
        require(message_hash not in all_claim_messages and
                message_hash not in seen_message_hashes,
                "cross-session signed statement replay")
        seen_message_hashes.add(message_hash)
        sig = verifier(session.get("public_key"),
                       session.get("signature"), pin, canonical(msg))
        check_sha(sig, "invalid session signature digest")
        origin = (msg["claimed_source_root_sha256"],
                  msg["acquisition_sha256"],
                  msg["operator_control_sha256"])
        if pin in previously_seen and origin not in previously_seen[pin]:
            conflicts.append({
                "pin": pin, "prior_claims": sorted(
                    [list(v) for v in previously_seen[pin]]),
                "current_claim": list(origin),
                "reason": "SESSION_SIGNER_ANCESTRY_CHANGED",
                "independent_control_verified": False,
            })
        signed_sessions.append({
            "signer_pin": pin, "message_sha256": message_hash,
            "signature_sha256": sig, "session_nonce_sha256": nonce,
            "claimed_source_root_sha256": origin[0],
            "acquisition_sha256": origin[1],
            "operator_control_sha256": origin[2],
            "independent_custody_verified": False,
        })
    result = {
        "phase": "RUST-053",
        "status": "HOLD_SIGNED_CHALLENGE_HIGHWATER_CUSTODY_UNVERIFIED",
        "previous_rust052_receipt_sha256": previous["receipt_sha256"],
        "current_rust052_receipt_sha256": current["receipt_sha256"],
        "signed_highwater": expected,
        "checkpoint_signer_pin": checkpoint_pin,
        "checkpoint_signature_sha256": signed,
        "retained_floor_claim_sha256": digest(retained_floor),
        "new_session_evidence": signed_sessions,
        "session_ancestry_conflicts": conflicts,
        "historical_ancestry_conflicts":
            current.get("source_ancestry_conflicts", []),
        "previous_count": len(prior_entries),
        "current_count": len(new_entries),
        "current_head_sha256": new_heads[-1],
        "challenge_history_prefix_preserved": True,
        "independent_external_custody_verified": False,
        "globally_latest_highwater_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {
        "phase": "RUST-053", "status": "HOLD_MISSING_SIGNED_CHALLENGE_HIGHWATER",
        "independent_external_custody_verified": False,
        "globally_latest_highwater_verified": False,
        "fork_resolved": False, "release_authorized": False,
        "live_gameplay_authority": False,
        "reason": "No independently retained signed challenge highwater or fresh sessions",
    }


def main():
    p = argparse.ArgumentParser()
    for name in ("previous", "current", "checkpoint", "checkpoint-key",
                 "checkpoint-signature", "checkpoint-pin", "floor",
                 "sessions", "session-pins"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    values = [a.previous, a.current, a.checkpoint, a.checkpoint_key,
              a.checkpoint_signature, a.checkpoint_pin, a.floor,
              a.sessions, a.session_pins]
    require(all(values) or not any(values), "partial session highwater evidence refused")
    if all(values):
        doc = lambda v: json.loads(Path(v).read_text(encoding="utf-8"))
        result = audit(doc(a.previous), doc(a.current), doc(a.checkpoint),
                       a.checkpoint_key, a.checkpoint_signature,
                       a.checkpoint_pin, doc(a.floor), doc(a.sessions),
                       doc(a.session_pins))
    else:
        result = hold()
    target = Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-053 HOLD: independent custody not established")


if __name__ == "__main__":
    main()
