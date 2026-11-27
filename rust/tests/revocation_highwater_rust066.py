#!/usr/bin/env python3
"""RUST-066 — signed revocation highwater and successor custody quarantine.

Signed checkpoints and claimed retention floors do not prove external
custody, independently controlled operators, or permission to recover.
This verifier has no release path.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from witness_rotation_rust065 import checked_history

def checkpoint_payload(history):
    events, heads = checked_history(history)
    require(events, "signed predecessor revocation history must be nonempty")
    return {
        "phase": "RUST-066",
        "kind": "REVOCATION_SUCCESSOR_HIGHWATER_V1",
        "revocation_count": len(events),
        "head_sha256": heads[-1],
        "events_sha256": digest(events),
        "revoked_pins_sha256": digest(history["revoked_signer_pins"]),
        "revoked_roots_sha256": digest(history["revoked_controller_roots"]),
        "conflicts_sha256": digest(history["rotation_conflicts"]),
        "source_rust065_receipt_sha256": history["receipt_sha256"],
        "release_authorized": False,
    }

def ancestry_conflicts(old, recent):
    """Compare every new quarantined replacement with all prior incidents."""
    old_controllers = {
        e["compromised_controller_sha256"] for e in old
    } | {
        e["replacement_controller_sha256"] for e in old
    }
    old_acquisitions = {
        e["replacement_acquisition_sha256"] for e in old
    }
    old_sources = {
        e["replacement_source_root_sha256"] for e in old
    }
    old_signer_claims = {}
    for e in old:
        old_signer_claims.setdefault(e["replacement_pin"], set()).add((
            e["replacement_controller_sha256"],
            e["replacement_source_root_sha256"],
            e["replacement_acquisition_sha256"],
        ))
    findings = []
    for e in recent:
        pin = e["replacement_pin"]
        if e["replacement_controller_sha256"] in old_controllers:
            findings.append({
                "reason": "SUCCESSOR_REUSES_PRIOR_CONTROL_ROOT",
                "replacement_pin": pin, "independent_control_verified": False,
            })
        if e["replacement_acquisition_sha256"] in old_acquisitions:
            findings.append({
                "reason": "SUCCESSOR_REUSES_PRIOR_ACQUISITION",
                "replacement_pin": pin, "independent_control_verified": False,
            })
        if e["replacement_source_root_sha256"] in old_sources:
            findings.append({
                "reason": "SUCCESSOR_REUSES_PRIOR_SOURCE_ROOT",
                "replacement_pin": pin, "independent_control_verified": False,
            })
        origin = (e["replacement_controller_sha256"],
                  e["replacement_source_root_sha256"],
                  e["replacement_acquisition_sha256"])
        if pin in old_signer_claims and origin not in old_signer_claims[pin]:
            findings.append({
                "reason": "SUCCESSOR_KEY_CHANGED_CLAIMED_ANCESTRY",
                "replacement_pin": pin, "independent_control_verified": False,
            })
    return findings

def audit(previous, current, checkpoint, public_key, signature, signer_pin,
          floor, observations, verifier=verify_key_and_signature):
    old, old_heads = checked_history(previous)
    recent, new_heads = checked_history(current)
    require(old and len(recent) > len(old),
            "successor revocation history must strictly extend predecessor")
    require(recent[:len(old)] == old and
            new_heads[:len(old_heads)] == old_heads,
            "revocation history prefix rewritten or truncated")
    for key in ("revoked_signer_pins", "revoked_controller_roots",
                "rotation_conflicts"):
        require(current[key][:len(previous[key])] == previous[key],
                "historical revocation evidence erased: " + key)
    expected = checkpoint_payload(previous)
    require(checkpoint == expected, "signed predecessor highwater substituted")
    check_sha(signer_pin, "checkpoint signing pin invalid")
    prior_replacements = {e["replacement_pin"] for e in recent}
    revoked = set(current["revoked_signer_pins"])
    require(signer_pin not in revoked and signer_pin not in prior_replacements
            and signer_pin not in {e["authority_pin"] for e in recent},
            "revoked, replacement or prior authority cannot self-sign highwater")
    signature_hash = verifier(public_key, signature, signer_pin,
                              canonical(expected))
    check_sha(signature_hash, "highwater signature fingerprint invalid")
    require(isinstance(floor, dict) and floor.get("phase") == "RUST-066",
            "separately retained revocation floor absent")
    n = floor.get("revocation_count")
    require(type(n) is int and len(old) <= n <= len(recent),
            "retained revocation floor outside successor history")
    check_sha(floor.get("head_sha256"), "retained head hash missing")
    require(new_heads[n] == floor["head_sha256"],
            "retained revocation highwater contradicts exact prefix")
    appended = recent[len(old):]
    require(isinstance(observations, list) and len(observations) == len(appended),
            "one successor custody observation required per new revocation")
    prior_nonces = {e["nonce_sha256"] for e in recent}
    observed_nonces = set()
    reviewed = []
    for event, observation in zip(appended, observations):
        require(isinstance(observation, dict) and
                observation.get("phase") == "RUST-066",
                "successor custody observation missing")
        for name in ("revocation_entry_sha256", "observation_nonce_sha256",
                     "claimed_controller_sha256",
                     "claimed_acquisition_sha256"):
            check_sha(observation.get(name), "successor observation missing " + name)
        require(observation["revocation_entry_sha256"] == event["entry_sha256"],
                "observation not bound to revocation event")
        require(observation["claimed_controller_sha256"] ==
                event["replacement_controller_sha256"] and
                observation["claimed_acquisition_sha256"] ==
                event["replacement_acquisition_sha256"],
                "successor observation changed claimed ancestry")
        nonce = observation["observation_nonce_sha256"]
        require(nonce not in prior_nonces and nonce not in observed_nonces,
                "successor custody observation replay")
        observed_nonces.add(nonce)
        require(observation.get("recovery_authorized") is False and
                observation.get("release_authorized") is False,
                "successor claimed restoration of authority")
        require(event.get("quarantined") is True and
                event.get("recovery_authorized") is False,
                "successor left quarantine")
        reviewed.append({
            "revocation_entry_sha256": event["entry_sha256"],
            "observation_sha256": digest(observation),
            "observation_nonce_sha256": nonce,
            "quarantine_persists": True,
            "independent_custody_verified": False,
            "recovery_authorized": False,
        })
    conflicts = ancestry_conflicts(old, appended)
    result = {
        "phase": "RUST-066",
        "status": "HOLD_REVOCATION_SUCCESSOR_QUARANTINE_HIGHWATER",
        "previous_rust065_receipt_sha256": previous["receipt_sha256"],
        "current_rust065_receipt_sha256": current["receipt_sha256"],
        "signed_checkpoint": expected,
        "checkpoint_signer_pin": signer_pin,
        "checkpoint_signature_sha256": signature_hash,
        "retained_floor_claim_sha256": digest(floor),
        "previous_revocation_count": len(old),
        "current_revocation_count": len(recent),
        "revocation_history_prefix_preserved": True,
        "revoked_signer_pins_preserved": current["revoked_signer_pins"],
        "revoked_controller_roots_preserved": current["revoked_controller_roots"],
        "historical_conflicts_preserved": previous["rotation_conflicts"],
        "current_conflicts_preserved": current["rotation_conflicts"],
        "successor_ancestry_conflicts": conflicts,
        "successor_observations": reviewed,
        "all_successors_quarantined": True,
        "independent_custody_verified": False,
        "globally_latest_highwater_verified": False,
        "global_anti_rollback_certified": False,
        "fork_resolved": False,
        "release_authorized": False,
        "live_gameplay_authority": False,
    }
    result["receipt_sha256"] = digest(result)
    return result

def hold():
    return {"phase": "RUST-066",
            "status": "HOLD_MISSING_REVOCATION_SUCCESSOR_HIGHWATER",
            "independent_custody_verified": False,
            "globally_latest_highwater_verified": False,
            "fork_resolved": False,
            "release_authorized": False,
            "live_gameplay_authority": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("previous", "current", "checkpoint", "public-key",
                 "signature", "signer-pin", "floor", "observations"):
        p.add_argument("--"+name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    bundle = [a.previous, a.current, a.checkpoint, a.public_key,
              a.signature, a.signer_pin, a.floor, a.observations]
    require(all(bundle) or not any(bundle),
            "partial signed revocation highwater bundle refused")
    if all(bundle):
        load = lambda x: json.loads(Path(x).read_text(encoding="utf-8"))
        result = audit(load(a.previous),load(a.current),load(a.checkpoint),
                       a.public_key,a.signature,a.signer_pin,
                       load(a.floor),load(a.observations))
    else:
        result = hold()
    dest = Path(a.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x", encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-066 HOLD: external revocation custody unverified")

if __name__ == "__main__":
    main()
