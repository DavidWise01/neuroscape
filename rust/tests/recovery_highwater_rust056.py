#!/usr/bin/env python3
"""RUST-056 — signed recovery highwater, epoch continuity, and rollback HOLD.

Verifies full RUST-055 recovery and RUST-054 revocation ancestry, a
signature over the predecessor recovery head, an externally supplied
retention floor, and successor observations. Neither possession of
signing keys nor declared source roots demonstrates independent custody.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from witness_recovery_rust055 import checked_recovery_history
from witness_revocation_rust054 import checked_history

def checkpoint_payload(ledger, revocation):
    entries, heads = checked_recovery_history(ledger)
    checked_history(revocation)
    require(entries, "nonempty recovery quarantine required")
    require(ledger.get("revoked_signer_pins_preserved") ==
            revocation["revoked_signer_pins"] and
            ledger.get("revoked_claimed_controllers_preserved") ==
            revocation["revoked_claimed_controllers"],
            "prior recovery does not preserve revocation registry")
    return {
        "phase": "RUST-056", "kind": "RECOVERY_QUARANTINE_HIGHWATER_V1",
        "recovery_event_count": len(entries),
        "recovery_head_sha256": heads[-1],
        "recovery_history_sha256": digest(entries),
        "recovery_receipt_sha256": ledger["receipt_sha256"],
        "revocation_receipt_sha256": revocation["receipt_sha256"],
        "revocation_head_sha256": revocation["head_sha256"],
        "release_authorized": False,
    }

def audit(previous, current, previous_revocation, current_revocation,
          checkpoint, public_key, signature, signing_pin, retained_floor,
          observations, verifier=verify_key_and_signature):
    prior, old_heads = checked_recovery_history(previous)
    latest, new_heads = checked_recovery_history(current)
    old_revokes, old_revoke_heads = checked_history(previous_revocation)
    new_revokes, new_revoke_heads = checked_history(current_revocation)
    require(prior and len(latest)>len(prior),
            "successor recovery history must strictly extend prior quarantine")
    require(latest[:len(prior)]==prior and
            new_heads[:len(old_heads)]==old_heads,
            "recovery history prefix rewritten or truncated")
    require(new_revokes[:len(old_revokes)]==old_revokes and
            new_revoke_heads[:len(old_revoke_heads)]==old_revoke_heads,
            "revocation ancestry rewritten or truncated")
    require(previous["revoked_signer_pins_preserved"] ==
            previous_revocation["revoked_signer_pins"] and
            previous["revoked_claimed_controllers_preserved"] ==
            previous_revocation["revoked_claimed_controllers"] and
            current["revoked_signer_pins_preserved"] ==
            current_revocation["revoked_signer_pins"] and
            current["revoked_claimed_controllers_preserved"] ==
            current_revocation["revoked_claimed_controllers"],
            "recovery does not retain exact revocation ancestry")
    all_revoked=set(current_revocation["revoked_signer_pins"])
    all_roots=set(current_revocation["revoked_claimed_controllers"])
    require(set(previous_revocation["revoked_signer_pins"])<=all_revoked and
            set(previous_revocation["revoked_claimed_controllers"])<=all_roots,
            "revoked witness or controller dropped")
    for e in latest:
        require(e.get("quarantine_persists") is True and
                e.get("independence_authenticated") is False and
                e.get("recovery_authorized") is False,
                "recovery candidate granted authority")
        require(e.get("revoked_signer_pin") in all_revoked,
                "recovery lost original revoked key")
        require(e.get("candidate_signer_pin") not in all_revoked,
                "later-revoked successor still represented as active")
    expected=checkpoint_payload(previous,previous_revocation)
    require(checkpoint==expected,"signed recovery checkpoint substituted")
    check_sha(signing_pin,"signed highwater witness pin invalid")
    require(signing_pin not in all_revoked,
            "revoked witness may not certify recovery highwater")
    signature_sha=verifier(public_key,signature,signing_pin,canonical(expected))
    check_sha(signature_sha,"highwater signature invalid")
    require(isinstance(retained_floor,dict) and
            retained_floor.get("phase")=="RUST-056",
            "separately retained recovery floor absent")
    n=retained_floor.get("recovery_event_count")
    require(type(n) is int and n>=len(prior),
            "recovery rollback below signed highwater")
    require(n<=len(latest),"recovery history withheld below retained floor")
    check_sha(retained_floor.get("recovery_head_sha256"),
              "retained recovery head invalid")
    require(new_heads[n]==retained_floor["recovery_head_sha256"],
            "retained recovery branch contradicts exact prefix")
    require(isinstance(observations,list) and
            len(observations)==len(latest)-len(prior),
            "each new recovery requires a successor observation")
    source_seen=set()
    used_nonces={e["candidate_nonce_sha256"] for e in latest}
    reviews=[]
    for event,obs in zip(latest[len(prior):],observations):
        require(isinstance(obs,dict),"successor observation missing")
        for key in ("recovery_entry_sha256","source_registry_receipt_sha256",
                    "observation_nonce_sha256","claimed_controller_sha256",
                    "acquisition_sha256","operator_control_sha256"):
            check_sha(obs.get(key),"successor evidence missing "+key)
        require(obs["recovery_entry_sha256"]==event["entry_sha256"] and
                obs["source_registry_receipt_sha256"]==
                current_revocation["receipt_sha256"],
                "successor observation not bound to recovery and revocation")
        nonce=obs["observation_nonce_sha256"]
        require(nonce not in source_seen and nonce not in used_nonces,
                "successor observation nonce replay")
        source_seen.add(nonce)
        require(obs["claimed_controller_sha256"]==
                event["claimed_controller_sha256"],
                "successor controller ancestry altered")
        require(obs.get("recovery_authorized") is False,
                "successor observation asserted authorization")
        reviews.append({
            "recovery_entry_sha256":event["entry_sha256"],
            "observation_sha256":digest(obs),
            "observation_nonce_sha256":nonce,
            "revoked_controller_claimed":
                obs["claimed_controller_sha256"] in all_roots,
            "independent_controller_verified":False,
            "recovery_authorized":False,
        })
    result={
        "phase":"RUST-056",
        "status":"HOLD_RECOVERY_QUARANTINE_HIGHWATER_UNVERIFIED",
        "previous_rust055_receipt_sha256":previous["receipt_sha256"],
        "current_rust055_receipt_sha256":current["receipt_sha256"],
        "current_rust054_receipt_sha256":current_revocation["receipt_sha256"],
        "signed_checkpoint":expected,
        "checkpoint_signature_sha256":signature_sha,
        "checkpoint_signing_pin":signing_pin,
        "retained_floor_claim_sha256":digest(retained_floor),
        "previous_recovery_count":len(prior),
        "current_recovery_count":len(latest),
        "revocation_history_prefix_preserved":True,
        "recovery_history_prefix_preserved":True,
        "successor_observations":reviews,
        "historical_recovery_attempts_preserved":latest,
        "revoked_witnesses_preserved":current_revocation["revoked_signer_pins"],
        "revoked_controllers_preserved":
            current_revocation["revoked_claimed_controllers"],
        "independent_external_custody_verified":False,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-056",
            "status":"HOLD_MISSING_RECOVERY_HIGHWATER_CUSTODY",
            "independent_external_custody_verified":False,
            "globally_latest_highwater_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False,
            "reason":"No signed predecessor recovery head and separately retained external floor"}

def main():
    p=argparse.ArgumentParser()
    for key in ("previous","current","previous-revocation",
                "current-revocation","checkpoint","public-key",
                "signature","signing-pin","floor","observations"):
        p.add_argument("--"+key)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    items=[a.previous,a.current,a.previous_revocation,
           a.current_revocation,a.checkpoint,a.public_key,
           a.signature,a.signing_pin,a.floor,a.observations]
    require(all(items) or not any(items),"partial recovery highwater bundle refused")
    if all(items):
        read=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(read(a.previous),read(a.current),
                     read(a.previous_revocation),read(a.current_revocation),
                     read(a.checkpoint),a.public_key,a.signature,a.signing_pin,
                     read(a.floor),read(a.observations))
    else:
        result=hold()
    dest=Path(a.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-056 HOLD: independently retained recovery authority unverified")

if __name__=="__main__":
    main()
