#!/usr/bin/env python3
"""RUST-043 — signed challenge highwater and dual-signed attestor rotation.

Cryptographic verification is relative to caller-supplied SPKI pins.
External retention, operator identity and globally latest custody are
not established by supplying signed JSON. All outcomes remain HOLD.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from challenge_ledger_rust042 import checked_history, check_floor

def highwater_payload(ledger):
    entries, heads=checked_history(ledger)
    require(ledger["epoch"]>=1,"signed highwater requires nonempty challenge history")
    return {
        "phase":"RUST-043","kind":"SIGNED_CHALLENGE_HIGHWATER",
        "epoch":ledger["epoch"],
        "entry_count":len(entries),
        "head_sha256":heads[-1],
        "ledger_receipt_sha256":ledger["receipt_sha256"],
        "entry_history_sha256":digest(entries),
        "release_authorized":False,
    }

def rotation_payload(prior, current, role, old_pin, new_pin):
    prior_entries,_=checked_history(prior)
    current_entries,_=checked_history(current)
    require(current["epoch"]==prior["epoch"]+1,"rotation requires adjacent epochs")
    require(current_entries[:len(prior_entries)]==prior_entries,
            "rotation prior history rewritten")
    before=[x for x in prior_entries if x["role"]==role]
    after=[x for x in current_entries if x["role"]==role]
    require(before and len(after)==len(before)+1,"missing adjoining attestor evidence")
    a,b=before[-1],after[-1]
    check_sha(old_pin,"old attestor pin invalid")
    check_sha(new_pin,"new attestor pin invalid")
    require(old_pin!=new_pin,"same key is not a rotation")
    require(a["attestor_key_spki_sha256"]==old_pin and
            b["attestor_key_spki_sha256"]==new_pin,
            "rotation pins do not match signed ledger")
    return {
        "phase":"RUST-043","kind":"DUAL_SIGNED_ATTESTOR_ROTATION",
        "role":role,
        "from_epoch":prior["epoch"],"to_epoch":current["epoch"],
        "from_ledger_receipt_sha256":prior["receipt_sha256"],
        "to_ledger_receipt_sha256":current["receipt_sha256"],
        "prior_challenge_sha256":a["entry_sha256"],
        "next_challenge_sha256":b["entry_sha256"],
        "old_attestor_spki_sha256":old_pin,
        "new_attestor_spki_sha256":new_pin,
        "old_attestor_root_sha256":a["external_attestor_root_sha256"],
        "new_attestor_root_sha256":b["external_attestor_root_sha256"],
        "release_authorized":False,
    }

def audit(prior,current,checkpoint,highwater_key,highwater_signature,
          highwater_pin,rotations,floor,verifier=verify_key_and_signature):
    prior_entries,prior_heads=checked_history(prior)
    current_entries,current_heads=checked_history(current)
    require(prior["epoch"]>=1 and current["epoch"]==prior["epoch"]+1,
            "highwater transition is not adjacent")
    require(current_entries[:len(prior_entries)]==prior_entries and
            current_heads[:len(prior_heads)]==prior_heads,
            "prior challenge history rewritten or truncated")
    require(isinstance(floor,dict),"externally retained highwater floor required")
    check_floor(floor,current_heads)
    require(floor["entry_count"]>=len(prior_entries),
            "retained floor does not cover complete prior epoch")
    expected=highwater_payload(prior)
    require(isinstance(checkpoint,dict) and checkpoint==expected,
            "signed highwater checkpoint does not match prior ledger")
    check_sha(highwater_pin,"externally retained highwater key pin absent")
    checkpoint_sig=verifier(highwater_key,highwater_signature,
                            highwater_pin,canonical(expected))
    check_sha(checkpoint_sig,"invalid highwater signature digest")
    require(isinstance(rotations,list),"rotation evidence list required")
    expected_roles=[]
    for role in ROLES:
        past=[x for x in prior_entries if x["role"]==role][-1]
        next_=[x for x in current_entries if x["role"]==role][-1]
        if (past["attestor_key_spki_sha256"] != next_["attestor_key_spki_sha256"]
                or past["external_attestor_root_sha256"] != next_["external_attestor_root_sha256"]):
            expected_roles.append(role)
    require(len(rotations)==len(expected_roles),"missing or extra attestor rotations")
    verified=[]
    for item,role in zip(rotations,expected_roles):
        require(isinstance(item,dict) and item.get("role")==role,
                "rotation role order mismatch")
        old_pin=item.get("old_attestor_spki_sha256")
        new_pin=item.get("new_attestor_spki_sha256")
        msg=rotation_payload(prior,current,role,old_pin,new_pin)
        require(item.get("payload")==msg,
                "rotation message differs from exact challenge history")
        oldsig=verifier(item.get("old_public_key"),item.get("old_signature"),
                        old_pin,canonical(msg))
        newsig=verifier(item.get("new_public_key"),item.get("new_signature"),
                        new_pin,canonical(msg))
        check_sha(oldsig,"old attestor signature invalid")
        check_sha(newsig,"new attestor signature invalid")
        verified.append({
            "role":role,"transition_sha256":digest(msg),
            "old_attestor_spki_sha256":old_pin,"new_attestor_spki_sha256":new_pin,
            "old_signature_sha256":oldsig,"new_signature_sha256":newsig,
            "dual_signature_verified":True,
            "independent_operator_control_verified":False,
        })
    conflicts=current.get("attestor_continuity_conflicts",[])
    require(isinstance(conflicts,list),"missing inherited conflicts")
    result={
        "phase":"RUST-043","status":"HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED"
            if verified or conflicts else "HOLD_EXTERNAL_HIGHWATER_UNVERIFIED",
        "prior_rust042_receipt_sha256":prior["receipt_sha256"],
        "current_rust042_receipt_sha256":current["receipt_sha256"],
        "signed_highwater_checkpoint":expected,
        "highwater_witness_spki_sha256":highwater_pin,
        "highwater_signature_sha256":checkpoint_sig,
        "floor_claim_sha256":digest(floor),
        "verified_rotation_signatures":verified,
        "preserved_attestor_conflicts":conflicts,
        "historical_prefix_preserved":True,
        "external_floor_custody_verified":False,
        "attestor_identity_independently_verified":False,
        "latest_external_epoch_authenticated":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-043","status":"HOLD_MISSING_SIGNED_CHALLENGE_HIGHWATER",
        "verified_rotation_signatures":[],
        "external_floor_custody_verified":False,
        "latest_external_epoch_authenticated":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
        "reason":"External highwater, exact retained floor or dual-signed rotation materials absent",
    }

def main():
    p=argparse.ArgumentParser()
    for field in ("prior","current","checkpoint","highwater-key",
                  "highwater-signature","rotations","floor"):
        p.add_argument("--"+field)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    names=[a.prior,a.current,a.checkpoint,a.highwater_key,
           a.highwater_signature,a.rotations,a.floor]
    require(all(names) or not any(names),"partial highwater/rotation evidence refused")
    if all(names):
        pin=os.getenv("RUST043_HIGHWATER_WITNESS_SPKI_SHA256")
        require(pin,"external highwater witness pin missing")
        prior,current,checkpoint,rotations,floor=[
            json.loads(Path(x).read_text(encoding="utf-8")) for x in
            (a.prior,a.current,a.checkpoint,a.rotations,a.floor)]
        result=audit(prior,current,checkpoint,a.highwater_key,
                     a.highwater_signature,pin,rotations,floor)
    else:
        result=hold()
    path=Path(a.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as out:
        json.dump(result,out,indent=2,sort_keys=True)
        out.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-043 HOLD: independent latest challenge custody unproven")
if __name__=="__main__":
    main()
