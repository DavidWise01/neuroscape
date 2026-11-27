#!/usr/bin/env python3
"""RUST-058 — signed custody-challenge highwater, multi-epoch ancestry fence.

Structural verification and pinned-key signature checks only. An external
floor or distinct signing keys do not establish independent external custody.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from recovery_custody_rust057 import checked_history

def checkpoint_payload(previous):
    entries, heads = checked_history(previous)
    require(entries, "previous custodian challenge history must be nonempty")
    return {
        "phase":"RUST-058",
        "kind":"RECOVERY_CUSTODY_HIGHWATER_V1",
        "challenge_count":len(entries),
        "head_sha256":heads[-1],
        "history_sha256":digest(entries),
        "upstream_rust057_receipt_sha256":previous["receipt_sha256"],
        "custody_conflicts_sha256":digest(previous["custody_conflicts"]),
        "release_authorized":False,
    }

def compare_ancestry(old, new):
    conflicts=[]
    old_by_key={}
    old_by_controller={}
    for entry in old:
        for witness in entry["witnesses"]:
            origin=(witness["claimed_controller_sha256"],
                    witness["claimed_source_root_sha256"],
                    witness["acquisition_sha256"])
            old_by_key.setdefault(witness["signer_pin"],set()).add(origin)
            old_by_controller.setdefault(origin[0],set()).add(witness["signer_pin"])
    for entry in new:
        for witness in entry["witnesses"]:
            pin=witness["signer_pin"]
            origin=(witness["claimed_controller_sha256"],
                    witness["claimed_source_root_sha256"],
                    witness["acquisition_sha256"])
            if pin in old_by_key and origin not in old_by_key[pin]:
                conflicts.append({
                    "reason":"SIGNER_ANCESTRY_CHANGED_ACROSS_EPOCHS",
                    "pin":pin,"current_origin":list(origin),
                    "prior_origins":sorted([list(x) for x in old_by_key[pin]]),
                    "independent_control_verified":False,
                })
            old_pins=old_by_controller.get(origin[0],set())
            if old_pins and pin not in old_pins:
                conflicts.append({
                    "reason":"RENAMED_CUSTODIAN_SAME_CLAIMED_CONTROLLER",
                    "pin":pin,"controller_sha256":origin[0],
                    "prior_pins":sorted(old_pins),
                    "independent_control_verified":False,
                })
    return conflicts

def audit(previous,current,checkpoint,public_key,signature,signer_pin,
          retained_floor,session_claims,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "successor challenge history must strictly advance")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "prior custodian challenge prefix rewritten or withheld")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],
            "earlier custody conflicts omitted")
    expected=checkpoint_payload(previous)
    require(checkpoint==expected,"signed custody highwater checkpoint substituted")
    check_sha(signer_pin,"custody highwater signer pin absent")
    seen_challenge_pins={c["signer_pin"] for e in new for c in e["witnesses"]}
    require(signer_pin not in seen_challenge_pins,
            "witness may not self-issue custody highwater")
    signed=verifier(public_key,signature,signer_pin,canonical(expected))
    check_sha(signed,"custody highwater signature digest invalid")
    require(isinstance(retained_floor,dict) and
            retained_floor.get("phase")=="RUST-058",
            "independently presented retained floor absent")
    n=retained_floor.get("challenge_count")
    require(type(n) is int and n>=len(old),
            "rollback below previously observed custody highwater")
    require(n<=len(new),"custodian challenges withheld below floor")
    check_sha(retained_floor.get("head_sha256"),"retained floor head invalid")
    require(new_heads[n]==retained_floor["head_sha256"],
            "competing highwater head at retained count")
    appended=new[len(old):]
    require(isinstance(session_claims,list) and
            len(session_claims)==len(appended),
            "each new custody challenge requires separate epoch claim")
    old_nonces={w["nonce_sha256"] for e in old for w in e["witnesses"]}
    new_nonces={w["nonce_sha256"] for e in new for w in e["witnesses"]}
    claim_nonces=set()
    observed=[]
    for entry,claim in zip(appended,session_claims):
        require(isinstance(claim,dict) and claim.get("phase")=="RUST-058",
                "invalid custody epoch claim")
        for k in ("challenge_entry_sha256","epoch_nonce_sha256",
                  "controller_sha256","acquisition_sha256"):
            check_sha(claim.get(k),"custody epoch field invalid: "+k)
        require(claim["challenge_entry_sha256"]==entry["entry_sha256"],
                "epoch claim not bound to challenge")
        nonce=claim["epoch_nonce_sha256"]
        require(nonce not in old_nonces and nonce not in new_nonces and
                nonce not in claim_nonces,
                "cross-epoch challenge nonce replay")
        claim_nonces.add(nonce)
        require(claim.get("release_authorized") is False,
                "epoch claim elevated authority")
        observed.append({
            "challenge_entry_sha256":entry["entry_sha256"],
            "claim_sha256":digest(claim),
            "nonce_sha256":nonce,
            "controller_sha256":claim["controller_sha256"],
            "acquisition_sha256":claim["acquisition_sha256"],
            "independent_custody_verified":False,
        })
    conflicts=compare_ancestry(old,appended)
    all_conflicts=previous["custody_conflicts"]+[
        c for e in appended for c in e["custody_conflicts"]]
    result={
        "phase":"RUST-058",
        "status":"HOLD_CUSTODIAN_HIGHWATER_INDEPENDENCE_UNVERIFIED",
        "previous_rust057_receipt_sha256":previous["receipt_sha256"],
        "current_rust057_receipt_sha256":current["receipt_sha256"],
        "signed_checkpoint":expected,
        "highwater_signer_pin":signer_pin,
        "highwater_signature_sha256":signed,
        "retained_floor_claim_sha256":digest(retained_floor),
        "previous_challenge_count":len(old),
        "current_challenge_count":len(new),
        "custody_history_prefix_preserved":True,
        "historical_custody_conflicts_preserved":previous["custody_conflicts"],
        "current_custody_conflicts_preserved":all_conflicts,
        "cross_epoch_ancestry_conflicts":conflicts,
        "new_epoch_observations":observed,
        "independent_custody_verified":False,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-058",
        "status":"HOLD_MISSING_CUSTODIAN_CHALLENGE_HIGHWATER",
        "independent_custody_verified":False,
        "globally_latest_highwater_verified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
        "reason":"Signed historical highwater and externally retained successor evidence absent",
    }

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","public-key","signature",
                 "signer-pin","floor","session-claims"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    vals=[a.previous,a.current,a.checkpoint,a.public_key,a.signature,
          a.signer_pin,a.floor,a.session_claims]
    require(all(vals) or not any(vals),
            "partial custody highwater material refused")
    if all(vals):
        doc=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        out=audit(doc(a.previous),doc(a.current),doc(a.checkpoint),
                  a.public_key,a.signature,a.signer_pin,doc(a.floor),
                  doc(a.session_claims))
    else:
        out=hold()
    path=Path(a.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-058 HOLD: real-world custodian independence unverified")

if __name__=="__main__":
    main()
