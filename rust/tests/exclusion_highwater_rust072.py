#!/usr/bin/env python3
"""RUST-072 — signed custodian exclusion highwater and permanent denial.

Local cryptographic verification is not independent external custody.
This protocol has no branch that authorizes recovery or release.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from custodian_exclusion_rust071 import checked_history

def highwater(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty RUST-071 predecessor required")
    return {"phase":"RUST-072","kind":"EXCLUSION_DENIAL_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "excluded_pins_sha256":digest(previous["excluded_pins"]),
            "excluded_controllers_sha256":digest(previous["excluded_controller_roots"]),
            "denials_sha256":digest(previous["recovery_denials"]),
            "conflicts_sha256":digest(previous["custody_conflicts"]),
            "source_rust071_receipt_sha256":previous["receipt_sha256"],
            "recovery_authorized":False,"release_authorized":False}

def audit(previous,current,checkpoint,key,signature,signer_pin,floor,
          observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "successor exclusion ledger must strictly extend predecessor")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historical denial events or predecessor heads rewritten")
    for field in ("excluded_pins","excluded_controller_roots","recovery_denials",
                  "custody_conflicts"):
        require(current[field][:len(previous[field])]==previous[field],
                "historic exclusions or denials erased: "+field)
    expected=highwater(previous)
    require(checkpoint==expected,"signed exclusion checkpoint substituted")
    check_sha(signer_pin,"highwater signer pin missing")
    prohibited=set(current["excluded_pins"])
    prohibited.update(e["candidate_pin"] for e in new)
    prohibited.update(e["challenger_pin"] for e in new)
    require(signer_pin not in prohibited,
            "excluded, candidate or challenger signer cannot self-attest highwater")
    signed=verifier(key,signature,signer_pin,canonical(expected))
    check_sha(signed,"highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-072",
            "separately retained exclusion floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retained exclusion floor outside successor history")
    check_sha(floor.get("head_sha256"),"retained floor head missing")
    require(new_heads[n]==floor["head_sha256"],
            "retained exclusion highwater contradicts exact prefix")
    appended=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(appended),
            "one fresh denial observation per new exclusion required")
    nonces={e["challenge_nonce_sha256"] for e in new}
    seen=set()
    prior_candidates={e["candidate_pin"]:set() for e in old}
    prior_controllers={}
    prior_acquisitions={}
    for event in old:
        prior_candidates[event["candidate_pin"]].add((
            event["candidate_controller_sha256"],
            event["candidate_source_root_sha256"],
            event["candidate_acquisition_sha256"]))
        prior_controllers.setdefault(event["candidate_controller_sha256"],set()).add(
            event["candidate_pin"])
        prior_acquisitions.setdefault(event["candidate_acquisition_sha256"],set()).add(
            event["candidate_pin"])
    conflicts=[];reviewed=[]
    for event,claim in zip(appended,observations):
        require(isinstance(claim,dict) and claim.get("phase")=="RUST-072",
                "cross-epoch denial observation missing")
        for field in ("denial_entry_sha256","observation_nonce_sha256",
                      "candidate_pin","controller_sha256",
                      "source_root_sha256","acquisition_sha256"):
            check_sha(claim.get(field),"denial observation field missing "+field)
        require(claim["denial_entry_sha256"]==event["entry_sha256"] and
                claim["candidate_pin"]==event["candidate_pin"],
                "denial observation not bound to excluded candidate")
        require(claim["controller_sha256"]==event["candidate_controller_sha256"] and
                claim["source_root_sha256"]==event["candidate_source_root_sha256"] and
                claim["acquisition_sha256"]==event["candidate_acquisition_sha256"],
                "denial observation substituted candidate ancestry")
        nonce=claim["observation_nonce_sha256"]
        require(nonce not in nonces and nonce not in seen,
                "denial observation nonce replay")
        seen.add(nonce)
        require(claim.get("recovery_denied") is True and
                claim.get("quarantine_persists") is True and
                claim.get("recovery_authorized") is False and
                claim.get("release_authorized") is False,
                "denial observation asserted release authority")
        pin=claim["candidate_pin"]
        if pin in current["excluded_pins"]:
            conflicts.append({"reason":"REVOKED_SIGNER_DENIAL_PERSISTS",
                              "pin":pin,"independent_custody_verified":False})
        if claim["controller_sha256"] in current["excluded_controller_roots"]:
            conflicts.append({"reason":"RENAMED_SIGNER_EXCLUDED_CONTROL_ROOT",
                              "pin":pin,"independent_custody_verified":False})
        origin=(claim["controller_sha256"],claim["source_root_sha256"],
                claim["acquisition_sha256"])
        if pin in prior_candidates and origin not in prior_candidates[pin]:
            conflicts.append({"reason":"SAME_SIGNER_CHANGED_DENIAL_ANCESTRY",
                              "pin":pin,"independent_custody_verified":False})
        prior_controller_pins=prior_controllers.get(claim["controller_sha256"],set())
        if prior_controller_pins and pin not in prior_controller_pins:
            conflicts.append({"reason":"RENAMED_SIGNER_SHARED_PRIOR_CONTROLLER",
                              "pin":pin,"independent_custody_verified":False})
        prior_acquisition_pins=prior_acquisitions.get(claim["acquisition_sha256"],set())
        if prior_acquisition_pins and pin not in prior_acquisition_pins:
            conflicts.append({"reason":"RENAMED_SIGNER_SHARED_PRIOR_ACQUISITION",
                              "pin":pin,"independent_custody_verified":False})
        reviewed.append({"denial_entry_sha256":event["entry_sha256"],
                         "observation_sha256":digest(claim),
                         "observation_nonce_sha256":nonce,
                         "recovery_denied":True,"independent_custody_verified":False})
    result={"phase":"RUST-072",
            "status":"HOLD_EXCLUSION_HIGHWATER_PERMANENT_DENIAL",
            "previous_rust071_receipt_sha256":previous["receipt_sha256"],
            "current_rust071_receipt_sha256":current["receipt_sha256"],
            "signed_checkpoint":expected,"checkpoint_signer_pin":signer_pin,
            "checkpoint_signature_sha256":signed,
            "retained_floor_claim_sha256":digest(floor),
            "previous_event_count":len(old),"current_event_count":len(new),
            "prior_excluded_pins_preserved":previous["excluded_pins"],
            "current_excluded_pins_preserved":current["excluded_pins"],
            "prior_excluded_controllers_preserved":previous["excluded_controller_roots"],
            "current_excluded_controllers_preserved":current["excluded_controller_roots"],
            "prior_recovery_denials_preserved":previous["recovery_denials"],
            "current_recovery_denials_preserved":current["recovery_denials"],
            "historical_conflicts_preserved":previous["custody_conflicts"],
            "current_conflicts_preserved":current["custody_conflicts"],
            "cross_epoch_denial_conflicts":conflicts,
            "cross_epoch_observations":reviewed,
            "all_recovery_denials_persist":True,
            "independent_custody_verified":False,
            "global_latest_highwater_verified":False,
            "global_anti_rollback_certified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-072",
            "status":"HOLD_MISSING_PERMANENT_DENIAL_HIGHWATER",
            "all_recovery_denials_persist":True,
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","key","signature",
                 "signer-pin","floor","observations"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    bundle=[a.previous,a.current,a.checkpoint,a.key,a.signature,a.signer_pin,
            a.floor,a.observations]
    require(all(bundle) or not any(bundle),"partial exclusion highwater bundle refused")
    if all(bundle):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(a.previous),read(a.current),read(a.checkpoint),
                  a.key,a.signature,a.signer_pin,read(a.floor),read(a.observations))
    else:out=hold()
    target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-072 HOLD: external recovery denial highwater unverified")
if __name__=="__main__":main()
