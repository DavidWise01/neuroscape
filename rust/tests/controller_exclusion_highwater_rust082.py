#!/usr/bin/env python3
"""RUST-082: signed controller exclusion highwater & permanent reentry denial.

Constrained local evidence only. Neither a signed checkpoint nor a claimed
retention floor proves independent custody, global latestness or release.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from controller_exclusion_rust081 import checked_history

EXCLUSIONS=("excluded_signer_pins","excluded_controllers",
            "excluded_source_roots","excluded_acquisitions")
DENIAL_FIELDS=("denied_reentries","custody_conflicts")
FALSITIES=("winner_selected","fork_resolved","independent_custody_verified",
           "recovery_authorized","release_authorized")

def highwater(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty RUST-081 controller exclusion history required")
    payload={"phase":"RUST-082","kind":"CONTROLLER_EXCLUSION_HIGHWATER_V1",
             "source_rust081_receipt_sha256":previous["receipt_sha256"],
             "event_count":len(events),"head_sha256":heads[-1],
             "events_sha256":digest(events),
             "both_branches_retained":True}
    for name in EXCLUSIONS+DENIAL_FIELDS:
        payload[name+"_sha256"]=digest(previous[name])
    payload.update({k:False for k in FALSITIES})
    return payload

def conflicts_from_prior(previous,new_denials):
    conflicts=[]
    named={
        "signer_pin":"excluded_signer_pins",
        "controller_sha256":"excluded_controllers",
        "source_root_sha256":"excluded_source_roots",
        "acquisition_sha256":"excluded_acquisitions"}
    for d in new_denials:
        matched=[field for field,excluded in named.items()
                 if d[field] in previous[excluded]]
        if matched:
            conflicts.append({
                "reason":"REENTRY_MATCHES_SIGNED_PRIOR_EXCLUSION",
                "role":d["role"],"signer_pin":d["signer_pin"],
                "matched_fields":matched,"reentry_denied":True,
                "independent_custody_verified":False})
        else:
            conflicts.append({
                "reason":"UNQUALIFIED_REENTRY_DENIED_WITHOUT_PRIOR_MATCH",
                "role":d["role"],"signer_pin":d["signer_pin"],
                "reentry_denied":True,"independent_custody_verified":False})
    return conflicts

def audit(previous,current,checkpoint,public_key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "controller exclusion highwater requires strict successor extension")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historical exclusion event or head rewritten")
    for name in EXCLUSIONS+DENIAL_FIELDS:
        require(current[name][:len(previous[name])]==previous[name],
                "historical exclusion or denial removed: "+name)
    require(all(e["both_branches_retained"] is True and
                all(e.get(k) is False for k in FALSITIES) for e in new),
            "controller recovery or branch winner falsely promoted")
    payload=highwater(previous)
    require(checkpoint==payload,"signed controller exclusion checkpoint substituted")
    check_sha(signer_pin,"highwater signing pin missing")
    banned=set(current["excluded_signer_pins"])
    banned.update(e["registrar_pin"] for e in new)
    require(signer_pin not in banned,
            "excluded custodian or registrar cannot sign controller highwater")
    signed=verifier(public_key,signature,signer_pin,canonical(payload))
    check_sha(signed,"highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-082",
            "retained controller floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retained controller floor outside known successor")
    check_sha(floor.get("head_sha256"),"retained controller floor invalid")
    require(new_heads[n]==floor["head_sha256"],
            "retained controller floor contradicts exact prefix")
    appended=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(appended),
            "one new controller-denial observation per epoch required")
    nonce_set={e["challenge_nonce_sha256"] for e in new}
    fresh=set();rows=[]
    new_denials=[]
    for event,ob in zip(appended,observations):
        require(isinstance(ob,dict) and ob.get("phase")=="RUST-082",
                "controller denial observation missing")
        for key in ("exclusion_entry_sha256","observation_nonce_sha256",
                    "denied_reentries_sha256","excluded_controllers_sha256",
                    "excluded_acquisitions_sha256"):
            check_sha(ob.get(key),"controller observation missing "+key)
        require(ob["exclusion_entry_sha256"]==event["entry_sha256"] and
                ob["denied_reentries_sha256"]==digest(event["denied_reentries"])
                and ob["excluded_controllers_sha256"]==
                    digest(event["excluded_controllers"])
                and ob["excluded_acquisitions_sha256"]==
                    digest(event["excluded_acquisitions"]),
                "controller denial snapshot or ancestry substituted")
        nonce=ob["observation_nonce_sha256"]
        require(nonce not in nonce_set and nonce not in fresh,
                "controller denial observation nonce replay")
        fresh.add(nonce)
        require(ob.get("all_reentries_denied") is True and
                ob.get("both_branches_retained") is True and
                all(ob.get(k) is False for k in FALSITIES),
                "fabricated recovery or controller reentry clearance")
        new_denials.extend(event["denied_reentries"])
        rows.append({"exclusion_entry_sha256":event["entry_sha256"],
                     "observation_sha256":digest(ob),
                     "observation_nonce_sha256":nonce,
                     "all_reentries_denied":True,
                     "independent_custody_verified":False})
    result={"phase":"RUST-082",
            "status":"HOLD_CONTROLLER_EXCLUSION_HIGHWATER_REENTRY_DENIAL",
            "previous_rust081_receipt_sha256":previous["receipt_sha256"],
            "current_rust081_receipt_sha256":current["receipt_sha256"],
            "signed_checkpoint":payload,
            "checkpoint_signer_pin":signer_pin,
            "checkpoint_signature_sha256":signed,
            "retained_floor_claim_sha256":digest(floor),
            "previous_count":len(old),"current_count":len(new),
            "new_observations":rows,
            "cross_epoch_reentry_conflicts":conflicts_from_prior(previous,new_denials),
            "all_reentries_denied":True,
            "both_branches_retained":True,
            "globally_latest_highwater_verified":False,
            "global_anti_rollback_certified":False,
            "live_gameplay_authority":False}
    for name in EXCLUSIONS+DENIAL_FIELDS:
        result["historical_"+name]=previous[name]
        result["current_"+name]=current[name]
    result.update({k:False for k in FALSITIES})
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-082",
            "status":"HOLD_MISSING_CONTROLLER_EXCLUSION_HIGHWATER",
            "all_reentries_denied":True,
            "both_branches_retained":False,
            "live_gameplay_authority":False,
            **{k:False for k in FALSITIES}}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","public-key",
                 "signature","signer-pin","floor","observations"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    bundle=[args.previous,args.current,args.checkpoint,args.public_key,
            args.signature,args.signer_pin,args.floor,args.observations]
    require(all(bundle) or not any(bundle),"partial controller highwater evidence refused")
    if all(bundle):
        load=lambda v:json.loads(Path(v).read_text(encoding="utf-8"))
        result=audit(load(args.previous),load(args.current),load(args.checkpoint),
                     args.public_key,args.signature,args.signer_pin,
                     load(args.floor),load(args.observations))
    else:result=hold()
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2);stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-082 HOLD: independent controller highwater absent")
if __name__=="__main__":main()
