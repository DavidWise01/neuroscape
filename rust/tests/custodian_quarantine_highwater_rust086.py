#!/usr/bin/env python3
"""RUST-086 — signed cross-custodian highwater and quarantine retention.

Only consistency of supplied signed claims is checked. All evidence remains
HOLD; no external custody, rollback authority or live gameplay promotion.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from cross_custodian_control_rust085 import checked_history,compare
from exclusion_custody_rust083 import FALSE,FIELDS,EXCLUSIONS,DENIAL_FIELDS

RETAIN=("custodian_claims","quarantined_claims","custody_conflicts",
        "excluded_snapshots","denial_snapshots")

def checkpoint(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty RUST-085 quarantine predecessor required")
    result={"phase":"RUST-086","kind":"CROSS_CUSTODIAN_QUARANTINE_HIGHWATER_V1",
        "source_rust085_receipt_sha256":previous["receipt_sha256"],
        "event_count":len(events),"head_sha256":heads[-1],
        "events_sha256":digest(events),"both_branches_retained":True}
    for field in RETAIN:
        result[field+"_sha256"]=digest(previous[field])
    result.update({key:False for key in FALSE})
    return result

def reentry_conflicts(past,added):
    observations=[]
    historical_claims=[c for e in past for c in e["claims"]]
    prior_quarantined_pins={q["pin"] for e in past for q in e["quarantined_claims"]}
    for event in added:
        witnesses=event["claims"]
        observations.extend(compare(historical_claims,witnesses))
        for claim in witnesses:
            if claim["pin"] in prior_quarantined_pins:
                observations.append({"reason":"QUARANTINED_CUSTODIAN_REENTERED",
                    "pin":claim["pin"],"independent_custody_verified":False})
        historical_claims.extend(witnesses)
    return observations

def audit(previous,current,payload,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    prior,prior_heads=checked_history(previous)
    later,later_heads=checked_history(current)
    require(prior and len(later)>len(prior),
            "cross-custodian successor must strictly extend predecessor")
    require(later[:len(prior)]==prior
            and later_heads[:len(prior_heads)]==prior_heads,
            "historical cross-custodian chain rewritten")
    for field in RETAIN:
        require(current[field][:len(previous[field])]==previous[field],
                "historical quarantine or denial erased: "+field)
    for event in later:
        require(event["both_branches_retained"] is True
                and all(event.get(k) is False for k in FALSE)
                and all(q.get("custody_independence_quarantined") is True
                        and q.get("independent_custody_verified") is False
                        for q in event["quarantined_claims"]),
                "historical quarantine improperly cleared")
    expected=checkpoint(previous)
    require(payload==expected,"signed control quarantine highwater substituted")
    check_sha(signer_pin,"highwater signer pin missing")
    banned={c["pin"] for c in current["custodian_claims"]}
    banned.update(e["registrar_pin"] for e in later)
    for e in later:
        banned.update(e["excluded_snapshot"]["excluded_signer_pins"])
    require(signer_pin not in banned,
            "custodian or registrar cannot self-sign highwater")
    signed=verifier(key,signature,signer_pin,canonical(expected))
    check_sha(signed,"invalid quarantine highwater signature")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-086",
            "retained quarantine floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(prior)<=n<=len(later),
            "quarantine floor outside successor")
    check_sha(floor.get("head_sha256"),"retained quarantine floor invalid")
    require(later_heads[n]==floor["head_sha256"],
            "retained quarantine floor contradicts prefix")
    added=later[len(prior):]
    require(isinstance(observations,list) and len(observations)==len(added),
            "fresh quarantine observation required per appended epoch")
    existing={e["challenge_nonce_sha256"] for e in later}
    seen=set();rows=[]
    for event,ob in zip(added,observations):
        require(isinstance(ob,dict) and ob.get("phase")=="RUST-086",
                "quarantine observation missing")
        for key in ("entry_sha256","nonce_sha256","claims_sha256",
                    "quarantine_sha256","exclusions_sha256","denials_sha256"):
            check_sha(ob.get(key),"quarantine observation field missing "+key)
        require(ob["entry_sha256"]==event["entry_sha256"]
                and ob["claims_sha256"]==event["claims_sha256"]
                and ob["quarantine_sha256"]==digest(event["quarantined_claims"])
                and ob["exclusions_sha256"]==event["excluded_snapshot_sha256"]
                and ob["denials_sha256"]==event["denial_snapshot_sha256"],
                "quarantine observation substituted source evidence")
        nonce=ob["nonce_sha256"]
        require(nonce not in existing and nonce not in seen,
                "quarantine observation nonce replay")
        seen.add(nonce)
        require(ob.get("both_quarantined") is True
                and ob.get("both_branches_retained") is True
                and all(ob.get(k) is False for k in FALSE),
                "quarantine observation falsely cleared independence")
        rows.append({"entry_sha256":event["entry_sha256"],
                     "observation_sha256":digest(ob),"nonce_sha256":nonce,
                     "both_quarantined":True,
                     "independent_custody_verified":False})
    output={"phase":"RUST-086",
        "status":"HOLD_CROSS_CUSTODIAN_QUARANTINE_HIGHWATER",
        "previous_rust085_receipt_sha256":previous["receipt_sha256"],
        "current_rust085_receipt_sha256":current["receipt_sha256"],
        "signed_checkpoint":expected,
        "checkpoint_signer_pin":signer_pin,
        "checkpoint_signature_sha256":signed,
        "retained_floor_sha256":digest(floor),
        "previous_count":len(prior),"current_count":len(later),
        "new_observations":rows,
        "cross_epoch_quarantine_conflicts":reentry_conflicts(prior,added),
        "both_quarantined":True,"both_branches_retained":True,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False}
    for field in RETAIN:
        output["historical_"+field]=previous[field]
        output["current_"+field]=current[field]
    output.update({k:False for k in FALSE})
    output["receipt_sha256"]=digest(output)
    return output

def hold():
    return {"phase":"RUST-086",
        "status":"HOLD_MISSING_CROSS_CUSTODIAN_QUARANTINE_HIGHWATER",
        "both_quarantined":False,"both_branches_retained":False,
        **{k:False for k in FALSE}}

def main():
    p=argparse.ArgumentParser()
    for key in ("previous","current","checkpoint","key","signature",
                "signer-pin","floor","observations"):
        p.add_argument("--"+key)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.previous,a.current,a.checkpoint,a.key,a.signature,
              a.signer_pin,a.floor,a.observations]
    require(all(required) or not any(required),
            "partial quarantine highwater bundle refused")
    if all(required):
        read=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(read(a.previous),read(a.current),read(a.checkpoint),
                     a.key,a.signature,a.signer_pin,read(a.floor),
                     read(a.observations))
    else:result=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-086 HOLD: independent third-party control unverified")
if __name__=="__main__":main()
