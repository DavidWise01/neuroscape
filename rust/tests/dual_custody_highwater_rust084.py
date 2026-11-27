#!/usr/bin/env python3
"""RUST-084: signed dual-custody highwater; immutable exclusion and denial ancestry.

This proves only consistency of supplied signed claims. It cannot establish
independent real-world custody, external retention, or globally latest state.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from exclusion_custody_rust083 import checked_history,FIELDS,FALSE,EXCLUSIONS,DENIAL_FIELDS

def checkpoint(previous):
    rows,heads=checked_history(previous)
    require(rows,"nonempty RUST-083 custody predecessor required")
    return {"phase":"RUST-084","kind":"DUAL_EXCLUSION_CUSTODY_HIGHWATER_V1",
        "source_rust083_receipt_sha256":previous["receipt_sha256"],
        "event_count":len(rows),"head_sha256":heads[-1],
        "events_sha256":digest(rows),
        "witness_pairs_sha256":digest([e["witnesses"] for e in rows]),
        "exclusion_snapshots_sha256":digest(previous["excluded_snapshots"]),
        "denial_snapshots_sha256":digest(previous["denial_snapshots"]),
        "conflicts_sha256":digest(previous["custody_conflicts"]),
        "both_branches_retained":True,
        **{k:False for k in FALSE}}

def witness_conflicts(previous,appended):
    past=[w for event in previous for w in event["witnesses"]]
    findings=[]
    for event in appended:
        left,right=event["witnesses"]
        for field in FIELDS:
            if left[field]==right[field]:
                findings.append({"reason":"NEW_PAIR_SHARED_CONTROL_ANCESTRY",
                    "field":field,"independent_custody_verified":False})
        for witness in (left,right):
            for older in past:
                shared=[k for k in FIELDS if witness[k]==older[k]]
                if witness["pin"]!=older["pin"] and shared:
                    findings.append({"reason":"RENAMED_WITNESS_REUSED_PREVIOUS_CONTROL",
                        "pin":witness["pin"],"fields":shared,
                        "independent_custody_verified":False})
                if witness["pin"]==older["pin"]:
                    changed=[k for k in FIELDS if witness[k]!=older[k]]
                    if changed:
                        findings.append({"reason":"SAME_WITNESS_CHANGED_CONTROL_ANCESTRY",
                            "pin":witness["pin"],"fields":changed,
                            "independent_custody_verified":False})
    return findings

def audit(previous,current,signed_checkpoint,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    prior,prior_heads=checked_history(previous)
    later,later_heads=checked_history(current)
    require(prior and len(later)>len(prior),
            "dual custody successor must strictly extend previous ledger")
    require(later[:len(prior)]==prior and
            later_heads[:len(prior_heads)]==prior_heads,
            "old dual custody chain rewritten")
    for field in ("excluded_snapshots","denial_snapshots","custody_conflicts"):
        require(current[field][:len(previous[field])]==previous[field],
                "historical custody exclusion or denial erased: "+field)
    wanted=checkpoint(previous)
    require(signed_checkpoint==wanted,"signed custody highwater substituted")
    check_sha(signer_pin,"custody highwater signing pin invalid")
    excluded={w["pin"] for e in later for w in e["witnesses"]}
    for e in later:
        excluded.update(e["exclusions"]["excluded_signer_pins"])
    require(signer_pin not in excluded,
            "excluded custodian/witness cannot self-sign highwater")
    signed=verifier(key,signature,signer_pin,canonical(wanted))
    check_sha(signed,"custody highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-084",
            "independent retained-floor claim missing")
    n=floor.get("event_count")
    require(type(n) is int and len(prior)<=n<=len(later),
            "retention floor outside successor history")
    check_sha(floor.get("head_sha256"),"retained-floor head invalid")
    require(later_heads[n]==floor["head_sha256"],
            "retention floor contradicts exact custody prefix")
    appended=later[len(prior):]
    require(isinstance(observations,list) and len(observations)==len(appended),
            "one custody snapshot observation required for every new epoch")
    used={w["nonce_sha256"] for e in later for w in e["witnesses"]}
    fresh=set();recorded=[]
    conflicts=witness_conflicts(prior,appended)
    for event,ob in zip(appended,observations):
        require(isinstance(ob,dict) and ob.get("phase")=="RUST-084",
                "custody observation missing")
        for key in ("custody_entry_sha256","nonce_sha256","witnesses_sha256",
                    "exclusions_sha256","denials_sha256"):
            check_sha(ob.get(key),"custody observation field missing "+key)
        require(ob["custody_entry_sha256"]==event["entry_sha256"]
                and ob["witnesses_sha256"]==digest(event["witnesses"])
                and ob["exclusions_sha256"]==event["exclusions_sha256"]
                and ob["denials_sha256"]==event["denials_sha256"],
                "custody observation substituted witnesses or denials")
        nonce=ob["nonce_sha256"]
        require(nonce not in used and nonce not in fresh,
                "custody observation nonce replay")
        fresh.add(nonce)
        require(ob.get("all_denials_retained") is True and
                ob.get("both_branches_retained") is True and
                all(ob.get(k) is False for k in FALSE),
                "custody observation asserted independence/recovery/release")
        recorded.append({"custody_entry_sha256":event["entry_sha256"],
                         "observation_sha256":digest(ob),
                         "nonce_sha256":nonce,
                         "all_denials_retained":True,
                         "independent_custody_verified":False})
    out={"phase":"RUST-084",
         "status":"HOLD_DUAL_CUSTODY_HIGHWATER_DENIAL_RETENTION",
         "previous_rust083_receipt_sha256":previous["receipt_sha256"],
         "current_rust083_receipt_sha256":current["receipt_sha256"],
         "signed_checkpoint":wanted,"checkpoint_signature_sha256":signed,
         "checkpoint_signer_pin":signer_pin,
         "retained_floor_claim_sha256":digest(floor),
         "previous_count":len(prior),"current_count":len(later),
         "historical_witness_pairs":[e["witnesses"] for e in prior],
         "current_witness_pairs":[e["witnesses"] for e in later],
         "historical_exclusions":previous["excluded_snapshots"],
         "current_exclusions":current["excluded_snapshots"],
         "historical_denials":previous["denial_snapshots"],
         "current_denials":current["denial_snapshots"],
         "historical_conflicts":previous["custody_conflicts"],
         "current_conflicts":current["custody_conflicts"],
         "cross_epoch_conflicts":conflicts,
         "new_custody_observations":recorded,
         "all_denials_retained":True,"both_branches_retained":True,
         "globally_latest_highwater_verified":False,
         "global_anti_rollback_certified":False,
         **{k:False for k in FALSE}}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-084",
            "status":"HOLD_MISSING_DUAL_CUSTODY_HIGHWATER",
            "all_denials_retained":False,
            "both_branches_retained":False,
            **{k:False for k in FALSE}}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","key","signature",
                 "signer-pin","floor","observations"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    arguments=[a.previous,a.current,a.checkpoint,a.key,a.signature,
               a.signer_pin,a.floor,a.observations]
    require(all(arguments) or not any(arguments),"partial highwater evidence refused")
    if all(arguments):
        load=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        out=audit(load(a.previous),load(a.current),load(a.checkpoint),
                  a.key,a.signature,a.signer_pin,
                  load(a.floor),load(a.observations))
    else:out=hold()
    path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-084 HOLD: independent custody not established")
if __name__=="__main__":
    main()
