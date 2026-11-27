#!/usr/bin/env python3
"""RUST-085 — cross-custodian control ancestry and independent-claim quarantine.

Two signed witness records are still a single *claimed* evidence ancestry.
This stage does not authenticate external custody, change release authority,
or elect a winner. Historical conflicts and denials are never erased.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from exclusion_custody_rust083 import (
    checked_history as checked_custody,FIELDS,FALSE,EXCLUSIONS,DENIAL_FIELDS)

GENESIS=digest({"phase":"RUST-085","kind":"CROSS_CUSTODIAN_CONTROL_GENESIS_V1"})

def source_event(highwater,custody):
    require(isinstance(highwater,dict) and
            highwater.get("phase")=="RUST-084" and
            highwater.get("status")=="HOLD_DUAL_CUSTODY_HIGHWATER_DENIAL_RETENTION"
            and highwater.get("all_denials_retained") is True
            and highwater.get("both_branches_retained") is True
            and all(highwater.get(k) is False for k in FALSE),
            "RUST-084 highwater absent or promoted")
    require(highwater.get("receipt_sha256")==digest({
        k:v for k,v in highwater.items() if k!="receipt_sha256"}),
        "RUST-084 receipt altered")
    events,_=checked_custody(custody)
    require(events and highwater.get("current_rust083_receipt_sha256")==
            custody["receipt_sha256"] and highwater.get("current_count")==len(events)
            and highwater.get("current_witness_pairs")==[e["witnesses"] for e in events]
            and highwater.get("current_exclusions")==custody["excluded_snapshots"]
            and highwater.get("current_denials")==custody["denial_snapshots"]
            and highwater.get("current_conflicts")==custody["custody_conflicts"],
            "RUST-084 source does not bind complete custody evidence")
    new=highwater.get("new_custody_observations")
    require(isinstance(new,list) and len(new)==1 and
            new[0].get("custody_entry_sha256")==events[-1]["entry_sha256"],
            "new custody observation unbound")
    return events[-1]

def genesis():
    out={"phase":"RUST-085","status":"HOLD_CROSS_CUSTODIAN_CONTROL_QUARANTINE",
         "events":[],"prefix_heads":[GENESIS],"event_count":0,
         "head_sha256":GENESIS,"custodian_claims":[],
         "quarantined_claims":[],"custody_conflicts":[],
         "excluded_snapshots":[],"denial_snapshots":[],
         "both_branches_retained":False,**{k:False for k in FALSE}}
    out["receipt_sha256"]=digest(out)
    return out

def claim_rows(event):
    return [{"role":w["role"],"pin":w["pin"],"nonce_sha256":w["nonce_sha256"],
             "signature_sha256":w["signature_sha256"],
             "message_sha256":w["message_sha256"],
             "custody_entry_sha256":event["entry_sha256"],
             **{k:w[k] for k in FIELDS},
             "independent_custody_verified":False}
            for w in event["witnesses"]]

def compare(old,new):
    conflicts=[]
    left,right=new
    shared=[k for k in FIELDS if left[k]==right[k]]
    if shared:
        conflicts.append({"reason":"CURRENT_CUSTODIANS_SHARE_CLAIMED_CONTROL",
                          "fields":shared,"independent_custody_verified":False})
    for claim in new:
        for historical in old:
            if claim["pin"]!=historical["pin"]:
                matching=[k for k in FIELDS if claim[k]==historical[k]]
                if matching:
                    conflicts.append({
                        "reason":"RENAMED_CUSTODIAN_REUSES_CONTROL_ANCESTRY",
                        "pin":claim["pin"],"prior_pin":historical["pin"],
                        "fields":matching,"independent_custody_verified":False})
            else:
                changed=[k for k in FIELDS if claim[k]!=historical[k]]
                if changed:
                    conflicts.append({
                        "reason":"CUSTODIAN_PIN_CHANGED_DECLARED_CONTROL",
                        "pin":claim["pin"],"fields":changed,
                        "independent_custody_verified":False})
    return conflicts

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-085"
            and history.get("status")=="HOLD_CROSS_CUSTODIAN_CONTROL_QUARANTINE"
            and all(history.get(k) is False for k in FALSE),
            "RUST-085 historical registry missing or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list)
            and len(heads)==len(events)+1 and heads[0]==GENESIS,
            "historical control registry truncated")
    head=GENESIS
    claims=[];quarantines=[];conflicts=[];excluded=[];denials=[]
    sources=set();nonces=set()
    for index,event in enumerate(events,1):
        require(isinstance(event,dict) and event.get("phase")=="RUST-085"
                and event.get("kind")=="CONTROL_QUARANTINE_SNAPSHOT_V1"
                and event.get("ordinal")==index
                and event.get("previous_entry_sha256")==head
                and event.get("both_branches_retained") is True
                and all(event.get(k) is False for k in FALSE),
                "historical quarantine falsely promoted")
        for field in ("source_rust084_receipt_sha256","source_rust083_receipt_sha256",
                      "custody_entry_sha256","registrar_pin","challenge_nonce_sha256",
                      "signature_sha256","challenge_sha256","claims_sha256",
                      "excluded_snapshot_sha256","denial_snapshot_sha256"):
            check_sha(event.get(field),"historical control evidence missing "+field)
        require(event["source_rust084_receipt_sha256"] not in sources and
                event["challenge_nonce_sha256"] not in nonces,
                "historical source or nonce replay")
        sources.add(event["source_rust084_receipt_sha256"])
        nonces.add(event["challenge_nonce_sha256"])
        pair=event.get("claims")
        require(isinstance(pair,list) and len(pair)==2
                and [w.get("role") for w in pair]==["left","right"]
                and pair[0]["pin"]!=pair[1]["pin"],
                "historical custody pair incomplete")
        for claim in pair:
            for k in ("pin","nonce_sha256","message_sha256","signature_sha256",
                      "custody_entry_sha256",*FIELDS):
                check_sha(claim.get(k),"custody control claim malformed "+k)
            require(claim.get("independent_custody_verified") is False and
                    claim["custody_entry_sha256"]==event["custody_entry_sha256"],
                    "historical control claim changed")
        require(digest(pair)==event["claims_sha256"],
                "historical custodian claims substituted")
        require(isinstance(event.get("quarantined_claims"),list)
                and len(event["quarantined_claims"])==2
                and all(r.get("custody_independence_quarantined") is True
                        and r.get("independent_custody_verified") is False
                        and r.get("role") in ("left","right")
                        for r in event["quarantined_claims"]),
                "quarantine row cleared")
        for w,quarantine in zip(pair,event["quarantined_claims"]):
            require(quarantine["role"]==w["role"]
                    and quarantine.get("pin")==w["pin"]
                    and quarantine.get("claim_sha256")==digest(w),
                    "quarantine row lost witness binding")
        snapshot=event.get("excluded_snapshot")
        denial=event.get("denial_snapshot")
        require(isinstance(snapshot,dict) and
                all(isinstance(snapshot.get(k),list) for k in EXCLUSIONS)
                and isinstance(denial,dict) and
                all(isinstance(denial.get(k),list) for k in DENIAL_FIELDS),
                "source exclusion and denial snapshots missing")
        require(event["excluded_snapshot_sha256"]==digest(snapshot)
                and event["denial_snapshot_sha256"]==digest(denial),
                "source exclusion or denial digest altered")
        if excluded:
            for key in EXCLUSIONS:
                require(snapshot[key][:len(excluded[-1][key])]==excluded[-1][key],
                        "old excluded controller erased")
            for key in DENIAL_FIELDS:
                require(denial[key][:len(denials[-1][key])]==denials[-1][key],
                        "old custody denial erased")
        require(isinstance(event.get("conflicts"),list),
                "historical quarantine conflicts absent")
        claims+=pair;quarantines+=event["quarantined_claims"]
        conflicts+=event["conflicts"];excluded.append(snapshot);denials.append(denial)
        require(event.get("entry_sha256")==digest({
            k:v for k,v in event.items() if k!="entry_sha256"}),
            "historical quarantine event hash invalid")
        head=event["entry_sha256"]
        require(heads[index]==head,"historical quarantine chain mutated")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==head and
            history.get("custodian_claims")==claims and
            history.get("quarantined_claims")==quarantines and
            history.get("custody_conflicts")==conflicts and
            history.get("excluded_snapshots")==excluded and
            history.get("denial_snapshots")==denials,
            "historical custody evidence or quarantine erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "cross-custodian registry receipt altered")
    return events,heads

def challenge(source,custody,previous,event,pin,nonce):
    check_sha(pin,"control registrar pin missing")
    check_sha(nonce,"fresh control nonce missing")
    return {"phase":"RUST-085","kind":"CROSS_CUSTODIAN_CONTROL_CHALLENGE_V1",
            "source_rust084_receipt_sha256":source["receipt_sha256"],
            "source_rust083_receipt_sha256":custody["receipt_sha256"],
            "previous_control_head_sha256":previous["head_sha256"],
            "custody_entry_sha256":event["entry_sha256"],
            "witnesses_sha256":digest(event["witnesses"]),
            "excluded_snapshot_sha256":event["exclusions_sha256"],
            "denial_snapshot_sha256":event["denials_sha256"],
            "registrar_pin":pin,"challenge_nonce_sha256":nonce,
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False}

def audit(source,custody,history,pin,nonce,public_key,signature,
          floor=None,verifier=verify_key_and_signature):
    event=source_event(source,custody)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in {
        e["source_rust084_receipt_sha256"] for e in old},
        "replayed RUST-084 highwater")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-085",
                "independent retention floor missing")
        index=floor.get("event_count")
        require(type(index) is int and 0<=index<len(heads),
                "retained control floor beyond history")
        check_sha(floor.get("head_sha256"),"control floor hash invalid")
        require(heads[index]==floor["head_sha256"],
                "control floor contradicts exact retained prefix")
    banned={w["pin"] for e in custody["events"] for w in e["witnesses"]}
    for e in custody["events"]:
        banned.update(e["exclusions"]["excluded_signer_pins"])
    banned.add(source["checkpoint_signer_pin"])
    require(pin not in banned,"source/excluded witness cannot self-sign control registry")
    used_nonces={e["challenge_nonce_sha256"] for e in old}
    used_nonces.update(w["nonce_sha256"] for e in custody["events"]
                       for w in e["witnesses"])
    require(nonce not in used_nonces,"cross-custodian nonce replay")
    msg=challenge(source,custody,history,event,pin,nonce)
    signed=verifier(public_key,signature,pin,canonical(msg))
    check_sha(signed,"control registry signature invalid")
    current_claims=claim_rows(event)
    conflicts=compare(history["custodian_claims"],current_claims)
    exclusions={k:event["exclusions"][k] for k in EXCLUSIONS}
    denials={k:event["denials"][k] for k in DENIAL_FIELDS}
    if old:
        for key in EXCLUSIONS:
            require(exclusions[key][:len(old[-1]["excluded_snapshot"][key])]==
                    old[-1]["excluded_snapshot"][key],
                    "previous control exclusions removed")
        for key in DENIAL_FIELDS:
            require(denials[key][:len(old[-1]["denial_snapshot"][key])]==
                    old[-1]["denial_snapshot"][key],
                    "previous custody denials removed")
    quarantined=[{"role":claim["role"],"pin":claim["pin"],
                  "claim_sha256":digest(claim),
                  "custody_independence_quarantined":True,
                  "independent_custody_verified":False}
                 for claim in current_claims]
    record={"phase":"RUST-085","kind":"CONTROL_QUARANTINE_SNAPSHOT_V1",
            "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
            "source_rust084_receipt_sha256":source["receipt_sha256"],
            "source_rust083_receipt_sha256":custody["receipt_sha256"],
            "custody_entry_sha256":event["entry_sha256"],
            "registrar_pin":pin,"challenge_nonce_sha256":nonce,
            "challenge_sha256":digest(msg),"signature_sha256":signed,
            "claims":current_claims,"claims_sha256":digest(current_claims),
            "quarantined_claims":quarantined,
            "excluded_snapshot":exclusions,
            "excluded_snapshot_sha256":digest(exclusions),
            "denial_snapshot":denials,
            "denial_snapshot_sha256":digest(denials),
            "conflicts":conflicts,"both_branches_retained":True,
            **{k:False for k in FALSE}}
    record["entry_sha256"]=digest(record)
    output={"phase":"RUST-085",
            "status":"HOLD_CROSS_CUSTODIAN_CONTROL_QUARANTINE",
            "events":old+[record],"prefix_heads":heads+[record["entry_sha256"]],
            "event_count":len(old)+1,"head_sha256":record["entry_sha256"],
            "custodian_claims":history["custodian_claims"]+current_claims,
            "quarantined_claims":history["quarantined_claims"]+quarantined,
            "custody_conflicts":history["custody_conflicts"]+conflicts,
            "excluded_snapshots":history["excluded_snapshots"]+[exclusions],
            "denial_snapshots":history["denial_snapshots"]+[denials],
            "retention_floor_compared":floor is not None,
            "retention_floor_claim_sha256":digest(floor) if floor else None,
            "both_branches_retained":True,"globally_latest_control_verified":False,
            "global_anti_rollback_certified":False,
            **{k:False for k in FALSE}}
    output["receipt_sha256"]=digest(output)
    return output

def hold():
    return {"phase":"RUST-085",
            "status":"HOLD_MISSING_CROSS_CUSTODIAN_CONTROL",
            "both_branches_retained":False,**{k:False for k in FALSE}}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","custody","history","pin","nonce",
                 "public-key","signature","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    required=[args.source,args.custody,args.history,args.pin,args.nonce,
              args.public_key,args.signature]
    require(all(required) or not any(required),
            "partial cross-custodian evidence bundle refused")
    require(not args.floor or all(required),"floor without custody evidence")
    if all(required):
        read=lambda f:json.loads(Path(f).read_text(encoding="utf-8"))
        out=audit(read(args.source),read(args.custody),read(args.history),
                  args.pin,args.nonce,args.public_key,args.signature,
                  read(args.floor) if args.floor else None)
    else:out=hold()
    destination=Path(args.output);destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2);stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-085 HOLD: independent external control unverified")
if __name__=="__main__":main()
