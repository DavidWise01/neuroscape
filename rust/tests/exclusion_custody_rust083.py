#!/usr/bin/env python3
"""RUST-083: dual witnessed exclusion-highwater custody, strict HOLD.

Claims of independent custody are never treated as proof of physical
custody, independently acquired bytes, global latestness, or release.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from controller_exclusion_rust081 import checked_history as checked_exclusion
from controller_exclusion_highwater_rust082 import EXCLUSIONS,DENIAL_FIELDS

GENESIS=digest({"phase":"RUST-083","kind":"DUAL_EXCLUSION_CUSTODY_GENESIS_V1"})
FIELDS=("controller_sha256","source_root_sha256","acquisition_sha256")
FALSE=("winner_selected","fork_resolved","independent_custody_verified",
       "recovery_authorized","release_authorized","live_gameplay_authority")

def checked_source(source,exclusion):
    require(isinstance(source,dict) and source.get("phase")=="RUST-082"
            and source.get("status")=="HOLD_CONTROLLER_EXCLUSION_HIGHWATER_REENTRY_DENIAL"
            and source.get("all_reentries_denied") is True
            and source.get("both_branches_retained") is True
            and all(source.get(k) is False for k in FALSE),
            "RUST-082 highwater missing or promoted")
    require(source.get("receipt_sha256")==digest({
        k:v for k,v in source.items() if k!="receipt_sha256"}),
        "RUST-082 receipt altered")
    events,_=checked_exclusion(exclusion)
    require(events and source.get("current_rust081_receipt_sha256")==
            exclusion["receipt_sha256"] and source.get("current_count")==len(events),
            "RUST-082 source does not bind RUST-081 registry")
    for name in EXCLUSIONS+DENIAL_FIELDS:
        require(source.get("current_"+name)==exclusion[name],
                "source exclusion/denial mismatch: "+name)
    require(len(source.get("new_observations",[]))==1 and
            source["new_observations"][0]["exclusion_entry_sha256"]==
            events[-1]["entry_sha256"],"source missing latest exclusion observation")
    return events[-1]

def genesis():
    out={"phase":"RUST-083","status":"HOLD_DUAL_EXCLUSION_CUSTODY",
         "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
         "event_count":0,"custody_conflicts":[],"excluded_snapshots":[],
         "denial_snapshots":[],"both_branches_retained":False,
         **{k:False for k in FALSE}}
    out["receipt_sha256"]=digest(out)
    return out

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-083"
            and history.get("status")=="HOLD_DUAL_EXCLUSION_CUSTODY"
            and all(history.get(k) is False for k in FALSE),
            "custody history missing or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list)
            and len(heads)==len(events)+1 and heads[0]==GENESIS,
            "custody history truncated")
    head=GENESIS;conflicts=[];exclusions=[];denials=[];receipts=set();nonces=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-083"
                and e.get("kind")=="DUAL_EXCLUSION_CUSTODY_SNAPSHOT_V1"
                and e.get("ordinal")==i and e.get("previous_entry_sha256")==head
                and e.get("both_branches_retained") is True
                and all(e.get(k) is False for k in FALSE),
                "custody record altered or falsely promoted")
        for f in ("source_rust082_receipt_sha256","source_rust081_receipt_sha256",
                  "source_exclusion_head_sha256","exclusions_sha256","denials_sha256"):
            check_sha(e.get(f),"historical source fingerprint missing "+f)
        require(e["source_rust082_receipt_sha256"] not in receipts,
                "historical custody highwater replay")
        receipts.add(e["source_rust082_receipt_sha256"])
        x=e.get("exclusions");d=e.get("denials")
        require(isinstance(x,dict) and all(isinstance(x.get(k),list) for k in EXCLUSIONS),
                "historical exclusion snapshot incomplete")
        require(isinstance(d,dict) and all(isinstance(d.get(k),list) for k in DENIAL_FIELDS),
                "historical denial snapshot incomplete")
        require(digest(x)==e["exclusions_sha256"] and digest(d)==e["denials_sha256"],
                "custody snapshot digest substituted")
        if exclusions:
            for k in EXCLUSIONS:
                require(x[k][:len(exclusions[-1][k])]==exclusions[-1][k],
                        "historical excluded ancestry erased")
            for k in DENIAL_FIELDS:
                require(d[k][:len(denials[-1][k])]==denials[-1][k],
                        "historical denial erased")
        witnesses=e.get("witnesses")
        require(isinstance(witnesses,list) and len(witnesses)==2
                and [w.get("role") for w in witnesses]==["left","right"],
                "historical dual custody claims incomplete")
        require(witnesses[0]["pin"]!=witnesses[1]["pin"],
                "historical dual custody key duplicated")
        for w in witnesses:
            for f in ("pin","nonce_sha256","message_sha256","signature_sha256",*FIELDS):
                check_sha(w.get(f),"historical witness fingerprint missing "+f)
            require(w["nonce_sha256"] not in nonces
                    and w.get("independent_custody_verified") is False,
                    "historical witness replay or independence promotion")
            nonces.add(w["nonce_sha256"])
        require(isinstance(e.get("conflicts"),list),"historical conflicts missing")
        conflicts+=e["conflicts"];exclusions.append(x);denials.append(d)
        require(e.get("entry_sha256")==digest({
            k:v for k,v in e.items() if k!="entry_sha256"}),
            "historical custody event digest altered")
        head=e["entry_sha256"]
        require(heads[i]==head,"historical custody head rewritten")
    require(history.get("head_sha256")==head and
            history.get("event_count")==len(events) and
            history.get("custody_conflicts")==conflicts and
            history.get("excluded_snapshots")==exclusions and
            history.get("denial_snapshots")==denials,
            "historical exclusion/denial history erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "custody history receipt altered")
    return events,heads

def challenge(source,exclusion,head,role,claim):
    require(isinstance(claim,dict) and claim.get("role")==role,
            "custody witness role invalid")
    for k in ("pin","nonce_sha256",*FIELDS):
        check_sha(claim.get(k),"custody witness field missing "+k)
    return {"phase":"RUST-083","kind":"EXCLUSION_CUSTODY_WITNESS_V1",
            "source_rust082_receipt_sha256":source["receipt_sha256"],
            "source_rust081_receipt_sha256":exclusion["receipt_sha256"],
            "previous_custody_head_sha256":head,
            "source_exclusion_head_sha256":exclusion["head_sha256"],
            "exclusions_sha256":digest({k:exclusion[k] for k in EXCLUSIONS}),
            "denials_sha256":digest({k:exclusion[k] for k in DENIAL_FIELDS}),
            "role":role,"pin":claim["pin"],"nonce_sha256":claim["nonce_sha256"],
            **{k:claim[k] for k in FIELDS},
            "recovery_authorized":False,"release_authorized":False}

def audit(source,exclusion,history,claims,floor=None,
          verifier=verify_key_and_signature):
    checked_source(source,exclusion)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in {
        e["source_rust082_receipt_sha256"] for e in old},
        "replayed exclusion highwater")
    require(isinstance(claims,list) and len(claims)==2
            and [c.get("role") for c in claims]==["left","right"],
            "two branch-exclusion custodian witnesses required")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-083",
                "retained custody floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained custody floor ahead")
        check_sha(floor.get("head_sha256"),"retained custody floor invalid")
        require(heads[n]==floor["head_sha256"],
                "retained custody floor contradicts prefix")
    exclusions={k:exclusion[k] for k in EXCLUSIONS}
    denials={k:exclusion[k] for k in DENIAL_FIELDS}
    if old:
        previous_exclusions=old[-1]["exclusions"]
        previous_denials=old[-1]["denials"]
        for k in EXCLUSIONS:
            require(exclusions[k][:len(previous_exclusions[k])]==previous_exclusions[k],
                    "previous excluded control ancestry lost")
        for k in DENIAL_FIELDS:
            require(denials[k][:len(previous_denials[k])]==previous_denials[k],
                    "previous denial or custody conflict erased")
    prohibited=set(exclusion["excluded_signer_pins"])
    prohibited.update(e["registrar_pin"] for e in exclusion["events"])
    prohibited.add(source["checkpoint_signer_pin"])
    historic_nonces={w["nonce_sha256"] for e in old for w in e["witnesses"]}
    historic_pins=[w for e in old for w in e["witnesses"]]
    fresh=set();pins=set();witnesses=[];conflicts=[]
    for role,claim in zip(("left","right"),claims):
        require(claim.get("recovery_authorized") is False and
                claim.get("release_authorized") is False and
                claim.get("independent_custody_verified") is False,
                "custody claim attempted release or independence")
        msg=challenge(source,exclusion,heads[-1],role,claim)
        pin=msg["pin"];nonce=msg["nonce_sha256"]
        require(pin not in prohibited and pin not in pins,
                "excluded/duplicate custodian signer")
        require(nonce not in historic_nonces and nonce not in fresh
                and nonce not in {e["challenge_nonce_sha256"] for e in exclusion["events"]},
                "custody witness nonce replay")
        pins.add(pin);fresh.add(nonce)
        signature_digest=verifier(claim.get("public_key"),
                                  claim.get("signature"),pin,canonical(msg))
        check_sha(signature_digest,"custody signature invalid")
        witnesses.append({"role":role,"pin":pin,"nonce_sha256":nonce,
            "message_sha256":digest(msg),"signature_sha256":signature_digest,
            **{k:msg[k] for k in FIELDS},
            "independent_custody_verified":False})
    for f in FIELDS:
        if witnesses[0][f]==witnesses[1][f]:
            conflicts.append({"reason":"SHARED_CUSTODY_CLAIM_ANCESTRY",
                "field":f,"independent_custody_verified":False})
    for witness in witnesses:
        for prior in historic_pins:
            shared=[k for k in FIELDS if witness[k]==prior[k]]
            if witness["pin"]!=prior["pin"] and shared:
                conflicts.append({"reason":"RENAMED_CUSTODY_WITNESS_REUSED_ANCESTRY",
                    "pin":witness["pin"],"fields":shared,
                    "independent_custody_verified":False})
            elif witness["pin"]==prior["pin"] and any(
                    witness[k]!=prior[k] for k in FIELDS):
                conflicts.append({"reason":"EXISTING_CUSTODY_PIN_CHANGED_ANCESTRY",
                    "pin":witness["pin"],"independent_custody_verified":False})
    entry={"phase":"RUST-083","kind":"DUAL_EXCLUSION_CUSTODY_SNAPSHOT_V1",
           "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
           "source_rust082_receipt_sha256":source["receipt_sha256"],
           "source_rust081_receipt_sha256":exclusion["receipt_sha256"],
           "source_exclusion_head_sha256":exclusion["head_sha256"],
           "exclusions":exclusions,"exclusions_sha256":digest(exclusions),
           "denials":denials,"denials_sha256":digest(denials),
           "witnesses":witnesses,"conflicts":conflicts,
           "both_branches_retained":True,**{k:False for k in FALSE}}
    entry["entry_sha256"]=digest(entry)
    out={"phase":"RUST-083","status":"HOLD_DUAL_EXCLUSION_CUSTODY",
         "events":old+[entry],"prefix_heads":heads+[entry["entry_sha256"]],
         "event_count":len(old)+1,"head_sha256":entry["entry_sha256"],
         "custody_conflicts":history["custody_conflicts"]+conflicts,
         "excluded_snapshots":history["excluded_snapshots"]+[exclusions],
         "denial_snapshots":history["denial_snapshots"]+[denials],
         "both_branches_retained":True,
         "globally_latest_highwater_verified":False,
         "global_anti_rollback_certified":False,**{k:False for k in FALSE}}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-083",
            "status":"HOLD_MISSING_DUAL_EXCLUSION_CUSTODY",
            "both_branches_retained":False,**{k:False for k in FALSE}}

def main():
    p=argparse.ArgumentParser()
    for k in ("source","exclusion","history","claims","floor"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    bundle=[a.source,a.exclusion,a.history,a.claims]
    require(all(bundle) or not any(bundle),"partial custody evidence refused")
    require(not a.floor or all(bundle),"floor without custody evidence")
    if all(bundle):
        read=lambda f:json.loads(Path(f).read_text(encoding="utf-8"))
        out=audit(read(a.source),read(a.exclusion),read(a.history),
                  read(a.claims),read(a.floor) if a.floor else None)
    else:out=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2);stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-083 HOLD: independently acquired custody not established")
if __name__=="__main__":main()
