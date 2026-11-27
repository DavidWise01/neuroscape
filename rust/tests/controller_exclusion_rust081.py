#!/usr/bin/env python3
"""RUST-081: append-only controller exclusion and custodian reentry denial.
This records claimed ancestry, not independently authenticated control.
No observation, matching or nonmatching, authorizes recovery or release.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from custodian_ancestry_rust079 import checked_history as checked_ancestry,ORIGINS

GENESIS=digest({"phase":"RUST-081","kind":"CONTROLLER_EXCLUSION_GENESIS_V1"})
FALSE=("independent_custody_verified","winner_selected","fork_resolved",
       "recovery_authorized","release_authorized")

def checked_source(source,ancestry):
    require(isinstance(source,dict) and source.get("phase")=="RUST-080"
            and source.get("status")=="HOLD_CUSTODIAN_ANCESTRY_HIGHWATER_EXCLUSION"
            and source.get("both_branches_retained") is True
            and all(source.get(k) is False for k in FALSE+("live_gameplay_authority",)),
            "RUST-080 ancestry highwater absent or promoted")
    require(source.get("receipt_sha256")==digest({
        k:v for k,v in source.items() if k!="receipt_sha256"}),
        "RUST-080 source receipt altered")
    events,_=checked_ancestry(ancestry)
    require(events and source.get("current_rust079_receipt_sha256")==
            ancestry["receipt_sha256"] and
            source.get("current_count")==len(events) and
            source.get("current_claims_preserved")==ancestry["custodian_claims"]
            and source.get("current_conflicts_preserved")==ancestry["custody_conflicts"],
            "RUST-080 ancestry source does not bind full RUST-079 ledger")
    new=source.get("new_ancestry_observations")
    require(isinstance(new,list) and len(new)==1 and
            new[0].get("ancestry_entry_sha256")==events[-1]["entry_sha256"],
            "RUST-080 new custody ancestry event mismatch")
    return events[-1]

def excluded_fingerprints(claims):
    require(isinstance(claims,list) and claims,"excluded ancestry missing")
    return {k:list(dict.fromkeys(c[k] for c in claims)) for k in
            ("signer_pin",*ORIGINS)}

def genesis():
    out={"phase":"RUST-081","status":"HOLD_CUSTODIAN_REENTRY_EXCLUSION",
         "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
         "event_count":0,"excluded_signer_pins":[],
         "excluded_controllers":[],"excluded_source_roots":[],
         "excluded_acquisitions":[],"denied_reentries":[],"custody_conflicts":[],
         "both_branches_retained":False,"winner_selected":False,"fork_resolved":False,
         "independent_custody_verified":False,"recovery_authorized":False,
         "release_authorized":False}
    out["receipt_sha256"]=digest(out)
    return out

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-081"
            and history.get("status")=="HOLD_CUSTODIAN_REENTRY_EXCLUSION"
            and all(history.get(k) is False for k in FALSE),
            "RUST-081 historical exclusion ledger absent or elevated")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "historical exclusion registry truncated")
    last=GENESIS
    names=("excluded_signer_pins","excluded_controllers",
           "excluded_source_roots","excluded_acquisitions")
    accumulated={k:[] for k in names}
    denied=[];conflicts=[];sources=set();nonces=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-081"
                and e.get("kind")=="CONTROLLER_REENTRY_DENIAL_V1"
                and e.get("ordinal")==i and e.get("previous_entry_sha256")==last
                and e.get("both_branches_retained") is True
                and all(e.get(k) is False for k in FALSE),
                "historical exclusion event falsely promoted")
        for key in ("source_rust080_receipt_sha256","source_rust079_receipt_sha256",
                    "ancestry_entry_sha256","challenge_nonce_sha256",
                    "registrar_pin","signature_sha256","challenge_sha256"):
            check_sha(e.get(key),"historical exclusion evidence missing "+key)
        require(e["source_rust080_receipt_sha256"] not in sources and
                e["challenge_nonce_sha256"] not in nonces,
                "historical exclusion source or nonce replay")
        sources.add(e["source_rust080_receipt_sha256"])
        nonces.add(e["challenge_nonce_sha256"])
        for name in names:
            snap=e.get(name)
            require(isinstance(snap,list) and snap[:len(accumulated[name])]==
                    accumulated[name] and len(set(snap))==len(snap),
                    "prior controller exclusion erased or duplicated")
            for sha in snap:check_sha(sha,"excluded fingerprint malformed")
            accumulated[name]=snap
        rows=e.get("denied_reentries")
        require(isinstance(rows,list) and len(rows)==2 and
                [r.get("role") for r in rows]==["a","b"] and
                all(r.get("reentry_denied") is True and
                    r.get("independent_custody_verified") is False for r in rows),
                "historical denial row missing")
        for row in rows:
            for field in ("signer_pin","branch_sha256",*ORIGINS):
                check_sha(row.get(field),"historical denial fingerprint invalid")
        denied+=rows
        require(isinstance(e.get("conflicts"),list),"historical conflicts absent")
        conflicts+=e["conflicts"]
        require(e.get("entry_sha256")==digest({
            k:v for k,v in e.items() if k!="entry_sha256"}),
            "historical denial event altered")
        last=e["entry_sha256"]
        require(heads[i]==last,"historical exclusion head altered")
    require(history.get("event_count")==len(events)
            and history.get("head_sha256")==last
            and history.get("denied_reentries")==denied
            and history.get("custody_conflicts")==conflicts
            and all(history.get(name)==accumulated[name] for name in names),
            "historical exclusion/denial records erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "exclusion registry receipt altered")
    return events,heads

def denial_rows(pair,excluded):
    out=[];conflicts=[]
    mappings={"signer_pin":"excluded_signer_pins",
              "controller_sha256":"excluded_controllers",
              "source_root_sha256":"excluded_source_roots",
              "acquisition_sha256":"excluded_acquisitions"}
    for c in pair:
        matches=[field for field,target in mappings.items()
                 if c[field] in excluded[target]]
        row={"role":c["role"],"branch_sha256":c["branch_sha256"],
             "signer_pin":c["signer_pin"],**{k:c[k] for k in ORIGINS},
             "matched_exclusions":matches,"reentry_denied":True,
             "independent_custody_verified":False}
        out.append(row)
        for field in matches:
            conflicts.append({"reason":"REENTRY_USES_EXCLUDED_"+field.upper(),
                "pin":c["signer_pin"],"independent_custody_verified":False})
        if not matches:
            conflicts.append({"reason":"NO_INDEPENDENT_CUSTODY_QUALIFICATION",
                "pin":c["signer_pin"],"independent_custody_verified":False})
    return out,conflicts

def challenge(source,ancestry,history,event,pin,nonce):
    check_sha(pin,"registrar signing pin invalid")
    check_sha(nonce,"fresh reentry nonce invalid")
    return {"phase":"RUST-081","kind":"CONTROLLER_REENTRY_DENIAL_CHALLENGE_V1",
        "source_rust080_receipt_sha256":source["receipt_sha256"],
        "source_rust079_receipt_sha256":ancestry["receipt_sha256"],
        "previous_registry_head_sha256":history["head_sha256"],
        "ancestry_entry_sha256":event["entry_sha256"],
        "claim_pair_sha256":event["claims_sha256"],
        "registrar_pin":pin,"challenge_nonce_sha256":nonce,
        "reentry_denied":True,"recovery_authorized":False,"release_authorized":False}

def audit(source,ancestry,history,pin,nonce,key,signature,floor=None,
          verifier=verify_key_and_signature):
    entry=checked_source(source,ancestry)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in {
        e["source_rust080_receipt_sha256"] for e in old},
        "replayed ancestry highwater")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-081",
                "retained exclusion floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained exclusion floor ahead of ledger")
        check_sha(floor.get("head_sha256"),"retained floor SHA invalid")
        require(heads[n]==floor["head_sha256"],
                "retained exclusion floor contradicts prefix")
    require(pin not in {c["signer_pin"] for c in ancestry["custodian_claims"]}
            and pin not in {e["signer_pin"] for e in ancestry["events"]}
            and pin!=source["checkpoint_signer_pin"],
            "excluded custodian cannot self-sign reentry denial")
    require(nonce not in {e["challenge_nonce_sha256"] for e in old}
            and nonce not in {e["observation_nonce_sha256"]
                               for e in ancestry["events"]},
            "reentry challenge nonce replay")
    msg=challenge(source,ancestry,history,entry,pin,nonce)
    signed=verifier(key,signature,pin,canonical(msg))
    check_sha(signed,"reentry denial signature invalid")
    latest=excluded_fingerprints(ancestry["custodian_claims"])
    names={"signer_pin":"excluded_signer_pins",
           "controller_sha256":"excluded_controllers",
           "source_root_sha256":"excluded_source_roots",
           "acquisition_sha256":"excluded_acquisitions"}
    excluded={}
    for f,name in names.items():
        before=history[name]
        require(latest[f][:len(before)]==before,
                "historical excluded control ancestry lost: "+f)
        excluded[name]=latest[f]
    rows,conflicts=denial_rows(entry["claims"],excluded)
    event={"phase":"RUST-081","kind":"CONTROLLER_REENTRY_DENIAL_V1",
        "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
        "source_rust080_receipt_sha256":source["receipt_sha256"],
        "source_rust079_receipt_sha256":ancestry["receipt_sha256"],
        "ancestry_entry_sha256":entry["entry_sha256"],
        "challenge_nonce_sha256":nonce,"registrar_pin":pin,
        "challenge_sha256":digest(msg),"signature_sha256":signed,
        **excluded,"denied_reentries":rows,"conflicts":conflicts,
        "both_branches_retained":True,"winner_selected":False,
        "fork_resolved":False,"independent_custody_verified":False,
        "recovery_authorized":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    result={"phase":"RUST-081","status":"HOLD_CUSTODIAN_REENTRY_EXCLUSION",
        "events":old+[event],"prefix_heads":heads+[event["entry_sha256"]],
        "head_sha256":event["entry_sha256"],"event_count":len(old)+1,
        **excluded,
        "denied_reentries":history["denied_reentries"]+rows,
        "custody_conflicts":history["custody_conflicts"]+conflicts,
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":digest(floor) if floor else None,
        "both_branches_retained":True,"winner_selected":False,
        "fork_resolved":False,"independent_custody_verified":False,
        "global_anti_rollback_certified":False,
        "recovery_authorized":False,"release_authorized":False,
        "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-081","status":"HOLD_MISSING_CONTROLLER_EXCLUSION_EVIDENCE",
        "both_branches_retained":False,"winner_selected":False,
        "fork_resolved":False,"independent_custody_verified":False,
        "recovery_authorized":False,"release_authorized":False,
        "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","ancestry","history","pin","nonce","key","signature","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    args=[a.source,a.ancestry,a.history,a.pin,a.nonce,a.key,a.signature]
    require(all(args) or not any(args),"partial reentry exclusion bundle refused")
    require(not a.floor or all(args),"floor without exclusion evidence")
    if all(args):
        read=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(read(a.source),read(a.ancestry),read(a.history),
                     a.pin,a.nonce,a.key,a.signature,
                     read(a.floor) if a.floor else None)
    else:result=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-081 HOLD: independent controller custody not established")
if __name__=="__main__":main()
