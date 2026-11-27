#!/usr/bin/env python3
"""RUST-079 — append-only cross-epoch custody ancestry registry.

Declared signing pins, controllers, source roots and acquisition fingerprints
are observations, not verified external identities. No fork is resolved.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from fork_branch_custody_rust077 import checked_history as checked_custody

GENESIS=digest({"phase":"RUST-079","kind":"CROSS_EPOCH_ANCESTRY_GENESIS_V1"})
ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checked_source(highwater,custody):
    require(isinstance(highwater,dict) and
            highwater.get("phase")=="RUST-078" and
            highwater.get("status")=="HOLD_BRANCH_CUSTODY_HIGHWATER_ANCESTRY"
            and highwater.get("both_branches_retained") is True and
            all(highwater.get(k) is False for k in
                ("winner_selected","fork_resolved","independent_custody_verified",
                 "recovery_authorized","release_authorized","live_gameplay_authority")),
            "RUST-078 highwater missing or elevated")
    require(highwater.get("receipt_sha256")==digest({
        k:v for k,v in highwater.items() if k!="receipt_sha256"}),
        "RUST-078 receipt altered")
    events,_=checked_custody(custody)
    require(events and highwater.get("current_rust077_receipt_sha256")==
            custody["receipt_sha256"] and
            highwater.get("current_event_count")==len(events) and
            highwater.get("current_branch_pairs")==[
                [e["branch_a_sha256"],e["branch_b_sha256"]] for e in events] and
            highwater.get("current_claim_digests")==[
                e["claims_sha256"] for e in events] and
            highwater.get("current_conflicts")==custody["custody_conflicts"],
            "RUST-078 does not bind complete branch custody history")
    observations=highwater.get("new_pair_observations")
    require(isinstance(observations,list) and len(observations)==1,
            "one newly acquired branch pair required")
    target=observations[0]["custody_entry_sha256"]
    matched=[e for e in events if e["entry_sha256"]==target]
    require(len(matched)==1,"new branch custody event not found")
    return matched[0]

def genesis():
    out={"phase":"RUST-079","status":"HOLD_CROSS_EPOCH_CUSTODIAN_ANCESTRY",
         "events":[],"prefix_heads":[GENESIS],"event_count":0,
         "head_sha256":GENESIS,"custodian_claims":[],"custody_conflicts":[],
         "both_branches_retained":False,"winner_selected":False,
         "fork_resolved":False,"independent_custody_verified":False,
         "recovery_authorized":False,"release_authorized":False}
    out["receipt_sha256"]=digest(out)
    return out

def claim_row(entry,role):
    witness=next(w for w in entry["branches"] if w["role"]==role)
    return {"phase":"RUST-079","role":role,"fork_entry_sha256":entry["fork_entry_sha256"],
            "custody_entry_sha256":entry["entry_sha256"],
            "branch_sha256":entry["branch_"+role+"_sha256"],
            "signer_pin":witness["pin"],
            "witness_message_sha256":witness["message_sha256"],
            "witness_signature_sha256":witness["signature_sha256"],
            **{k:witness[k] for k in ORIGINS},
            "independent_custody_verified":False}

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-079"
            and history.get("status")=="HOLD_CROSS_EPOCH_CUSTODIAN_ANCESTRY"
            and all(history.get(k) is False for k in
                ("winner_selected","fork_resolved","independent_custody_verified",
                 "recovery_authorized","release_authorized")),
            "RUST-079 ancestry ledger missing or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "ancestry registry truncated")
    head=GENESIS;claims=[];conflicts=[];receipts=set();nonces=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-079" and
                e.get("kind")=="CUSTODIAN_ANCESTRY_SNAPSHOT_V1" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==head
                and e.get("both_branches_retained") is True and
                all(e.get(k) is False for k in
                    ("fork_resolved","winner_selected","recovery_authorized",
                     "release_authorized","independent_custody_verified")),
                "historical custodian ancestry promoted")
        for key in ("source_rust078_receipt_sha256","source_rust077_receipt_sha256",
                    "fork_entry_sha256","custody_entry_sha256","observation_nonce_sha256",
                    "signature_sha256","signer_pin"):
            check_sha(e.get(key),"historical ancestry evidence missing "+key)
        require(e["source_rust078_receipt_sha256"] not in receipts and
                e["observation_nonce_sha256"] not in nonces,
                "ancestry source or nonce replay")
        receipts.add(e["source_rust078_receipt_sha256"])
        nonces.add(e["observation_nonce_sha256"])
        pair=e.get("claims")
        require(isinstance(pair,list) and len(pair)==2 and
                [c.get("role") for c in pair]==["a","b"],
                "historical branch ancestry pair incomplete")
        for c in pair:
            for key in ("fork_entry_sha256","custody_entry_sha256",
                        "branch_sha256","signer_pin","witness_message_sha256",
                        "witness_signature_sha256",*ORIGINS):
                check_sha(c.get(key),"historical ancestry claim missing "+key)
            require(c.get("phase")=="RUST-079" and
                    c.get("independent_custody_verified") is False and
                    c["fork_entry_sha256"]==e["fork_entry_sha256"] and
                    c["custody_entry_sha256"]==e["custody_entry_sha256"],
                    "historical ancestry claim substituted")
        require(pair[0]["branch_sha256"]!=pair[1]["branch_sha256"] and
                pair[0]["signer_pin"]!=pair[1]["signer_pin"],
                "historical fork falsely merged")
        require(e.get("claims_sha256")==digest(pair),
                "ancestry pair digest mismatch")
        claims+=pair
        require(isinstance(e.get("conflicts"),list),
                "historical ancestry conflicts missing")
        conflicts+=e["conflicts"]
        require(e.get("entry_sha256")==digest({
            k:v for k,v in e.items() if k!="entry_sha256"}),
            "historical ancestry entry hash altered")
        head=e["entry_sha256"]
        require(heads[i]==head,"historical ancestry chain rewritten")
    require(history.get("head_sha256")==head and
            history.get("event_count")==len(events) and
            history.get("custodian_claims")==claims and
            history.get("custody_conflicts")==conflicts,
            "historical claimed ancestry or conflicts erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "ancestry registry receipt altered")
    return events,heads

def contradictions(old_claims,new_claims):
    findings=[]
    for c in new_claims:
        for p in old_claims:
            if c["signer_pin"]==p["signer_pin"]:
                changed=[f for f in ORIGINS if c[f]!=p[f]]
                if changed:
                    findings.append({"reason":"SAME_SIGNER_CHANGED_ANCESTRY",
                        "new_pin":c["signer_pin"],"prior_pin":p["signer_pin"],
                        "changed_fields":changed,"independent_custody_verified":False})
            else:
                repeated=[f for f in ORIGINS if c[f]==p[f]]
                if repeated:
                    findings.append({"reason":"RENAMED_SIGNER_SHARED_ANCESTRY",
                        "new_pin":c["signer_pin"],"prior_pin":p["signer_pin"],
                        "shared_fields":repeated,"independent_custody_verified":False})
    a,b=new_claims
    same=[f for f in ORIGINS if a[f]==b[f]]
    if same:
        findings.append({"reason":"COMPETING_BRANCHES_SHARE_ANCESTRY",
            "shared_fields":same,"independent_custody_verified":False})
    return findings

def challenge(highwater,custody,head,entry,nonce,signer_pin):
    check_sha(nonce,"fresh ancestry observation nonce invalid")
    check_sha(signer_pin,"ancestry registrar signer invalid")
    return {"phase":"RUST-079","kind":"CROSS_EPOCH_ANCESTRY_OBSERVATION_V1",
            "source_rust078_receipt_sha256":highwater["receipt_sha256"],
            "source_rust077_receipt_sha256":custody["receipt_sha256"],
            "previous_registry_head_sha256":head,
            "custody_entry_sha256":entry["entry_sha256"],
            "fork_entry_sha256":entry["fork_entry_sha256"],
            "branch_claims_sha256":entry["claims_sha256"],
            "observation_nonce_sha256":nonce,"signer_pin":signer_pin,
            "fork_resolved":False,"recovery_authorized":False,
            "release_authorized":False}

def audit(highwater,custody,history,nonce,signer_pin,key,signature,
          floor=None,verifier=verify_key_and_signature):
    entry=checked_source(highwater,custody)
    previous,heads=checked_history(history)
    require(highwater["receipt_sha256"] not in {
        e["source_rust078_receipt_sha256"] for e in previous},
        "replayed RUST-078 custody ancestry highwater")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-079",
                "retained ancestry floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained ancestry floor ahead")
        check_sha(floor.get("head_sha256"),"retained ancestry floor head invalid")
        require(heads[n]==floor["head_sha256"],
                "retained ancestry floor contradicts prefix")
    forbidden={w["pin"] for e in custody["events"] for w in e["branches"]}
    forbidden.add(highwater["checkpoint_signer_pin"])
    require(signer_pin not in forbidden,
            "source custodian cannot self-sign ancestry registry")
    require(nonce not in {e["observation_nonce_sha256"] for e in previous} and
            nonce not in {w["nonce_sha256"] for e in custody["events"]
                          for w in e["branches"]},
            "ancestry observation nonce replay")
    msg=challenge(highwater,custody,heads[-1],entry,nonce,signer_pin)
    signed=verifier(key,signature,signer_pin,canonical(msg))
    check_sha(signed,"invalid ancestry registrar signature")
    pair=[claim_row(entry,r) for r in ("a","b")]
    require(pair[0]["branch_sha256"]!=pair[1]["branch_sha256"],
            "source fork collapsed")
    conflicts=contradictions(history["custodian_claims"],pair)
    event={"phase":"RUST-079","kind":"CUSTODIAN_ANCESTRY_SNAPSHOT_V1",
           "ordinal":len(previous)+1,"previous_entry_sha256":heads[-1],
           "source_rust078_receipt_sha256":highwater["receipt_sha256"],
           "source_rust077_receipt_sha256":custody["receipt_sha256"],
           "custody_entry_sha256":entry["entry_sha256"],
           "fork_entry_sha256":entry["fork_entry_sha256"],
           "observation_nonce_sha256":nonce,
           "signer_pin":signer_pin,"signature_sha256":signed,
           "challenge_sha256":digest(msg),
           "claims":pair,"claims_sha256":digest(pair),
           "conflicts":conflicts,"both_branches_retained":True,
           "winner_selected":False,"fork_resolved":False,
           "independent_custody_verified":False,
           "recovery_authorized":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    result={"phase":"RUST-079","status":"HOLD_CROSS_EPOCH_CUSTODIAN_ANCESTRY",
            "events":previous+[event],
            "prefix_heads":heads+[event["entry_sha256"]],
            "head_sha256":event["entry_sha256"],
            "event_count":len(previous)+1,
            "custodian_claims":history["custodian_claims"]+pair,
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
    return {"phase":"RUST-079",
            "status":"HOLD_MISSING_CUSTODIAN_ANCESTRY_EVIDENCE",
            "both_branches_retained":False,"winner_selected":False,
            "fork_resolved":False,"independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("highwater","custody","history","nonce","signer-pin",
                 "key","signature","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    bundle=[a.highwater,a.custody,a.history,a.nonce,a.signer_pin,
            a.key,a.signature]
    require(all(bundle) or not any(bundle),
            "partial ancestry evidence bundle refused")
    require(not a.floor or all(bundle),"floor supplied without ancestry evidence")
    if all(bundle):
        load=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(load(a.highwater),load(a.custody),load(a.history),
                  a.nonce,a.signer_pin,a.key,a.signature,
                  load(a.floor) if a.floor else None)
    else:out=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2);stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-079 HOLD: independent custodian control not verified")
if __name__=="__main__":main()
