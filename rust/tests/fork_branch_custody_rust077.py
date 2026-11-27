#!/usr/bin/env python3
"""RUST-077 — independent fork-branch custody challenge ledger.

Bind two signed, fresh claims separately to the two RUST-075 branch heads
preserved by RUST-076. No physical custody, fork resolution, or authority.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from custody_fork_rust075 import checked_history as checked_forks

GENESIS=digest({"phase":"RUST-077","kind":"FORK_BRANCH_CHALLENGE_GENESIS_V1"})
ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checked_source(highwater,forks):
    require(isinstance(highwater,dict) and highwater.get("phase")=="RUST-076"
        and highwater.get("status")=="HOLD_CUSTODY_FORK_HIGHWATER_RETENTION"
        and highwater.get("both_branches_retained") is True
        and all(highwater.get(k) is False for k in
            ("fork_resolved","winner_selected","independent_custody_verified",
             "recovery_authorized","release_authorized","live_gameplay_authority")),
        "RUST-076 highwater absent or authority promoted")
    require(highwater.get("receipt_sha256")==digest({
        k:v for k,v in highwater.items() if k!="receipt_sha256"}),
        "RUST-076 receipt changed")
    events,_=checked_forks(forks)
    require(events and highwater.get("current_rust075_receipt_sha256")==
        forks["receipt_sha256"] and highwater.get("current_fork_count")==len(events)
        and highwater.get("current_fork_pairs_preserved")==forks["fork_pairs"]
        and highwater.get("current_conflicts_preserved")==forks["custody_conflicts"],
        "RUST-076 custody fork ancestry not bound")
    require(len(highwater.get("new_fork_observations",[]))>0,
        "new RUST-076 fork evidence absent")
    target={o["fork_entry_sha256"] for o in highwater["new_fork_observations"]}
    matching=[e for e in events if e["entry_sha256"] in target]
    require(len(matching)==len(target)==len(highwater["new_fork_observations"]),
        "RUST-076 new fork observations incomplete")
    return matching

def genesis():
    result={"phase":"RUST-077","status":"HOLD_FORK_BRANCH_CUSTODY_CHALLENGES",
            "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
            "event_count":0,"custody_conflicts":[],
            "fork_resolved":False,"independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False}
    result["receipt_sha256"]=digest(result)
    return result

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-077"
        and history.get("status")=="HOLD_FORK_BRANCH_CUSTODY_CHALLENGES"
        and all(history.get(k) is False for k in
            ("fork_resolved","independent_custody_verified",
             "recovery_authorized","release_authorized")),
        "historical branch custody ledger absent or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list)
        and len(heads)==len(events)+1 and heads[0]==GENESIS,
        "historical custody prefix missing")
    head=GENESIS;seen_sources=set();nonces=set();conflicts=[]
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-077"
            and e.get("kind")=="UNRESOLVED_FORK_BRANCH_CUSTODY_V1"
            and e.get("ordinal")==i and e.get("previous_entry_sha256")==head
            and e.get("both_branches_retained") is True
            and all(e.get(k) is False for k in
                ("winner_selected","fork_resolved","recovery_authorized",
                 "release_authorized","independent_custody_verified")),
            "historical custody fork falsely reconciled")
        for field in ("source_rust076_receipt_sha256","source_rust075_receipt_sha256",
                      "fork_entry_sha256","branch_a_sha256","branch_b_sha256"):
            check_sha(e.get(field),"historical fork hash missing")
        require(e["branch_a_sha256"]!=e["branch_b_sha256"],
                "historical forks merged")
        require(e["source_rust076_receipt_sha256"] not in seen_sources,
                "historical fork source replay")
        seen_sources.add(e["source_rust076_receipt_sha256"])
        claims=e.get("branches")
        require(isinstance(claims,list) and len(claims)==2
                and [c.get("role") for c in claims]==["a","b"],
                "historical branch custody claims missing")
        for role,c in zip(("a","b"),claims):
            for f in ("pin","nonce_sha256","message_sha256","signature_sha256",*ORIGINS):
                check_sha(c.get(f),"historical custody claim incomplete")
            require(c.get("branch_sha256")==e["branch_"+role+"_sha256"],
                    "historical claim moved to other branch")
            require(c["nonce_sha256"] not in nonces,
                    "historical challenge nonce replay")
            nonces.add(c["nonce_sha256"])
            require(c.get("independent_custody_verified") is False,
                    "historical independence falsely asserted")
        require(claims[0]["pin"]!=claims[1]["pin"],
                "historical custody signer duplicated")
        require(e.get("claims_sha256")==digest(claims),
                "historical custody claims changed")
        require(isinstance(e.get("conflicts"),list),"historical conflicts missing")
        conflicts+=e["conflicts"]
        require(e.get("entry_sha256")==digest({
            k:v for k,v in e.items() if k!="entry_sha256"}),
            "historical custody event digest changed")
        head=e["entry_sha256"]
        require(heads[i]==head,"historical custody chain altered")
    require(history.get("event_count")==len(events)
        and history.get("head_sha256")==head
        and history.get("custody_conflicts")==conflicts,
        "historical custody conflicts or events erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "historical custody ledger receipt invalid")
    return events,heads

def challenge(highwater,forks,entry,head,claim):
    require(isinstance(claim,dict) and claim.get("role") in ("a","b"),
            "branch role missing")
    for f in ("signer_pin","nonce_sha256",*ORIGINS):
        check_sha(claim.get(f),"custody challenge missing "+f)
    role=claim["role"]
    return {"phase":"RUST-077","kind":"FORK_BRANCH_CUSTODY_CHALLENGE_V1",
            "source_rust076_receipt_sha256":highwater["receipt_sha256"],
            "source_rust075_receipt_sha256":forks["receipt_sha256"],
            "fork_entry_sha256":entry["entry_sha256"],
            "previous_branch_custody_head_sha256":head,
            "role":role,"branch_head_sha256":entry["branch_"+role+"_head_sha256"],
            "signer_pin":claim["signer_pin"],"nonce_sha256":claim["nonce_sha256"],
            **{f:claim[f] for f in ORIGINS},
            "winner_selected":False,"fork_resolved":False,
            "recovery_authorized":False,"release_authorized":False}

def audit(highwater,forks,history,claims,floor=None,
          verifier=verify_key_and_signature):
    eligible=checked_source(highwater,forks)
    old,heads=checked_history(history)
    require(highwater["receipt_sha256"] not in {
        e["source_rust076_receipt_sha256"] for e in old},
        "RUST-076 highwater replay")
    require(len(eligible)==1,"one new fork challenge per acquisition required")
    entry=eligible[0]
    require(isinstance(claims,list) and len(claims)==2 and
            [c.get("role") for c in claims]==["a","b"],
            "two separately pinned branch challenges required")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-077",
                "separate custody floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained custody floor ahead")
        check_sha(floor.get("head_sha256"),"retained custody floor hash invalid")
        require(heads[n]==floor["head_sha256"],
                "retained custody floor contradicts history")
    prohibited={highwater["checkpoint_signer_pin"]}
    prior_nonces={c["nonce_sha256"] for e in old for c in e["branches"]}
    historic_pins={c["pin"] for e in old for c in e["branches"]}
    for e in forks["events"]:
        prohibited.update((e["witness_a_pin"],e["witness_b_pin"]))
        prior_nonces.update((e["nonce_a_sha256"],e["nonce_b_sha256"]))
    rows=[];used=set()
    for role,c in zip(("a","b"),claims):
        msg=challenge(highwater,forks,entry,heads[-1],c)
        pin=msg["signer_pin"];nonce=msg["nonce_sha256"]
        require(pin not in prohibited and pin not in used,
                "branch witness signer reused or duplicated")
        require(nonce not in prior_nonces,
                "custody branch nonce replay")
        require(c.get("winner_selected") is False
                and c.get("fork_resolved") is False
                and c.get("release_authorized") is False,
                "branch claim asserted false resolution")
        used.add(pin);prior_nonces.add(nonce)
        signed=verifier(c.get("public_key"),c.get("signature"),
                        pin,canonical(msg))
        check_sha(signed,"invalid branch custody signature")
        rows.append({"role":role,"branch_sha256":msg["branch_head_sha256"],
                     "pin":pin,"nonce_sha256":nonce,
                     "message_sha256":digest(msg),"signature_sha256":signed,
                     **{f:msg[f] for f in ORIGINS},
                     "independent_custody_verified":False})
    conflicts=[]
    for field in ORIGINS:
        if rows[0][field]==rows[1][field]:
            conflicts.append({"reason":"BRANCH_WITNESSES_SHARE_ANCESTRY",
                              "field":field,"independent_custody_verified":False})
    for c in rows:
        if c["pin"] in historic_pins:
            conflicts.append({"reason":"REPLAYED_CUSTODY_SIGNER_NEW_EPOCH",
                              "pin":c["pin"],"independent_custody_verified":False})
        for prior in old:
            for w in prior["branches"]:
                if w["pin"]!=c["pin"] and (
                    w["controller_sha256"]==c["controller_sha256"] or
                    w["acquisition_sha256"]==c["acquisition_sha256"]):
                    conflicts.append({"reason":"RENAMED_CUSTODIAN_REUSED_ANCESTRY",
                                      "pin":c["pin"],"independent_custody_verified":False})
                    break
    event={"phase":"RUST-077","kind":"UNRESOLVED_FORK_BRANCH_CUSTODY_V1",
           "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
           "source_rust076_receipt_sha256":highwater["receipt_sha256"],
           "source_rust075_receipt_sha256":forks["receipt_sha256"],
           "fork_entry_sha256":entry["entry_sha256"],
           "branch_a_sha256":entry["branch_a_head_sha256"],
           "branch_b_sha256":entry["branch_b_head_sha256"],
           "branches":rows,"claims_sha256":digest(rows),"conflicts":conflicts,
           "both_branches_retained":True,"winner_selected":False,
           "fork_resolved":False,"independent_custody_verified":False,
           "recovery_authorized":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    result={"phase":"RUST-077","status":"HOLD_FORK_BRANCH_CUSTODY_CHALLENGES",
            "events":old+[event],"prefix_heads":heads+[event["entry_sha256"]],
            "event_count":len(old)+1,"head_sha256":event["entry_sha256"],
            "custody_conflicts":history["custody_conflicts"]+conflicts,
            "both_branches_retained":True,"winner_selected":False,
            "fork_resolved":False,"independent_custody_verified":False,
            "globally_latest_custody_verified":False,
            "global_anti_rollback_certified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-077","status":"HOLD_MISSING_FORK_BRANCH_CUSTODY_CHALLENGES",
            "both_branches_retained":False,"winner_selected":False,
            "fork_resolved":False,"independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("highwater","forks","history","claims","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    pieces=[a.highwater,a.forks,a.history,a.claims]
    require(all(pieces) or not any(pieces),"partial branch custody bundle refused")
    require(not a.floor or all(pieces),"custody floor without bundle refused")
    if all(pieces):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        result=audit(read(a.highwater),read(a.forks),read(a.history),
                     read(a.claims),read(a.floor) if a.floor else None)
    else: result=hold()
    target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True);stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-077 HOLD: independent custody unverified")
if __name__=="__main__":main()
