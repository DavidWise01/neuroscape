#!/usr/bin/env python3
"""RUST-075 — incompatible custody branch registry and denial contradictions.

A fork is recorded, not resolved. Both branches retain their entire
authenticated-by-hash RUST-073 histories, and all authority remains HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from denial_custody_rust073 import checked_history as checked_custody

GENESIS=digest({"phase":"RUST-075","kind":"DENIAL_CUSTODY_FORK_GENESIS_V1"})

def checked_source(source,base,branch_a,branch_b):
    require(isinstance(source,dict) and source.get("phase")=="RUST-074"
            and source.get("status")=="HOLD_DENIAL_CUSTODY_HIGHWATER_REPLAY"
            and source.get("all_denials_retained") is True
            and all(source.get(k) is False for k in
                    ("independent_custody_verified","recovery_authorized",
                     "release_authorized","live_gameplay_authority")),
            "RUST-074 denial assessment unavailable or promoted")
    require(source.get("receipt_sha256")==digest({
        k:v for k,v in source.items() if k!="receipt_sha256"}),
        "RUST-074 receipt changed")
    before,old_heads=checked_custody(base)
    a,heads_a=checked_custody(branch_a)
    b,heads_b=checked_custody(branch_b)
    require(before and len(a)>len(before) and len(b)>len(before),
            "both custody branches must extend shared predecessor")
    require(a[:len(before)]==b[:len(before)]==before and
            heads_a[:len(old_heads)]==heads_b[:len(old_heads)]==old_heads,
            "custody branch overwrote shared prefix")
    require(heads_a[len(before)+1]!=heads_b[len(before)+1],
            "no conflicting custody fork at first successor")
    require(source.get("previous_rust073_receipt_sha256")==base["receipt_sha256"]
            and source.get("current_rust073_receipt_sha256")==branch_a["receipt_sha256"]
            and source.get("previous_count")==len(before)
            and source.get("current_count")==len(a),
            "RUST-074 assessment unbound to branch A")
    for branch in (branch_a,branch_b):
        for key in ("denials","excluded_pins","excluded_controllers"):
            require(branch["events"][-1][key][:len(before[-1][key])]==before[-1][key],
                    "fork branch lost denial or exclusion")
    return len(before),a,b

def genesis():
    x={"phase":"RUST-075","status":"HOLD_CUSTODY_FORK_CONTRADICTIONS",
       "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
       "event_count":0,"fork_pairs":[],"custody_conflicts":[],
       "fork_resolved":False,"independent_custody_verified":False,
       "recovery_authorized":False,"release_authorized":False}
    x["receipt_sha256"]=digest(x)
    return x

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-075"
            and history.get("status")=="HOLD_CUSTODY_FORK_CONTRADICTIONS"
            and all(history.get(k) is False for k in
                ("fork_resolved","independent_custody_verified",
                 "recovery_authorized","release_authorized")),
            "fork registry invalid or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "fork ledger truncated")
    head=GENESIS;forks=[];conflicts=[];nonces=set();sources=set()
    for i,e in enumerate(events,1):
        require(e.get("phase")=="RUST-075" and
                e.get("kind")=="INCOMPATIBLE_DENIAL_CUSTODY_FORK_V1" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==head and
                e.get("winner_selected") is False and
                e.get("fork_resolved") is False and
                e.get("release_authorized") is False,
                "historical fork resolution forged")
        for k in ("source_rust074_receipt_sha256","base_rust073_receipt_sha256",
                  "branch_a_receipt_sha256","branch_b_receipt_sha256",
                  "branch_a_head_sha256","branch_b_head_sha256",
                  "witness_a_pin","witness_b_pin",
                  "nonce_a_sha256","nonce_b_sha256",
                  "signature_a_sha256","signature_b_sha256"):
            check_sha(e.get(k),"historical fork claim missing "+k)
        require(e["source_rust074_receipt_sha256"] not in sources and
                e["nonce_a_sha256"] not in nonces and
                e["nonce_b_sha256"] not in nonces and
                e["nonce_a_sha256"]!=e["nonce_b_sha256"],
                "historical fork source/nonce replay")
        sources.add(e["source_rust074_receipt_sha256"])
        nonces.update((e["nonce_a_sha256"],e["nonce_b_sha256"]))
        pair=[e["branch_a_head_sha256"],e["branch_b_head_sha256"]]
        require(pair[0]!=pair[1] and e.get("fork_pair")==pair,
                "historical fork silently merged")
        forks.append(pair)
        require(isinstance(e.get("conflicts"),list) and e["conflicts"],
                "historical fork conflicts erased")
        conflicts+=e["conflicts"]
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical fork digest altered")
        head=e["entry_sha256"]
        require(heads[i]==head,"historical fork prefix altered")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==head and
            history.get("fork_pairs")==forks and
            history.get("custody_conflicts")==conflicts,
            "historical fork keys/conflicts lost")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "fork registry receipt altered")
    return events,heads

def statement(source,base,branch,head,role,pin,nonce):
    check_sha(pin,"witness pin invalid")
    check_sha(nonce,"fresh fork nonce invalid")
    require(role in ("a","b"),"fork side invalid")
    return {"phase":"RUST-075","kind":"CUSTODY_FORK_WITNESS_V1",
            "source_rust074_receipt_sha256":source["receipt_sha256"],
            "base_rust073_receipt_sha256":base["receipt_sha256"],
            "branch_rust073_receipt_sha256":branch["receipt_sha256"],
            "branch_head_sha256":branch["head_sha256"],
            "previous_registry_head_sha256":head,
            "role":role,"pin":pin,"nonce_sha256":nonce,
            "winner_selected":False,"release_authorized":False}

def audit(source,base,branch_a,branch_b,history,claims,floor=None,
          verifier=verify_key_and_signature):
    count,a,b=checked_source(source,base,branch_a,branch_b)
    previous,heads=checked_history(history)
    require(source["receipt_sha256"] not in {
        e["source_rust074_receipt_sha256"] for e in previous},
        "fork assessment replay")
    require(isinstance(claims,list) and len(claims)==2 and
            [c.get("role") for c in claims]==["a","b"],
            "two separately pinned branch claims required")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-075",
                "retained fork floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained fork floor ahead of registry")
        check_sha(floor.get("head_sha256"),"retained fork SHA invalid")
        require(heads[n]==floor["head_sha256"],"retained fork floor contradictory")
    prohibited={source["checkpoint_signer_pin"]}
    for e in a+b:
        prohibited.update(w["pin"] for w in e["witnesses"])
        prohibited.update(e["excluded_pins"])
    old_nonces={n for e in previous for n in
                (e["nonce_a_sha256"],e["nonce_b_sha256"])}
    pins=[];nonces=[];signed=[]
    for claim,branch,role in zip(claims,(branch_a,branch_b),("a","b")):
        msg=statement(source,base,branch,heads[-1],role,
                      claim.get("pin"),claim.get("nonce_sha256"))
        pin=msg["pin"];nonce=msg["nonce_sha256"]
        require(pin not in prohibited and pin not in pins,
                "fork witness shares branch custody ancestry key")
        require(nonce not in old_nonces and nonce not in nonces,
                "fork witness nonce replay")
        pins.append(pin);nonces.append(nonce)
        sig=verifier(claim.get("public_key"),claim.get("signature"),
                     pin,canonical(msg))
        check_sha(sig,"invalid fork witness signature")
        signed.append(sig)
    conflicts=[{"reason":"INCOMPATIBLE_CUSTODY_BRANCH_HEADS",
                "first_divergent_ordinal":count+1,
                "branch_a_sha256":a[count]["entry_sha256"],
                "branch_b_sha256":b[count]["entry_sha256"],
                "independent_custody_verified":False}]
    for k in ("denials","excluded_pins","excluded_controllers"):
        if a[-1][k]!=b[-1][k]:
            conflicts.append({"reason":"BRANCH_RETENTION_CONTRADICTION",
                              "field":k,"independent_custody_verified":False})
    if any(claims[0].get(k)==claims[1].get(k) for k in
           ("controller_sha256","acquisition_sha256")):
        conflicts.append({"reason":"FORK_WITNESSES_SHARE_CLAIMED_CONTROL",
                          "independent_custody_verified":False})
    e={"phase":"RUST-075","kind":"INCOMPATIBLE_DENIAL_CUSTODY_FORK_V1",
       "ordinal":len(previous)+1,"previous_entry_sha256":heads[-1],
       "source_rust074_receipt_sha256":source["receipt_sha256"],
       "base_rust073_receipt_sha256":base["receipt_sha256"],
       "branch_a_receipt_sha256":branch_a["receipt_sha256"],
       "branch_b_receipt_sha256":branch_b["receipt_sha256"],
       "branch_a_head_sha256":branch_a["head_sha256"],
       "branch_b_head_sha256":branch_b["head_sha256"],
       "branch_a_full_history_sha256":digest(a),
       "branch_b_full_history_sha256":digest(b),
       "branch_a_denials_sha256":digest(a[-1]["denials"]),
       "branch_b_denials_sha256":digest(b[-1]["denials"]),
       "fork_pair":[branch_a["head_sha256"],branch_b["head_sha256"]],
       "witness_a_pin":pins[0],"witness_b_pin":pins[1],
       "nonce_a_sha256":nonces[0],"nonce_b_sha256":nonces[1],
       "signature_a_sha256":signed[0],"signature_b_sha256":signed[1],
       "conflicts":conflicts,"winner_selected":False,"fork_resolved":False,
       "release_authorized":False}
    e["entry_sha256"]=digest(e)
    result={"phase":"RUST-075","status":"HOLD_CUSTODY_FORK_CONTRADICTIONS",
            "events":previous+[e],"prefix_heads":heads+[e["entry_sha256"]],
            "event_count":len(previous)+1,"head_sha256":e["entry_sha256"],
            "fork_pairs":history["fork_pairs"]+[e["fork_pair"]],
            "custody_conflicts":history["custody_conflicts"]+conflicts,
            "winner_selected":False,"fork_resolved":False,
            "independent_custody_verified":False,
            "globally_latest_registry_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-075","status":"HOLD_MISSING_CUSTODY_FORK_EVIDENCE",
            "fork_resolved":False,"independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("source","base","branch-a","branch-b","history","claims","floor"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    required=[args.source,args.base,args.branch_a,args.branch_b,
              args.history,args.claims]
    require(all(required) or not any(required),"partial custody fork evidence refused")
    require(not args.floor or all(required),"fork floor without evidence")
    if all(required):
        load=lambda f:json.loads(Path(f).read_text(encoding="utf-8"))
        output=audit(load(args.source),load(args.base),load(args.branch_a),
                     load(args.branch_b),load(args.history),load(args.claims),
                     load(args.floor) if args.floor else None)
    else:output=hold()
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(output,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(output,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-075 HOLD: independent fork custody unverified")
if __name__=="__main__":main()
