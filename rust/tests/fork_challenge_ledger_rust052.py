#!/usr/bin/env python3
"""RUST-052 — immutable fork-continuity challenge ledger.

Records RUST-051 fork reviews plus independently pinned signatures over
fresh nonce-bound, fork-specific challenges. Rejects recycled nonces,
messages, changed claimed ancestry and missing prior fork references.
Neither key possession nor declared provenance establishes custody.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from multiwitness_rust026 import ROLES

GENESIS = digest({"phase":"RUST-052","kind":"FORK_CHALLENGE_GENESIS_V1"})


def checked_review(review):
    require(isinstance(review,dict) and review.get("phase")=="RUST-051" and
            review.get("status")=="HOLD_UNRESOLVED_FORK_CONTINUITY",
            "RUST-051 continuity review missing")
    require(review.get("fork_resolved") is False and
            review.get("release_authorized") is False and
            review.get("independent_branch_witnessing_authenticated") is False,
            "RUST-051 authority escalation")
    require(digest({k:v for k,v in review.items() if k!="receipt_sha256"})==
            review.get("receipt_sha256"),"RUST-051 receipt altered")
    rows=review.get("historical_fork_reviews")
    require(isinstance(rows,list) and
            len(rows)==review.get("historical_fork_count") and rows,
            "unaccounted historical fork")
    require(review.get("historical_fork_events_preserved") is not None and
            len(review["historical_fork_events_preserved"])==len(rows),
            "earlier fork evidence missing")
    seen=set()
    for row in rows:
        require(row.get("both_historical_branches_accounted_for") is True and
                row.get("fork_resolved") is False and
                len(row.get("branch_reviews",[]))==2,
                "historic branch omitted")
        for key in ("historical_registry_entry_sha256",
                    "historical_fork_sha256",
                    "historical_source_rust049_receipt_sha256"):
            check_sha(row.get(key),"fork review hash invalid")
        ident=row["historical_registry_entry_sha256"]
        require(ident not in seen,"duplicate historical fork")
        seen.add(ident)
        for i,branch in enumerate(row["branch_reviews"]):
            require(branch.get("historical_branch_index")==i and
                    branch.get("independent_operator_custody_verified") is False,
                    "branch classification authority changed")
            check_sha(branch.get("historical_branch_sha256"),
                      "historical branch hash invalid")
    return rows


def payload(review,row,witness,nonce):
    require(witness.get("role") in ROLES,"unknown witness role")
    check_sha(nonce,"challenge nonce absent")
    for field in ("source_root_sha256","acquisition_sha256",
                  "operator_control_sha256"):
        check_sha(witness.get(field),"claimed witness origin missing")
    return {
        "phase":"RUST-052","kind":"FORK_CONTINUITY_CHALLENGE_V1",
        "source_rust051_receipt_sha256":review["receipt_sha256"],
        "historical_fork_sha256":row["historical_fork_sha256"],
        "historical_registry_entry_sha256":
            row["historical_registry_entry_sha256"],
        "historical_branch_pair_sha256":digest([
            b["historical_branch_sha256"] for b in row["branch_reviews"]]),
        "witness_role":witness["role"],
        "source_root_sha256":witness["source_root_sha256"],
        "acquisition_sha256":witness["acquisition_sha256"],
        "operator_control_sha256":witness["operator_control_sha256"],
        "challenge_nonce_sha256":nonce,
        "fork_resolved":False,"release_authorized":False,
    }


def genesis():
    out={"phase":"RUST-052","status":"HOLD_FORK_WITNESS_LEDGER",
         "entries":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
         "entry_count":0,"source_ancestry_conflicts":[],
         "release_authorized":False,"fork_resolved":False,
         "independent_witness_custody_verified":False}
    out["receipt_sha256"]=digest(out)
    return out


def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-052" and
            history.get("status")=="HOLD_FORK_WITNESS_LEDGER",
            "RUST-052 predecessor missing")
    require(history.get("release_authorized") is False and
            history.get("fork_resolved") is False,"historical authority escalation")
    entries=history.get("entries")
    heads=history.get("prefix_heads")
    require(isinstance(entries,list) and isinstance(heads,list) and
            len(heads)==len(entries)+1 and heads[0]==GENESIS,
            "historical challenge ledger truncated")
    previous=GENESIS
    seen_nonces=set()
    seen_messages=set()
    observed_conflicts=[]
    for i,event in enumerate(entries,1):
        require(isinstance(event,dict) and
                event.get("phase")=="RUST-052" and
                event.get("kind")=="FORK_WITNESS_CHALLENGE_ENTRY" and
                event.get("ordinal")==i and
                event.get("previous_entry_sha256")==previous,
                "historical event chain changed")
        claims=event.get("witness_claims")
        require(isinstance(claims,list) and len(claims)==3 and
                [c.get("role") for c in claims]==list(ROLES),
                "historical three witness claims missing")
        require(event.get("quarantine_persists") is True and
                event.get("fork_resolved") is False and
                event.get("release_authorized") is False,
                "historical challenge promoted authority")
        check_sha(event.get("historical_fork_sha256"),"historical fork invalid")
        for c in claims:
            for field in ("pin","nonce_sha256","message_sha256",
                          "signature_sha256","source_root_sha256",
                          "acquisition_sha256","operator_control_sha256"):
                check_sha(c.get(field),"historical witness field invalid")
            require(c["nonce_sha256"] not in seen_nonces and
                    c["message_sha256"] not in seen_messages,
                    "historic challenge replay")
            seen_nonces.add(c["nonce_sha256"])
            seen_messages.add(c["message_sha256"])
        require(digest(claims)==event.get("witness_claims_sha256"),
                "historical challenge claims changed")
        conflicts=event.get("ancestry_conflicts")
        require(isinstance(conflicts,list),"missing historical ancestry conflicts")
        observed_conflicts.extend(conflicts)
        require(digest({k:v for k,v in event.items() if k!="entry_sha256"})==
                event.get("entry_sha256"),"historical event rewritten")
        previous=event["entry_sha256"]
        require(heads[i]==previous,"historical prefix altered")
    require(history.get("entry_count")==len(entries) and
            history.get("head_sha256")==previous,
            "historical highwater changed")
    require(history.get("source_ancestry_conflicts")==observed_conflicts,
            "historical ancestry conflict erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"historical receipt altered")
    return entries,heads


def audit(review,history,challenge_sets,pin_sets,nonce_sets,
          retained_floor=None,verifier=verify_key_and_signature):
    rows=checked_review(review)
    old,heads=checked_history(history)
    require(isinstance(challenge_sets,list) and len(challenge_sets)==len(rows)
            and isinstance(pin_sets,list) and len(pin_sets)==len(rows)
            and isinstance(nonce_sets,list) and len(nonce_sets)==len(rows),
            "one complete witness set per historical fork required")
    if retained_floor is not None:
        require(isinstance(retained_floor,dict) and
                retained_floor.get("phase")=="RUST-052",
                "retained fork-challenge floor invalid")
        count=retained_floor.get("entry_count")
        require(type(count) is int and 0<=count<len(heads),
                "retained challenge history incomplete")
        check_sha(retained_floor.get("head_sha256"),"retained head invalid")
        require(heads[count]==retained_floor["head_sha256"],
                "retained challenge history substituted")
    seen_nonces={c["nonce_sha256"] for e in old for c in e["witness_claims"]}
    seen_messages={c["message_sha256"] for e in old for c in e["witness_claims"]}
    known={}
    for event in old:
        for c in event["witness_claims"]:
            known.setdefault(c["pin"],set()).add((
                c["source_root_sha256"],c["acquisition_sha256"],
                c["operator_control_sha256"]))
    entries=list(old)
    new_heads=list(heads)
    conflicts=list(history["source_ancestry_conflicts"])
    for row,group,pins,nonces in zip(rows,challenge_sets,pin_sets,nonce_sets):
        require(isinstance(group,list) and len(group)==3 and
                [x.get("role") for x in group]==list(ROLES) and
                isinstance(pins,list) and len(pins)==3 and
                isinstance(nonces,list) and len(nonces)==3,
                "three ordered ff/cf/rr challenges required")
        require(len(set(pins))==3,"witness signing pin reused within fork")
        claims=[]
        local_conflicts=[]
        for witness,pin,nonce in zip(group,pins,nonces):
            check_sha(pin,"witness pin missing")
            msg=payload(review,row,witness,nonce)
            msg_hash=digest(msg)
            require(nonce not in seen_nonces and msg_hash not in seen_messages,
                    "replayed witness challenge or signed statement")
            seen_nonces.add(nonce)
            seen_messages.add(msg_hash)
            signed=verifier(witness.get("public_key"),witness.get("signature"),
                            pin,canonical(msg))
            check_sha(signed,"invalid witness signature fingerprint")
            origin=(msg["source_root_sha256"],msg["acquisition_sha256"],
                    msg["operator_control_sha256"])
            if known.get(pin) and origin not in known[pin]:
                local_conflicts.append({
                    "witness_pin":pin,"reason":"PIN_SOURCE_ANCESTRY_CHANGED",
                    "historical_claims":sorted([list(x) for x in known[pin]]),
                    "new_claim":list(origin),
                    "independent_control_authenticated":False,
                })
            known.setdefault(pin,set()).add(origin)
            claims.append({
                "role":witness["role"],"pin":pin,
                "nonce_sha256":nonce,"message_sha256":msg_hash,
                "signature_sha256":signed,
                "source_root_sha256":origin[0],
                "acquisition_sha256":origin[1],
                "operator_control_sha256":origin[2],
                "independent_custody_authenticated":False,
            })
        if (len({c["source_root_sha256"] for c in claims})<3 or
                len({c["acquisition_sha256"] for c in claims})<3 or
                len({c["operator_control_sha256"] for c in claims})<3):
            local_conflicts.append({
                "reason":"SHARED_CLAIMED_WITNESS_ANCESTRY",
                "fork_sha256":row["historical_fork_sha256"],
                "independent_control_authenticated":False,
            })
        event={
            "phase":"RUST-052","kind":"FORK_WITNESS_CHALLENGE_ENTRY",
            "ordinal":len(entries)+1,
            "previous_entry_sha256":new_heads[-1],
            "source_rust051_receipt_sha256":review["receipt_sha256"],
            "historical_fork_sha256":row["historical_fork_sha256"],
            "historical_registry_entry_sha256":
                row["historical_registry_entry_sha256"],
            "witness_claims":claims,"witness_claims_sha256":digest(claims),
            "ancestry_conflicts":local_conflicts,
            "quarantine_persists":True,"fork_resolved":False,
            "release_authorized":False,
        }
        event["entry_sha256"]=digest(event)
        entries.append(event)
        new_heads.append(event["entry_sha256"])
        conflicts.extend(local_conflicts)
    result={
        "phase":"RUST-052","status":"HOLD_FORK_WITNESS_LEDGER",
        "entries":entries,"prefix_heads":new_heads,
        "head_sha256":new_heads[-1],"entry_count":len(entries),
        "source_ancestry_conflicts":conflicts,
        "last_rust051_receipt_sha256":review["receipt_sha256"],
        "retained_floor_compared":retained_floor is not None,
        "retained_floor_claim_sha256":digest(retained_floor)
           if retained_floor is not None else None,
        "independent_witness_custody_verified":False,
        "globally_latest_fork_highwater_verified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result


def hold():
    return {"phase":"RUST-052","status":"HOLD_MISSING_EXTERNAL_WITNESS_CHALLENGES",
            "independent_witness_custody_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False,
            "reason":"No independently retained fork challenges and witness signatures"}


def main():
    p=argparse.ArgumentParser()
    for name in ("review","history","challenges","pins","nonces","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.review,a.history,a.challenges,a.pins,a.nonces]
    require(all(required) or not any(required),
            "partial fork challenge evidence refused")
    require(not a.floor or all(required),
            "retained floor without complete review refused")
    if all(required):
        docs=[json.loads(Path(x).read_text(encoding="utf-8")) for x in required]
        floor=json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None
        result=audit(*docs,retained_floor=floor)
    else:
        result=hold()
    out=Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-052 HOLD: witness custody remains unverified")


if __name__=="__main__":
    main()
