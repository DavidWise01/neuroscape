#!/usr/bin/env python3
"""RUST-061 — persistent control-reconciliation ledger and retention challenge.

Preserve every RUST-060 branch, fork and custody conflict. Check a
separately pinned third-party retention signature over immutable evidence.
Signature validity is NOT independent custody. All outcomes stay HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature

GENESIS=digest({"phase":"RUST-061","kind":"RECONCILIATION_RETENTION_GENESIS_V1"})

def checked_source(s):
    require(isinstance(s,dict) and s.get("phase")=="RUST-060" and
            s.get("status")=="HOLD_EXTERNAL_CONTROL_RECONCILIATION",
            "RUST-060 reconciliation unavailable")
    for name in ("winner_selected","fork_resolved","release_authorized",
                 "independent_custodians_authenticated","live_gameplay_authority"):
        require(s.get(name) is False,"source attempted authority promotion")
    require(digest({k:v for k,v in s.items() if k!="receipt_sha256"})==
            s.get("receipt_sha256"),"source receipt altered")
    for side in ("left","right"):
        rows=s.get(side+"_branch_events_preserved")
        conflicts=s.get(side+"_control_conflicts_preserved")
        require(isinstance(rows,list) and rows and isinstance(conflicts,list) and
                s.get(side+"_count")==len(rows) and
                s.get(side+"_head_sha256")==rows[-1].get("entry_sha256"),
                "missing preserved "+side+" branch")
        for row in rows:
            check_sha(row.get("entry_sha256"),"source branch hash invalid")
    require(isinstance(s.get("reconciliation_disagreements"),list),
            "reconciliation disputes missing")
    return s

def genesis():
    x={"phase":"RUST-061","status":"HOLD_RECONCILIATION_RETENTION",
       "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
       "event_count":0,"unresolved_disputes":[],
       "release_authorized":False,"fork_resolved":False,
       "independent_retention_verified":False}
    x["receipt_sha256"]=digest(x)
    return x

def checked_history(h):
    require(isinstance(h,dict) and h.get("phase")=="RUST-061" and
            h.get("status")=="HOLD_RECONCILIATION_RETENTION" and
            h.get("release_authorized") is False and
            h.get("fork_resolved") is False and
            h.get("independent_retention_verified") is False,
            "retention ledger missing or promoted")
    es=h.get("events"); heads=h.get("prefix_heads")
    require(isinstance(es,list) and isinstance(heads,list) and
            len(heads)==len(es)+1 and heads[0]==GENESIS,
            "retention ledger truncated")
    last=GENESIS; disputes=[]; sources=set(); nonces=set()
    for i,e in enumerate(es,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-061" and
                e.get("kind")=="RECONCILIATION_RETENTION_EVENT" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==last and
                e.get("release_authorized") is False and
                e.get("fork_resolved") is False and
                e.get("winner_selected") is False,
                "historical retention event changed")
        for field in ("source_rust060_receipt_sha256","left_branch_sha256",
                      "right_branch_sha256","retention_nonce_sha256",
                      "retention_pin","signature_sha256","payload_sha256"):
            check_sha(e.get(field),"historical retention field invalid")
        require(e["source_rust060_receipt_sha256"] not in sources and
                e["retention_nonce_sha256"] not in nonces,
                "historical retention source/nonce replay")
        sources.add(e["source_rust060_receipt_sha256"])
        nonces.add(e["retention_nonce_sha256"])
        require(isinstance(e.get("left_events"),list) and
                isinstance(e.get("right_events"),list) and
                isinstance(e.get("disagreements"),list),
                "historical branch evidence omitted")
        require(e["left_events"] and e["right_events"] and
                e["left_events"][-1]["entry_sha256"]==e["left_branch_sha256"] and
                e["right_events"][-1]["entry_sha256"]==e["right_branch_sha256"],
                "historical branch head altered")
        disputes.extend(e["disagreements"])
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical event hash modified")
        last=e["entry_sha256"]
        require(heads[i]==last,"retention prefix rewritten")
    require(h.get("event_count")==len(es) and
            h.get("head_sha256")==last and
            h.get("unresolved_disputes")==disputes,
            "historical disputes erased")
    require(digest({k:v for k,v in h.items() if k!="receipt_sha256"})==
            h.get("receipt_sha256"),"retention receipt altered")
    return es,heads

def payload(source,head,witness):
    for k in ("retention_nonce_sha256","claimed_custodian_root_sha256",
              "claimed_acquisition_sha256","claimed_operator_sha256"):
        check_sha(witness.get(k),"third-party retention evidence absent: "+k)
    return {
        "phase":"RUST-061","kind":"RECONCILIATION_RETENTION_CHALLENGE_V1",
        "source_rust060_receipt_sha256":source["receipt_sha256"],
        "previous_retention_head_sha256":head,
        "left_branch_sha256":source["left_head_sha256"],
        "right_branch_sha256":source["right_head_sha256"],
        "disagreements_sha256":digest(source["reconciliation_disagreements"]),
        "left_history_sha256":digest(source["left_branch_events_preserved"]),
        "right_history_sha256":digest(source["right_branch_events_preserved"]),
        **{k:witness[k] for k in ("retention_nonce_sha256",
           "claimed_custodian_root_sha256","claimed_acquisition_sha256",
           "claimed_operator_sha256")},
        "release_authorized":False,
    }

def audit(source,history,witness,retention_pin,floor=None,
          verifier=verify_key_and_signature):
    checked_source(source)
    prior,heads=checked_history(history)
    require(source["receipt_sha256"] not in
            {e["source_rust060_receipt_sha256"] for e in prior},
            "reconciliation receipt replay")
    require(isinstance(witness,dict),"third-party retention witness missing")
    msg=payload(source,heads[-1],witness)
    check_sha(retention_pin,"retention signer pin invalid")
    require(retention_pin!=source["highwater_signer_pin"],
            "original highwater signer cannot self-retain")
    require(retention_pin not in
            {e["retention_pin"] for e in prior if
             e["claimed_custodian_root_sha256"]!=
             msg["claimed_custodian_root_sha256"]},
            "retention pin changed claimed origin")
    require(msg["retention_nonce_sha256"] not in
            {e["retention_nonce_sha256"] for e in prior},
            "retention challenge nonce replay")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-061",
                "retained ledger floor unavailable")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained floor beyond local history")
        check_sha(floor.get("head_sha256"),"retained floor hash missing")
        require(heads[n]==floor["head_sha256"],
                "retention ledger rollback or fork")
    sig=verifier(witness.get("public_key"),witness.get("signature"),
                 retention_pin,canonical(msg))
    check_sha(sig,"retention signature invalid")
    disagreements=list(source["reconciliation_disagreements"])
    if source["incompatible_history_detected"]:
        disagreements.append({
            "kind":"HISTORICAL_CONTROL_FORK_REMAINS_UNRESOLVED",
            "left_head_sha256":source["left_head_sha256"],
            "right_head_sha256":source["right_head_sha256"]})
    for e in prior:
        if e["claimed_custodian_root_sha256"]==msg["claimed_custodian_root_sha256"]:
            if e["retention_pin"]!=retention_pin:
                disagreements.append({
                    "kind":"RENAMED_RETENTION_PIN_SHARED_CUSTODIAN_ROOT",
                    "previous_entry_sha256":e["entry_sha256"]})
        if (e["claimed_operator_sha256"]==msg["claimed_operator_sha256"] and
                e["retention_pin"]!=retention_pin):
            disagreements.append({
                "kind":"MULTIPLE_RETENTION_KEYS_SHARED_OPERATOR",
                "previous_entry_sha256":e["entry_sha256"]})
    event={
        "phase":"RUST-061","kind":"RECONCILIATION_RETENTION_EVENT",
        "ordinal":len(prior)+1,"previous_entry_sha256":heads[-1],
        "source_rust060_receipt_sha256":source["receipt_sha256"],
        "left_branch_sha256":source["left_head_sha256"],
        "right_branch_sha256":source["right_head_sha256"],
        "left_events":source["left_branch_events_preserved"],
        "right_events":source["right_branch_events_preserved"],
        "left_control_conflicts":source["left_control_conflicts_preserved"],
        "right_control_conflicts":source["right_control_conflicts_preserved"],
        "retention_nonce_sha256":msg["retention_nonce_sha256"],
        "claimed_custodian_root_sha256":msg["claimed_custodian_root_sha256"],
        "claimed_acquisition_sha256":msg["claimed_acquisition_sha256"],
        "claimed_operator_sha256":msg["claimed_operator_sha256"],
        "retention_pin":retention_pin,"signature_sha256":sig,
        "payload_sha256":digest(msg),"disagreements":disagreements,
        "winner_selected":False,"fork_resolved":False,
        "independent_retention_verified":False,"release_authorized":False,
    }
    event["entry_sha256"]=digest(event)
    result={
        "phase":"RUST-061","status":"HOLD_RECONCILIATION_RETENTION",
        "events":prior+[event],"prefix_heads":heads+[event["entry_sha256"]],
        "event_count":len(prior)+1,"head_sha256":event["entry_sha256"],
        "unresolved_disputes":history["unresolved_disputes"]+disagreements,
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
        "independent_retention_verified":False,
        "globally_latest_reconciliation_verified":False,
        "global_anti_rollback_certified":False,
        "winner_selected":False,"fork_resolved":False,
        "release_authorized":False,"live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-061","status":"HOLD_MISSING_EXTERNAL_RECONCILIATION_RETENTION",
            "independent_retention_verified":False,
            "winner_selected":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False,
            "reason":"No independently acquired retained branch evidence or custody signature"}

def main():
    p=argparse.ArgumentParser()
    for k in ("source","history","witness","retention-pin","floor"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    vals=[args.source,args.history,args.witness,args.retention_pin]
    require(all(vals) or not any(vals),"partial reconciliation retention evidence refused")
    require(not args.floor or all(vals),"retained floor without complete evidence refused")
    if all(vals):
        read=lambda q:json.loads(Path(q).read_text(encoding="utf-8"))
        result=audit(read(args.source),read(args.history),read(args.witness),
                     args.retention_pin,read(args.floor) if args.floor else None)
    else:result=hold()
    dest=Path(args.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-061 HOLD: independent custody unverified")
if __name__=="__main__":main()
