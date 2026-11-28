#!/usr/bin/env python3
"""RUST-105: append-only cross-operator acquisition continuity.

Every observation is bound to a RUST-104 HOLD report and two declared operator
ancestries. Recompute all cross-epoch conflicts; never trust a stored conflict
list. This is local structural evidence, NOT authenticated external custody.
"""
import argparse
import json
from pathlib import Path
from century_source_freeze_rust100 import canonical
from dual_response_custody_rust104 import DOMAIN as UPSTREAM_DOMAIN, HOLD as UPSTREAM_HOLD, FIELDS

DOMAIN = "NEUROSCAPE_RUST105_OPERATOR_CONTINUITY_V1"
HOLD = "HOLD_OPERATOR_CONTINUITY_INDEPENDENCE_UNVERIFIED"
ZERO = "0"*64
LIMIT = 1024

def need(condition, why):
    if not condition: raise ValueError(why)

def digest(obj):
    import hashlib
    return hashlib.sha256(canonical(obj)).hexdigest()

def sha(v):
    need(isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v),
         "invalid SHA-256 fingerprint")
    return v

def observation(report, ancestries):
    need(isinstance(report,dict) and report.get("phase")=="RUST-104"
         and report.get("domain")==UPSTREAM_DOMAIN
         and report.get("status")==UPSTREAM_HOLD,
         "RUST-104 HOLD report required")
    for key in ("independent_external_custody_verified","release_authorized",
                "fork_selected","recovery_authorized"):
        need(report.get(key) is False,"unearned upstream authority")
    need(isinstance(ancestries,list) and len(ancestries)==2,
         "exactly two bound operator ancestries")
    rows=report.get("retrieval_receipts")
    pins=report.get("claimed_operator_ancestry_sha256")
    need(isinstance(rows,list) and len(rows)==2
         and isinstance(pins,list) and len(pins)==2,
         "two upstream retrieval receipts required")
    checked=[]
    for i,(row,ancestry) in enumerate(zip(rows,ancestries)):
        need(isinstance(row,dict) and isinstance(ancestry,dict)
             and set(ancestry)==set(FIELDS), "incomplete operator evidence")
        need(digest(ancestry)==sha(pins[i]),
             "operator lineage not bound to RUST-104 report")
        for k in FIELDS:sha(ancestry[k])
        data={}
        for k in ("operator_pin","acquisition_nonce_sha256",
                  "report_sha256","archive_sha256","frozen_source_sha256"):
            data[k]=sha(row.get(k))
        need(type(row.get("archive_length")) is int
             and 0<row["archive_length"]<=25*1024*1024,
             "invalid archive length")
        data["ancestry"]={k:ancestry[k] for k in FIELDS}
        checked.append(data)
    return {"rust104_sha256":digest(report),
            "century_checkpoint_sha256":sha(report.get("century_checkpoint_sha256")),
            "operators":checked,
            "upstream_conflicts":report.get("correlation_reasons")}

def conflicts(history, item):
    reasons=set()
    for old_entry in history:
        old=old_entry["observation"]
        if old["rust104_sha256"]==item["rust104_sha256"]:
            reasons.add("REPLAYED_RUST104_REPORT")
        if old["century_checkpoint_sha256"]!=item["century_checkpoint_sha256"]:
            reasons.add("CENTURY_CHECKPOINT_FORK")
        for older in old["operators"]:
            for newer in item["operators"]:
                for field,reason in (("operator_pin","REUSED_OPERATOR_PIN"),
                                     ("acquisition_nonce_sha256","REPLAYED_ACQUISITION_NONCE"),
                                     ("report_sha256","REUSED_RETRIEVAL_REPORT"),
                                     ("archive_sha256","REUSED_ARCHIVE_BYTES")):
                    if older[field]==newer[field]:reasons.add(reason)
                for field in FIELDS:
                    if older["ancestry"][field]==newer["ancestry"][field]:
                        reasons.add("REUSED_"+field.upper()+"_ANCESTRY")
    return sorted(reasons)

def validate(ledger):
    need(isinstance(ledger,list) and len(ledger)<=LIMIT,"invalid ledger size")
    head=ZERO
    for idx,event in enumerate(ledger):
        need(isinstance(event,dict) and set(event)=={
            "domain","index","previous_sha256","observation","cross_epoch_conflicts",
            "entry_sha256","independent_external_custody_verified","release_authorized",
            "recovery_authorized","fork_selected"},"malformed ledger event")
        body={k:v for k,v in event.items() if k!="entry_sha256"}
        need(body["domain"]==DOMAIN and body["index"]==idx
             and body["previous_sha256"]==head
             and event["entry_sha256"]==digest(body),
             "rewritten predecessor or entry digest")
        obs=body["observation"]
        need(isinstance(obs,dict) and set(obs)=={
            "rust104_sha256","century_checkpoint_sha256","operators","upstream_conflicts"},
            "observation schema invalid")
        sha(obs["rust104_sha256"]);sha(obs["century_checkpoint_sha256"])
        need(isinstance(obs["operators"],list) and len(obs["operators"])==2,
             "two operator records required")
        for op in obs["operators"]:
            need(isinstance(op,dict) and set(op)=={
                "operator_pin","acquisition_nonce_sha256","report_sha256",
                "archive_sha256","frozen_source_sha256","ancestry"},
                "operator record incomplete")
            for k in ("operator_pin","acquisition_nonce_sha256","report_sha256",
                      "archive_sha256","frozen_source_sha256"):sha(op[k])
            need(isinstance(op["ancestry"],dict) and set(op["ancestry"])==set(FIELDS),
                 "operator ancestry incomplete")
            for k in FIELDS:sha(op["ancestry"][k])
        upstream=obs["upstream_conflicts"]
        need(isinstance(upstream,list) and upstream==sorted(set(upstream))
             and all(isinstance(x,str) and 0<len(x)<128 for x in upstream),
             "upstream contradictions malformed")
        need(event["cross_epoch_conflicts"]==conflicts(ledger[:idx],obs),
             "cross-epoch conflict erased")
        need(all(event[k] is False for k in
                 ("independent_external_custody_verified","release_authorized",
                  "recovery_authorized","fork_selected")),"authority promotion")
        head=event["entry_sha256"]
    return head

def append(ledger, report, ancestries):
    head=validate(ledger)
    need(len(ledger)<LIMIT,"bounded ledger full; do not overwrite")
    obs=observation(report,ancestries)
    body={"domain":DOMAIN,"index":len(ledger),"previous_sha256":head,
          "observation":obs,"cross_epoch_conflicts":conflicts(ledger,obs),
          "independent_external_custody_verified":False,"release_authorized":False,
          "recovery_authorized":False,"fork_selected":False}
    result=ledger+[{**body,"entry_sha256":digest(body)}]
    validate(result)
    return result

def audit(previous, current):
    old,new=validate(previous),validate(current)
    need(len(current)>len(previous) and current[:len(previous)]==previous,
         "rollback or revised historical custody ledger")
    return {"phase":"RUST-105","status":HOLD,"previous_head_sha256":old,
            "head_sha256":new,"epoch_count":len(current),
            "retained_cross_epoch_conflicts":[
                {"index":entry["index"],"reasons":entry["cross_epoch_conflicts"]}
                for entry in current if entry["cross_epoch_conflicts"]],
            "independent_external_custody_verified":False,
            "global_anti_rollback_verified":False,"fork_selected":False,
            "release_authorized":False,"recovery_authorized":False,
            "live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-105","status":"HOLD_MISSING_OPERATOR_CONTINUITY_LEDGER",
            "independent_external_custody_verified":False,
            "release_authorized":False,"recovery_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--previous");p.add_argument("--current")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    need(bool(a.previous)==bool(a.current),"partial ledger")
    if a.previous:
        load=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        result=audit(load(a.previous),load(a.current))
    else:result=missing()
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-105 HOLD: no independent external custody")
if __name__=="__main__":
    main()
