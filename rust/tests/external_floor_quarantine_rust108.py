#!/usr/bin/env python3
"""RUST-108: append-only stale-floor quarantine for RUST-107 evidence.

Recorded reports are local observations, not independent external custody.
Never promote a stale floor, erase contradiction history or authorize release.
"""
import argparse
import json
from pathlib import Path
from century_source_freeze_rust100 import canonical
from operator_continuity_rust105 import need

DOMAIN = "NEUROSCAPE_RUST108_STALE_FLOOR_QUARANTINE_V1"
PRIOR = "HOLD_EXTERNAL_HIGHWATER_FLOOR_UNVERIFIED"
HOLD = "HOLD_STALE_FLOOR_QUARANTINE"
ZERO = "0" * 64
MAX_EPOCHS = 1024

def hash_obj(data):
    import hashlib
    return hashlib.sha256(canonical(data)).hexdigest()

def sha(s):
    need(isinstance(s,str) and len(s)==64
         and all(c in "0123456789abcdef" for c in s),
         "lowercase SHA-256 required")
    return s

def observation(report):
    need(isinstance(report,dict)
         and report.get("domain")=="NEUROSCAPE_RUST107_EXTERNAL_FLOOR_COPIES_V1"
         and report.get("phase")=="RUST-107" and report.get("status")==PRIOR,
         "RUST-107 HOLD report required")
    head=sha(report.get("local_highwater_head_sha256"))
    copies=report.get("copies")
    need(isinstance(copies,list) and len(copies)==2,"two highwater copies required")
    normalized=[]
    for c in copies:
        need(isinstance(c,dict),"missing external copy")
        need(type(c.get("ledger_epoch")) is int
             and c["ledger_epoch"] in (0,1),"unsupported copy epoch")
        for k in ("head_sha256","highwater_signature_sha256","payload_sha256",
                  "acquisition_nonce_sha256","signer_pin"):sha(c.get(k))
        normalized.append({k:c[k] for k in ("ledger_epoch","head_sha256",
                   "highwater_signature_sha256","payload_sha256",
                   "acquisition_nonce_sha256","signer_pin")})
    claimed=report.get("custody_ancestry_sha256")
    need(isinstance(claimed,list) and len(claimed)==2,
         "custody ancestry digest pair required")
    for v in claimed:sha(v)
    conflicts=report.get("provenance_conflicts")
    need(isinstance(conflicts,list) and conflicts==sorted(set(conflicts))
         and all(isinstance(s,str) and 0<len(s)<128 for s in conflicts),
         "upstream conflict list invalid")
    need(report.get("external_acquisition_authenticated") is False
         and report.get("independent_external_custody_verified") is False
         and report.get("global_latest_floor_authenticated") is False
         and report.get("release_authorized") is False
         and report.get("recovery_authorized") is False
         and report.get("fork_selected") is False,"unearned authority")
    need(any(c["head_sha256"]==head and c["ledger_epoch"]==1
             for c in normalized),"no local current-floor witness")
    derived=set()
    if any(c["ledger_epoch"]==0 or c["head_sha256"]!=head
           for c in normalized):
        derived.add("STALE_COPY_RETAINED")
    if normalized[0]["head_sha256"]!=normalized[1]["head_sha256"]:
        derived.add("INTRA_EPOCH_FLOOR_CONFLICT")
    if normalized[0]["payload_sha256"]==normalized[1]["payload_sha256"]:
        derived.add("REPLAYED_COPY_BYTES")
    return {"rust107_report_sha256":hash_obj(report),
            "local_head_sha256":head,
            "copies":normalized,
            "custody_ancestry_sha256":claimed,
            "upstream_conflicts":conflicts,
            "derived_conflicts":sorted(derived)}

def conflicts(history,obs):
    reasons=set(obs["derived_conflicts"])
    for past in history:
        prior=past["observation"]
        if prior["rust107_report_sha256"]==obs["rust107_report_sha256"]:
            reasons.add("REPLAYED_RUST107_REPORT")
        if prior["local_head_sha256"]!=obs["local_head_sha256"]:
            reasons.add("UNPROVEN_CROSS_EPOCH_FLOOR_ORDER")
        for old in prior["copies"]:
            for new in obs["copies"]:
                if old["payload_sha256"]==new["payload_sha256"]:
                    reasons.add("REINTRODUCED_HIGHWATER_COPY")
                if old["acquisition_nonce_sha256"]==new["acquisition_nonce_sha256"]:
                    reasons.add("REUSED_ACQUISITION_NONCE")
                if old["signer_pin"]==new["signer_pin"]:
                    reasons.add("REUSED_HIGHWATER_SIGNER")
        if set(prior["custody_ancestry_sha256"]) & set(obs["custody_ancestry_sha256"]):
            reasons.add("REUSED_CUSTODY_ANCESTRY")
    return sorted(reasons)

def validate(history):
    need(isinstance(history,list) and len(history)<=MAX_EPOCHS,
         "invalid bounded quarantine ledger")
    head=ZERO
    for i,e in enumerate(history):
        need(isinstance(e,dict) and set(e)=={"domain","index","previous_sha256",
            "observation","quarantine_reasons","quarantine_retained",
            "global_latest_floor_authenticated","independent_external_custody_verified",
            "release_authorized","recovery_authorized","fork_selected","entry_sha256"},
            "quarantine event schema changed")
        body={k:v for k,v in e.items() if k!="entry_sha256"}
        need(body["domain"]==DOMAIN and type(body["index"]) is int
             and body["index"]==i and body["previous_sha256"]==head
             and hash_obj(body)==e["entry_sha256"],
             "quarantine hash chain rewritten")
        ob=e["observation"]
        need(isinstance(ob,dict) and set(ob)=={"rust107_report_sha256",
             "local_head_sha256","copies","custody_ancestry_sha256",
             "upstream_conflicts","derived_conflicts"},"stored observation invalid")
        sha(ob["rust107_report_sha256"]);sha(ob["local_head_sha256"])
        need(isinstance(ob["copies"],list) and len(ob["copies"])==2,
             "stored copy pair invalid")
        for copy in ob["copies"]:
            need(isinstance(copy,dict) and set(copy)=={"ledger_epoch",
                 "head_sha256","highwater_signature_sha256","payload_sha256",
                 "acquisition_nonce_sha256","signer_pin"},"copy schema rewritten")
            need(type(copy["ledger_epoch"]) is int and copy["ledger_epoch"] in (0,1),
                 "stored copy epoch invalid")
            for field in ("head_sha256","highwater_signature_sha256","payload_sha256",
                          "acquisition_nonce_sha256","signer_pin"):sha(copy[field])
        ancestry=ob["custody_ancestry_sha256"]
        need(isinstance(ancestry,list) and len(ancestry)==2,
             "ancestry pair invalid")
        for v in ancestry:sha(v)
        for field in ("upstream_conflicts","derived_conflicts"):
            items=ob[field]
            need(isinstance(items,list) and items==sorted(set(items))
                 and all(isinstance(x,str) and 0<len(x)<128 for x in items),
                 "stored conflicts invalid")
        derived=set()
        if any(c["ledger_epoch"]==0 or c["head_sha256"]!=ob["local_head_sha256"]
               for c in ob["copies"]):derived.add("STALE_COPY_RETAINED")
        if ob["copies"][0]["head_sha256"]!=ob["copies"][1]["head_sha256"]:
            derived.add("INTRA_EPOCH_FLOOR_CONFLICT")
        if ob["copies"][0]["payload_sha256"]==ob["copies"][1]["payload_sha256"]:
            derived.add("REPLAYED_COPY_BYTES")
        need(ob["derived_conflicts"]==sorted(derived),
             "derived stale-floor contradiction erased")
        need(any(c["ledger_epoch"]==1 and c["head_sha256"]==ob["local_head_sha256"]
                 for c in ob["copies"]),"current local floor absent")
        need(e["quarantine_reasons"]==conflicts(history[:i],ob),
             "historical quarantine reason erased")
        need(e["quarantine_retained"] is True
             and all(e[k] is False for k in ("global_latest_floor_authenticated",
                "independent_external_custody_verified","release_authorized",
                "recovery_authorized","fork_selected")),"authority promotion")
        head=e["entry_sha256"]
    return head

def append(history,report):
    head=validate(history)
    need(len(history)<MAX_EPOCHS,"capacity reached: no overwrite")
    ob=observation(report)
    body={"domain":DOMAIN,"index":len(history),"previous_sha256":head,
          "observation":ob,"quarantine_reasons":conflicts(history,ob),
          "quarantine_retained":True,"global_latest_floor_authenticated":False,
          "independent_external_custody_verified":False,"release_authorized":False,
          "recovery_authorized":False,"fork_selected":False}
    out=history+[{**body,"entry_sha256":hash_obj(body)}]
    validate(out)
    return out

def audit(previous,current):
    prior,now=validate(previous),validate(current)
    need(len(current)>len(previous) and current[:len(previous)]==previous,
         "rollback or deletion of prior quarantine")
    return {"phase":"RUST-108","status":HOLD,
            "previous_head_sha256":prior,"current_head_sha256":now,
            "epochs":len(current),"retained_quarantine":[
                {"epoch":e["index"],"reasons":e["quarantine_reasons"]}
                for e in current if e["quarantine_reasons"]],
            "independent_external_custody_verified":False,
            "global_latest_floor_authenticated":False,
            "release_authorized":False,"recovery_authorized":False,
            "live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-108",
            "status":"HOLD_MISSING_EXTERNAL_FLOOR_QUARANTINE_HISTORY",
            "global_latest_floor_authenticated":False,
            "independent_external_custody_verified":False,
            "release_authorized":False,"recovery_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--previous");p.add_argument("--current")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    need(bool(args.previous)==bool(args.current),"partial quarantine bundle")
    if args.previous:
        load=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(load(args.previous),load(args.current))
    else:result=missing()
    target=Path(args.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-108 HOLD: no independently authenticated floor")
if __name__=="__main__":main()
