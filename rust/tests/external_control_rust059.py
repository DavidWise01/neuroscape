#!/usr/bin/env python3
"""RUST-059: cross-epoch external control claim challenge (authority HOLD)."""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
GENESIS=digest({"phase":"RUST-059","kind":"EXTERNAL_CONTROL_GENESIS_V1"})
def checked_source(s):
    require(isinstance(s,dict) and s.get("phase")=="RUST-058" and
            s.get("status")=="HOLD_CUSTODIAN_HIGHWATER_INDEPENDENCE_UNVERIFIED",
            "RUST-058 source missing")
    require(all(s.get(k) is False for k in
            ("release_authorized","fork_resolved","independent_custody_verified")),
            "source asserted authority")
    require(digest({k:v for k,v in s.items() if k!="receipt_sha256"})==
            s.get("receipt_sha256"),"source receipt altered")
    require(isinstance(s.get("cross_epoch_ancestry_conflicts"),list) and
            isinstance(s.get("current_custody_conflicts_preserved"),list),
            "source conflict ancestry omitted")
    return s
def genesis():
    v={"phase":"RUST-059","status":"HOLD_EXTERNAL_CONTROL_CONTINUITY",
       "events":[],"prefix_heads":[GENESIS],"event_count":0,
       "head_sha256":GENESIS,"control_conflicts":[],
       "independent_external_control_verified":False,
       "release_authorized":False,"fork_resolved":False}
    v["receipt_sha256"]=digest(v)
    return v
def checked_history(h):
    require(isinstance(h,dict) and h.get("phase")=="RUST-059" and
            h.get("status")=="HOLD_EXTERNAL_CONTROL_CONTINUITY" and
            h.get("release_authorized") is False and
            h.get("fork_resolved") is False and
            h.get("independent_external_control_verified") is False,
            "control history missing or elevated")
    es=h.get("events"); heads=h.get("prefix_heads")
    require(isinstance(es,list) and isinstance(heads,list) and
            len(heads)==len(es)+1 and heads[0]==GENESIS,
            "control ledger truncated")
    last=GENESIS; conflicts=[]; nonces=set(); receipts=set()
    for i,e in enumerate(es,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-059" and
                e.get("kind")=="EXTERNAL_CONTROL_CHALLENGE_EVENT" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==last and
                e.get("release_authorized") is False and
                e.get("control_authorized") is False and
                e.get("independent_external_control_verified") is False,
                "historical control challenge rewritten")
        for f in ("source_rust058_receipt_sha256","nonce_sha256",
                  "message_sha256","custodian_pin","authority_pin",
                  "custodian_signature_sha256","authority_signature_sha256",
                  "claimed_controller_sha256","claimed_operator_sha256",
                  "claimed_acquisition_sha256","external_evidence_sha256"):
            check_sha(e.get(f),"historic external control field invalid")
        require(e["nonce_sha256"] not in nonces and
                e["source_rust058_receipt_sha256"] not in receipts,
                "control nonce or source receipt replay")
        nonces.add(e["nonce_sha256"]); receipts.add(e["source_rust058_receipt_sha256"])
        require(isinstance(e.get("control_conflicts"),list),
                "historical conflicts missing")
        conflicts.extend(e["control_conflicts"])
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical control entry changed")
        last=e["entry_sha256"]
        require(heads[i]==last,"control prefix rewritten")
    require(h.get("head_sha256")==last and h.get("event_count")==len(es) and
            h.get("control_conflicts")==conflicts,
            "historical conflicts or highwater erased")
    require(digest({k:v for k,v in h.items() if k!="receipt_sha256"})==
            h.get("receipt_sha256"),"control registry receipt altered")
    return es,heads
def payload(s,head,claim):
    fields=("custodian_pin","claimed_controller_sha256",
            "claimed_operator_sha256","claimed_acquisition_sha256",
            "nonce_sha256","external_evidence_sha256")
    for f in fields: check_sha(claim.get(f),"control evidence missing: "+f)
    return {"phase":"RUST-059","kind":"EXTERNAL_CONTROL_CHALLENGE_V1",
            "source_rust058_receipt_sha256":s["receipt_sha256"],
            "previous_registry_head_sha256":head,
            **{f:claim[f] for f in fields},
            "control_authorized":False,"release_authorized":False}
def audit(source,history,claim,authority_pin,floor=None,
          verifier=verify_key_and_signature):
    checked_source(source)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in
            {e["source_rust058_receipt_sha256"] for e in old},
            "source receipt replay")
    require(isinstance(claim,dict),"external control claim missing")
    m=payload(source,heads[-1],claim); pin=m["custodian_pin"]
    check_sha(authority_pin,"authority signing pin missing")
    require(authority_pin!=pin and
            authority_pin not in {e["custodian_pin"] for e in old},
            "custodian self-attestation rejected")
    require(m["nonce_sha256"] not in {e["nonce_sha256"] for e in old},
            "control challenge nonce replay")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-059",
                "retained floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "floor exceeds known history")
        check_sha(floor.get("head_sha256"),"floor head invalid")
        require(heads[n]==floor["head_sha256"],
                "retained control history forked")
    a=verifier(claim.get("custodian_public_key"),
               claim.get("custodian_signature"),pin,canonical(m))
    b=verifier(claim.get("authority_public_key"),
               claim.get("authority_signature"),authority_pin,canonical(m))
    check_sha(a,"custodian signature invalid")
    check_sha(b,"authority signature invalid")
    conflicts=[]
    for e in old:
        if e["custodian_pin"]==pin:
            for field in ("claimed_controller_sha256","claimed_operator_sha256",
                          "claimed_acquisition_sha256"):
                if e[field]!=m[field]:
                    conflicts.append({"reason":"SAME_PIN_CHANGED_"+field.upper(),
                                      "previous_entry_sha256":e["entry_sha256"]})
        else:
            for field in ("claimed_controller_sha256","claimed_operator_sha256"):
                if e[field]==m[field]:
                    conflicts.append({"reason":"NEW_PIN_SHARED_"+field.upper(),
                                      "previous_entry_sha256":e["entry_sha256"]})
    event={"phase":"RUST-059","kind":"EXTERNAL_CONTROL_CHALLENGE_EVENT",
           "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
           "source_rust058_receipt_sha256":source["receipt_sha256"],
           "nonce_sha256":m["nonce_sha256"],"message_sha256":digest(m),
           "custodian_pin":pin,"authority_pin":authority_pin,
           "custodian_signature_sha256":a,"authority_signature_sha256":b,
           "claimed_controller_sha256":m["claimed_controller_sha256"],
           "claimed_operator_sha256":m["claimed_operator_sha256"],
           "claimed_acquisition_sha256":m["claimed_acquisition_sha256"],
           "external_evidence_sha256":m["external_evidence_sha256"],
           "source_ancestry_conflicts_sha256":digest(source["cross_epoch_ancestry_conflicts"]),
           "control_conflicts":conflicts,"independent_external_control_verified":False,
           "control_authorized":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    out={"phase":"RUST-059","status":"HOLD_EXTERNAL_CONTROL_CONTINUITY",
         "events":old+[event],"prefix_heads":heads+[event["entry_sha256"]],
         "head_sha256":event["entry_sha256"],"event_count":len(old)+1,
         "control_conflicts":history["control_conflicts"]+conflicts,
         "upstream_custody_conflicts_preserved":
             source["current_custody_conflicts_preserved"],
         "upstream_ancestry_conflicts_preserved":
             source["cross_epoch_ancestry_conflicts"],
         "independent_external_control_verified":False,
         "globally_latest_highwater_verified":False,
         "fork_resolved":False,"release_authorized":False,
         "live_gameplay_authority":False}
    out["receipt_sha256"]=digest(out)
    return out
def hold():
    return {"phase":"RUST-059","status":"HOLD_MISSING_EXTERNAL_CONTROL_CHALLENGE",
            "independent_external_control_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False}
def main():
    p=argparse.ArgumentParser()
    for k in ("source","history","claim","authority-pin","floor"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    args=[a.source,a.history,a.claim,a.authority_pin]
    require(all(args) or not any(args),"partial control evidence refused")
    require(not a.floor or all(args),"floor without full evidence refused")
    if all(args):
        read=lambda v:json.loads(Path(v).read_text(encoding="utf-8"))
        out=audit(read(a.source),read(a.history),read(a.claim),
                  a.authority_pin,read(a.floor) if a.floor else None)
    else: out=hold()
    target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-059 HOLD: external control unverified")
if __name__=="__main__":main()
