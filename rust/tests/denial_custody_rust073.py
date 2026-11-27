#!/usr/bin/env python3
"""RUST-073: independently claimed third-party denial-custody snapshots.

Checks complete RUST-071 ancestry, two separately pinned signatures and
append-only snapshot retention. Claims are not independent external custody.
Recovery, release, and global-rollback authority remain HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from custodian_exclusion_rust071 import checked_history as checked_denials

GENESIS=digest({"phase":"RUST-073","kind":"DENIAL_CUSTODY_GENESIS_V1"})
FIELDS=("controller_sha256","source_root_sha256","acquisition_sha256")
ROLES=("left","right")

def checked_source(source,denial):
    require(isinstance(source,dict) and source.get("phase")=="RUST-072" and
            source.get("status")=="HOLD_EXCLUSION_HIGHWATER_PERMANENT_DENIAL" and
            source.get("all_recovery_denials_persist") is True and
            all(source.get(k) is False for k in
                ("independent_custody_verified","recovery_authorized",
                 "release_authorized","live_gameplay_authority")),
            "RUST-072 denial highwater missing or promoted")
    require(source.get("receipt_sha256")==digest({
        k:v for k,v in source.items() if k!="receipt_sha256"}),
        "RUST-072 highwater receipt altered")
    events,heads=checked_denials(denial)
    require(events and source.get("current_rust071_receipt_sha256")==
            denial["receipt_sha256"] and
            source.get("current_event_count")==len(events) and
            source.get("current_recovery_denials_preserved")==denial["recovery_denials"] and
            source.get("current_excluded_pins_preserved")==denial["excluded_pins"] and
            source.get("current_excluded_controllers_preserved")==
            denial["excluded_controller_roots"] and
            source.get("current_conflicts_preserved")==denial["custody_conflicts"],
            "RUST-072 source does not bind complete denial ledger")
    return events,heads

def genesis():
    h={"phase":"RUST-073","status":"HOLD_INDEPENDENT_DENIAL_CUSTODY",
       "events":[],"prefix_heads":[GENESIS],"event_count":0,
       "head_sha256":GENESIS,"custody_conflicts":[],
       "independent_custody_verified":False,
       "recovery_authorized":False,"release_authorized":False}
    h["receipt_sha256"]=digest(h)
    return h

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-073"
            and history.get("status")=="HOLD_INDEPENDENT_DENIAL_CUSTODY"
            and all(history.get(k) is False for k in
                ("independent_custody_verified","recovery_authorized",
                 "release_authorized")),"RUST-073 custody history missing or promoted")
    rows,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(rows,list) and isinstance(heads,list) and
            len(heads)==len(rows)+1 and heads[0]==GENESIS,
            "custody ledger prefix truncated")
    head=GENESIS;conflicts=[];nonces=set();sources=set()
    for i,e in enumerate(rows,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-073"
                and e.get("kind")=="DENIAL_CUSTODY_SNAPSHOT_V1"
                and e.get("ordinal")==i and e.get("previous_entry_sha256")==head
                and all(e.get(k) is False for k in
                    ("independent_custody_verified","recovery_authorized",
                     "release_authorized")),
                "previous custody entry rewritten or promoted")
        for k in ("source_rust072_receipt_sha256","source_rust071_receipt_sha256",
                  "denials_sha256","excluded_pins_sha256",
                  "excluded_controllers_sha256"):
            check_sha(e.get(k),"historical snapshot fingerprint invalid")
        require(e["source_rust072_receipt_sha256"] not in sources,
                "replayed denial custody source")
        sources.add(e["source_rust072_receipt_sha256"])
        witnesses=e.get("witnesses")
        require(isinstance(witnesses,list) and len(witnesses)==2
                and [w.get("role") for w in witnesses]==list(ROLES),
                "historical custodians missing")
        for w in witnesses:
            for f in ("pin","nonce_sha256","message_sha256",
                      "signature_sha256",*FIELDS):
                check_sha(w.get(f),"historical custodian claim incomplete")
            require(w["nonce_sha256"] not in nonces,
                    "historical custody nonce replay")
            nonces.add(w["nonce_sha256"])
        require(isinstance(e.get("denials"),list) and e["denials"] and
                all(d.get("recovery_denied") is True for d in e["denials"]),
                "historical recovery denial erased")
        require(digest(e["denials"])==e["denials_sha256"],
                "historical denial digest replaced")
        if i>1:
            prev=rows[i-2]
            require(e["denials"][:len(prev["denials"])]==prev["denials"] and
                    e["excluded_pins"][:len(prev["excluded_pins"])]==
                    prev["excluded_pins"] and
                    e["excluded_controllers"][:len(prev["excluded_controllers"])]==
                    prev["excluded_controllers"],
                    "prior denial or exclusion disappeared")
        require(digest(e.get("excluded_pins"))==e["excluded_pins_sha256"] and
                digest(e.get("excluded_controllers"))==
                e["excluded_controllers_sha256"],"custodian snapshot rewritten")
        conflicts+=e.get("conflicts",[])
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"custody entry digest altered")
        head=e["entry_sha256"]
        require(heads[i]==head,"custody predecessor head altered")
    require(history.get("event_count")==len(rows) and
            history.get("head_sha256")==head and
            history.get("custody_conflicts")==conflicts,
            "previous custody conflicts erased")
    require(history.get("receipt_sha256")==digest({
        k:v for k,v in history.items() if k!="receipt_sha256"}),
        "custody receipt altered")
    return rows,heads

def challenge(source,denial,prior_head,witness):
    require(isinstance(witness,dict),"custodian evidence missing")
    for f in ("signer_pin","nonce_sha256",*FIELDS):
        check_sha(witness.get(f),"custodian evidence missing "+f)
    return {"phase":"RUST-073","kind":"DENIAL_CUSTODY_CHALLENGE_V1",
            "source_rust072_receipt_sha256":source["receipt_sha256"],
            "source_rust071_receipt_sha256":denial["receipt_sha256"],
            "previous_custody_head_sha256":prior_head,
            "denials_sha256":digest(denial["recovery_denials"]),
            "excluded_pins_sha256":digest(denial["excluded_pins"]),
            "excluded_controllers_sha256":digest(denial["excluded_controller_roots"]),
            "role":witness["role"],"signer_pin":witness["signer_pin"],
            **{k:witness[k] for k in ("nonce_sha256",*FIELDS)},
            "recovery_authorized":False,"release_authorized":False}

def audit(source,denial,history,witnesses,floor=None,
          verifier=verify_key_and_signature):
    events,_=checked_source(source,denial)
    prior,heads=checked_history(history)
    require(source["receipt_sha256"] not in {
        e["source_rust072_receipt_sha256"] for e in prior},
        "duplicate source highwater snapshot")
    if prior:
        last=prior[-1]
        require(denial["recovery_denials"][:len(last["denials"])]==
                last["denials"] and
                denial["excluded_pins"][:len(last["excluded_pins"])]==
                last["excluded_pins"] and
                denial["excluded_controller_roots"][:len(last["excluded_controllers"])]==
                last["excluded_controllers"],
                "prior denial snapshot erased by claimed custodian")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-073",
                "external custody floor missing")
        count=floor.get("event_count")
        require(type(count) is int and 0<=count<len(heads),
                "retained custody floor exceeds current history")
        check_sha(floor.get("head_sha256"),"retained head invalid")
        require(heads[count]==floor["head_sha256"],
                "retained custody floor contradicts history")
    require(isinstance(witnesses,list) and len(witnesses)==2 and
            [w.get("role") for w in witnesses]==list(ROLES),
            "two left/right custody observations required")
    prior_nonces={w["nonce_sha256"] for e in prior for w in e["witnesses"]}
    source_nonces={e["challenge_nonce_sha256"] for e in events}
    source_pins={e["candidate_pin"] for e in events}
    source_pins.update(e["challenger_pin"] for e in events)
    source_pins.update(denial["excluded_pins"])
    source_pins.add(source["checkpoint_signer_pin"])
    pins=set();snap=[];conflicts=[]
    for w in witnesses:
        require(w.get("recovery_authorized") is False and
                w.get("release_authorized") is False,
                "custodian claimed unauthorized release")
        require(w["role"] in ROLES,"invalid custody role")
        message=challenge(source,denial,heads[-1],w)
        pin=message["signer_pin"]; nonce=message["nonce_sha256"]
        require(pin not in source_pins and pin not in pins,
                "source or duplicate signer cannot attest custody")
        require(nonce not in prior_nonces and nonce not in source_nonces,
                "custodian nonce replay")
        pins.add(pin);prior_nonces.add(nonce)
        signed=verifier(w.get("public_key"),w.get("signature"),
                        pin,canonical(message))
        check_sha(signed,"custody witness signature invalid")
        snap.append({"role":w["role"],"pin":pin,
                     "nonce_sha256":nonce,"message_sha256":digest(message),
                     "signature_sha256":signed,
                     **{k:message[k] for k in FIELDS},
                     "independent_custody_verified":False})
    for k in FIELDS:
        if snap[0][k]==snap[1][k]:
            conflicts.append({"reason":"SHARED_CLAIMED_CUSTODIAN_ANCESTRY",
                              "field":k,"independent_custody_verified":False})
    for old in prior:
        for ow in old["witnesses"]:
            for w in snap:
                if w["pin"]!=ow["pin"] and (
                    w["controller_sha256"]==ow["controller_sha256"] or
                    w["acquisition_sha256"]==ow["acquisition_sha256"]):
                    conflicts.append({"reason":"RENAMED_CUSTODIAN_REUSED_PRIOR_ANCESTRY",
                                      "pin":w["pin"],
                                      "independent_custody_verified":False})
    entry={"phase":"RUST-073","kind":"DENIAL_CUSTODY_SNAPSHOT_V1",
           "ordinal":len(prior)+1,"previous_entry_sha256":heads[-1],
           "source_rust072_receipt_sha256":source["receipt_sha256"],
           "source_rust071_receipt_sha256":denial["receipt_sha256"],
           "denials":denial["recovery_denials"],
           "denials_sha256":digest(denial["recovery_denials"]),
           "excluded_pins":denial["excluded_pins"],
           "excluded_pins_sha256":digest(denial["excluded_pins"]),
           "excluded_controllers":denial["excluded_controller_roots"],
           "excluded_controllers_sha256":digest(denial["excluded_controller_roots"]),
           "witnesses":snap,"conflicts":conflicts,
           "independent_custody_verified":False,
           "recovery_authorized":False,"release_authorized":False}
    entry["entry_sha256"]=digest(entry)
    result={"phase":"RUST-073","status":"HOLD_INDEPENDENT_DENIAL_CUSTODY",
            "events":prior+[entry],
            "prefix_heads":heads+[entry["entry_sha256"]],
            "event_count":len(prior)+1,"head_sha256":entry["entry_sha256"],
            "custody_conflicts":history["custody_conflicts"]+conflicts,
            "retained_floor_compared":floor is not None,
            "retained_floor_claim_sha256":digest(floor) if floor else None,
            "independent_custody_verified":False,
            "globally_latest_denial_verified":False,
            "global_anti_rollback_certified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-073","status":"HOLD_MISSING_INDEPENDENT_DENIAL_CUSTODY",
            "independent_custody_verified":False,"recovery_authorized":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","denial","history","witnesses","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.source,a.denial,a.history,a.witnesses]
    require(all(required) or not any(required),
            "partial denial custody evidence refused")
    require(not a.floor or all(required),"floor without custody evidence refused")
    if all(required):
        read=lambda f:json.loads(Path(f).read_text(encoding="utf-8"))
        out=audit(read(a.source),read(a.denial),read(a.history),
                  read(a.witnesses),read(a.floor) if a.floor else None)
    else:out=hold()
    output=Path(a.output);output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-073 HOLD: independent custody not proven")
if __name__=="__main__":main()
