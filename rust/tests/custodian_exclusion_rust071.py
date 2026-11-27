#!/usr/bin/env python3
"""RUST-071: append-only exclusion ledger and recovery denial persistence.
External custody, global anti-rollback, and release authority remain HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature

GENESIS=digest({"phase":"RUST-071","kind":"CUSTODIAN_EXCLUSION_GENESIS_V1"})
ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checked_source(source):
    require(isinstance(source,dict) and source.get("phase")=="RUST-070" and
            source.get("status")=="HOLD_REVOCATION_HIGHWATER_CUSTODIAN_EXCLUSION",
            "RUST-070 exclusion highwater missing")
    require(digest({k:v for k,v in source.items() if k!="receipt_sha256"})==
            source.get("receipt_sha256"),"RUST-070 source receipt altered")
    require(source.get("all_successors_quarantined") is True and all(
            source.get(k) is False for k in
            ("independent_custody_verified","recovery_authorized",
             "release_authorized","live_gameplay_authority")),
            "RUST-070 tried to restore recovery authority")
    pins=source.get("current_revoked_pins_preserved")
    roots=source.get("current_revoked_roots_preserved")
    conflicts=source.get("current_conflicts_preserved")
    require(isinstance(pins,list) and pins and isinstance(roots,list) and
            isinstance(conflicts,list) and
            pins[:len(source.get("prior_revoked_pins_preserved",[]))]==
            source.get("prior_revoked_pins_preserved") and
            roots[:len(source.get("prior_revoked_roots_preserved",[]))]==
            source.get("prior_revoked_roots_preserved") and
            conflicts[:len(source.get("historical_conflicts_preserved",[]))]==
            source.get("historical_conflicts_preserved"),
            "RUST-070 prior exclusions disappeared")
    return pins,roots,conflicts

def genesis():
    out={"phase":"RUST-071","status":"HOLD_CUSTODIAN_EXCLUSION_RECOVERY_DENIAL",
         "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
         "event_count":0,"excluded_pins":[],"excluded_controller_roots":[],
         "recovery_denials":[],"custody_conflicts":[],
         "independent_custody_verified":False,
         "recovery_authorized":False,"release_authorized":False}
    out["receipt_sha256"]=digest(out)
    return out

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-071" and
            history.get("status")=="HOLD_CUSTODIAN_EXCLUSION_RECOVERY_DENIAL" and
            all(history.get(k) is False for k in
                ("independent_custody_verified","recovery_authorized",
                 "release_authorized")),"prior exclusion ledger missing or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "historical exclusion ledger truncated")
    last=GENESIS;pins=[];roots=[];denials=[];conflicts=[];seen_nonces=set();seen_receipts=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-071" and
                e.get("kind")=="EXCLUDED_CUSTODIAN_RECOVERY_DENIAL" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==last and
                e.get("recovery_denied") is True and
                e.get("quarantine_persists") is True and
                e.get("recovery_authorized") is False and
                e.get("release_authorized") is False,
                "historical exclusion event altered")
        for k in ("source_rust070_receipt_sha256","candidate_pin",
                  "candidate_controller_sha256","candidate_source_root_sha256",
                  "candidate_acquisition_sha256","challenge_nonce_sha256",
                  "challenger_pin","challenge_sha256","signature_sha256"):
            check_sha(e.get(k),"historical denial field missing: "+k)
        require(e["source_rust070_receipt_sha256"] not in seen_receipts and
                e["challenge_nonce_sha256"] not in seen_nonces,
                "historical denial source/nonce replay")
        seen_receipts.add(e["source_rust070_receipt_sha256"])
        seen_nonces.add(e["challenge_nonce_sha256"])
        expected_pins=e.get("excluded_pins_snapshot")
        expected_roots=e.get("excluded_controller_roots_snapshot")
        require(isinstance(expected_pins,list) and
                isinstance(expected_roots,list) and
                expected_pins[:len(pins)]==pins and
                expected_roots[:len(roots)]==roots,
                "historical exclusion snapshot dropped ancestry")
        for pin in expected_pins:check_sha(pin,"historical excluded pin invalid")
        for root in expected_roots:check_sha(root,"historical excluded root invalid")
        pins=expected_pins;roots=expected_roots
        require(isinstance(e.get("denial_conflicts"),list),"denial conflicts omitted")
        conflicts+=e["denial_conflicts"]
        denial={"candidate_pin":e["candidate_pin"],
                "source_rust070_receipt_sha256":e["source_rust070_receipt_sha256"],
                "recovery_denied":True}
        denials.append(denial)
        require(e.get("denial_record")==denial,"historical denial record erased")
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical exclusion entry hash altered")
        last=e["entry_sha256"]
        require(heads[i]==last,"historical exclusion prefix rewritten")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==last and
            history.get("excluded_pins")==pins and
            history.get("excluded_controller_roots")==roots and
            history.get("recovery_denials")==denials and
            history.get("custody_conflicts")==conflicts,
            "historical excluded identities or denial records erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"exclusion ledger receipt altered")
    return events,heads

def challenge(source,prior_head,candidate,nonce):
    require(isinstance(candidate,dict),"recovery candidate missing")
    for k in ("signer_pin",*ORIGINS):
        check_sha(candidate.get(k),"recovery candidate missing "+k)
    check_sha(nonce,"fresh recovery nonce missing")
    return {"phase":"RUST-071","kind":"EXCLUDED_CUSTODIAN_RECOVERY_DENIAL_V1",
            "source_rust070_receipt_sha256":source["receipt_sha256"],
            "previous_exclusion_head_sha256":prior_head,
            "candidate_pin":candidate["signer_pin"],
            **{k:candidate[k] for k in ORIGINS},
            "challenge_nonce_sha256":nonce,"recovery_denied":True,
            "release_authorized":False}

def audit(source,history,candidate,nonce,challenger_pin,public_key,signature,
          floor=None,verifier=verify_key_and_signature):
    source_pins,source_roots,source_conflicts=checked_source(source)
    prior,heads=checked_history(history)
    require(source["receipt_sha256"] not in
            {e["source_rust070_receipt_sha256"] for e in prior},
            "source exclusion highwater replay")
    require(source_pins[:len(history["excluded_pins"])]==
            history["excluded_pins"] and
            source_roots[:len(history["excluded_controller_roots"])]==
            history["excluded_controller_roots"],
            "previously excluded custodian disappeared")
    msg=challenge(source,heads[-1],candidate,nonce)
    check_sha(challenger_pin,"challenger pin missing")
    require(challenger_pin not in set(source_pins) and
            challenger_pin!=candidate["signer_pin"],
            "revoked or candidate signer cannot self-attest denial")
    require(nonce not in {e["challenge_nonce_sha256"] for e in prior},
            "recovery challenge nonce replay")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-071",
                "externally retained exclusion floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained exclusion floor outside history")
        check_sha(floor.get("head_sha256"),"retained floor hash invalid")
        require(heads[n]==floor["head_sha256"],
                "retained exclusion floor contradicts prefix")
    sig=verifier(public_key,signature,challenger_pin,canonical(msg))
    check_sha(sig,"challenger signature invalid")
    denial_conflicts=[]
    if candidate["signer_pin"] in source_pins:
        denial_conflicts.append({"reason":"EXCLUDED_SIGNER_REENTRY",
                                 "independent_custody_verified":False})
    if candidate["controller_sha256"] in source_roots:
        denial_conflicts.append({"reason":"RENAMED_SIGNER_REUSES_EXCLUDED_CONTROLLER",
                                 "independent_custody_verified":False})
    if any(e["candidate_pin"]==candidate["signer_pin"] and
           e["candidate_controller_sha256"]!=candidate["controller_sha256"]
           for e in prior):
        denial_conflicts.append({"reason":"SAME_SIGNER_CHANGED_CLAIMED_CONTROLLER",
                                 "independent_custody_verified":False})
    if any(e["candidate_acquisition_sha256"]==candidate["acquisition_sha256"]
           and e["candidate_pin"]!=candidate["signer_pin"] for e in prior):
        denial_conflicts.append({"reason":"RENAMED_SIGNER_SHARED_ACQUISITION",
                                 "independent_custody_verified":False})
    denial={"candidate_pin":candidate["signer_pin"],
            "source_rust070_receipt_sha256":source["receipt_sha256"],
            "recovery_denied":True}
    e={"phase":"RUST-071","kind":"EXCLUDED_CUSTODIAN_RECOVERY_DENIAL",
       "ordinal":len(prior)+1,"previous_entry_sha256":heads[-1],
       "source_rust070_receipt_sha256":source["receipt_sha256"],
       "candidate_pin":candidate["signer_pin"],
       "candidate_controller_sha256":candidate["controller_sha256"],
       "candidate_source_root_sha256":candidate["source_root_sha256"],
       "candidate_acquisition_sha256":candidate["acquisition_sha256"],
       "challenge_nonce_sha256":nonce,"challenger_pin":challenger_pin,
       "challenge_sha256":digest(msg),"signature_sha256":sig,
       "excluded_pins_snapshot":source_pins,
       "excluded_controller_roots_snapshot":source_roots,
       "source_custody_conflicts_sha256":digest(source_conflicts),
       "denial_record":denial,"denial_conflicts":denial_conflicts,
       "quarantine_persists":True,"recovery_denied":True,
       "recovery_authorized":False,"release_authorized":False}
    e["entry_sha256"]=digest(e)
    out={"phase":"RUST-071","status":"HOLD_CUSTODIAN_EXCLUSION_RECOVERY_DENIAL",
         "events":prior+[e],"prefix_heads":heads+[e["entry_sha256"]],
         "event_count":len(prior)+1,"head_sha256":e["entry_sha256"],
         "excluded_pins":source_pins,
         "excluded_controller_roots":source_roots,
         "recovery_denials":history["recovery_denials"]+[denial],
         "custody_conflicts":history["custody_conflicts"]+denial_conflicts,
         "retained_floor_compared":floor is not None,
         "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
         "independent_custody_verified":False,
         "globally_latest_exclusion_verified":False,
         "global_anti_rollback_certified":False,
         "recovery_authorized":False,"release_authorized":False,
         "live_gameplay_authority":False}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-071","status":"HOLD_MISSING_CUSTODIAN_EXCLUSION_EVIDENCE",
            "independent_custody_verified":False,"recovery_authorized":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","history","candidate","nonce","challenger-pin",
                 "public-key","signature","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    required=[args.source,args.history,args.candidate,args.nonce,
              args.challenger_pin,args.public_key,args.signature]
    require(all(required) or not any(required),"partial exclusion evidence refused")
    require(not args.floor or all(required),"floor without exclusion evidence")
    if all(required):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(args.source),read(args.history),read(args.candidate),
                  args.nonce,args.challenger_pin,args.public_key,args.signature,
                  read(args.floor) if args.floor else None)
    else:out=hold()
    dest=Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-071 HOLD: independent exclusion custody unverified")
if __name__=="__main__":main()
