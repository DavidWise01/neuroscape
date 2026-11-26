#!/usr/bin/env python3
"""RUST-032: retrieval-session challenge freshness and append-only replay ledger.

A signed challenge from a separately pinned issuer establishes only that key
signed the bytes; local ledgers cannot guarantee independent custody or
anti-rollback. Unseen or missing history is HOLD, never release authority.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

def check_upstream(upstream):
    require(isinstance(upstream,dict) and upstream.get("phase")=="RUST-031","upstream RUST-031 absent")
    require(upstream.get("status") in ("HOLD_DUPLICATED_RETRIEVAL_ANCESTRY","HOLD_OPERATOR_CONTROL_UNPROVEN"),
            "unqualified retrieval ancestor")
    require(upstream.get("release_authorized") is False and upstream.get("fork_resolved") is False,
            "upstream authority escalation")
    require(digest({k:v for k,v in upstream.items() if k!="receipt_sha256"})==
            upstream.get("receipt_sha256"),"upstream receipt modified")
    records=upstream.get("observations")
    require(isinstance(records,list) and len(records)==3,"three retrieval observations needed")
    require([x.get("role") for x in records]==list(ROLES),"upstream roles inconsistent")
    return records

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-032","historical ledger absent")
    require(history.get("status")=="HOLD_RETRIEVAL_FRESHNESS","unqualified prior ledger")
    require(type(history.get("epoch")) is int and history["epoch"]>=0,"invalid prior epoch")
    require(isinstance(history.get("entries"),list),"history entries absent")
    require(history.get("release_authorized") is False,"historical release escalation")
    require(digest({k:v for k,v in history.items() if k!="ledger_sha256"})==
            history.get("ledger_sha256"),"history altered")
    for entry in history["entries"]:
        require(isinstance(entry,dict),"malformed historical entry")
        for field in ("nonce_sha256","retrieval_session_sha256","challenge_signature_sha256"):
            check_sha(entry.get(field),"missing historical "+field)
    return history

def fresh_payload(upstream,record,entry,epoch,previous_ledger_sha256):
    require(isinstance(entry,dict) and entry.get("role")==record["role"],
            "challenge role mismatch")
    check_sha(entry.get("nonce_sha256"),"nonce absent")
    check_sha(entry.get("retrieval_session_sha256"),"session absent")
    check_sha(entry.get("retrieval_endpoint_sha256"),"endpoint absent")
    require(entry["retrieval_session_sha256"]==record["retrieval_session_sha256"],
            "session differs from authenticated retrieval")
    require(entry["retrieval_endpoint_sha256"]==record["retrieval_endpoint_sha256"],
            "endpoint differs from upstream retrieval")
    return {
        "phase":"RUST-032","kind":"EXTERNAL_SESSION_CHALLENGE",
        "role":record["role"],"epoch":epoch,
        "upstream_rust031_receipt_sha256":upstream["receipt_sha256"],
        "prior_ledger_sha256":previous_ledger_sha256,
        "nonce_sha256":entry["nonce_sha256"],
        "retrieval_session_sha256":entry["retrieval_session_sha256"],
        "retrieval_endpoint_sha256":entry["retrieval_endpoint_sha256"],
        "retrieved_archive_sha256":record["retrieved_archive_sha256"],
    }

def audit(upstream, signed_challenges, issuer_pins, history, verifier=verify_key_and_signature):
    sources=check_upstream(upstream)
    prior=checked_history(history)
    require(isinstance(signed_challenges,list) and len(signed_challenges)==3,
            "three independent challenge declarations required")
    require(isinstance(issuer_pins,list) and len(issuer_pins)==3,
            "three external issuer pins required")
    for p in issuer_pins:
        check_sha(p,"issuer fingerprint invalid")
    require(len(set(issuer_pins))==3,"challenge issuers share signing key")
    epoch=prior["epoch"]+1
    old_nonces={x["nonce_sha256"] for x in prior["entries"]}
    old_sessions={x["retrieval_session_sha256"] for x in prior["entries"]}
    used_nonces=set()
    used_sessions=set()
    records=[]
    for role,source,item,pin in zip(ROLES,sources,signed_challenges,issuer_pins):
        candidate=fresh_payload(upstream,source,item,epoch,prior["ledger_sha256"])
        nonce=candidate["nonce_sha256"]
        session=candidate["retrieval_session_sha256"]
        require(nonce not in old_nonces and nonce not in used_nonces,
                "challenge nonce replay")
        require(session not in old_sessions and session not in used_sessions,
                "retrieval session replay")
        used_nonces.add(nonce)
        used_sessions.add(session)
        signature=verifier(item.get("issuer_public_key"),item.get("issuer_signature"),
                           pin,canonical(candidate))
        records.append({
            **candidate,"issuer_spki_sha256":pin,
            "challenge_signature_sha256":signature,
            "external_issuer_identity_verified":False,
            "nonce_freshness_globally_verified":False,
        })
    result={
        "phase":"RUST-032","status":"HOLD_RETRIEVAL_FRESHNESS",
        "epoch":epoch,"previous_ledger_sha256":prior["ledger_sha256"],
        "upstream_rust031_receipt_sha256":upstream["receipt_sha256"],
        "entries":prior["entries"]+records,
        "current_observations":records,
        "external_latest_ledger_confirmed":False,
        "independent_issuer_custody_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["ledger_sha256"]=digest(result)
    return result

def genesis_history():
    """Explicit empty local history; not a substitute for external highwater."""
    base={
        "phase":"RUST-032","status":"HOLD_RETRIEVAL_FRESHNESS",
        "epoch":0,"entries":[],"release_authorized":False,
        "external_latest_ledger_confirmed":False,
    }
    base["ledger_sha256"]=digest(base)
    return base

def hold():
    return {
        "phase":"RUST-032","status":"HOLD_MISSING_EXTERNAL_SESSION_LEDGER",
        "entries":[],"release_authorized":False,
        "external_latest_ledger_confirmed":False,
        "independent_issuer_custody_verified":False,
        "live_gameplay_authority":False,
        "reason":"No externally retained highwater ledger and issuer-authenticated challenges",
    }

def main():
    parser=argparse.ArgumentParser()
    for arg in ("upstream","challenges","history"):
        parser.add_argument("--"+arg)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    supplied=[args.upstream,args.challenges,args.history]
    require(all(supplied) or not any(supplied),"partial external session evidence refused")
    if not all(supplied):
        result=hold()
    else:
        pins=[os.getenv("RUST032_ISSUER_PIN_"+role.upper()) for role in ROLES]
        require(all(pins),"external witness issuer pins missing")
        result=audit(
            json.loads(Path(args.upstream).read_text(encoding="utf-8")),
            json.loads(Path(args.challenges).read_text(encoding="utf-8")),
            pins,json.loads(Path(args.history).read_text(encoding="utf-8")))
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-032 HOLD: independent session freshness not established")

if __name__=="__main__":
    main()
