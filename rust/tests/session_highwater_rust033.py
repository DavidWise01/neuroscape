#!/usr/bin/env python3
"""RUST-033 — signed external session highwater with withheld-history checks.

The exact RUST-032 ledger hash, epoch and ordered entry count are bound by an
Ed25519 witness signature. This detects truncation/substitution relative to
the supplied signed checkpoint. It cannot prove that the checkpoint is the
latest one; external freshness and independent custody remain HOLD.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from session_freshness_rust032 import checked_history

def checkpoint_payload(ledger):
    history=checked_history(ledger)
    entries=history["entries"]
    nonces=[e["nonce_sha256"] for e in entries]
    sessions=[e["retrieval_session_sha256"] for e in entries]
    require(len(set(nonces))==len(nonces),"historical nonce reuse")
    require(len(set(sessions))==len(sessions),"historical session reuse")
    require(len(entries)==history["epoch"]*3,
            "session epoch entry cardinality mismatch")
    for index,item in enumerate(entries):
        require(item.get("role")==("ff","cf","rr")[index%3],
                "historical witness ordering mismatch")
        require(item.get("epoch")==index//3+1,
                "historical epoch gap")
    return {
        "phase":"RUST-033","kind":"SIGNED_SESSION_HIGHWATER",
        "ledger_sha256":history["ledger_sha256"],
        "epoch":history["epoch"],
        "entry_count":len(entries),
        "entries_sha256":digest(entries),
        "last_entry_sha256":digest(entries[-1]) if entries else "0"*64,
        "release_authorized":False,
        "global_anti_rollback_certified":False,
    }

def check_signed_checkpoint(candidate):
    require(isinstance(candidate,dict),"signed highwater missing")
    require(candidate.get("phase")=="RUST-033" and
            candidate.get("kind")=="SIGNED_SESSION_HIGHWATER",
            "wrong highwater claim")
    for field in ("ledger_sha256","entries_sha256","last_entry_sha256"):
        check_sha(candidate.get(field),"invalid "+field)
    require(type(candidate.get("epoch")) is int and candidate["epoch"]>=0,
            "invalid checkpoint epoch")
    require(type(candidate.get("entry_count")) is int and
            candidate["entry_count"]==candidate["epoch"]*3,
            "invalid signed checkpoint entry count")
    require(candidate.get("release_authorized") is False and
            candidate.get("global_anti_rollback_certified") is False,
            "unsupported checkpoint authority")
    require(set(candidate)==set(checkpoint_payload_keys()),"unknown checkpoint fields")
    return candidate

def checkpoint_payload_keys():
    return ("phase","kind","ledger_sha256","epoch","entry_count",
            "entries_sha256","last_entry_sha256","release_authorized",
            "global_anti_rollback_certified")

def verify(ledger, checkpoint, public_key, signature, external_pin,
           signature_verifier=verify_key_and_signature):
    expected=checkpoint_payload(ledger)
    signed=check_signed_checkpoint(checkpoint)
    require(expected==signed,"signed highwater disagrees with ledger or entries missing")
    check_sha(external_pin,"separately pinned witness key required")
    sig_sha=signature_verifier(public_key,signature,external_pin,canonical(signed))
    result={
        "phase":"RUST-033","status":"HOLD_LATEST_HIGHWATER_UNCONFIRMED",
        "ledger_sha256":expected["ledger_sha256"],
        "epoch":expected["epoch"],"entry_count":expected["entry_count"],
        "entries_sha256":expected["entries_sha256"],
        "highwater_witness_key_spki_sha256":external_pin,
        "highwater_witness_signature_sha256":sig_sha,
        "retained_entry_count_matches":True,
        "independent_external_custody_verified":False,
        "latest_highwater_independently_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def compare_with_retained_floor(checkpoint, externally_retained_epoch,
                                 externally_retained_ledger_hash):
    """Requires an authenticated floor supplied out of band.
    This helper checks the values but does NOT authenticate their origin.
    """
    check_signed_checkpoint(checkpoint)
    require(type(externally_retained_epoch) is int and externally_retained_epoch>=0,
            "externally retained epoch invalid")
    check_sha(externally_retained_ledger_hash,"external ledger fingerprint absent")
    require(checkpoint["epoch"]>=externally_retained_epoch,"signed checkpoint rollback")
    if checkpoint["epoch"]==externally_retained_epoch:
        require(checkpoint["ledger_sha256"]==externally_retained_ledger_hash,
                "equivocated highwater at retained epoch")
    return True

def hold():
    return {
        "phase":"RUST-033","status":"HOLD_MISSING_SIGNED_SESSION_HIGHWATER",
        "release_authorized":False,
        "latest_highwater_independently_verified":False,
        "global_anti_rollback_certified":False,
        "live_gameplay_authority":False,
        "reason":"No independently pinned witness signature on exact retained session history",
    }

def main():
    parser=argparse.ArgumentParser()
    for field in ("ledger","checkpoint","public-key","signature"):
        parser.add_argument("--"+field)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    inputs=(args.ledger,args.checkpoint,args.public_key,args.signature)
    require(all(inputs) or not any(inputs),"partial signed highwater input refused")
    if all(inputs):
        pin=os.getenv("RUST033_HIGHWATER_WITNESS_SPKI_SHA256")
        require(pin,"externally pinned highwater witness key missing")
        result=verify(json.loads(Path(args.ledger).read_text(encoding="utf-8")),
                      json.loads(Path(args.checkpoint).read_text(encoding="utf-8")),
                      args.public_key,args.signature,pin)
    else:
        result=hold()
    out=Path(args.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,sort_keys=True,indent=2)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-033 HOLD: latest external session highwater not authenticated")

if __name__=="__main__":
    main()
