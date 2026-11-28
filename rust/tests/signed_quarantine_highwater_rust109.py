#!/usr/bin/env python3
"""RUST-109 — signed, append-only quarantine highwater.

Signatures bind exact RUST-108 ledger history and all exclusion reasons.
They DO NOT establish independent external custody or a globally latest head.
"""
import argparse
import json
from pathlib import Path
from external_floor_quarantine_rust108 import validate, hash_obj, need
from rotation_rust022 import canonical, verify_key_and_signature

DOMAIN = "NEUROSCAPE_RUST109_SIGNED_QUARANTINE_HIGHWATER_V1"
HOLD = "HOLD_SIGNED_QUARANTINE_HIGHWATER_INDEPENDENCE_UNVERIFIED"

def sha(s):
    need(isinstance(s, str) and len(s) == 64
         and all(c in "0123456789abcdef" for c in s),
         "lowercase SHA-256 required")
    return s

def exclusions(history):
    validate(history)
    return [{"index": e["index"],
             "local_head_sha256": e["observation"]["local_head_sha256"],
             "upstream_conflicts": e["observation"]["upstream_conflicts"],
             "derived_conflicts": e["observation"]["derived_conflicts"],
             "quarantine_reasons": e["quarantine_reasons"]}
            for e in history]

def checkpoint(history, signer_pin, nonce):
    head = validate(history)
    need(len(history)>0,"nonempty quarantine history required")
    return {"phase":"RUST-109", "domain":DOMAIN,
            "epoch_count":len(history), "head_sha256":head,
            "history_sha256":hash_obj(history),
            "excluded_history_sha256":hash_obj(exclusions(history)),
            "signer_pin":sha(signer_pin), "nonce_sha256":sha(nonce),
            "quarantine_retained":True, "independent_external_custody_verified":False,
            "globally_authenticated_latest":False, "fork_selected":False,
            "release_authorized":False, "recovery_authorized":False}

def verify_signed(history,signed,verifier=verify_key_and_signature):
    need(isinstance(signed,dict),"signed highwater record required")
    pin,nonce=sha(signed.get("signer_pin")),sha(signed.get("nonce_sha256"))
    expected=checkpoint(history,pin,nonce)
    need(signed.get("payload")==expected,"signed quarantine highwater differs")
    receipt=verifier(signed.get("public_key"),signed.get("signature"),
                     pin,canonical(expected))
    return expected,sha(receipt)

def audit(previous,current,prior_signed,later_signed,verifier=verify_key_and_signature):
    old_head,new_head=validate(previous),validate(current)
    need(bool(previous) and len(current)>len(previous)
         and current[:len(previous)]==previous,
         "rollback, divergent predecessor, or rewritten quarantine history")
    before,before_sig=verify_signed(previous,prior_signed,verifier)
    after,after_sig=verify_signed(current,later_signed,verifier)
    need(before["head_sha256"]==old_head
         and after["head_sha256"]==new_head,
         "signed highwater head mismatch")
    need(current[len(previous)]["previous_sha256"]==old_head,
         "missing exact predecessor linkage")
    need(before["signer_pin"]!=after["signer_pin"],"signer rotation not distinct")
    need(before["nonce_sha256"]!=after["nonce_sha256"],"highwater nonce replay")
    return {"phase":"RUST-109","domain":DOMAIN,"status":HOLD,
            "prior_head_sha256":old_head,"current_head_sha256":new_head,
            "prior_checkpoint_sha256":hash_obj(before),
            "current_checkpoint_sha256":hash_obj(after),
            "prior_signature_receipt_sha256":before_sig,
            "current_signature_receipt_sha256":after_sig,
            "excluded_history_sha256":after["excluded_history_sha256"],
            "exclusion_history_preserved":True,
            "independent_external_custody_verified":False,
            "globally_authenticated_latest":False,"fork_selected":False,
            "release_authorized":False,"recovery_authorized":False,
            "live_gameplay_authorized":False}

def competing(history,left_signed,right_signed,verifier=verify_key_and_signature):
    left,left_sig=verify_signed(history,left_signed,verifier)
    right,right_sig=verify_signed(history,right_signed,verifier)
    need(left["signer_pin"]!=right["signer_pin"]
         and left["nonce_sha256"]!=right["nonce_sha256"],
         "duplicated signer or nonce in competing highwater claims")
    return {"phase":"RUST-109","status":HOLD,
            "preserved_claims":[
                {"checkpoint_sha256":hash_obj(left),"signature_receipt_sha256":left_sig},
                {"checkpoint_sha256":hash_obj(right),"signature_receipt_sha256":right_sig}],
            "common_history_head_sha256":left["head_sha256"],
            "fork_selected":False,
            "independent_external_custody_verified":False,
            "release_authorized":False,"recovery_authorized":False}

def missing():
    return {"phase":"RUST-109",
            "status":"HOLD_MISSING_SIGNED_QUARANTINE_HIGHWATER",
            "independent_external_custody_verified":False,
            "globally_authenticated_latest":False,
            "fork_selected":False,"release_authorized":False,
            "recovery_authorized":False,"live_gameplay_authorized":False}

def main():
    parser=argparse.ArgumentParser()
    for key in ("previous","current","previous-signed","current-signed"):
        parser.add_argument("--"+key)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    a=parser.parse_args()
    sources=(a.previous,a.current,a.previous_signed,a.current_signed)
    need(all(sources) or not any(sources),"partial signed quarantine bundle")
    if all(sources):
        read=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(read(a.previous),read(a.current),
                     read(a.previous_signed),read(a.current_signed))
    else:result=missing()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as out:
        json.dump(result,out,indent=2,sort_keys=True);out.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-109 HOLD: independently authenticated custody unverified")
if __name__=="__main__":main()
