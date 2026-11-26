#!/usr/bin/env python3
"""RUST-038 — immutable revocation ancestry and historical-prefix fencing.

Reverify a RUST-037 anchor signature against an externally pinned key,
then hash every RUST-036 revocation as an ordered predecessor-linked
event. Compare the exact chain prefix with an externally held floor.
A locally supplied floor is NOT authenticated independent custody.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from registry_highwater_rust037 import anchor_payload
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

GENESIS = digest({"phase":"RUST-038","kind":"REVOCATION_GENESIS_V1"})

def build_chain(revocations):
    require(isinstance(revocations,list),"revocation history missing")
    entries=[]
    heads=[GENESIS]
    seen=set()
    previous=GENESIS
    for i,rev in enumerate(revocations,1):
        require(isinstance(rev,dict) and rev.get("phase")=="RUST-036" and
                rev.get("kind")=="KEY_REVOCATION","unrecognized revocation event")
        require(rev.get("role") in ("ff","cf","rr"),"invalid revocation witness role")
        for field in ("revoked_pin","evidence_sha256","authority_pin","authority_signature_sha256"):
            check_sha(rev.get(field),"revocation field invalid: "+field)
        require(type(rev.get("effective_epoch")) is int and rev["effective_epoch"]>=0,
                "revocation effective epoch invalid")
        key=(rev["role"],rev["revoked_pin"])
        require(key not in seen,"revoked key repeated in history")
        seen.add(key)
        value={
            "phase":"RUST-038","kind":"REVOCATION_CHAIN_ENTRY",
            "ordinal":i,
            "previous_entry_sha256":previous,
            "source_revocation_sha256":digest(rev),
            "role":rev["role"],
            "revoked_pin":rev["revoked_pin"],
            "effective_epoch":rev["effective_epoch"],
            "authority_pin":rev["authority_pin"],
            "release_authorized":False,
        }
        value["entry_sha256"]=digest(value)
        entries.append(value)
        previous=value["entry_sha256"]
        heads.append(previous)
    return entries,heads

def check_floor(floor,heads):
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-038",
            "retained chain floor missing")
    require(type(floor.get("entry_count")) is int and floor["entry_count"]>=0,
            "retained count invalid")
    check_sha(floor.get("head_sha256"),"retained head fingerprint invalid")
    require(floor["entry_count"]<len(heads),"revocation history truncated")
    require(floor["head_sha256"]==heads[floor["entry_count"]],
            "revocation prefix rewritten or superseded")
    return True

def audit(registry,anchor_receipt,anchor_public_key,anchor_signature,anchor_pin,
          floor,verifier=verify_key_and_signature):
    expected=anchor_payload(registry)
    require(isinstance(anchor_receipt,dict) and anchor_receipt.get("phase")=="RUST-037",
            "signed RUST-037 receipt required")
    require(anchor_receipt.get("status") in
            ("HOLD_REGISTRY_EQUIVOCATION","HOLD_EXTERNAL_LATEST_REGISTRY_UNVERIFIED"),
            "invalid upstream anchor status")
    require(anchor_receipt.get("release_authorized") is False and
            anchor_receipt.get("fork_resolved") is False,"upstream authority promotion")
    require(digest({k:v for k,v in anchor_receipt.items() if k!="receipt_sha256"})==
            anchor_receipt.get("receipt_sha256"),"anchor receipt altered")
    require(anchor_receipt.get("signed_anchor")==expected,
            "anchor does not bind exact source registry history")
    check_sha(anchor_pin,"externally pinned anchor key absent")
    require(anchor_receipt.get("anchor_witness_key_spki_sha256")==anchor_pin,
            "anchor signer differs from external pin")
    signature_hash=verifier(anchor_public_key,anchor_signature,anchor_pin,canonical(expected))
    check_sha(signature_hash,"anchor signature fingerprint missing")
    require(anchor_receipt.get("anchor_signature_sha256")==signature_hash,
            "anchor signature differs from retained RUST-037 receipt")

    revocations=registry["revocation_evidence"]
    entries,heads=build_chain(revocations)
    require(expected["revocation_count"]==len(entries),"signed revocation count inconsistent")
    require(expected["revocations_sha256"]==digest(revocations),
            "signed revocation sequence modified")
    if floor is not None:
        check_floor(floor,heads)
    result={
        "phase":"RUST-038",
        "status":"HOLD_PRESERVED_EQUIVOCATION" if
            anchor_receipt["status"]=="HOLD_REGISTRY_EQUIVOCATION" else
            "HOLD_EXTERNAL_PREFIX_CUSTODY_UNVERIFIED",
        "upstream_rust037_receipt_sha256":anchor_receipt["receipt_sha256"],
        "upstream_rust036_receipt_sha256":registry["receipt_sha256"],
        "signed_anchor_witness_spki_sha256":anchor_pin,
        "reverified_anchor_signature_sha256":signature_hash,
        "revocation_chain":entries,
        "revocation_entry_count":len(entries),
        "revocation_chain_head_sha256":heads[-1],
        "prefix_head_sha256_by_count":heads,
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
        "preserved_equivocation_evidence":anchor_receipt.get("preserved_equivocation_evidence",[]),
        "external_floor_custody_authenticated":False,
        "external_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-038","status":"HOLD_MISSING_EXTERNAL_REVOCATION_ANCESTRY",
        "revocation_chain":[],"release_authorized":False,
        "external_floor_custody_authenticated":False,
        "global_anti_rollback_certified":False,"fork_resolved":False,
        "live_gameplay_authority":False,
        "reason":"No independently retained revocation prefix and authenticated anchor material",
    }

def main():
    parser=argparse.ArgumentParser()
    for name in ("registry","anchor-receipt","anchor-public-key","anchor-signature","floor"):
        parser.add_argument("--"+name)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    a=parser.parse_args()
    supplied=(a.registry,a.anchor_receipt,a.anchor_public_key,a.anchor_signature)
    require(all(supplied) or not any(supplied),"partial anchored registry material refused")
    require(not a.floor or all(supplied),"floor without signed registry refused")
    if all(supplied):
        pin=os.getenv("RUST038_ANCHOR_WITNESS_SPKI_SHA256")
        require(pin,"external anchor key pin required")
        floor=json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None
        result=audit(
            json.loads(Path(a.registry).read_text(encoding="utf-8")),
            json.loads(Path(a.anchor_receipt).read_text(encoding="utf-8")),
            a.anchor_public_key,a.anchor_signature,pin,floor)
    else:
        result=hold()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as file:
        json.dump(result,file,sort_keys=True,indent=2)
        file.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-038 HOLD: independent revocation ancestry not established")
if __name__=="__main__":
    main()
