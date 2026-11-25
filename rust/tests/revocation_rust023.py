#!/usr/bin/env python3
"""RUST-023: emergency custodian revocation and recovery gate.

All assertions of revocation require an external, pre-pinned recovery public key
and a valid Ed25519 signature. Old compromised keys cannot authorize recovery.
This script never creates keys or claims external custody it cannot observe.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from adjudicate_rust018 import load
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, verify_key_and_signature, check_anchor

HEX64 = re.compile(r"^[0-9a-f]{64}$")

def valid_sha(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None

def revocation_proposal(predecessor, revoked_key, recovery_key, reason):
    prev=check_anchor(predecessor)
    require(valid_sha(revoked_key), "revoked key fingerprint missing")
    require(valid_sha(recovery_key), "recovery key fingerprint missing")
    require(revoked_key != recovery_key, "compromised custodian cannot be its own recovery key")
    # A previously committed key must be identified by externally retained
    # custody evidence. RUST-021 does not store the genesis signer fingerprint.
    if prev["phase"]=="RUST-022":
        require(revoked_key == prev.get("new_key_spki_sha256"), "revoked key is not current custodian")
    require(reason in ("COMPROMISE", "LOSS", "EMERGENCY_FREEZE"), "unknown reason")
    value={
        "phase":"RUST-023","status":"REVOCATION_PROPOSAL",
        "sequence":prev["sequence"]+1,
        "predecessor_sha256":prev["entry_sha256"],
        "predecessor_source_commit":prev["source_commit"],
        "revoked_key_spki_sha256":revoked_key,
        "recovery_key_spki_sha256":recovery_key,
        "reason":reason,"effective_policy":"DENY_FUTURE_SIGNATURES",
        "live_gameplay_authority":False,"global_anti_rollback_certified":False,
    }
    value["proposal_sha256"]=digest(value)
    return value

def qualify(predecessor, revoked_key, recovery_key, reason, public_key, signature, external_recovery_pin):
    require(valid_sha(external_recovery_pin), "independently pinned recovery key missing")
    require(external_recovery_pin==recovery_key, "external recovery key fingerprint disagreement")
    proposal=revocation_proposal(predecessor,revoked_key,recovery_key,reason)
    sig=verify_key_and_signature(public_key,signature,recovery_key,canonical(proposal))
    record={
        **proposal,
        "status":"REVOKED_EMERGENCY_FREEZE",
        "recovery_signature_sha256":sig,
        "recovery_key_externally_pinned":True,
        "frozen":True,"external_custodian_identity_verified":False,
        "source_independence_certified":False,
    }
    record["entry_sha256"]=digest(record)
    return record

def validate_revocation(record, predecessor):
    prev=check_anchor(predecessor)
    require(isinstance(record,dict), "revocation absent")
    require(record.get("phase")=="RUST-023" and record.get("status")=="REVOKED_EMERGENCY_FREEZE", "not authenticated revocation record")
    require(record.get("frozen") is True, "revocation freeze not active")
    require(record.get("recovery_key_externally_pinned") is True, "external pin not attested")
    require(record.get("live_gameplay_authority") is False, "gameplay authority prohibited")
    require(record.get("global_anti_rollback_certified") is False, "unsupported global claim")
    require(record.get("predecessor_sha256")==prev["entry_sha256"], "revocation predecessor mismatch")
    require(type(record.get("sequence")) is int and record["sequence"]==prev["sequence"]+1, "revocation sequence mismatch")
    require(valid_sha(record.get("entry_sha256")), "revocation digest absent")
    require(digest({k:v for k,v in record.items() if k!="entry_sha256"})==record["entry_sha256"], "revocation tampered")
    return record

def deny_if_revoked(custodian_key_fingerprint, revocations, predecessor):
    require(valid_sha(custodian_key_fingerprint), "custodian key absent")
    for item in revocations:
        record=validate_revocation(item, predecessor)
        if custodian_key_fingerprint==record["revoked_key_spki_sha256"]:
            raise ValueError("HOLD: revoked key cannot sign future checkpoints")
    return True

def hold_record(reason):
    return {
        "phase":"RUST-023","status":"HOLD_REVOCATION_CUSTODY_UNVERIFIED",
        "frozen":True,"custody_rotation_authorized":False,
        "reason":reason,"live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }

def exclusive(path,value):
    target=Path(path)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as stream:
        json.dump(value,stream,indent=2,sort_keys=True)
        stream.write("\n")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--previous")
    p.add_argument("--revoked-key")
    p.add_argument("--reason",default="EMERGENCY_FREEZE")
    p.add_argument("--recovery-key-public")
    p.add_argument("--recovery-signature")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    pin=os.environ.get("RUST023_RECOVERY_KEY_SPKI_SHA256")
    inputs=(args.previous,args.revoked_key,args.recovery_key_public,args.recovery_signature,pin)
    if not all(inputs):
        value=hold_record("No independently held revocation proof or pre-pinned recovery custodian")
    else:
        value=qualify(load(args.previous),args.revoked_key,pin,args.reason,
            args.recovery_key_public,args.recovery_signature,pin)
    exclusive(args.output,value)
    print(json.dumps(value,sort_keys=True))
    if value["status"]!="REVOKED_EMERGENCY_FREEZE" and not args.allow_hold_record:
        raise SystemExit("RUST-023 HOLD: external recovery custody missing")

if __name__=="__main__":
    main()
