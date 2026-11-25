#!/usr/bin/env python3
"""RUST-024 — quarantined recovery epochs.

No key may re-enter after authenticated revocation. An external monotonic
checkpoint is mandatory to authorize a new epoch. Local observations can
record HOLD but cannot assert custody, OS-time or global anti-rollback.
"""
import argparse
import json
import os
from pathlib import Path
import re

from adjudicate_rust018 import load
from lineage_rust019 import digest, require
from revocation_rust023 import validate_revocation, valid_sha
from rotation_rust022 import check_anchor, verify_key_and_signature, canonical

HEX40 = re.compile(r"^[0-9a-f]{40}$")

def validate_highwater(value):
    require(isinstance(value, dict), "externally held highwater absent")
    require(value.get("phase") == "RUST-024" and value.get("status") == "EXTERNAL_HIGHWATER",
            "highwater not externally acknowledged")
    require(type(value.get("epoch")) is int and value["epoch"] >= 0, "invalid highwater epoch")
    require(type(value.get("sequence")) is int and value["sequence"] >= 1, "invalid highwater sequence")
    require(valid_sha(value.get("checkpoint_sha256")), "invalid highwater checkpoint")
    require(valid_sha(value.get("key_spki_sha256")), "invalid highwater key fingerprint")
    require(value.get("live_gameplay_authority") is False, "invalid gameplay authority")
    require(digest({k:v for k,v in value.items() if k != "highwater_sha256"}) ==
            value.get("highwater_sha256"), "highwater tampered")
    return value

def recovery_proposal(predecessor, revocation, highwater, quarantined, new_key):
    previous = check_anchor(predecessor)
    revoked = validate_revocation(revocation, previous)
    floor = validate_highwater(highwater)
    require(isinstance(quarantined, list) and len(quarantined) >= 1, "quarantine missing")
    require(len(set(quarantined)) == len(quarantined), "duplicated quarantine key")
    require(all(valid_sha(k) for k in quarantined), "invalid quarantine key")
    require(revoked["revoked_key_spki_sha256"] in quarantined, "revoked key not quarantined")
    require(valid_sha(new_key), "new key missing")
    require(new_key not in quarantined, "revoked key replay forbidden")
    require(new_key != revoked["recovery_key_spki_sha256"], "recovery signer cannot be promoted automatically")
    require(floor["checkpoint_sha256"] == previous["entry_sha256"], "external checkpoint disagreement")
    require(floor["sequence"] == previous["sequence"], "stale highwater sequence")
    require(floor["key_spki_sha256"] == revoked["revoked_key_spki_sha256"],
            "external key ancestry mismatch")
    require(floor["epoch"] >= 0, "negative epoch")
    data={
        "phase":"RUST-024","status":"RECOVERY_PROPOSAL",
        "epoch":floor["epoch"]+1,
        "sequence":revoked["sequence"]+1,
        "predecessor_sha256":revoked["entry_sha256"],
        "predecessor_source_commit":previous["source_commit"],
        "revocation_sha256":revoked["entry_sha256"],
        "prior_highwater_sha256":floor["highwater_sha256"],
        "quarantined_key_spki_sha256":sorted(quarantined),
        "recovery_signer_spki_sha256":revoked["recovery_key_spki_sha256"],
        "new_custodian_spki_sha256":new_key,
        "live_gameplay_authority":False,
        "source_independence_certified":False,
        "global_anti_rollback_certified":False,
    }
    data["proposal_sha256"]=digest(data)
    return data

def qualify(predecessor, revocation, highwater, quarantined, new_key,
            recovery_public, recovery_signature, new_public, new_signature,
            external_recovery_pin, external_new_pin, prior_authenticated=False):
    """External callers must first authenticate custody of predecessor,
    revocation and highwater, not merely check self-reported JSON fields."""
    require(prior_authenticated is True, "external prior custody authentication missing")
    require(valid_sha(external_recovery_pin) and valid_sha(external_new_pin),
            "externally pinned recovery and new custodian keys required")
    require(external_new_pin == new_key, "new key substitution")
    proposal = recovery_proposal(predecessor,revocation,highwater,quarantined,new_key)
    require(external_recovery_pin==proposal["recovery_signer_spki_sha256"],
            "recovery signer key substitution")
    require(external_new_pin != external_recovery_pin, "no self-issued recovery rotation")
    message=canonical(proposal)
    recovery_digest=verify_key_and_signature(
        recovery_public,recovery_signature,external_recovery_pin,message)
    new_digest=verify_key_and_signature(
        new_public,new_signature,external_new_pin,message)
    result={
        **proposal,
        "status":"RECOVERY_EPOCH_SIGNATURES_VERIFIED",
        "recovery_signature_sha256":recovery_digest,
        "new_key_signature_sha256":new_digest,
        "external_source_custody_verified":False,
        "global_anti_rollback_certified":False,
        "custody_resume_authorized":False,
    }
    result["entry_sha256"]=digest(result)
    return result

def hold(reason):
    return {
        "phase":"RUST-024","status":"HOLD_QUARANTINED",
        "epoch":None,"sequence":None,
        "quarantine_enforced":True,
        "custody_resume_authorized":False,
        "live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
        "reason":reason,
    }

def save_exclusive(path,value):
    p=Path(path)
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("x",encoding="utf-8") as file:
        json.dump(value,file,indent=2,sort_keys=True)
        file.write("\n")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True)
    p.add_argument("--previous")
    p.add_argument("--revocation")
    p.add_argument("--highwater")
    p.add_argument("--quarantine")
    p.add_argument("--new-key")
    p.add_argument("--recovery-public")
    p.add_argument("--recovery-signature")
    p.add_argument("--new-public")
    p.add_argument("--new-signature")
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    pin_recovery=os.getenv("RUST024_RECOVERY_SPKI_SHA256")
    pin_new=os.getenv("RUST024_NEW_CUSTODIAN_SPKI_SHA256")
    # The workflow deliberately has no means to self-issue the prior-
    # authenticated assertion; that evidence needs external qualification.
    inputs=(args.previous,args.revocation,args.highwater,args.quarantine,
            args.new_key,args.recovery_public,args.recovery_signature,
            args.new_public,args.new_signature,pin_recovery,pin_new)
    if not all(inputs):
        result=hold("No externally authenticated monotonic custody checkpoint and dual signatures")
    else:
        result=qualify(
            load(args.previous),load(args.revocation),load(args.highwater),
            load(args.quarantine),args.new_key,args.recovery_public,
            args.recovery_signature,args.new_public,args.new_signature,
            pin_recovery,pin_new,prior_authenticated=False)
    save_exclusive(args.output,result)
    print(json.dumps(result,sort_keys=True))
    if result["status"]!="RECOVERY_EPOCH_SIGNATURES_VERIFIED" and not args.allow_hold_record:
        raise SystemExit("RUST-024 HOLD: recovery epoch not authorized")

if __name__=="__main__":
    main()
