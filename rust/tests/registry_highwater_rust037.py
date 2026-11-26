#!/usr/bin/env python3
"""RUST-037 — signed external registry highwater and revocation floor.

A RUST-036 evidence receipt is cryptographically bound to a separate
witness-signed checkpoint. Local comparisons cannot authenticate the
witness's independence or the true latest external checkpoint.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from multiwitness_rust026 import ROLES


def validate_registry(record):
    require(isinstance(record, dict) and record.get("phase") == "RUST-036",
            "RUST-036 registry receipt missing")
    require(record.get("status") in ("HOLD_EQUIVOCATION_OR_SHARED_KEYS",
                                     "HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN"),
            "invalid predecessor status")
    require(record.get("release_authorized") is False and record.get("fork_resolved") is False,
            "predecessor asserted release authority")
    require(record.get("external_key_registry_ancestry_verified") is False,
            "unsupported registry independence claim")
    require(digest({k:v for k,v in record.items() if k != "receipt_sha256"}) ==
            record.get("receipt_sha256"), "RUST-036 receipt altered")
    claims=record.get("epoch_key_claims")
    revocations=record.get("revocation_evidence")
    rotations=record.get("verified_rotations")
    require(isinstance(claims,list) and len(claims)>=3, "epoch key claims missing")
    require(isinstance(revocations,list) and isinstance(rotations,list),
            "revocation or rotation history missing")
    require({x.get("role") for x in claims} == set(ROLES), "witness roles incomplete")
    for role in ROLES:
        epochs=[x.get("epoch") for x in claims if x.get("role")==role]
        require(all(type(n) is int and n>=0 for n in epochs), "invalid epoch in registry")
        require(epochs==list(range(epochs[0],epochs[-1]+1)), "missing or reordered key epoch")
    for x in claims:
        check_sha(x.get("signing_key_spki_sha256"),"invalid epoch key fingerprint")
        check_sha(x.get("checkpoint_sha256"),"missing checkpoint fingerprint")
        check_sha(x.get("signature_sha256"),"missing signed checkpoint fingerprint")
        require(x.get("signed_checkpoint_verified") is True,"unsigned epoch")
    for x in revocations:
        check_sha(x.get("revoked_pin"),"invalid revoked fingerprint")
        check_sha(x.get("authority_signature_sha256"),"invalid revocation signature")
        require(type(x.get("effective_epoch")) is int and x["effective_epoch"]>=0,
                "invalid revocation effective epoch")
    return claims, rotations, revocations


def anchor_payload(record):
    claims, rotations, revocations=validate_registry(record)
    highwater=max(x["epoch"] for x in claims)
    return {
        "phase":"RUST-037","kind":"SIGNED_REGISTRY_HIGHWATER",
        "rust036_receipt_sha256":record["receipt_sha256"],
        "highwater_epoch":highwater,
        "key_claim_count":len(claims),
        "key_claims_sha256":digest(claims),
        "rotation_count":len(rotations),
        "rotations_sha256":digest(rotations),
        "revocation_count":len(revocations),
        "revocations_sha256":digest(revocations),
        "release_authorized":False,
        "global_anti_rollback_certified":False,
    }


def check_floor(payload, floor):
    """Compare with a separately acquired floor. Its custody is not proved here."""
    require(isinstance(floor,dict), "external retention floor missing")
    require(type(floor.get("highwater_epoch")) is int and floor["highwater_epoch"]>=0,
            "invalid externally retained epoch")
    for field in ("rust036_receipt_sha256","revocations_sha256"):
        check_sha(floor.get(field),"invalid external floor "+field)
    require(type(floor.get("revocation_count")) is int and floor["revocation_count"]>=0,
            "invalid external revocation count")
    require(payload["highwater_epoch"]>=floor["highwater_epoch"],
            "highwater epoch rollback")
    require(payload["revocation_count"]>=floor["revocation_count"],
            "withheld revocations")
    if payload["highwater_epoch"]==floor["highwater_epoch"]:
        require(payload["rust036_receipt_sha256"]==floor["rust036_receipt_sha256"],
                "equivocated registry at retained highwater")
        require(payload["revocations_sha256"]==floor["revocations_sha256"],
                "revocation history substitution")
    if payload["revocation_count"]==floor["revocation_count"]:
        require(payload["revocations_sha256"]==floor["revocations_sha256"],
                "equal-count revocation history rewrite")
    return True


def verify(record, anchor, key, signature, external_pin, floor=None,
           verifier=verify_key_and_signature):
    expected=anchor_payload(record)
    require(isinstance(anchor,dict) and anchor==expected,
            "signed anchor does not match exact registry and revocation history")
    check_sha(external_pin,"external anchor witness pin missing")
    signature_sha=verifier(key,signature,external_pin,canonical(anchor))
    check_sha(signature_sha,"invalid witness signature digest")
    if floor is not None:
        check_floor(anchor,floor)
    result={
        "phase":"RUST-037",
        "status":"HOLD_REGISTRY_EQUIVOCATION" if record.get("status")==
            "HOLD_EQUIVOCATION_OR_SHARED_KEYS" else "HOLD_EXTERNAL_LATEST_REGISTRY_UNVERIFIED",
        "signed_anchor":anchor,
        "anchor_witness_key_spki_sha256":external_pin,
        "anchor_signature_sha256":signature_sha,
        "external_floor_compared":floor is not None,
        "external_floor_claim_sha256":digest(floor) if floor is not None else None,
        "preserved_equivocation_evidence":record.get("equivocation_evidence",[]),
        "preserved_shared_witness_keys":record.get("shared_witness_key_evidence",[]),
        "external_anchor_independence_verified":False,
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
        "phase":"RUST-037","status":"HOLD_MISSING_EXTERNAL_REGISTRY_HIGHWATER",
        "release_authorized":False,"fork_resolved":False,
        "external_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "live_gameplay_authority":False,
        "reason":"Externally signed registry anchor and independently retained revocation floor unavailable",
    }


def main():
    p=argparse.ArgumentParser()
    for field in ("registry","anchor","public-key","signature","floor"):
        p.add_argument("--"+field)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    inputs=[a.registry,a.anchor,a.public_key,a.signature]
    require(all(inputs) or not any(inputs),"partial signed anchor input refused")
    require(not a.floor or all(inputs),"retention floor without signed anchor refused")
    if all(inputs):
        pin=os.getenv("RUST037_ANCHOR_WITNESS_SPKI_SHA256")
        require(pin,"externally pinned witness key required")
        floor=json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None
        result=verify(json.loads(Path(a.registry).read_text(encoding="utf-8")),
                      json.loads(Path(a.anchor).read_text(encoding="utf-8")),
                      a.public_key,a.signature,pin,floor=floor)
    else:
        result=hold()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,sort_keys=True,indent=2)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-037 HOLD: external registry custody/latest-state unverified")


if __name__=="__main__":
    main()
