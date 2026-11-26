#!/usr/bin/env python3
"""RUST-029 — custody-root challenge-response and acquisition-path ancestry.

A signed challenge binds an archive digest, acquisition chain, custodian
assertion and prior RUST-028 evidence. No signature proves organizational
independence or that a custodian actually operates a claimed archive.
Every result is HOLD: a structural audit cannot confer release authority.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

def check_upstream(record):
    require(isinstance(record,dict) and record.get("phase")=="RUST-028","upstream ancestry audit absent")
    require(isinstance(record.get("status"),str) and record["status"].startswith("HOLD"),
            "unexpected upstream release status")
    require(record.get("release_authorized") is False and record.get("fork_resolved") is False,
            "upstream attempted to promote fork")
    require(record.get("independent_source_roots_certified") is False,
            "upstream independence falsely certified")
    require(digest({k:v for k,v in record.items() if k!="receipt_sha256"}) ==
            record.get("receipt_sha256"), "upstream receipt integrity mismatch")
    assertions=record.get("provenance_assertions")
    require(isinstance(assertions,list) and len(assertions)==3,"three upstream provenance assertions needed")
    require([r.get("role") for r in assertions]==list(ROLES),"upstream witness roles mismatch")
    return assertions

def challenge_payload(upstream, source, declaration, nonce):
    role=source["role"]
    require(isinstance(declaration,dict) and declaration.get("role")==role,
            "custody role mismatch")
    for field in ("archive_digest_sha256","acquisition_path_sha256","operator_registry_sha256"):
        check_sha(declaration.get(field),"missing "+field)
    for field in ("archive_origin","archive_operator","acquisition_method","acquisition_controller"):
        value=declaration.get(field)
        require(isinstance(value,str) and 0<len(value)<=200 and value.strip()==value,
                "invalid "+field)
    check_sha(nonce,"independent challenge nonce invalid")
    require(declaration.get("source_root")==source["source_root"] and
            declaration.get("source_family")==source["source_family"] and
            declaration.get("custody_controller")==source["custody_controller"],
            "custody assertion contradicts upstream ancestry")
    require(declaration["archive_digest_sha256"]==source["capture_sha256"],
            "archive content does not match original capture")
    return {
        "phase":"RUST-029","kind":"CUSTODY_ROOT_CHALLENGE",
        "role":role,"upstream_receipt_sha256":upstream["receipt_sha256"],
        "witness_head_sha256":source["head_sha256"],
        "source_root":source["source_root"],
        "source_family":source["source_family"],
        "custody_controller":source["custody_controller"],
        "archive_digest_sha256":declaration["archive_digest_sha256"],
        "archive_origin":declaration["archive_origin"],
        "archive_operator":declaration["archive_operator"],
        "operator_registry_sha256":declaration["operator_registry_sha256"],
        "acquisition_path_sha256":declaration["acquisition_path_sha256"],
        "acquisition_method":declaration["acquisition_method"],
        "acquisition_controller":declaration["acquisition_controller"],
        "challenge_nonce_sha256":nonce,
    }

def audit(upstream, declarations, pinned_keys, external_nonces, verify=verify_key_and_signature):
    ancestry=check_upstream(upstream)
    require(isinstance(declarations,list) and len(declarations)==3,"three custody declarations required")
    require(isinstance(pinned_keys,list) and len(pinned_keys)==3,"three separately supplied key pins required")
    require(isinstance(external_nonces,list) and len(external_nonces)==3,"three external challenges required")
    require(len(set(pinned_keys))==3 and len(set(external_nonces))==3,
            "duplicate custody keys or challenge nonces")
    records=[]
    for role,source,claim,pin,nonce in zip(ROLES,ancestry,declarations,pinned_keys,external_nonces):
        check_sha(pin,"missing external custodian key fingerprint")
        payload=challenge_payload(upstream,source,claim,nonce)
        signature_digest=verify(claim.get("public_key"),claim.get("signature"),pin,canonical(payload))
        records.append({
            **payload,
            "custodian_signing_key_spki_sha256":pin,
            "response_signature_sha256":signature_digest,
            "challenge_signature_verified":True,
            "archive_control_independently_verified":False,
            "organization_control_independently_verified":False,
        })
    collision_fields=("source_root","source_family","custody_controller",
                      "archive_digest_sha256","archive_origin","archive_operator",
                      "operator_registry_sha256","acquisition_path_sha256",
                      "acquisition_controller")
    shared=[]
    for i in range(3):
        for j in range(i+1,3):
            overlaps=[field for field in collision_fields
                      if records[i][field]==records[j][field]]
            if overlaps:
                shared.append({
                    "roles":[records[i]["role"],records[j]["role"]],
                    "matching_ancestry_fields":overlaps,
                })
    result={
        "phase":"RUST-029",
        "status":"HOLD_SHARED_CUSTODY_OR_ACQUISITION" if shared else "HOLD_CUSTODY_CONTROL_UNPROVEN",
        "upstream_rust028_receipt_sha256":upstream["receipt_sha256"],
        "preserved_fork_heads_sha256":upstream.get("fork_heads_sha256"),
        "preserved_ancestry_collisions":upstream.get("shared_ancestry_collisions"),
        "witness_custody_claims":records,
        "shared_custody_or_acquisition":shared,
        "distinct_custodian_signing_keys":3,
        "archive_control_independently_verified":False,
        "independent_source_roots_certified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-029","status":"HOLD_MISSING_EXTERNAL_CUSTODY_ROOTS",
        "witness_custody_claims":[],"release_authorized":False,
        "fork_resolved":False,"independent_source_roots_certified":False,
        "live_gameplay_authority":False,
        "reason":"No independently challenged custody roots, external pins and archived acquisition evidence",
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--upstream")
    parser.add_argument("--declarations")
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    require(bool(args.upstream)==bool(args.declarations),"partial external custody input refused")
    if not args.upstream:
        result=hold()
    else:
        pins=[os.getenv("RUST029_PIN_"+role.upper()) for role in ROLES]
        nonces=[os.getenv("RUST029_NONCE_"+role.upper()) for role in ROLES]
        require(all(pins) and all(nonces),"separate external custodian pins and challenge nonces required")
        result=audit(
            json.loads(Path(args.upstream).read_text(encoding="utf-8")),
            json.loads(Path(args.declarations).read_text(encoding="utf-8")),
            pins,nonces)
    out=Path(args.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,indent=2,sort_keys=True)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-029 HOLD: custody roots not independently authenticated")
if __name__=="__main__":
    main()
