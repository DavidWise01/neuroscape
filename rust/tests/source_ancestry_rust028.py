#!/usr/bin/env python3
"""RUST-028: independently signed provenance assertions, not presumed independence.

A mirror, duplicated archive, or two keys controlled by one operator are NOT
two independent source roots. This audit preserves raw ancestry assertions,
groups shared origins, and never resolves a fork by voting.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, verify_key_and_signature, check_sha

def validate_fork(report):
    require(isinstance(report, dict) and report.get("phase")=="RUST-027",
            "RUST-027 fork record required")
    require(report.get("status", "").startswith("HOLD"), "fork audit cannot inherit release authority")
    require(report.get("release_authorized") is False, "fork record falsely authorizes release")
    require(digest({k:v for k,v in report.items() if k!="receipt_sha256"}) ==
            report.get("receipt_sha256"), "fork receipt integrity mismatch")
    branches=report.get("branches")
    require(isinstance(branches,list) and len(branches)==3,"three preserved branches required")
    require([b.get("role") for b in branches] == list(ROLES),"branch roles mismatch")
    return branches

def assertion_payload(role, branch, source_root, source_family, custody_controller, capture_sha):
    require(role in ROLES and role==branch.get("role"),"provenance role mismatch")
    for name,value in (("root",source_root),("family",source_family),("controller",custody_controller)):
        require(isinstance(value,str) and 0<len(value)<=200 and value.strip()==value,
                "invalid "+name)
    check_sha(capture_sha,"missing capture digest")
    return {
        "phase":"RUST-028","kind":"SOURCE_PROVENANCE_ASSERTION",
        "role":role,"head_sha256":branch["head_sha256"],
        "source_root":source_root,"source_family":source_family,
        "custody_controller":custody_controller,
        "capture_sha256":capture_sha,
    }

def audit(fork_report, attestations, pins, verify=verify_key_and_signature):
    branches=validate_fork(fork_report)
    require(isinstance(attestations,list) and len(attestations)==3,"three attestations required")
    require(isinstance(pins,list) and len(pins)==3,"three separately pinned attestor keys required")
    require(all(isinstance(p,str) for p in pins) and len(set(pins))==3,
            "duplicate provenance attestor key")
    records=[]
    for role,branch,claim,pin in zip(ROLES,branches,attestations,pins):
        check_sha(pin,"missing independently pinned provenance key")
        require(isinstance(claim,dict) and claim.get("role")==role,"attestation role mismatch")
        payload=assertion_payload(role,branch,claim.get("source_root"),
                                 claim.get("source_family"),claim.get("custody_controller"),
                                 claim.get("capture_sha256"))
        signature_hash=verify(claim.get("public_key"),claim.get("signature"),pin,canonical(payload))
        records.append({
            **payload,
            "attestor_spki_sha256":pin,
            "attestor_signature_sha256":signature_hash,
            "cryptographic_assertion_verified":True,
            "source_control_independence_verified":False,
        })
    # A shared declared family, root, capture, or controller disqualifies
    # independent provenance. Different assertions alone still cannot PROVE
    # independent organizations, data acquisition or key custody.
    collisions=[]
    for i in range(3):
        for j in range(i+1,3):
            overlaps=[field for field in ("source_root","source_family","custody_controller","capture_sha256")
                      if records[i][field]==records[j][field]]
            if overlaps:
                collisions.append({
                    "roles":[records[i]["role"],records[j]["role"]],
                    "shared_fields":overlaps,
                })
    categories = {
        "unique_declared_roots":len({r["source_root"] for r in records}),
        "unique_declared_families":len({r["source_family"] for r in records}),
        "unique_declared_controllers":len({r["custody_controller"] for r in records}),
        "unique_capture_digests":len({r["capture_sha256"] for r in records}),
    }
    status = "HOLD_SHARED_SOURCE_ANCESTRY" if collisions else "HOLD_INDEPENDENCE_UNPROVEN"
    if fork_report.get("fork_detected") is True:
        status="HOLD_FORK_AND_SHARED_ANCESTRY" if collisions else "HOLD_FORK_INDEPENDENCE_UNPROVEN"
    result={
        "phase":"RUST-028","status":status,
        "upstream_rust027_receipt_sha256":fork_report["receipt_sha256"],
        "observed_common_ancestor_sha256":fork_report.get("observed_common_ancestor_sha256"),
        "fork_heads_sha256":fork_report.get("fork_heads_sha256"),
        "provenance_assertions":records,
        "shared_ancestry_collisions":collisions,
        **categories,
        "independent_source_roots_certified":False,
        "independent_custody_ancestries_verified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-028","status":"HOLD_NO_EXTERNAL_PROVENANCE",
        "provenance_assertions":[],"fork_resolved":False,
        "independent_source_roots_certified":False,
        "release_authorized":False,"live_gameplay_authority":False,
        "reason":"Signed source-ancestry attestations and independent custody records unavailable",
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--fork")
    parser.add_argument("--attestations")
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    require(bool(args.fork)==bool(args.attestations),"partial provenance input refused")
    if not args.fork:
        result=hold()
    else:
        pins=[os.getenv("RUST028_PIN_"+role.upper()) for role in ROLES]
        require(all(pins),"independent provenance key pins missing")
        result=audit(
            json.loads(Path(args.fork).read_text(encoding="utf-8")),
            json.loads(Path(args.attestations).read_text(encoding="utf-8")),
            pins)
    dest=Path(args.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,indent=2,sort_keys=True)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if result["status"].startswith("HOLD") and not args.allow_hold_record:
        raise SystemExit("RUST-028 HOLD: no qualified independent source provenance")
if __name__=="__main__":
    main()
