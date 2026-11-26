#!/usr/bin/env python3
"""RUST-031: archive retrieval and operator-control challenge evidence.

The verifier checks three independently supplied retrieval files and signed
operator challenges against RUST-030. File paths are provided externally,
but file access alone is not evidence of an independent network session,
freshness or organizational control. This protocol never authorizes release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

def checked_upstream(record):
    require(isinstance(record,dict) and record.get("phase")=="RUST-030",
            "upstream acquisition record missing")
    require(record.get("status") in ("HOLD_SHARED_ACQUISITION","HOLD_INDEPENDENT_CONTROL_UNPROVEN"),
            "invalid upstream status")
    require(record.get("release_authorized") is False and record.get("fork_resolved") is False,
            "upstream authority escalation")
    require(digest({k:v for k,v in record.items() if k!="receipt_sha256"})==
            record.get("receipt_sha256"),"upstream digest mismatch")
    entries=record.get("observations")
    require(isinstance(entries,list) and len(entries)==3,"three upstream acquisitions required")
    require([x.get("role") for x in entries]==list(ROLES),"upstream role order invalid")
    return entries

def payload(upstream, record, claim, nonce, archive_bytes):
    require(isinstance(claim,dict) and claim.get("role")==record["role"],
            "operator role mismatch")
    check_sha(nonce,"external challenge invalid")
    require(isinstance(archive_bytes,bytes) and len(archive_bytes)>0,"retrieval bytes missing")
    archive_sha=hashlib.sha256(archive_bytes).hexdigest()
    require(archive_sha==record.get("archive_digest_sha256"),
            "retrieved archive does not match inherited capture")
    for field in ("retrieval_session_sha256","operator_registry_sha256",
                  "operator_account_sha256","retrieval_endpoint_sha256"):
        check_sha(claim.get(field),"invalid "+field)
    require(claim.get("archive_operator")==record.get("archive_operator") and
            claim.get("custody_controller")==record.get("custody_controller") and
            claim.get("acquisition_controller")==record.get("acquisition_controller"),
            "operator identity disagrees with acquisition ledger")
    return {
        "phase":"RUST-031",
        "kind":"RETRIEVAL_OPERATOR_CHALLENGE",
        "role":record["role"],
        "upstream_rust030_receipt_sha256":upstream["receipt_sha256"],
        "retrieved_archive_sha256":archive_sha,
        "retrieved_archive_bytes":len(archive_bytes),
        "retrieval_session_sha256":claim["retrieval_session_sha256"],
        "retrieval_endpoint_sha256":claim["retrieval_endpoint_sha256"],
        "operator_registry_sha256":claim["operator_registry_sha256"],
        "operator_account_sha256":claim["operator_account_sha256"],
        "archive_operator":record["archive_operator"],
        "custody_controller":record["custody_controller"],
        "acquisition_controller":record["acquisition_controller"],
        "external_challenge_nonce_sha256":nonce,
    }

def audit(upstream, retrievals, pins, nonces, verifier=verify_key_and_signature):
    originals=checked_upstream(upstream)
    require(isinstance(retrievals,list) and len(retrievals)==3,
            "three retrieval records required")
    require(isinstance(pins,list) and len(pins)==3 and
            isinstance(nonces,list) and len(nonces)==3,
            "three key pins and nonces required")
    for value in pins+nonces:
        check_sha(value,"invalid external pin or nonce")
    require(len(set(pins))==3 and len(set(nonces))==3,
            "reused key or nonce")
    evidence=[]
    for role,original,claim,pin,nonce in zip(ROLES,originals,retrievals,pins,nonces):
        require(isinstance(claim,dict) and claim.get("role")==role,
                "retrieval witness role mismatch")
        raw=Path(claim["retrieved_archive_path"]).read_bytes()
        message=payload(upstream,original,claim,nonce,raw)
        sig=verifier(claim.get("operator_public_key"),
                     claim.get("operator_signature"),pin,canonical(message))
        evidence.append({
            **message,
            "operator_signing_key_spki_sha256":pin,
            "operator_response_signature_sha256":sig,
            "archive_bytes_matched":True,
            "direct_external_retrieval_attested":False,
            "operator_control_independently_verified":False,
        })
    fields=("retrieved_archive_sha256","retrieval_session_sha256",
            "retrieval_endpoint_sha256","operator_registry_sha256",
            "operator_account_sha256","archive_operator",
            "custody_controller","acquisition_controller")
    overlaps=[]
    for i in range(3):
        for j in range(i+1,3):
            shared=[field for field in fields if evidence[i][field]==evidence[j][field]]
            if shared:
                overlaps.append({"roles":[ROLES[i],ROLES[j]],"shared_fields":shared})
    result={
        "phase":"RUST-031",
        "status":"HOLD_DUPLICATED_RETRIEVAL_ANCESTRY" if overlaps else "HOLD_OPERATOR_CONTROL_UNPROVEN",
        "upstream_rust030_receipt_sha256":upstream["receipt_sha256"],
        "observations":evidence,
        "shared_retrieval_ancestry":overlaps,
        "preserved_fork_heads_sha256":upstream.get("preserved_fork_heads_sha256"),
        "independent_archive_custody_verified":False,
        "nonce_freshness_independently_verified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-031","status":"HOLD_MISSING_OPERATOR_CONTROL_EVIDENCE",
        "release_authorized":False,"fork_resolved":False,
        "independent_archive_custody_verified":False,
        "live_gameplay_authority":False,
        "reason":"Three independently obtained retrieval transcripts and operator signatures unavailable",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream")
    p.add_argument("--retrievals")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.upstream)==bool(a.retrievals),"partial inputs refused")
    if a.upstream:
        pins=[os.getenv("RUST031_PIN_"+role.upper()) for role in ROLES]
        nonces=[os.getenv("RUST031_NONCE_"+role.upper()) for role in ROLES]
        require(all(pins) and all(nonces),"external witness pins and challenges required")
        result=audit(json.loads(Path(a.upstream).read_text(encoding="utf-8")),
                     json.loads(Path(a.retrievals).read_text(encoding="utf-8")),
                     pins,nonces)
    else:
        result=hold()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,indent=2,sort_keys=True)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-031 HOLD: independent custody and retrieval provenance unverified")

if __name__=="__main__":
    main()
