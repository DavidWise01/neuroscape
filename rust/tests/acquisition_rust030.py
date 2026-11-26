#!/usr/bin/env python3
"""RUST-030 — archive byte-possession and custody challenge evidence.

Verify original archive bytes and a challenge-derived slice, bind the
RUST-029 custody record to a fresh externally provided nonce and a
separately pinned Ed25519 key. No cryptographic proof of operator
independence or globally fresh nonce is asserted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

def check_upstream(value):
    require(isinstance(value,dict) and value.get("phase")=="RUST-029", "RUST-029 custody receipt required")
    require(value.get("status") in ("HOLD_CUSTODY_CONTROL_UNPROVEN","HOLD_SHARED_CUSTODY_OR_ACQUISITION"),
            "RUST-029 authority state invalid")
    require(value.get("release_authorized") is False and value.get("fork_resolved") is False,
            "upstream may not authorize release")
    require(value.get("independent_source_roots_certified") is False,
            "unsupported source independence")
    require(digest({k:v for k,v in value.items() if k!="receipt_sha256"})==value.get("receipt_sha256"),
            "upstream receipt altered")
    claims=value.get("witness_custody_claims")
    require(isinstance(claims,list) and len(claims)==3, "three custody records required")
    require([x.get("role") for x in claims]==list(ROLES), "custody role mismatch")
    return claims

def challenge(source, role, archive_bytes, nonce, window=32):
    check_sha(nonce, "external challenge nonce absent")
    require(isinstance(archive_bytes,bytes) and len(archive_bytes)>=window,
            "archive too short for byte challenge")
    require(source.get("role")==role,"role not bound to archive")
    check_sha(source.get("archive_digest_sha256"),"archive digest missing")
    expected=source["archive_digest_sha256"]
    actual=hashlib.sha256(archive_bytes).hexdigest()
    require(actual==expected,"original archive content mismatch")
    offset=int.from_bytes(hashlib.sha256(bytes.fromhex(nonce)+bytes.fromhex(expected)).digest()[:8],
                          "big")%(len(archive_bytes)-window+1)
    sample=archive_bytes[offset:offset+window]
    return {
        "phase":"RUST-030","kind":"ARCHIVE_ACQUISITION_CHALLENGE",
        "role":role,
        "upstream_custody_receipt_sha256":source["upstream_custody_receipt_sha256"],
        "archive_digest_sha256":expected,
        "archive_bytes":len(archive_bytes),
        "slice_offset":offset,
        "slice_bytes":window,
        "slice_sha256":hashlib.sha256(sample).hexdigest(),
        "challenge_nonce_sha256":nonce,
        "custody_controller":source["custody_controller"],
        "archive_operator":source["archive_operator"],
        "acquisition_controller":source["acquisition_controller"],
        "acquisition_path_sha256":source["acquisition_path_sha256"],
    }

def audit(upstream, samples, pins, nonces, verify=verify_key_and_signature):
    claims=check_upstream(upstream)
    require(isinstance(samples,list) and len(samples)==3,"three archive samples required")
    require(isinstance(pins,list) and len(pins)==3 and
            isinstance(nonces,list) and len(nonces)==3,"three pins and challenges required")
    for pin,nonce in zip(pins,nonces):
        check_sha(pin,"external signing pin invalid")
        check_sha(nonce,"external nonce invalid")
    require(len(set(pins))==3 and len(set(nonces))==3,"reused signing key or nonce")
    evidence=[]
    for role,claim,entry,pin,nonce in zip(ROLES,claims,samples,pins,nonces):
        require(isinstance(entry,dict) and entry.get("role")==role,"sample role mismatch")
        payload=challenge({**claim,"upstream_custody_receipt_sha256":upstream["receipt_sha256"]},
                          role,Path(entry["archive_path"]).read_bytes(),nonce)
        signed=verify(entry.get("public_key"),entry.get("signature"),pin,canonical(payload))
        evidence.append({
            **payload,"witness_key_spki_sha256":pin,
            "challenge_response_signature_sha256":signed,
            "archive_bytes_matched":True,
            "operator_control_independently_verified":False,
        })
    collision_fields=("archive_digest_sha256","custody_controller","archive_operator",
                      "acquisition_controller","acquisition_path_sha256")
    collisions=[]
    for i in range(3):
        for j in range(i+1,3):
            shared=[field for field in collision_fields if evidence[i][field]==evidence[j][field]]
            if shared:
                collisions.append({"roles":[ROLES[i],ROLES[j]],"shared_fields":shared})
    result={
        "phase":"RUST-030",
        "status":"HOLD_SHARED_ACQUISITION" if collisions else "HOLD_INDEPENDENT_CONTROL_UNPROVEN",
        "upstream_rust029_receipt_sha256":upstream["receipt_sha256"],
        "observations":evidence,
        "shared_custody_collisions":collisions,
        "preserved_fork_heads_sha256":upstream.get("preserved_fork_heads_sha256"),
        "archive_possession_samples_verified":3,
        "operator_control_independently_verified":False,
        "nonce_freshness_independently_verified":False,
        "independent_source_roots_certified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-030","status":"HOLD_MISSING_EXTERNAL_ACQUISITION",
        "observations":[],"fork_resolved":False,"release_authorized":False,
        "independent_source_roots_certified":False,"live_gameplay_authority":False,
        "reason":"Externally acquired archives, fresh challenges and operator signatures unavailable",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream")
    p.add_argument("--samples")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    require(bool(args.upstream)==bool(args.samples),"partial external acquisition input refused")
    if not args.upstream:
        result=hold()
    else:
        pins=[os.getenv("RUST030_PIN_"+role.upper()) for role in ROLES]
        nonces=[os.getenv("RUST030_NONCE_"+role.upper()) for role in ROLES]
        require(all(pins) and all(nonces),"separately supplied challenge pins and nonces missing")
        result=audit(json.loads(Path(args.upstream).read_text(encoding="utf-8")),
                     json.loads(Path(args.samples).read_text(encoding="utf-8")),pins,nonces)
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-030 HOLD: physical custody independence has not been proven")

if __name__=="__main__":
    main()
