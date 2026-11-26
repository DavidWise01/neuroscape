#!/usr/bin/env python3
"""RUST-041 — challenge-bound custodian-control and ancestry attestations.

Rechecks the RUST-040 receipt, a custodian-key signature, and a separately
pinned attestor signature over the same nonce-bound acquisition assertion.
Multiple signatures alone are NOT independent source custody, identity,
freshness or external control. Every outcome is HOLD.
"""
import argparse
import json
import os
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

def parent_claims(parent):
    require(isinstance(parent,dict) and parent.get("phase")=="RUST-040",
            "RUST-040 ancestry receipt missing")
    require(parent.get("status") in (
        "HOLD_POTENTIAL_COMMON_CONTROL","HOLD_IDENTITY_ANCESTRY_UNPROVEN"),
        "unqualified ancestry predecessor")
    require(parent.get("release_authorized") is False and parent.get("fork_resolved") is False,
            "upstream authority escalation")
    require(digest({k:v for k,v in parent.items() if k!="receipt_sha256"})==
            parent.get("receipt_sha256"),"RUST-040 ancestry receipt altered")
    claims=parent.get("custodian_claims")
    require(isinstance(claims,list) and len(claims)==3 and
            [c.get("role") for c in claims]==list(ROLES),
            "three ordered ff/cf/rr custody claims required")
    for c in claims:
        for f in ("key_spki_sha256","source_root_sha256","acquisition_path_sha256",
                  "custody_controller_sha256","operator_registry_sha256"):
            check_sha(c.get(f),"missing upstream "+f)
    return claims

def challenge_payload(parent,claim,item,nonce):
    require(isinstance(item,dict) and item.get("role")==claim["role"],
            "custody challenge role mismatch")
    check_sha(nonce,"externally issued challenge nonce missing")
    for f in ("retrieved_archive_sha256","retrieval_session_sha256",
              "external_attestor_root_sha256"):
        check_sha(item.get(f),"invalid "+f)
    for f in ("source_root_sha256","acquisition_path_sha256",
              "custody_controller_sha256","operator_registry_sha256"):
        require(item.get(f)==claim[f],"attestation ancestry substitution: "+f)
    return {
        "phase":"RUST-041","kind":"INDEPENDENT_CUSTODY_CHALLENGE_V1",
        "upstream_rust040_receipt_sha256":parent["receipt_sha256"],
        "role":claim["role"],
        "key_spki_sha256":claim["key_spki_sha256"],
        "source_root_sha256":claim["source_root_sha256"],
        "acquisition_path_sha256":claim["acquisition_path_sha256"],
        "custody_controller_sha256":claim["custody_controller_sha256"],
        "operator_registry_sha256":claim["operator_registry_sha256"],
        "retrieved_archive_sha256":item["retrieved_archive_sha256"],
        "retrieval_session_sha256":item["retrieval_session_sha256"],
        "external_attestor_root_sha256":item["external_attestor_root_sha256"],
        "externally_issued_nonce_sha256":nonce,
        "release_authorized":False,
    }

def audit(parent,challenges,attestor_pins,nonces,
          prior_nonce_fingerprints,verifier=verify_key_and_signature):
    sources=parent_claims(parent)
    require(isinstance(challenges,list) and len(challenges)==3,
            "three separately collected custody challenges required")
    require(isinstance(attestor_pins,list) and len(attestor_pins)==3 and
            isinstance(nonces,list) and len(nonces)==3,
            "three external attestor pins and nonce fingerprints required")
    require(isinstance(prior_nonce_fingerprints,list),
            "externally retained nonce history missing")
    for value in attestor_pins+nonces+prior_nonce_fingerprints:
        check_sha(value,"invalid key pin or nonce fingerprint")
    require(len(set(attestor_pins))==3,"reused attestor signing key")
    require(len(set(nonces))==3,"nonce replay within challenge batch")
    require(len(set(prior_nonce_fingerprints))==len(prior_nonce_fingerprints),
            "historical nonce ledger repeated")
    require(not(set(nonces)&set(prior_nonce_fingerprints)),
            "challenge replayed against supplied prior nonce history")
    prior=set(prior_nonce_fingerprints)
    observations=[]
    for claim,item,attestor_pin,nonce in zip(sources,challenges,attestor_pins,nonces):
        require(attestor_pin!=claim["key_spki_sha256"],
                "custodian self-attestation is not a second witness")
        payload=challenge_payload(parent,claim,item,nonce)
        own_sig=verifier(item.get("custodian_public_key"),
                         item.get("custodian_signature"),
                         claim["key_spki_sha256"],canonical(payload))
        att_sig=verifier(item.get("attestor_public_key"),
                         item.get("attestor_signature"),attestor_pin,canonical(payload))
        for signature in (own_sig,att_sig):
            check_sha(signature,"signature digest invalid")
        observations.append({
            **payload,
            "custodian_signature_sha256":own_sig,
            "attestor_signature_sha256":att_sig,
            "attestor_key_spki_sha256":attestor_pin,
            "dual_signature_checked":True,
            "independent_control_authenticated":False,
            "nonce_externally_fresh_authenticated":False,
        })
    collisions=[]
    fields=("source_root_sha256","acquisition_path_sha256",
            "custody_controller_sha256","operator_registry_sha256",
            "retrieval_session_sha256","external_attestor_root_sha256")
    for i in range(3):
        for j in range(i+1,3):
            overlaps=[f for f in fields if observations[i][f]==observations[j][f]]
            if overlaps:
                collisions.append({
                    "roles":[ROLES[i],ROLES[j]],
                    "shared_fields":overlaps,
                    "left_challenge_sha256":digest(observations[i]),
                    "right_challenge_sha256":digest(observations[j]),
                })
    out={
        "phase":"RUST-041",
        "status":"HOLD_SHARED_ATTESTATION_ANCESTRY" if collisions or
            parent["status"]=="HOLD_POTENTIAL_COMMON_CONTROL" else
            "HOLD_INDEPENDENT_CONTROL_UNVERIFIED",
        "upstream_rust040_receipt_sha256":parent["receipt_sha256"],
        "observations":observations,
        "attestation_ancestry_collisions":collisions,
        "preserved_upstream_collisions":parent.get("pairwise_ancestry_collisions",[]),
        "preserved_upstream_replacements":parent.get("suspected_replacement_lineages",[]),
        "prior_nonce_history_sha256":digest(prior_nonce_fingerprints),
        "new_nonce_fingerprints":nonces,
        "candidate_extended_nonce_history_sha256":digest(prior_nonce_fingerprints+nonces),
        "external_nonce_ledger_custody_verified":False,
        "independent_source_ancestry_verified":False,
        "real_world_operator_control_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {
        "phase":"RUST-041","status":"HOLD_MISSING_EXTERNAL_CONTROL_CHALLENGES",
        "observations":[],"attestation_ancestry_collisions":[],
        "independent_source_ancestry_verified":False,
        "real_world_operator_control_verified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
        "reason":"No external signed acquisition challenges or independently retained nonce ledger",
    }

def main():
    p=argparse.ArgumentParser()
    for name in ("parent","challenges","nonce-history"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    inputs=(a.parent,a.challenges,a.nonce_history)
    require(all(inputs) or not any(inputs),"partial control-challenge evidence refused")
    if all(inputs):
        pins=[os.getenv("RUST041_ATTESTOR_PIN_"+role.upper()) for role in ROLES]
        nonces=[os.getenv("RUST041_NONCE_"+role.upper()) for role in ROLES]
        require(all(pins) and all(nonces),"external pins and nonces required")
        out=audit(json.loads(Path(a.parent).read_text(encoding="utf-8")),
                  json.loads(Path(a.challenges).read_text(encoding="utf-8")),
                  pins,nonces,json.loads(Path(a.nonce_history).read_text(encoding="utf-8")))
    else:
        out=hold()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-041 HOLD: independent real-world custody not authenticated")

if __name__=="__main__":
    main()
