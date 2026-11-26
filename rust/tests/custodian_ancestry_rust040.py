#!/usr/bin/env python3
"""RUST-040 — claimed custodian ancestry, aliases and acquisition paths.

The evidence graph links signer fingerprints to source roots, controller
aliases, and acquisition-path fingerprints. Collisions and contradictory
claims are preserved, never voted away. Identity declarations alone do
not authenticate ownership, organizational independence, or authority.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import check_sha
from multiwitness_rust026 import ROLES

STATUSES = ("HOLD_SHARED_CUSTODY_LINEAGE", "HOLD_EXTERNAL_CUSTODY_UNPROVEN")

def checked_parent(parent):
    require(isinstance(parent,dict) and parent.get("phase")=="RUST-039",
            "RUST-039 parent missing")
    require(parent.get("status") in STATUSES, "unrecognized parent status")
    require(parent.get("fork_resolved") is False and
            parent.get("release_authorized") is False,
            "upstream authority promotion")
    require(digest({k:v for k,v in parent.items() if k!="receipt_sha256"})==
            parent.get("receipt_sha256"),"upstream RUST-039 digest altered")
    inherited=parent.get("inherited_revocations")
    lineage=parent.get("custodian_lineage_claims")
    require(isinstance(inherited,list) and isinstance(lineage,list),
            "upstream source ancestry missing")
    for item in inherited:
        require(item.get("role") in ROLES, "revocation role invalid")
        check_sha(item.get("revoked_pin"),"revocation pin missing")
        check_sha(item.get("source_sha256"),"revocation provenance missing")
    for item in lineage:
        require(item.get("role") in ROLES, "lineage role invalid")
        check_sha(item.get("key_spki_sha256"),"lineage key missing")
        require(item.get("independently_verified") is False,
                "parent incorrectly certified lineage")
    return inherited,lineage

def audit(parent, claims):
    inherited, lineage=checked_parent(parent)
    require(isinstance(claims,list) and len(claims)>0, "acquisition ancestry claims missing")
    allowed={(item["role"],item["key_spki_sha256"]) for item in lineage}
    seen=set()
    clean=[]
    for claim in claims:
        require(isinstance(claim,dict),"malformed custody claim")
        role=claim.get("role")
        pin=claim.get("key_spki_sha256")
        require(role in ROLES,"unknown witness role")
        check_sha(pin,"missing claim signing-key fingerprint")
        require((role,pin) in allowed,"unbound custodian claim")
        require((role,pin) not in seen,"duplicate signer ancestry claim")
        seen.add((role,pin))
        for field in ("source_root_sha256","acquisition_path_sha256",
                      "custody_controller_sha256","operator_registry_sha256"):
            check_sha(claim.get(field),"invalid "+field)
        alias=claim.get("aliases")
        require(isinstance(alias,list) and alias,"aliases required")
        require(all(isinstance(x,str) and x and x.strip()==x and len(x)<=120
                    for x in alias),"invalid custodian alias")
        require(len(set(alias))==len(alias),"repeated alias in claim")
        clean.append({
            "role":role,"key_spki_sha256":pin,
            "source_root_sha256":claim["source_root_sha256"],
            "acquisition_path_sha256":claim["acquisition_path_sha256"],
            "custody_controller_sha256":claim["custody_controller_sha256"],
            "operator_registry_sha256":claim["operator_registry_sha256"],
            "aliases":alias,
            "identity_independently_verified":False,
        })
    missing=sorted(allowed-seen)
    # The graph is meaningful only when the entire claimed source
    # lineage is present. Missing claims must not certify separation.
    require(not missing,"withheld custodian ancestry claims")
    # One spelling, one root? Contradictory roots are retained explicitly.
    conflicts=[]
    fields=("source_root_sha256","acquisition_path_sha256",
            "custody_controller_sha256","operator_registry_sha256")
    for i in range(len(clean)):
        for j in range(i+1,len(clean)):
            a,b=clean[i],clean[j]
            shared=[f for f in fields if a[f]==b[f]]
            shared_aliases=sorted(set(a["aliases"]) & set(b["aliases"]))
            if shared or shared_aliases:
                conflicts.append({
                    "left":{"role":a["role"],"key_spki_sha256":a["key_spki_sha256"]},
                    "right":{"role":b["role"],"key_spki_sha256":b["key_spki_sha256"]},
                    "shared_fields":shared,
                    "shared_aliases":shared_aliases,
                    "different_declared_roots":a["source_root_sha256"]!=b["source_root_sha256"],
                })
    revoked={(x["role"],x["revoked_pin"]) for x in inherited}
    suspected=[]
    for old in clean:
        if (old["role"],old["key_spki_sha256"]) not in revoked:
            continue
        for other in clean:
            if other is old or other["key_spki_sha256"]==old["key_spki_sha256"]:
                continue
            connecting=[f for f in fields if old[f]==other[f]]
            aliases=sorted(set(old["aliases"]) & set(other["aliases"]))
            if connecting or aliases:
                suspected.append({
                    "revoked_role":old["role"],
                    "revoked_pin":old["key_spki_sha256"],
                    "replacement_role":other["role"],
                    "replacement_pin":other["key_spki_sha256"],
                    "shared_fields":connecting,
                    "shared_aliases":aliases,
                    "control_independently_verified":False,
                })
    result={
        "phase":"RUST-040",
        "status":"HOLD_POTENTIAL_COMMON_CONTROL" if conflicts or suspected or
            parent["status"]=="HOLD_SHARED_CUSTODY_LINEAGE"
            else "HOLD_IDENTITY_ANCESTRY_UNPROVEN",
        "upstream_rust039_receipt_sha256":parent["receipt_sha256"],
        "custodian_claims":clean,
        "pairwise_ancestry_collisions":conflicts,
        "suspected_replacement_lineages":suspected,
        "preserved_upstream_suspicions":
            parent.get("suspected_same_custodian_replacements",[]),
        "preserved_upstream_equivocation":
            parent.get("preserved_upstream_equivocation",[]),
        "independent_custodian_roots_verified":False,
        "external_latest_highwater_verified":False,
        "fork_resolved":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-040","status":"HOLD_MISSING_CUSTODIAN_ANCESTRY",
        "custodian_claims":[],"pairwise_ancestry_collisions":[],
        "suspected_replacement_lineages":[],
        "independent_custodian_roots_verified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
        "reason":"Missing out-of-band source-root and acquisition-path identity evidence",
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--parent")
    parser.add_argument("--claims")
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    require(bool(args.parent)==bool(args.claims),"partial custodian ancestry input refused")
    if args.parent:
        report=audit(json.loads(Path(args.parent).read_text(encoding="utf-8")),
                     json.loads(Path(args.claims).read_text(encoding="utf-8")))
    else:
        report=hold()
    target=Path(args.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as out:
        json.dump(report,out,sort_keys=True,indent=2)
        out.write("\n")
    print(json.dumps(report,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-040 HOLD: independent ancestry not established")

if __name__=="__main__":
    main()
