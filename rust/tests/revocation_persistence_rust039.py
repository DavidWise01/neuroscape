#!/usr/bin/env python3
"""RUST-039 — cross-epoch persistence of every retained revocation.

Compare two complete, integrity-checked RUST-036 registry receipts and
their corresponding RUST-038 revocation-chain receipts. Require exact
prefix ancestry, reject revived revoked keys after their effective epoch,
and retain *claimed* shared-custodian lineage as unresolved evidence.

This does not authenticate independently owned custody or a globally
latest registry. It NEVER grants release or gameplay authority.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import check_sha
from registry_highwater_rust037 import validate_registry
from revocation_ancestry_rust038 import build_chain
from multiwitness_rust026 import ROLES


def checked_pair(registry, chain):
    claims, rotations, revocations = validate_registry(registry)
    require(isinstance(chain, dict) and chain.get("phase") == "RUST-038",
            "RUST-038 chain receipt required")
    require(chain.get("status") in (
        "HOLD_PRESERVED_EQUIVOCATION", "HOLD_EXTERNAL_PREFIX_CUSTODY_UNVERIFIED"),
        "unexpected revocation-chain status")
    require(chain.get("release_authorized") is False and chain.get("fork_resolved") is False,
            "source chain claimed authority")
    require(digest({k:v for k,v in chain.items() if k != "receipt_sha256"}) ==
            chain.get("receipt_sha256"), "revocation-chain receipt modified")
    require(chain.get("upstream_rust036_receipt_sha256") ==
            registry["receipt_sha256"], "revocation chain bound to a different registry")
    entries, heads = build_chain(revocations)
    require(chain.get("revocation_chain") == entries and
            chain.get("prefix_head_sha256_by_count") == heads and
            chain.get("revocation_entry_count") == len(entries) and
            chain.get("revocation_chain_head_sha256") == heads[-1],
            "revocation chain differs from RUST-036 history")
    return claims, rotations, revocations, heads


def audit(previous_registry, current_registry, previous_chain, current_chain, controllers):
    old_keys, old_rotations, old_revocations, old_heads = checked_pair(
        previous_registry, previous_chain)
    new_keys, new_rotations, new_revocations, new_heads = checked_pair(
        current_registry, current_chain)
    require(len(new_revocations) >= len(old_revocations), "revocations omitted")
    require(old_heads[-1] == new_heads[len(old_revocations)],
            "previously retained revocation prefix rewritten")
    require(new_revocations[:len(old_revocations)] == old_revocations,
            "historical revocation contents changed")
    previous_by_role = {}
    current_by_role = {}
    for role in ROLES:
        a = [c for c in old_keys if c["role"] == role]
        b = [c for c in new_keys if c["role"] == role]
        require(a and b, "missing witness epoch history")
        require(len(b) >= len(a) and b[:len(a)] == a,
                "prior epoch key history rewritten or withheld")
        previous_by_role[role] = a
        current_by_role[role] = b
    require(len(new_rotations) >= len(old_rotations) and
            new_rotations[:len(old_rotations)] == old_rotations,
            "predecessor rotation history rewritten")
    # For all keys, including those introduced in newly extended epochs,
    # inherited revocations prevent signing at/after their effective epoch.
    violations = []
    for rev in new_revocations:
        for claim in current_by_role[rev["role"]]:
            if (claim["signing_key_spki_sha256"] == rev["revoked_pin"]
                    and claim["epoch"] >= rev["effective_epoch"]):
                violations.append({
                    "role":rev["role"],
                    "revoked_pin":rev["revoked_pin"],
                    "effective_epoch":rev["effective_epoch"],
                    "observed_epoch":claim["epoch"],
                    "checkpoint_sha256":claim["checkpoint_sha256"],
                })
    require(not violations,"revoked key used in later epoch")

    # Observations of shared controllers are not authenticated identity
    # assertions. Missing identity information is never certified distinct.
    require(isinstance(controllers, list), "controller lineage claims required")
    lineage = []
    seen = set()
    for item in controllers:
        require(isinstance(item, dict), "malformed custodian lineage claim")
        role = item.get("role")
        require(role in ROLES, "unknown custodian role")
        pin = item.get("key_spki_sha256")
        check_sha(pin,"controller lineage key fingerprint missing")
        require(pin in {x["signing_key_spki_sha256"] for x in current_by_role[role]},
                "controller claim references unknown epoch key")
        controller = item.get("custody_controller")
        require(isinstance(controller,str) and 0 < len(controller) <= 200 and
                controller.strip() == controller, "controller identity invalid")
        key = (role,pin)
        require(key not in seen,"duplicate controller lineage claim")
        seen.add(key)
        lineage.append({"role":role,"key_spki_sha256":pin,
                        "claimed_custody_controller":controller,
                        "independently_verified":False})
    inherited_revoked = {(r["role"],r["revoked_pin"]) for r in old_revocations}
    new_pins = {(x["role"],x["signing_key_spki_sha256"]) for x in new_keys}
    controller_by_key = {
        (r["role"],r["key_spki_sha256"]):r["claimed_custody_controller"]
        for r in lineage
    }
    suspected_replacements=[]
    for role,old_pin in sorted(inherited_revoked):
        old_controller = controller_by_key.get((role,old_pin))
        if old_controller is None:
            continue
        for new_role,new_pin in sorted(new_pins):
            if new_pin != old_pin and controller_by_key.get((new_role,new_pin)) == old_controller:
                suspected_replacements.append({
                    "revoked_role":role, "revoked_pin":old_pin,
                    "replacement_role":new_role, "replacement_pin":new_pin,
                    "claimed_shared_controller":old_controller,
                    "control_independently_verified":False,
                })
    result = {
        "phase":"RUST-039",
        "status":("HOLD_SHARED_CUSTODY_LINEAGE" if suspected_replacements else
                  "HOLD_EXTERNAL_CUSTODY_UNPROVEN"),
        "previous_rust038_receipt_sha256":previous_chain["receipt_sha256"],
        "current_rust038_receipt_sha256":current_chain["receipt_sha256"],
        "previous_rust036_receipt_sha256":previous_registry["receipt_sha256"],
        "current_rust036_receipt_sha256":current_registry["receipt_sha256"],
        "inherited_revocation_count":len(old_revocations),
        "current_revocation_count":len(new_revocations),
        "preserved_revocation_prefix_sha256":old_heads[-1],
        "current_revocation_head_sha256":new_heads[-1],
        "inherited_revocations":[{"role":r["role"],"revoked_pin":r["revoked_pin"],
            "effective_epoch":r["effective_epoch"],"source_sha256":digest(r)}
            for r in old_revocations],
        "custodian_lineage_claims":lineage,
        "suspected_same_custodian_replacements":suspected_replacements,
        "preserved_upstream_equivocation":
            previous_chain.get("preserved_equivocation_evidence",[]) +
            current_chain.get("preserved_equivocation_evidence",[]),
        "revoked_key_reuse_detected":False,
        "external_custodian_identity_verified":False,
        "external_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result


def hold():
    return {
        "phase":"RUST-039","status":"HOLD_MISSING_CROSS_EPOCH_CUSTODY",
        "inherited_revocations":[],"suspected_same_custodian_replacements":[],
        "release_authorized":False,"fork_resolved":False,
        "external_custodian_identity_verified":False,
        "global_anti_rollback_certified":False,"live_gameplay_authority":False,
        "reason":"Two intact registry and revocation-chain receipts with externally grounded custody claims are unavailable",
    }


def main():
    parser=argparse.ArgumentParser()
    for name in ("previous-registry","current-registry","previous-chain","current-chain","controllers"):
        parser.add_argument("--"+name)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    args=parser.parse_args()
    sources=[args.previous_registry,args.current_registry,args.previous_chain,
             args.current_chain,args.controllers]
    require(all(sources) or not any(sources),"partial cross-epoch evidence refused")
    if all(sources):
        objs=[json.loads(Path(path).read_text(encoding="utf-8")) for path in sources]
        result=audit(*objs)
    else:
        result=hold()
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,sort_keys=True,indent=2)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-039 HOLD: independent cross-epoch custody unavailable")


if __name__=="__main__":
    main()
