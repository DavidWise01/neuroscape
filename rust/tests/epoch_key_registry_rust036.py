#!/usr/bin/env python3
"""RUST-036: epoch-scoped Ed25519 witness keys, dual-signed rotation,
revocation records and signed highwater. Retains all historical evidence.

A key valid in one epoch is not automatically valid in another. Signatures
and separately supplied pins do not establish independently owned custody.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from session_highwater_rust033 import check_signed_checkpoint


def rotation_message(role, old, new, previous_checkpoint, next_checkpoint):
    require(new["epoch"] == old["epoch"] + 1, "rotation skipped epoch")
    return {
        "phase": "RUST-036", "kind": "KEY_ROTATION",
        "role": role, "from_epoch": old["epoch"], "to_epoch": new["epoch"],
        "old_pin": old["pin"], "new_pin": new["pin"],
        "from_checkpoint_sha256": digest(previous_checkpoint),
        "to_checkpoint_sha256": digest(next_checkpoint),
        "release_authorized": False,
    }


def revoked_message(role, pin, effective_epoch, evidence_sha256):
    check_sha(pin, "revoked key fingerprint invalid")
    check_sha(evidence_sha256, "revocation evidence digest invalid")
    require(type(effective_epoch) is int and effective_epoch >= 0, "invalid revocation epoch")
    return {
        "phase": "RUST-036", "kind": "KEY_REVOCATION",
        "role": role, "revoked_pin": pin,
        "effective_epoch": effective_epoch,
        "evidence_sha256": evidence_sha256,
        "release_authorized": False,
    }


def audit(histories, pinned_registries, verifier=verify_key_and_signature):
    require(isinstance(histories, list) and len(histories) == 3, "three histories required")
    require(isinstance(pinned_registries, list) and len(pinned_registries) == 3,
            "three independently pinned key registries required")
    all_claims = []
    all_rotations = []
    all_revocations = []
    used_pins_by_role = {}
    for role, series, registry in zip(ROLES, histories, pinned_registries):
        require(isinstance(series, dict) and series.get("role") == role, "history role mismatch")
        require(isinstance(registry, dict) and registry.get("role") == role, "registry role mismatch")
        snapshots = series.get("snapshots")
        keys = registry.get("epochs")
        require(isinstance(snapshots, list) and snapshots, "empty history")
        require(isinstance(keys, list) and len(keys) == len(snapshots), "epoch key pin count mismatch")
        role_claims = []
        role_pins = []
        for index, (snapshot, epochkey) in enumerate(zip(snapshots, keys)):
            require(isinstance(snapshot, dict) and isinstance(epochkey, dict),
                    "malformed epoch key record")
            checkpoint = check_signed_checkpoint(snapshot.get("checkpoint"))
            epoch = checkpoint["epoch"]
            require(type(epochkey.get("epoch")) is int and epochkey["epoch"] == epoch,
                    "key pin is bound to wrong epoch")
            if index:
                require(epoch == role_claims[-1]["epoch"] + 1,
                        "missing/replayed epoch in key history")
            pin = epochkey.get("pin")
            check_sha(pin, "epoch key pin not externally supplied")
            require(pin not in role_pins or pin == role_pins[-1],
                    "revoked or superseded key reused")
            signature_sha = verifier(snapshot.get("public_key"),
                                     snapshot.get("signature"), pin, canonical(checkpoint))
            check_sha(signature_sha, "invalid checkpoint signature digest")
            claim = {
                "role": role, "epoch": epoch,
                "ledger_sha256": checkpoint["ledger_sha256"],
                "checkpoint_sha256": digest(checkpoint),
                "signing_key_spki_sha256": pin,
                "signature_sha256": signature_sha,
                "signed_checkpoint_verified": True,
            }
            role_claims.append(claim)
            all_claims.append(claim)
            role_pins.append(pin)
        used_pins_by_role[role] = set(role_pins)
        expected_rotations = sum(
            role_pins[i] != role_pins[i-1] for i in range(1, len(role_pins))
        )
        rotations = series.get("rotations", [])
        require(isinstance(rotations, list) and len(rotations) == expected_rotations,
                "missing or excess key rotation")
        cursor = 0
        for i in range(1, len(role_pins)):
            if role_pins[i] == role_pins[i-1]:
                continue
            item = rotations[cursor]
            cursor += 1
            require(isinstance(item, dict), "malformed rotation")
            msg = rotation_message(role,
                                   {"epoch": role_claims[i-1]["epoch"], "pin": role_pins[i-1]},
                                   {"epoch": role_claims[i]["epoch"], "pin": role_pins[i]},
                                   snapshots[i-1]["checkpoint"], snapshots[i]["checkpoint"])
            require(item.get("from_epoch") == msg["from_epoch"] and
                    item.get("to_epoch") == msg["to_epoch"] and
                    item.get("old_pin") == msg["old_pin"] and
                    item.get("new_pin") == msg["new_pin"], "rotation mismatch")
            oldsig = verifier(item.get("old_public_key"), item.get("old_signature"),
                              role_pins[i-1], canonical(msg))
            newsig = verifier(item.get("new_public_key"), item.get("new_signature"),
                              role_pins[i], canonical(msg))
            check_sha(oldsig, "old signature invalid")
            check_sha(newsig, "new signature invalid")
            all_rotations.append({
                **msg, "old_signature_sha256": oldsig,
                "new_signature_sha256": newsig,
                "dual_signature_verified": True,
            })
        revocations = series.get("revocations", [])
        require(isinstance(revocations, list), "revocation list absent")
        seen_revoked = set()
        for rev in revocations:
            require(isinstance(rev, dict), "malformed revocation")
            pin = rev.get("revoked_pin")
            require(pin in role_pins and pin not in seen_revoked, "unknown or repeated revocation")
            seen_revoked.add(pin)
            msg = revoked_message(role, pin, rev.get("effective_epoch"), rev.get("evidence_sha256"))
            # No previously revoked key may sign an epoch at or beyond its effective epoch.
            require(all(c["epoch"] < msg["effective_epoch"] for c in role_claims
                        if c["signing_key_spki_sha256"] == pin),
                    "revoked key used at or after effective epoch")
            # A revocation is signed by a separately pinned registry authority,
            # not the revoked key itself. Its actual organizational custody is unverified.
            authority_pin = registry.get("revocation_authority_pin")
            check_sha(authority_pin, "externally pinned revocation authority missing")
            require(authority_pin != pin, "revocation self-issued by revoked key")
            signature = verifier(rev.get("authority_public_key"),
                                 rev.get("authority_signature"),
                                 authority_pin, canonical(msg))
            check_sha(signature, "revocation signature invalid")
            all_revocations.append({
                **msg,"authority_pin":authority_pin,
                "authority_signature_sha256":signature,
            })
    # One signing pin reused across multiple witness roles is shared ancestry.
    overlap = []
    for i in range(3):
        for j in range(i+1,3):
            cross = sorted(used_pins_by_role[ROLES[i]] & used_pins_by_role[ROLES[j]])
            if cross:
                overlap.append({"roles":[ROLES[i],ROLES[j]],"shared_key_pins":cross})
    contradictions = []
    for epoch in sorted({x["epoch"] for x in all_claims}):
        claims = [x for x in all_claims if x["epoch"] == epoch]
        digests = sorted({x["ledger_sha256"] for x in claims})
        if len(digests)>1:
            contradictions.append({"epoch":epoch,"ledger_sha256_variants":digests,
                                   "claims":claims})
    result = {
        "phase":"RUST-036",
        "status":"HOLD_EQUIVOCATION_OR_SHARED_KEYS" if contradictions or overlap
                 else "HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN",
        "epoch_key_claims":all_claims,
        "verified_rotations":all_rotations,
        "revocation_evidence":all_revocations,
        "equivocation_evidence":contradictions,
        "shared_witness_key_evidence":overlap,
        "per_epoch_signature_checks_completed":len(all_claims),
        "rotation_signature_checks_completed":len(all_rotations)*2,
        "external_key_registry_ancestry_verified":False,
        "independent_custodian_control_verified":False,
        "external_latest_highwater_verified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result


def hold():
    return {
        "phase":"RUST-036","status":"HOLD_MISSING_EPOCH_KEY_REGISTRY",
        "release_authorized":False,"fork_resolved":False,
        "external_key_registry_ancestry_verified":False,
        "live_gameplay_authority":False,
        "reason":"No externally pinned epoch-key registry with checkpoint and rotation signatures",
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--histories")
    p.add_argument("--registries")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.histories)==bool(a.registries),"partial epoch-key bundle refused")
    if a.histories:
        result=audit(json.loads(Path(a.histories).read_text(encoding="utf-8")),
                     json.loads(Path(a.registries).read_text(encoding="utf-8")))
    else:
        result=hold()
    out=Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-036 HOLD: external registry custody not independently verified")


if __name__=="__main__":
    main()
