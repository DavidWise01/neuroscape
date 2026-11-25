#!/usr/bin/env python3
"""RUST-021: first successor of an externally signed RUST-020 genesis.

A candidate alone cannot authorize succession. Caller must supply custody
material via an external mount plus a separately pinned Ed25519 SPKI digest.
No keys, trust roots, signatures or synthetic genesis are generated here.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from adjudicate_rust018 import load
from genesis_rust020 import authenticated, check_candidate
from lineage_rust019 import digest, require, validate_receipt

def git_descendant(older, newer):
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        capture_output=True, check=False,
    )
    return result.returncode == 0

def first_successor(current, genesis_candidate, verified_attestation, descendant):
    """Pure validation after signature checking by genesis_rust020.authenticated."""
    current = validate_receipt(current)
    genesis = check_candidate(genesis_candidate)
    require(verified_attestation.get("phase") == "RUST-020", "attestation phase invalid")
    require(verified_attestation.get("status") == "CUSTODY_SIGNATURE_VERIFIED", "genesis custody unverified")
    require(verified_attestation.get("custody_authenticated") is True, "custodian signature absent")
    require(verified_attestation.get("source_independence_certified") is False, "false source-independence claim")
    require(verified_attestation.get("live_gameplay_authority") is False, "unauthorized gameplay authority")
    require(verified_attestation.get("candidate_sha256") == genesis["candidate_sha256"], "genesis candidate mismatch")
    require(verified_attestation.get("source_commit") == genesis["source_commit"], "genesis source mismatch")
    require(verified_attestation.get("sequence") == 0, "invalid genesis sequence")
    require(verified_attestation.get("external_key_pin_required") is True, "missing external key pin assertion")
    require(
        digest({k: v for k, v in verified_attestation.items() if k != "attestation_sha256"})
        == verified_attestation.get("attestation_sha256"), "attestation digest mismatch",
    )
    require(current["source_commit"] != genesis["source_commit"], "same-commit genesis replay")
    require(callable(descendant) and descendant(genesis["source_commit"], current["source_commit"]),
            "successor is not descendant of anchored genesis")
    require(current["receipt_sha256"] != genesis["adjudication_sha256"], "genesis observation reused")
    result = {
        "phase": "RUST-021",
        "status": "FIRST_SUCCESSOR_OF_SIGNED_GENESIS",
        "sequence": 1,
        "source_commit": current["source_commit"],
        "receipt_sha256": current["receipt_sha256"],
        "genesis_source_commit": genesis["source_commit"],
        "genesis_candidate_sha256": genesis["candidate_sha256"],
        "predecessor_attestation_sha256": verified_attestation["attestation_sha256"],
        "external_key_pin_verified": True,
        "external_custodian_identity_verified": False,
        "global_anti_rollback_certified": False,
        "source_independence_certified": False,
        "live_gameplay_authority": False,
    }
    result["entry_sha256"] = digest(result)
    return result

def hold(current, reason):
    receipt = validate_receipt(current)
    return {
        "phase": "RUST-021",
        "status": "HOLD_EXTERNAL_GENESIS",
        "source_commit": receipt["source_commit"],
        "receipt_sha256": receipt["receipt_sha256"],
        "sequence": None,
        "reason": reason,
        "external_key_pin_verified": False,
        "global_anti_rollback_certified": False,
        "live_gameplay_authority": False,
    }

def exclusive_write(path, payload):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8") as writer:
        json.dump(payload, writer, indent=2, sort_keys=True)
        writer.write("\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--current", required=True)
    p.add_argument("--candidate")
    p.add_argument("--public-key")
    p.add_argument("--signature")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    current = load(args.current)
    inputs = (args.candidate, args.public_key, args.signature)
    pin = os.environ.get("RUST020_CUSTODIAN_PUBKEY_SHA256")
    if not all(inputs) or not pin:
        value = hold(current, "External signed genesis and independently pinned key not supplied")
    else:
        candidate = load(args.candidate)
        # Verify the real Ed25519 signature and pinned public key BEFORE
        # interpreting the claimed custody attestation.
        verified = authenticated(candidate, args.public_key, args.signature, pin)
        value = first_successor(current, candidate, verified, git_descendant)
    exclusive_write(args.output, value)
    print(json.dumps(value, sort_keys=True))
    if value["status"] != "FIRST_SUCCESSOR_OF_SIGNED_GENESIS" and not args.allow_hold_record:
        raise SystemExit("RUST-021 HOLD: no authenticated genesis successor")

if __name__ == "__main__":
    main()
