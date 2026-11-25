#!/usr/bin/env python3
"""RUST-022: custodian continuity and dual-signed rotation for copied-state releases.

A signature alone never proves an externally controlled custody key. The
old and, on rotation, new key fingerprints must be pinned outside the repo.
No release authority is granted by this module.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from adjudicate_rust018 import load
from lineage_rust019 import digest, require, validate_receipt
from successor_rust021 import git_descendant

HEX64 = re.compile(r"^[a-f0-9]{64}$")

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def check_sha(value, message):
    require(isinstance(value, str) and bool(HEX64.fullmatch(value)), message)

def check_anchor(previous):
    require(isinstance(previous, dict), "previous record absent")
    require(previous.get("phase") in ("RUST-021", "RUST-022"), "unknown predecessor phase")
    require(previous.get("status") in ("FIRST_SUCCESSOR_OF_SIGNED_GENESIS", "CUSTODIAN_CONTINUITY"), "unqualified predecessor")
    require(type(previous.get("sequence")) is int and previous["sequence"] >= 1, "invalid sequence")
    require(previous.get("source_independence_certified") is False, "invalid independent ancestry claim")
    require(previous.get("live_gameplay_authority") is False, "predecessor gameplay authority")
    require(previous.get("global_anti_rollback_certified") is False, "unsupported global anti-rollback claim")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", str(previous.get("source_commit", "")))), "predecessor commit invalid")
    for field in ("entry_sha256", "receipt_sha256"):
        check_sha(previous.get(field), "predecessor " + field)
    require(digest({k: v for k, v in previous.items() if k != "entry_sha256"}) == previous["entry_sha256"], "predecessor modified")
    return previous

def proposal(previous, current, old_pin, new_pin=None):
    previous = check_anchor(previous)
    current = validate_receipt(current)
    check_sha(old_pin, "external old-key pin absent")
    next_pin = new_pin if new_pin is not None else old_pin
    check_sha(next_pin, "new-key pin absent")
    require(current["source_commit"] != previous["source_commit"], "replayed source commit")
    require(current["receipt_sha256"] != previous["receipt_sha256"], "replayed observation receipt")
    value = {
        "phase": "RUST-022",
        "kind": "ROTATION" if next_pin != old_pin else "CONTINUITY",
        "predecessor_sha256": previous["entry_sha256"],
        "predecessor_source_commit": previous["source_commit"],
        "source_commit": current["source_commit"],
        "receipt_sha256": current["receipt_sha256"],
        "sequence": previous["sequence"] + 1,
        "old_key_spki_sha256": old_pin,
        "new_key_spki_sha256": next_pin,
        "live_gameplay_authority": False,
        "source_independence_certified": False,
    }
    value["proposal_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
    return value

def verify_key_and_signature(key, signature, pinned, message):
    check_sha(pinned, "external key pin absent")
    path = Path(key)
    sig = Path(signature)
    require(path.is_file() and sig.is_file(), "custody key/signature missing")
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    require(hashlib.sha256(spki).hexdigest() == pinned, "custodian key substitution")
    info = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-text_pub", "-noout"],
        capture_output=True, check=True, text=True,
    ).stdout
    require("ED25519" in info.upper(), "custodian key is not Ed25519")
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "checkpoint.json"
        target.write_bytes(message)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(path),
             "-rawin", "-in", str(target), "-sigfile", str(sig)],
            capture_output=True, check=False,
        )
    require(result.returncode == 0, "custody signature rejected")
    return hashlib.sha256(sig.read_bytes()).hexdigest()

def qualify(previous, current, old_pin, old_key, old_signature,
            new_pin=None, new_key=None, new_signature=None, descendant=git_descendant):
    value = proposal(previous, current, old_pin, new_pin)
    require(callable(descendant) and descendant(value["predecessor_source_commit"], value["source_commit"]),
            "source is not a descendant")
    bytes_to_sign = canonical(value)
    old_sig = verify_key_and_signature(old_key, old_signature, old_pin, bytes_to_sign)
    if value["kind"] == "ROTATION":
        require(new_pin is not None and new_key is not None and new_signature is not None,
                "rotation needs independently pinned new key and dual signatures")
        new_sig = verify_key_and_signature(new_key, new_signature, new_pin, bytes_to_sign)
    else:
        require(new_key is None and new_signature is None, "unexpected new key on continuity")
        new_sig = None
    value = {
        **value,
        "status": "CUSTODIAN_CONTINUITY",
        "proposal_sha256": value["proposal_sha256"],
        "old_signature_sha256": old_sig,
        "new_signature_sha256": new_sig,
        "external_pin_required": True,
        "external_custodian_identity_verified": False,
        "global_anti_rollback_certified": False,
    }
    value["entry_sha256"] = digest(value)
    return value

def hold(current):
    current = validate_receipt(current)
    return {
        "phase": "RUST-022", "status": "HOLD_CUSTODIAN_CONTINUITY",
        "source_commit": current["source_commit"],
        "receipt_sha256": current["receipt_sha256"],
        "sequence": None,
        "external_pin_verified": False,
        "global_anti_rollback_certified": False,
        "live_gameplay_authority": False,
        "reason": "No externally retained and pinned predecessor custody",
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True)
    parser.add_argument("--previous")
    parser.add_argument("--old-key")
    parser.add_argument("--old-signature")
    parser.add_argument("--new-key")
    parser.add_argument("--new-signature")
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-hold-record", action="store_true")
    args = parser.parse_args()
    current = load(args.current)
    old_pin = os.getenv("RUST022_OLD_KEY_SPKI_SHA256")
    new_pin = os.getenv("RUST022_NEW_KEY_SPKI_SHA256")
    if not (args.previous and args.old_key and args.old_signature and old_pin):
        value = hold(current)
    else:
        value = qualify(load(args.previous), current, old_pin,
                        args.old_key, args.old_signature, new_pin,
                        args.new_key, args.new_signature)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as file:
        json.dump(value, file, sort_keys=True, indent=2)
        file.write("\n")
    print(json.dumps(value, sort_keys=True))
    if value["status"] != "CUSTODIAN_CONTINUITY" and not args.allow_hold_record:
        raise SystemExit("RUST-022 HOLD: custody not verified")

if __name__ == "__main__":
    main()
