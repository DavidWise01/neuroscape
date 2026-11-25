#!/usr/bin/env python3
"""RUST-020 · Candidate genesis with optional external Ed25519 custody proof.

Emit creates an immutable *candidate*, never a trusted anchor.
Verify requires an externally pinned public-key fingerprint plus an Ed25519
signature on the exact canonical candidate bytes. No key is generated here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from adjudicate_rust018 import load, require
from lineage_rust019 import validate_receipt

H40 = re.compile(r"^[a-f0-9]{40}$")
H64 = re.compile(r"^[a-f0-9]{64}$")

def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def candidate(receipt):
    r = validate_receipt(receipt)
    data = {
        "phase": "RUST-020",
        "status": "GENESIS_CANDIDATE",
        "sequence": 0,
        "source_commit": r["source_commit"],
        "adjudication_sha256": r["receipt_sha256"],
        "wasm_sha256": r["wasm_sha256"],
        "replay_sha256": r["replay_sha256"],
        "custody_authenticated": False,
        "independent_source_ancestries": 1,
        "live_gameplay_authority": False,
    }
    data["candidate_sha256"] = sha(canonical(data))
    return data

def check_candidate(data):
    require(isinstance(data, dict) and data.get("status") == "GENESIS_CANDIDATE", "not genesis candidate")
    require(data.get("phase") == "RUST-020" and data.get("sequence") == 0, "wrong phase/sequence")
    require(data.get("custody_authenticated") is False and data.get("live_gameplay_authority") is False, "forbidden self-authority")
    require(data.get("independent_source_ancestries") == 1, "source ancestry misdeclared")
    require(isinstance(data.get("source_commit"), str) and H40.fullmatch(data["source_commit"]), "invalid source")
    for k in ("candidate_sha256","adjudication_sha256","wasm_sha256","replay_sha256"):
        require(isinstance(data.get(k), str) and H64.fullmatch(data[k]), "invalid " + k)
    raw = {k:v for k,v in data.items() if k != "candidate_sha256"}
    require(sha(canonical(raw)) == data["candidate_sha256"], "candidate altered")
    return data

def authenticated(candidate_data, public_key, signature, externally_pinned_digest):
    obj = check_candidate(candidate_data)
    require(isinstance(externally_pinned_digest, str) and H64.fullmatch(externally_pinned_digest), "missing external public-key pin")
    public_key = Path(public_key)
    signature = Path(signature)
    require(public_key.is_file() and signature.is_file(), "missing public key or signature")
    export = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    require(sha(export) == externally_pinned_digest, "custodian key differs from external pin")
    details = subprocess.run(
        ["openssl","pkey","-pubin","-in",str(public_key),"-text_pub","-noout"],
        capture_output=True, check=True, text=True,
    ).stdout
    require("ED25519" in details.upper(), "custodian key must be Ed25519")
    # Ed25519 keys use the SPKI algorithm OID 1.3.101.112, DER ending
    # is not relied upon; OpenSSL performs signature and key-type validation.
    with tempfile.TemporaryDirectory() as temporary:
        message = Path(temporary) / "genesis.canonical.json"
        message.write_bytes(canonical(obj))
        result = subprocess.run(
            ["openssl","pkeyutl","-verify","-pubin","-inkey",str(public_key),
             "-rawin","-in",str(message),"-sigfile",str(signature)],
            capture_output=True, check=False,
        )
    require(result.returncode == 0, "external signature not verified")
    validated = {
        "phase": "RUST-020",
        "status": "CUSTODY_SIGNATURE_VERIFIED",
        "sequence": 0,
        "source_commit": obj["source_commit"],
        "candidate_sha256": obj["candidate_sha256"],
        "custodian_key_spki_sha256": externally_pinned_digest,
        "signature_sha256": sha(signature.read_bytes()),
        "external_key_pin_required": True,
        "custody_authenticated": True,
        "source_independence_certified": False,
        "live_gameplay_authority": False,
        "scope": "signature_on_candidate_only",
    }
    validated["attestation_sha256"] = sha(canonical(validated))
    return validated

def save_exclusive(path, value):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as writer:
        json.dump(value, writer, indent=2, sort_keys=True)
        writer.write("\n")
    return output

def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("emit","verify"))
    p.add_argument("--receipt")
    p.add_argument("--candidate")
    p.add_argument("--public-key")
    p.add_argument("--signature")
    p.add_argument("--output",required=True)
    args = p.parse_args()
    if args.action == "emit":
        require(args.receipt is not None, "missing adjudication")
        result = candidate(load(args.receipt))
    else:
        require(all((args.candidate, args.public_key, args.signature)), "missing external verification inputs")
        pin = os.environ.get("RUST020_CUSTODIAN_PUBKEY_SHA256")
        result = authenticated(load(args.candidate), args.public_key, args.signature, pin)
    path = save_exclusive(args.output, result)
    print(path, json.dumps(result, sort_keys=True))
    if args.action == "emit":
        print("RUST-020 HOLD: genesis candidate recorded, external custody unverified")

if __name__ == "__main__":
    main()
