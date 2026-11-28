#!/usr/bin/env python3
"""RUST-097 — cross-ancestry highwater byte custody (strict HOLD).

Submitted bytes and locally checked signatures do not authenticate external
custody, witness independence, or a globally latest checkpoint.
"""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
from cross_run_acquisition_ledger_rust091 import digest, require
from rotation_rust022 import canonical, verify_key_and_signature
from quarantine_highwater_rust096 import HOLD as PRIOR_HOLD

DOMAIN = "NEUROSCAPE_RUST097_EXTERNAL_HIGHWATER_V1"
HOLD = "HOLD_EXTERNAL_HIGHWATER_CUSTODY_UNVERIFIED"
CAP = 1024 * 1024
FIELDS = ("controller", "root", "source", "acquisition")

def sha(s):
    require(isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s),
            "lowercase SHA-256 required")
    return s

def signed_payload(highwater_sha, signer, nonce, ancestry, byte_sha):
    for value in (highwater_sha, signer, nonce, byte_sha):
        sha(value)
    require(isinstance(ancestry, dict) and set(ancestry) == set(FIELDS),
            "complete ancestry required")
    for field in FIELDS:
        sha(ancestry[field])
    return {"phase":"RUST-097", "domain":DOMAIN,
            "highwater_receipt_sha256": highwater_sha,
            "signer_pin": signer, "nonce_sha256": nonce,
            "evidence_sha256": byte_sha, "control_ancestry": ancestry,
            "independent_custody_verified": False,
            "global_anti_rollback_verified": False,
            "recovery_authorized": False, "release_authorized": False}

def verify(highwater, witnesses, verifier=verify_key_and_signature):
    require(isinstance(highwater, dict)
            and highwater.get("phase") == "RUST-096"
            and highwater.get("status") == PRIOR_HOLD
            and highwater.get("independent_external_custody_verified") is False
            and highwater.get("global_latest_floor_authenticated") is False
            and highwater.get("release_authorized") is False,
            "RUST-096 HOLD checkpoint required")
    head = sha(highwater.get("current_head_sha256"))
    receipt = digest(highwater)
    require(isinstance(witnesses, list) and len(witnesses) == 2,
            "two custody witness claims required")
    pins, nonces, ancestors = set(), set(), set()
    rows = []
    for witness in witnesses:
        require(isinstance(witness, dict), "witness record required")
        pin = sha(witness.get("signer_pin"))
        nonce = sha(witness.get("nonce_sha256"))
        require(pin not in pins and nonce not in nonces,
                "signer or nonce reused")
        pins.add(pin)
        nonces.add(nonce)
        ancestry = witness.get("control_ancestry")
        require(isinstance(ancestry, dict) and set(ancestry) == set(FIELDS),
                "incomplete ancestry")
        for field in FIELDS:
            value = sha(ancestry[field])
            require(value not in ancestors, "shared control ancestry")
            ancestors.add(value)
        encoded = witness.get("highwater_base64")
        require(isinstance(encoded, str) and 0 < len(encoded) <= 1400000,
                "bounded external byte representation required")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("malformed highwater bytes") from None
        require(0 < len(data) <= CAP, "highwater byte bound violated")
        actual = hashlib.sha256(data).hexdigest()
        require(actual == sha(witness.get("evidence_sha256")),
                "highwater byte digest mismatch")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("highwater must contain canonical JSON") from None
        require(canonical(parsed) == data,
                "noncanonical or repackaged checkpoint")
        require(parsed == highwater, "externally supplied checkpoint differs")
        require(parsed.get("current_head_sha256") == head,
                "historical highwater substituted")
        expected = signed_payload(receipt, pin, nonce, ancestry, actual)
        require(witness.get("payload") == expected,
                "signature payload or authority substitution")
        checked = verifier(witness.get("public_key"), witness.get("signature"),
                           pin, canonical(expected))
        sha(checked)
        rows.append({"signer_pin":pin, "nonce_sha256":nonce,
                     "evidence_sha256":actual, "signature_receipt_sha256":checked,
                     "control_ancestry_sha256":digest(ancestry)})
    return {"phase":"RUST-097", "status":HOLD,
            "rust096_receipt_sha256":receipt,
            "highwater_head_sha256":head,
            "witness_receipts":rows,
            "matching_submitted_highwater_bytes":True,
            "independent_external_custody_verified":False,
            "global_anti_rollback_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-097",
            "status":"HOLD_MISSING_EXTERNAL_HIGHWATER_WITNESSES",
            "independent_external_custody_verified":False,
            "global_anti_rollback_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--highwater")
    p.add_argument("--witnesses")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.highwater)==bool(a.witnesses), "partial witness bundle")
    if a.highwater:
        load=lambda file:json.loads(Path(file).read_text(encoding="utf-8"))
        result=verify(load(a.highwater),load(a.witnesses))
    else:
        result=missing()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-097 HOLD: independent external custody unverified")
if __name__=="__main__":
    main()
