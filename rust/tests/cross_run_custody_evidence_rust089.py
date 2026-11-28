#!/usr/bin/env python3
"""RUST-089: supplied cross-run artifact byte evidence; NEVER custody authorization.

Checks exact SHA-256 of artifact bytes plus claimed GitHub run and acquisition
ancestry. The inputs are locally supplied; this does not authenticate GitHub
or prove external custody. Refuses promotion and preserves HOLD.
"""
import base64
import binascii
import hashlib
import json

DOMAIN = "NEUROSCAPE_RUST089_CROSS_RUN_EVIDENCE_V1"
HOLD = "HOLD_EXTERNAL_CUSTODY_NOT_AUTHENTICATED"

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha256(blob):
    return hashlib.sha256(blob).hexdigest()

def hex_digest(value):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value),
            "lowercase 64-digit sha256 required")

def record_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8"))

def audit(checkpoint, acquisitions, denied_history, quarantined_history):
    require(isinstance(checkpoint, dict)
            and checkpoint.get("phase") == "RUST-086"
            and checkpoint.get("kind") == "CROSS_CUSTODIAN_QUARANTINE_HIGHWATER_V1",
            "invalid RUST-086 highwater")
    require(isinstance(denied_history, list) and isinstance(quarantined_history, list),
            "both immutable history collections required")
    require(isinstance(acquisitions, list) and len(acquisitions) == 2,
            "exactly two acquisition observations required")
    pins, runs, ancestries, nonces = set(), set(), set(), set()
    rows = []
    frozen = record_digest(checkpoint)
    for item in acquisitions:
        require(isinstance(item, dict) and item.get("domain") == DOMAIN,
                "domain-separated acquisition missing")
        require(item.get("checkpoint_sha256") == frozen,
                "checkpoint substitution")
        run_id = item.get("run_id")
        require(type(run_id) is int and run_id > 0 and run_id not in runs,
                "same or invalid GitHub run")
        runs.add(run_id)
        pin = item.get("custodian_pin")
        hex_digest(pin)
        require(pin not in pins, "duplicate acquisition custodian")
        pins.add(pin)
        nonce = item.get("acquisition_nonce_sha256")
        hex_digest(nonce)
        require(nonce not in nonces, "replayed acquisition nonce")
        nonces.add(nonce)
        ancestry = item.get("control_ancestry")
        require(isinstance(ancestry, dict), "acquisition control ancestry missing")
        for key in ("controller", "root", "source", "acquisition"):
            value = ancestry.get(key)
            hex_digest(value)
            require(value not in ancestries, "shared custody ancestry")
            ancestries.add(value)
        expected = item.get("artifact_sha256")
        hex_digest(expected)
        raw = item.get("artifact_base64")
        require(isinstance(raw, str) and len(raw) <= 1400000,
                "bounded artifact byte payload required")
        try:
            data = base64.b64decode(raw, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("malformed artifact bytes") from None
        require(len(data) > 0 and len(data) <= 1048576,
                "artifact empty or over 1 MiB")
        require(sha256(data) == expected, "artifact hash mismatch")
        require(item.get("external_custody_verified") is False
                and item.get("release_authorized") is False,
                "authority promoted by supplied record")
        rows.append({"run_id": run_id, "custodian_pin": pin,
                     "artifact_sha256": expected,
                     "artifact_length": len(data),
                     "acquisition_record_sha256": record_digest(
                         {k: v for k, v in item.items() if k != "artifact_base64"})})
    return {"phase": "RUST-089", "status": HOLD,
            "checkpoint_sha256": frozen,
            "observations": rows,
            "denial_history_sha256": record_digest(denied_history),
            "quarantine_history_sha256": record_digest(quarantined_history),
            "locally_supplied_bytes_hash_verified": True,
            "independent_external_custody_verified": False,
            "github_run_provenance_authenticated": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def hold():
    return {"phase": "RUST-089", "status": "HOLD_MISSING_CROSS_RUN_CUSTODY_EVIDENCE",
            "independent_external_custody_verified": False,
            "github_run_provenance_authenticated": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

if __name__ == "__main__":
    import argparse
    from pathlib import Path
    p = argparse.ArgumentParser()
    p.add_argument("--bundle")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    if args.bundle:
        b = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        result = audit(b["checkpoint"], b["acquisitions"],
                       b["denied_history"], b["quarantined_history"])
    else:
        result = hold()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-089 HOLD: external acquisition authentication unavailable")
