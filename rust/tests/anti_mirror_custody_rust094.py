#!/usr/bin/env python3
"""RUST-094 — anti-mirror evidence byte ancestry and append-only quarantine.

Compares two supplied RUST-093 witness bundles, including canonical JSON
payload equivalence across formatting variations. Correlation is recorded
as quarantine, not independence. No physical custody is authenticated.
No archive extraction, arbitrary URLs, or executable evaluation.
"""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
from cross_run_acquisition_ledger_rust091 import digest, require
from witness_byte_replay_rust093 import HOLD as PRIOR_HOLD

DOMAIN = "NEUROSCAPE_RUST094_ANTI_MIRROR_V1"
HOLD = "HOLD_ANTI_MIRROR_CUSTODY_UNVERIFIED"
MAX_BYTES = 1024 * 1024
FIELDS = ("controller", "root", "source", "acquisition")

def byte_hash(data):
    return hashlib.sha256(data).hexdigest()

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key refused")
        result[key] = value
    return result

def canonical_evidence(data):
    """Return bounded semantic fingerprint for valid JSON, otherwise None."""
    if len(data) > MAX_BYTES:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return byte_hash(json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False).encode("utf-8"))

def decode(item):
    require(isinstance(item, dict), "witness bundle object required")
    encoded = item.get("evidence_base64")
    require(isinstance(encoded, str) and 0 < len(encoded) <= 1400000,
            "missing or oversized witness bytes")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("malformed witness Base64") from None
    require(0 < len(data) <= MAX_BYTES, "empty or oversized witness bytes")
    return data

def analyze(reconciliation, witnesses, prior_quarantine=None):
    upstream = check_rust093(reconciliation, witnesses)
    require(upstream["status"] == PRIOR_HOLD, "RUST-093 must remain HOLD")
    previous = [] if prior_quarantine is None else prior_quarantine
    require(isinstance(previous, list), "prior quarantine must be a list")
    for entry in previous:
        require(isinstance(entry, dict) and entry.get("phase") == "RUST-094"
                and entry.get("status") == "QUARANTINED"
                and isinstance(entry.get("reasons"), list)
                and entry["reasons"], "invalid prior quarantine")
    left, right = witnesses
    a, b = decode(left), decode(right)
    reasons = []
    if byte_hash(a) == byte_hash(b):
        reasons.append("IDENTICAL_BYTES")
    semantic_a, semantic_b = canonical_evidence(a), canonical_evidence(b)
    if semantic_a is not None and semantic_a == semantic_b:
        reasons.append("EQUIVALENT_JSON_CONTENT")
    for field in FIELDS:
        if left["control_ancestry"][field] == right["control_ancestry"][field]:
            reasons.append("SHARED_" + field.upper() + "_ANCESTRY")
    # External source ownership cannot be deduced from different names or bytes.
    if left.get("acquisition_custodian_id") is not None and (
            left.get("acquisition_custodian_id") == right.get("acquisition_custodian_id")):
        reasons.append("SAME_DECLARED_CUSTODIAN")
    new = ({"phase": "RUST-094", "status": "QUARANTINED",
            "reasons": sorted(set(reasons)),
            "left_evidence_sha256": byte_hash(a),
            "right_evidence_sha256": byte_hash(b)}
           if reasons else None)
    log = previous + ([new] if new else [])
    return {"phase": "RUST-094", "domain": DOMAIN, "status": HOLD,
            "rust093_receipt_sha256": digest(upstream),
            "prior_quarantine_sha256": digest(previous),
            "quarantine_log": log,
            "quarantine_log_sha256": digest(log),
            "new_mirror_conflict_count": len(reasons),
            "claimed_source_separation_sufficient": False,
            "independent_external_custody_verified": False,
            "recovery_authorized": False,
            "release_authorized": False,
            "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-094", "status": "HOLD_MISSING_ANTI_MIRROR_BYTES",
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reconciliation")
    p.add_argument("--witnesses")
    p.add_argument("--quarantine")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    require(bool(a.reconciliation) == bool(a.witnesses),
            "partial evidence bundle refused")
    require(not a.quarantine or a.reconciliation,
            "quarantine requires complete evidence bundle")
    if a.reconciliation:
        read = lambda filename: json.loads(Path(filename).read_text(encoding="utf-8"))
        result = analyze(read(a.reconciliation), read(a.witnesses),
                         read(a.quarantine) if a.quarantine else None)
    else:
        result = missing()
    output = Path(a.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-094 HOLD: mirrored and independent custody unproven")

if __name__ == "__main__":
    main()
