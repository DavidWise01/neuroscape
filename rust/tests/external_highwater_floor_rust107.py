#!/usr/bin/env python3
"""RUST-107: external highwater copy replay, stale-floor and ancestry fencing.

All external copies are submitted evidence. RUST-106 signature checks can
authenticate a signed payload relative to a trusted key pin, but cannot
authenticate the acquisition channel, independent custodians, or latest floor.
"""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path

from rotation_rust022 import canonical, verify_key_and_signature
from operator_highwater_rust106 import verify_signed
from operator_continuity_rust105 import validate, need

DOMAIN = "NEUROSCAPE_RUST107_EXTERNAL_FLOOR_COPIES_V1"
HOLD = "HOLD_EXTERNAL_HIGHWATER_FLOOR_UNVERIFIED"
FIELDS = ("controller", "operator", "root", "network", "acquisition")
LIMIT = 1024 * 1024

def sha(value):
    need(isinstance(value, str) and len(value) == 64
         and all(ch in "0123456789abcdef" for ch in value),
         "lowercase SHA-256 required")
    return value

def digest(data):
    return hashlib.sha256(data).hexdigest()

def copy_evidence(copy, histories, verifier):
    need(isinstance(copy, dict), "custody copy required")
    need(copy.get("domain") == DOMAIN
         and copy.get("independent_custody_verified") is False
         and copy.get("release_authorized") is False,
         "unearned external copy authority")
    index = copy.get("ledger_epoch")
    need(type(index) is int and index in (0, 1),
         "external copy must bind a known history epoch")
    signed = copy.get("signed_highwater")
    history = histories[index]
    payload, signature_digest = verify_signed(history, signed, verifier)
    encoded = copy.get("payload_base64")
    need(isinstance(encoded, str) and 0 < len(encoded) <= 1400000,
         "bounded exact highwater payload required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid highwater Base64") from None
    need(0 < len(raw) <= LIMIT, "highwater copy oversized")
    need(raw == canonical(payload),
         "external bytes differ from signed canonical highwater")
    need(digest(raw) == sha(copy.get("payload_sha256")),
         "highwater payload digest mismatch")
    custody = copy.get("custody")
    need(isinstance(custody, dict) and set(custody) == set(FIELDS),
         "complete custody lineage required")
    for field in FIELDS: sha(custody[field])
    nonce = sha(copy.get("acquisition_nonce_sha256"))
    return {"ledger_epoch": index, "head_sha256": payload["head_sha256"],
            "highwater_signature_sha256": signature_digest,
            "payload_sha256": digest(raw), "acquisition_nonce_sha256": nonce,
            "signer_pin": payload["signer_pin"],
            "custody": {field: custody[field] for field in FIELDS}}

def compare(old, current, copies, verifier=verify_key_and_signature):
    need(isinstance(old, list) and old, "nonempty previous ledger required")
    need(isinstance(current, list) and len(current) > len(old)
         and current[:len(old)] == old, "rollback or rewritten ledger prefix")
    validate(old)
    latest_head = validate(current)
    need(isinstance(copies, list) and len(copies) == 2,
         "two supplied external highwater copies required")
    seen = [copy_evidence(c, (old, current), verifier) for c in copies]
    reasons = set()
    for item in seen:
        if item["ledger_epoch"] == 0:
            reasons.add("STALE_HIGHWATER_COPY")
        if item["head_sha256"] != latest_head:
            reasons.add("COPY_BELOW_LOCAL_HIGHWATER")
    if seen[0]["payload_sha256"] == seen[1]["payload_sha256"]:
        reasons.add("IDENTICAL_HIGHWATER_COPY")
    if seen[0]["acquisition_nonce_sha256"] == seen[1]["acquisition_nonce_sha256"]:
        reasons.add("REPLAYED_ACQUISITION_NONCE")
    if seen[0]["signer_pin"] == seen[1]["signer_pin"]:
        reasons.add("REUSED_HIGHWATER_SIGNER")
    if seen[0]["head_sha256"] != seen[1]["head_sha256"]:
        reasons.add("CONFLICTING_OBSERVED_FLOORS")
    for field in FIELDS:
        if seen[0]["custody"][field] == seen[1]["custody"][field]:
            reasons.add("SHARED_" + field.upper() + "_ANCESTRY")
    return {"phase": "RUST-107", "domain": DOMAIN, "status": HOLD,
            "local_highwater_head_sha256": latest_head,
            "copies": [{k: v for k, v in item.items() if k != "custody"}
                       for item in seen],
            "custody_ancestry_sha256": [
                digest(canonical(item["custody"])) for item in seen],
            "provenance_conflicts": sorted(reasons),
            "historic_conflicts_retained": True,
            "external_acquisition_authenticated": False,
            "independent_external_custody_verified": False,
            "global_latest_floor_authenticated": False,
            "fork_selected": False, "recovery_authorized": False,
            "release_authorized": False, "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-107",
            "status": "HOLD_MISSING_EXTERNAL_HIGHWATER_COPY_BYTES",
            "external_acquisition_authenticated": False,
            "independent_external_custody_verified": False,
            "global_latest_floor_authenticated": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("previous", "current", "external-copies"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    names = (a.previous, a.current, a.external_copies)
    need(all(names) or not any(names), "partial external witness bundle")
    if all(names):
        load = lambda path: json.loads(Path(path).read_text(encoding="utf-8"))
        result = compare(load(a.previous), load(a.current),
                         load(a.external_copies))
    else:
        result = missing()
    path = Path(a.output); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2); f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-107 HOLD: external custody not authenticated")

if __name__ == "__main__":
    main()
