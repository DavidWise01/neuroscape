#!/usr/bin/env python3
"""RUST-087 — independent custody challenge fence (fail-closed).

Validates *submitted* cryptographic challenges over a frozen RUST-086
highwater. Two valid signatures alone do not prove independent physical
custody. This module never grants recovery, release, or gameplay authority.
"""
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

DOMAIN = "NEUROSCAPE_RUST087_CUSTODY_CHALLENGE_V1"
ANCESTRY = ("controller", "root", "source", "acquisition")
HOLD = "HOLD_INDEPENDENT_CUSTODY_UNVERIFIED"

def _fingerprints(challenge):
    record = challenge.get("control_ancestry")
    require(isinstance(record, dict), "control ancestry required")
    out = {}
    for field in ANCESTRY:
        value = record.get(field)
        check_sha(value, "missing ancestry fingerprint: " + field)
        out[field] = value
    return out

def challenge_payload(checkpoint, nonce, signer_pin, ancestry):
    require(isinstance(checkpoint, dict)
            and checkpoint.get("phase") == "RUST-086"
            and checkpoint.get("kind") == "CROSS_CUSTODIAN_QUARANTINE_HIGHWATER_V1",
            "RUST-086 checkpoint required")
    check_sha(nonce, "challenge nonce missing")
    check_sha(signer_pin, "signer pin missing")
    return {"phase": "RUST-087", "domain": DOMAIN,
            "highwater_sha256": digest(checkpoint),
            "nonce_sha256": nonce, "signer_pin": signer_pin,
            "control_ancestry": ancestry,
            "custody_independence_verified": False,
            "recovery_authorized": False,
            "release_authorized": False}

def fence(checkpoint, challenges, retained_denials, retained_quarantines,
          verifier=verify_key_and_signature):
    require(isinstance(challenges, list) and len(challenges) == 2,
            "exactly two signed custody challenges required")
    require(isinstance(retained_denials, list)
            and isinstance(retained_quarantines, list),
            "historical denials and quarantines must be supplied")
    payloads = []
    pins = set()
    nonces = set()
    ancestry_values = set()
    for challenge in challenges:
        require(isinstance(challenge, dict), "challenge must be object")
        pin = challenge.get("signer_pin")
        nonce = challenge.get("nonce_sha256")
        check_sha(pin, "signer pin missing")
        check_sha(nonce, "challenge nonce missing")
        require(pin not in pins and nonce not in nonces,
                "duplicate signer or replayed nonce")
        pins.add(pin)
        nonces.add(nonce)
        lineage = _fingerprints(challenge)
        require(not (set(lineage.values()) & ancestry_values),
                "shared control ancestry across witnesses")
        ancestry_values.update(lineage.values())
        payload = challenge_payload(checkpoint, nonce, pin, lineage)
        require(challenge.get("payload") == payload,
                "signed payload substituted or authority asserted")
        verified = verifier(challenge.get("public_key"),
                            challenge.get("signature"), pin, canonical(payload))
        check_sha(verified, "custody challenge signature rejected")
        payloads.append(payload)
    return {"phase": "RUST-087", "status": HOLD,
            "highwater_sha256": digest(checkpoint),
            "challenge_payload_sha256": [digest(v) for v in payloads],
            "denial_retention_sha256": digest(retained_denials),
            "quarantine_retention_sha256": digest(retained_quarantines),
            "submitted_signatures_valid": True,
            "distinct_claimed_ancestry": True,
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}
