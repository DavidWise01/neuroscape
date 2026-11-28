#!/usr/bin/env python3
"""RUST-096: signed, monotone quarantine highwater over RUST-095 epochs.

Signature checks and locally supplied floor comparisons never establish an
independent latest checkpoint, external custody or global anti-rollback.
"""
import argparse
import json
from pathlib import Path
from persistent_anti_mirror_rust095 import validate, compare
from cross_run_acquisition_ledger_rust091 import digest, require
from rotation_rust022 import canonical, verify_key_and_signature

DOMAIN = "NEUROSCAPE_RUST096_QUARANTINE_HIGHWATER_V1"
HOLD = "HOLD_QUARANTINE_HIGHWATER_INDEPENDENCE_UNVERIFIED"

def sha(value):
    require(isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value),
            "invalid SHA-256")
    return value

def checkpoint(history, signer_pin, nonce):
    head = validate(history)
    require(history, "nonempty RUST-095 quarantine required")
    sha(signer_pin)
    sha(nonce)
    conflicts = [{"index":e["index"],
                  "within_epoch":e["within_epoch_reasons"],
                  "cross_epoch":e["cross_epoch_reasons"]}
                 for e in history]
    return {"domain":DOMAIN, "phase":"RUST-096",
            "event_count":len(history), "head_sha256":head,
            "history_sha256":digest(history),
            "quarantine_conflicts_sha256":digest(conflicts),
            "signer_pin":signer_pin, "nonce_sha256":nonce,
            "quarantine_cleared":False,
            "independent_external_custody_verified":False,
            "release_authorized":False, "recovery_authorized":False}

def verify_signed(history, signed, verifier):
    require(isinstance(signed, dict), "signed highwater record required")
    pin = sha(signed.get("signer_pin"))
    nonce = sha(signed.get("nonce_sha256"))
    expected = checkpoint(history, pin, nonce)
    require(signed.get("payload") == expected, "signed highwater payload substituted")
    signature_digest = verifier(signed.get("public_key"), signed.get("signature"),
                                pin, canonical(expected))
    sha(signature_digest)
    return expected, signature_digest

def audit(previous, current, prior_signed, current_signed,
          verifier=verify_key_and_signature):
    old = validate(previous)
    new = validate(current)
    require(previous and len(current) > len(previous)
            and current[:len(previous)] == previous,
            "stale highwater or rewritten quarantine prefix")
    prior, prior_sig = verify_signed(previous, prior_signed, verifier)
    later, later_sig = verify_signed(current, current_signed, verifier)
    require(prior["head_sha256"] == old and later["head_sha256"] == new,
            "quarantine highwater mismatch")
    require(prior["event_count"] < later["event_count"],
            "quarantine highwater not monotone")
    require(prior["nonce_sha256"] != later["nonce_sha256"],
            "replayed checkpoint nonce")
    require(prior["signer_pin"] != later["signer_pin"],
            "same checkpoint signer controls both epochs")
    # A submitted successor must extend the exact signed predecessor head.
    require(current[len(previous)]["previous_sha256"] == prior["head_sha256"],
            "first successor does not extend signed predecessor")
    retention = compare(previous, current)
    return {"phase":"RUST-096", "status":HOLD,
            "previous_signed_highwater_sha256":digest(prior),
            "current_signed_highwater_sha256":digest(later),
            "previous_signature_receipt_sha256":prior_sig,
            "current_signature_receipt_sha256":later_sig,
            "previous_head_sha256":old, "current_head_sha256":new,
            "retained_conflicts_sha256":digest(retention["quarantine_conflicts_retained"]),
            "historic_quarantine_retained":True,
            "locally_checked_monotone_signatures":True,
            "global_latest_floor_authenticated":False,
            "independent_external_custody_verified":False,
            "quarantine_cleared":False, "recovery_authorized":False,
            "release_authorized":False, "live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-096",
            "status":"HOLD_MISSING_SIGNED_QUARANTINE_HIGHWATER",
            "global_latest_floor_authenticated":False,
            "independent_external_custody_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","prior-signed","current-signed"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    values=(a.previous,a.current,a.prior_signed,a.current_signed)
    require(all(values) or not any(values), "partial highwater bundle refused")
    if all(values):
        load=lambda name:json.loads(Path(name).read_text(encoding="utf-8"))
        result=audit(load(a.previous),load(a.current),
                     load(a.prior_signed),load(a.current_signed))
    else:
        result=missing()
    path=Path(a.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-096 HOLD: no globally authenticated highwater")
if __name__=="__main__":
    main()
