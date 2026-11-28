#!/usr/bin/env python3
"""RUST-098 — append-only highwater custody continuity and fork observation.

Observes RUST-097 HOLD receipts. Tracks competing highwater heads and reused
claimed control ancestry without selecting winners or releasing quarantine.
Locally submitted receipts cannot prove independent external custody or a
globally current highwater.
"""
import argparse
import json
from pathlib import Path
from cross_run_acquisition_ledger_rust091 import digest, require

DOMAIN = "NEUROSCAPE_RUST098_CUSTODY_CONTINUITY_V1"
HOLD = "HOLD_CUSTODY_CONTINUITY_AND_FORKS"
ZERO = "0" * 64
FIELDS = ("controller", "root", "source", "acquisition")
PRIOR = "HOLD_EXTERNAL_HIGHWATER_CUSTODY_UNVERIFIED"

def sha(v):
    require(isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdef" for c in v),
            "valid lowercase SHA-256 required")
    return v

def observe(receipt, source_claims):
    require(isinstance(receipt, dict) and receipt.get("phase") == "RUST-097"
            and receipt.get("status") == PRIOR,
            "RUST-097 HOLD receipt required")
    head = sha(receipt.get("highwater_head_sha256"))
    sha(receipt.get("rust096_receipt_sha256"))
    require(receipt.get("independent_external_custody_verified") is False
            and receipt.get("global_anti_rollback_verified") is False
            and receipt.get("release_authorized") is False,
            "upstream authority promotion")
    stored = receipt.get("witness_receipts")
    require(isinstance(stored, list) and len(stored) == 2,
            "two RUST-097 witness receipts required")
    require(isinstance(source_claims, list) and len(source_claims) == 2,
            "two ancestry claim records required")
    seen_pins, seen_nonces, seen_ancestry = set(), set(), set()
    checked = []
    for r, claim in zip(stored, source_claims):
        require(isinstance(r, dict) and isinstance(claim, dict),
                "incomplete receipt or ancestry")
        pin, nonce = sha(r.get("signer_pin")), sha(r.get("nonce_sha256"))
        sha(r.get("evidence_sha256"))
        sha(r.get("signature_receipt_sha256"))
        require(pin not in seen_pins and nonce not in seen_nonces,
                "same-epoch signer or nonce replay")
        seen_pins.add(pin)
        seen_nonces.add(nonce)
        require(claim.get("signer_pin") == pin, "ancestry signer substitution")
        roots = claim.get("control_ancestry")
        require(isinstance(roots, dict) and set(roots) == set(FIELDS),
                "four ancestry fingerprints required")
        for k in FIELDS:
            value = sha(roots[k])
            require(value not in seen_ancestry, "same-epoch shared ancestry")
            seen_ancestry.add(value)
        require(digest(roots) == sha(r.get("control_ancestry_sha256")),
                "ancestry not bound to RUST-097 receipt")
        checked.append({"signer_pin": pin, "nonce_sha256": nonce,
                        "evidence_sha256": r["evidence_sha256"],
                        "control_ancestry": {k: roots[k] for k in FIELDS}})
    return {"rust097_sha256": digest(receipt),
            "highwater_head_sha256": head,
            "rust096_receipt_sha256": receipt["rust096_receipt_sha256"],
            "witnesses": checked}

def conflicts(previous, observation):
    reasons = set()
    for entry in previous:
        old = entry["observation"]
        if old["rust096_receipt_sha256"] == observation["rust096_receipt_sha256"]:
            if old["highwater_head_sha256"] != observation["highwater_head_sha256"]:
                reasons.add("CONFLICTING_HEAD_FOR_HIGHWATER_RECEIPT")
            else:
                reasons.add("REPEATED_HIGHWATER_RECEIPT")
        if old["highwater_head_sha256"] == observation["highwater_head_sha256"]:
            reasons.add("REPEATED_HIGHWATER_HEAD")
        for a in old["witnesses"]:
            for b in observation["witnesses"]:
                if a["signer_pin"] == b["signer_pin"]:
                    reasons.add("REAPPEARING_SIGNER")
                if a["nonce_sha256"] == b["nonce_sha256"]:
                    reasons.add("REPLAYED_WITNESS_NONCE")
                if a["evidence_sha256"] == b["evidence_sha256"]:
                    reasons.add("REUSED_HIGHWATER_BYTES")
                for k in FIELDS:
                    if a["control_ancestry"][k] == b["control_ancestry"][k]:
                        reasons.add("REUSED_" + k.upper() + "_ANCESTRY")
    return sorted(reasons)

def validate(history):
    require(isinstance(history, list), "ledger must be a list")
    head = ZERO
    for i, entry in enumerate(history):
        require(isinstance(entry, dict), "ledger entry required")
        core = {k:v for k,v in entry.items() if k != "entry_sha256"}
        require(entry.get("entry_sha256") == digest(core),
                "entry hash mismatch")
        require(core.get("domain") == DOMAIN and core.get("index") == i
                and core.get("previous_sha256") == head,
                "ledger predecessor or index rewritten")
        observation = core.get("observation")
        require(isinstance(observation, dict)
                and set(observation) == {"rust097_sha256",
                    "highwater_head_sha256", "rust096_receipt_sha256", "witnesses"},
                "invalid observation")
        for k in ("rust097_sha256", "highwater_head_sha256",
                  "rust096_receipt_sha256"):
            sha(observation[k])
        witnesses = observation["witnesses"]
        require(isinstance(witnesses, list) and len(witnesses) == 2,
                "two witness fingerprints required")
        for w in witnesses:
            require(isinstance(w, dict), "witness fingerprint missing")
            for k in ("signer_pin", "nonce_sha256", "evidence_sha256"):
                sha(w.get(k))
            lineage = w.get("control_ancestry")
            require(isinstance(lineage, dict) and set(lineage) == set(FIELDS),
                    "historical ancestry incomplete")
            for k in FIELDS: sha(lineage[k])
        require(core.get("conflicts") == conflicts(history[:i], observation),
                "historic fork or ancestry conflict erased")
        require(core.get("quarantine_retained") is True
                and core.get("independent_external_custody_verified") is False
                and core.get("release_authorized") is False,
                "illegal quarantine clearance")
        head = entry["entry_sha256"]
    return head

def append(history, receipt, source_claims):
    head = validate(history)
    observation = observe(receipt, source_claims)
    core = {"domain": DOMAIN, "index": len(history),
            "previous_sha256": head, "observation": observation,
            "conflicts": conflicts(history, observation),
            "quarantine_retained": True,
            "independent_external_custody_verified": False,
            "release_authorized": False}
    output = history + [{**core, "entry_sha256": digest(core)}]
    validate(output)
    return output

def audit(previous, current):
    old, new = validate(previous), validate(current)
    require(len(current) > len(previous)
            and current[:len(previous)] == previous,
            "rollback or rewritten custody history")
    return {"phase": "RUST-098", "status": HOLD,
            "previous_head_sha256": old, "current_head_sha256": new,
            "entry_count": len(current),
            "retained_conflicts": [
                {"index": e["index"], "reasons": e["conflicts"]}
                for e in current if e["conflicts"]],
            "global_latest_floor_authenticated": False,
            "independent_external_custody_verified": False,
            "fork_selected": False, "recovery_authorized": False,
            "release_authorized": False, "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-098",
            "status": "HOLD_MISSING_CUSTODY_CONTINUITY_LEDGER",
            "independent_external_custody_verified": False,
            "fork_selected": False, "recovery_authorized": False,
            "release_authorized": False, "live_gameplay_authorized": False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--previous"); p.add_argument("--current")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args=p.parse_args()
    require(bool(args.previous) == bool(args.current), "partial ledger bundle")
    if args.previous:
        read=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(read(args.previous), read(args.current))
    else:
        result=missing()
    target=Path(args.output); target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2); f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-098 HOLD: custody and global anti-rollback unverified")
if __name__ == "__main__":
    main()
