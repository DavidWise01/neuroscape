#!/usr/bin/env python3
"""RUST-095 — append-only anti-mirror quarantine and exact historical replay.

Supplied evidence is not an authenticated third-party custody source.
All accepted records retain HOLD; no recovery, release or gameplay authority.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from cross_run_acquisition_ledger_rust091 import digest, require
from anti_mirror_custody_rust094 import (
    analyze, canonical_evidence, decode, byte_hash, FIELDS)

DOMAIN = "NEUROSCAPE_RUST095_QUARANTINE_REPLAY_V1"
HOLD = "HOLD_PERSISTENT_ANTI_MIRROR_CUSTODY_UNVERIFIED"
ZERO = "0" * 64

def hexsha(value):
    require(isinstance(value, str) and len(value) == 64
            and all(x in "0123456789abcdef" for x in value),
            "malformed SHA-256")
    return value

def witness_fingerprints(rows):
    out = []
    for row in rows:
        data = decode(row)
        lineage = row["control_ancestry"]
        require(isinstance(lineage, dict) and set(lineage) == set(FIELDS),
                "incomplete lineage")
        for field in FIELDS:
            hexsha(lineage[field])
        out.append({"signer_pin": hexsha(row["signer_pin"]),
                    "raw_sha256": byte_hash(data),
                    "semantic_json_sha256": canonical_evidence(data),
                    "lineage": {k: lineage[k] for k in FIELDS},
                    "declared_custodian": row.get("acquisition_custodian_id")})
    return out

def new_conflicts(history, fingerprints):
    reasons = set()
    old = [f for entry in history for f in entry["fingerprints"]]
    for new in fingerprints:
        for past in old:
            if new["signer_pin"] == past["signer_pin"]:
                reasons.add("REINTRODUCED_SIGNER")
            if new["raw_sha256"] == past["raw_sha256"]:
                reasons.add("REINTRODUCED_IDENTICAL_BYTES")
            if new["semantic_json_sha256"] is not None and (
                    new["semantic_json_sha256"] == past["semantic_json_sha256"]):
                reasons.add("REINTRODUCED_REPACKAGED_JSON")
            for field in FIELDS:
                if new["lineage"][field] == past["lineage"][field]:
                    reasons.add("REINTRODUCED_" + field.upper() + "_ANCESTRY")
            if (new["declared_custodian"] is not None
                    and new["declared_custodian"] == past["declared_custodian"]):
                reasons.add("REINTRODUCED_DECLARED_CUSTODIAN")
    return sorted(reasons)

def validate(history):
    require(isinstance(history, list), "history must be array")
    head = ZERO
    checked = []
    for i, entry in enumerate(history):
        require(isinstance(entry, dict), "entry not a mapping")
        assert_digest = hexsha(entry.get("entry_sha256"))
        core = {k:v for k,v in entry.items() if k != "entry_sha256"}
        require(assert_digest == digest(core),
                "historical entry digest rewritten")
        require(core.get("domain") == DOMAIN and core.get("index") == i
                and core.get("previous_sha256") == head,
                "predecessor or ordering rewritten")
        fingerprints = core.get("fingerprints")
        require(isinstance(fingerprints, list) and len(fingerprints) == 2,
                "every epoch must retain exactly two witnesses")
        for f in fingerprints:
            require(isinstance(f, dict), "fingerprint missing")
            hexsha(f.get("signer_pin"))
            hexsha(f.get("raw_sha256"))
            semantic = f.get("semantic_json_sha256")
            if semantic is not None:
                hexsha(semantic)
            lineage = f.get("lineage")
            require(isinstance(lineage, dict)
                    and set(lineage) == set(FIELDS), "invalid ancestry")
            for k in FIELDS: hexsha(lineage[k])
        require(core.get("cross_epoch_reasons")
                == new_conflicts(checked, fingerprints),
                "quarantined historical conflicts cleared")
        require(isinstance(core.get("within_epoch_reasons"), list)
                and core["within_epoch_reasons"] == sorted(set(core["within_epoch_reasons"])),
                "within-epoch contradictions malformed")
        require(core.get("independent_external_custody_verified") is False
                and core.get("release_authorized") is False
                and core.get("recovery_authorized") is False,
                "prohibited authority promotion")
        require(isinstance(core.get("source_rust094_sha256"), str),
                "anti-mirror ancestry missing")
        hexsha(core["source_rust094_sha256"])
        head = assert_digest
        checked.append(entry)
    return head

def append(history, reconciliation, witnesses):
    head = validate(history)
    report = analyze(reconciliation, witnesses)
    fps = witness_fingerprints(witnesses)
    within = sorted(set(
        reason for row in report["quarantine_log"] for reason in row["reasons"]))
    prior_reasons = new_conflicts(history, fps)
    record = {"domain": DOMAIN, "index": len(history),
              "previous_sha256": head, "source_rust094_sha256": digest(report),
              "fingerprints": fps, "within_epoch_reasons": within,
              "cross_epoch_reasons": prior_reasons,
              "independent_external_custody_verified": False,
              "recovery_authorized": False, "release_authorized": False}
    result = history + [{**record, "entry_sha256": digest(record)}]
    validate(result)
    return result

def compare(previous, current):
    old_head = validate(previous)
    new_head = validate(current)
    require(len(current) > len(previous)
            and current[:len(previous)] == previous,
            "historical quarantine prefix removed or rewritten")
    return {"phase":"RUST-095", "status": HOLD,
            "previous_head_sha256":old_head, "head_sha256":new_head,
            "epoch_count":len(current),
            "quarantine_conflicts_retained": [
                {"index":e["index"],
                 "within_epoch":e["within_epoch_reasons"],
                 "cross_epoch":e["cross_epoch_reasons"]}
                for e in current if e["within_epoch_reasons"] or e["cross_epoch_reasons"]],
            "independent_external_custody_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-095",
            "status":"HOLD_MISSING_PERSISTENT_ANTI_MIRROR_QUARANTINE",
            "independent_external_custody_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--previous")
    p.add_argument("--current")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.previous) == bool(a.current), "partial ledger bundle refused")
    if a.previous:
        previous=json.loads(Path(a.previous).read_text(encoding="utf-8"))
        current=json.loads(Path(a.current).read_text(encoding="utf-8"))
        result=compare(previous,current)
    else:
        result=missing()
    output=Path(a.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,sort_keys=True)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-095 HOLD: no independent custody authority")
if __name__=="__main__":
    main()
