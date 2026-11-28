#!/usr/bin/env python3
"""RUST-091: append-only cross-run acquisition evidence ledger.

Records supplied RUST-090 receipts and contradictions. No local claim of
control, acquisition or custody is elevated to independent authority.
"""
import hashlib
import json

DOMAIN = "NEUROSCAPE_RUST091_ACQUISITION_LEDGER_V1"
ZERO = "0" * 64
HOLD = "HOLD_CROSS_RUN_ANCESTRY_UNVERIFIED"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()

def sha(value):
    require(isinstance(value, str) and len(value) == 64
        and all(c in "0123456789abcdef" for c in value),
        "64 lowercase SHA-256 hex required")

def validate_observation(o):
    require(isinstance(o, dict) and o.get("phase") == "RUST-090",
        "RUST-090 observation required")
    require(o.get("status") == "HOLD_EXTERNAL_INDEPENDENT_CUSTODY_UNVERIFIED",
        "only HOLD acquisition evidence accepted")
    require(o.get("repository") == "DavidWise01/neuroscape",
        "unexpected repository")
    for k in ("run_id", "artifact_id", "archive_length"):
        require(type(o.get(k)) is int and o[k] > 0, "invalid " + k)
    require(type(o.get("archive_length")) is int
        and o["archive_length"] <= 25*1024*1024,
        "oversized archive")
    for k in ("archive_sha256", "run_metadata_sha256",
              "artifact_metadata_sha256"):
        sha(o.get(k))
    require(isinstance(o.get("run_commit_sha"), str)
        and len(o["run_commit_sha"]) == 40
        and all(c in "0123456789abcdef" for c in o["run_commit_sha"]),
        "invalid commit ancestry")
    require(o.get("bytes_acquired_via_github_api") is True,
        "no bytes acquired")
    for k in ("independent_external_custody_verified",
              "global_anti_rollback_verified", "recovery_authorized",
              "release_authorized", "live_gameplay_authorized"):
        require(o.get(k) is False, "forbidden authority: " + k)

def contradictions(previous, observation):
    found = []
    for entry in previous:
        p = entry["observation"]
        if p["run_id"] == observation["run_id"]:
            found.append("REUSED_RUN")
        if p["artifact_id"] == observation["artifact_id"]:
            found.append("REUSED_ARTIFACT")
        if p["archive_sha256"] == observation["archive_sha256"]:
            found.append("REUSED_ARCHIVE_BYTES")
        if (p["run_metadata_sha256"] == observation["run_metadata_sha256"]
            or p["artifact_metadata_sha256"] == observation["artifact_metadata_sha256"]):
            found.append("REUSED_METADATA_ANCESTRY")
        if (p["run_id"] == observation["run_id"]
            and p["run_commit_sha"] != observation["run_commit_sha"]):
            found.append("CONTRADICTORY_RUN_COMMIT")
    return sorted(set(found))

def verify_ledger(ledger):
    require(isinstance(ledger, list), "ledger must be a list")
    head = ZERO
    for n, entry in enumerate(ledger):
        require(isinstance(entry, dict), "entry must be a mapping")
        obs = entry.get("observation")
        validate_observation(obs)
        reasons = contradictions(ledger[:n], obs)
        expected = {"domain": DOMAIN, "index": n,
                    "previous_sha256": head, "observation": obs,
                    "contradictions": reasons,
                    "independent_external_custody_verified": False,
                    "recovery_authorized": False, "release_authorized": False}
        require(entry == {**expected, "entry_sha256": digest(expected)},
            "historical ledger entry or contradiction rewritten")
        head = entry["entry_sha256"]
    return head

def append(previous, observation):
    head = verify_ledger(previous)
    validate_observation(observation)
    reasons = contradictions(previous, observation)
    record = {"domain": DOMAIN, "index": len(previous),
              "previous_sha256": head, "observation": observation,
              "contradictions": reasons,
              "independent_external_custody_verified": False,
              "recovery_authorized": False, "release_authorized": False}
    result = previous + [{**record, "entry_sha256": digest(record)}]
    verify_ledger(result)
    return result

def audit(previous, current):
    old_head = verify_ledger(previous)
    new_head = verify_ledger(current)
    require(len(current) > len(previous) and current[:len(previous)] == previous,
        "no strict append-only extension")
    return {"phase": "RUST-091", "status": HOLD,
            "previous_head_sha256": old_head, "head_sha256": new_head,
            "entry_count": len(current),
            "contradictions_retained": [
                {"index": e["index"], "reasons": e["contradictions"]}
                for e in current if e["contradictions"]],
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-091", "status": "HOLD_MISSING_ACQUISITION_LEDGER",
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

if __name__ == "__main__":
    import argparse
    from pathlib import Path
    p = argparse.ArgumentParser()
    p.add_argument("--previous")
    p.add_argument("--current")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    args = p.parse_args()
    require(bool(args.previous) == bool(args.current), "partial ledger bundle")
    if args.previous:
        previous = json.loads(Path(args.previous).read_text(encoding="utf-8"))
        current = json.loads(Path(args.current).read_text(encoding="utf-8"))
        output = audit(previous, current)
    else:
        output = missing()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as f:
        json.dump(output, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(output, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-091 HOLD: independent custody unverified")
