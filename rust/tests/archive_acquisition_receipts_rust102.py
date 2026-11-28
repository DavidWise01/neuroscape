#!/usr/bin/env python3
"""RUST-102 — acquisition provenance receipts for two RUST-101 ZIP snapshots.

Read-only verification of caller-supplied archive bytes and acquisition
metadata. Reported origins are NOT authenticated independent custodians.
No network requests are made and no release authority is granted.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from century_archive_replay_rust101 import verify as replay, HOLD as PRIOR_HOLD
from century_source_freeze_rust100 import canonical

DOMAIN = "NEUROSCAPE_RUST102_ACQUISITION_RECEIPTS_V1"
HOLD = "HOLD_INDEPENDENT_ARCHIVE_ACQUISITION_UNVERIFIED"
ANCESTRY = ("controller", "root", "source", "acquisition")

def require(ok, why):
    if not ok:
        raise ValueError(why)

def sha(v):
    require(isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdef" for c in v),
            "invalid lowercase SHA-256")
    return v

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def origin(value):
    require(isinstance(value, str) and len(value) < 2048,
            "source URL invalid")
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname
            and not parsed.username and not parsed.password
            and not parsed.fragment, "non-HTTPS or ambiguous origin")
    return parsed.hostname.lower()

def verify_receipts(manifest, archives, receipts):
    require(isinstance(receipts, list) and len(receipts) == 2,
            "exactly two acquisition receipts required")
    claims = []
    for receipt in receipts:
        require(isinstance(receipt, dict)
                and receipt.get("phase") == "RUST-102"
                and receipt.get("domain") == DOMAIN,
                "invalid receipt domain")
        require(receipt.get("method") == "GET"
                and type(receipt.get("http_status")) is int
                and receipt["http_status"] == 200,
                "successful GET evidence required")
        require(receipt.get("content_type") in (
            "application/zip", "application/octet-stream"),
            "unexpected response media type")
        require(type(receipt.get("content_length")) is int
                and receipt["content_length"] > 0,
                "content-length evidence required")
        require(isinstance(receipt.get("retrieval_id"), str)
                and 0 < len(receipt["retrieval_id"]) <= 128,
                "retrieval identity required")
        host = origin(receipt.get("source_url"))
        claim = receipt.get("ancestry")
        require(isinstance(claim, dict)
                and set(claim) == set(ANCESTRY),
                "complete provenance ancestry required")
        for k in ANCESTRY: sha(claim[k])
        require(receipt.get("independent_custody_verified") is False
                and receipt.get("release_authorized") is False,
                "unearned authority promotion")
        claims.append({"archive_sha256": sha(receipt.get("archive_sha256")),
                       "ancestry": claim})
    baseline = replay(manifest, archives, claims)
    require(baseline["status"] == PRIOR_HOLD,
            "RUST-101 parity must remain HOLD")
    ancestry_conflicts = set(baseline["provenance_conflicts"])
    origins = [origin(r["source_url"]) for r in receipts]
    if origins[0] == origins[1]:
        ancestry_conflicts.add("SAME_DECLARED_ORIGIN_HOST")
    if receipts[0]["retrieval_id"] == receipts[1]["retrieval_id"]:
        ancestry_conflicts.add("REUSED_RETRIEVAL_ID")
    if receipts[0]["archive_sha256"] == receipts[1]["archive_sha256"]:
        ancestry_conflicts.add("REPEATED_ARCHIVE_DIGEST")
    for i, receipt in enumerate(receipts):
        require(receipt["content_length"] == len(archives[i]),
                "retrieval length not equal to original bytes")
        if receipt.get("response_sha256") is not None:
            require(sha(receipt["response_sha256"]) == sha(receipt["archive_sha256"]),
                    "response digest contradicts original archive")
    rows = [{"receipt_sha256": digest(r),
             "source_host_claim": origins[i],
             "retrieval_id": r["retrieval_id"],
             "archive_sha256": r["archive_sha256"],
             "archive_length": len(archives[i])}
            for i, r in enumerate(receipts)]
    return {"phase": "RUST-102", "domain": DOMAIN, "status": HOLD,
            "rust101_replay_sha256": digest(baseline),
            "acquisition_receipts": rows,
            "provenance_conflicts": sorted(ancestry_conflicts),
            "snapshot_byte_parity": True,
            "source_urls_independently_authenticated": False,
            "external_custody_independence_verified": False,
            "global_anti_rollback_verified": False,
            "fork_selected": False, "recovery_authorized": False,
            "release_authorized": False, "live_gameplay_authorized": False}

def missing():
    return {"phase": "RUST-102",
            "status": "HOLD_MISSING_EXTERNAL_ARCHIVE_ACQUISITION_RECEIPTS",
            "external_custody_independence_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("manifest", "archive-a", "archive-b", "receipts"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    sources = (a.manifest, a.archive_a, a.archive_b, a.receipts)
    require(all(sources) or not any(sources), "partial external acquisition bundle")
    if all(sources):
        load = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
        result = verify_receipts(load(a.manifest),
            [Path(a.archive_a).read_bytes(), Path(a.archive_b).read_bytes()],
            load(a.receipts))
    else:
        result = missing()
    target = Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-102 HOLD: independent acquisition unverified")

if __name__ == "__main__":
    main()
