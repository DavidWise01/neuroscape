#!/usr/bin/env python3
"""RUST-104: two-operator response-byte custody fence.

Compare two separately supplied RUST-103 retrieval reports and their exact ZIP
bytes against the immutable RUST-100 source manifest. Submitted operators,
network infrastructure and acquisition ancestry are *claims*, not authenticated
third-party custody. GitHub API and codeload count as one source ancestry.
All outcomes retain HOLD; no release, recovery or fork arbitration is allowed.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from century_archive_replay_rust101 import archive_fingerprints, validate_manifest
from century_source_freeze_rust100 import canonical
from http_archive_acquisition_rust103 import (
    ALLOWED_HOSTS, HOLD as UPSTREAM_HOLD, permitted)

DOMAIN = "NEUROSCAPE_RUST104_DUAL_RESPONSE_CUSTODY_V1"
HOLD = "HOLD_DUAL_RESPONSE_EXTERNAL_CUSTODY_UNVERIFIED"
FIELDS = ("controller", "operator", "root", "network", "acquisition")
SOURCE_ANCESTRY = "github.com/api.github.com/codeload.github.com"

def require(condition, why):
    if not condition:
        raise ValueError(why)

def sha(value):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value),
            "lowercase SHA-256 required")
    return value

def digest(item):
    return hashlib.sha256(canonical(item)).hexdigest()

def inspect_one(manifest, entries, report, data, claim):
    require(isinstance(report, dict)
            and report.get("phase") == "RUST-103"
            and report.get("domain") == "NEUROSCAPE_RUST103_HTTP_ACQUISITION_V1"
            and report.get("status") == UPSTREAM_HOLD,
            "RUST-103 observed acquisition receipt required")
    require(report.get("century_checkpoint_sha256")
            == manifest["checkpoint_sha256"], "frozen manifest substitution")
    require(report.get("response_observed_by_this_process") is True
            and report.get("archive_bytes_locally_verified") is True,
            "receipt must report observed and locally checked bytes")
    require(report.get("independent_external_custody_verified") is False
            and report.get("global_anti_rollback_verified") is False
            and report.get("release_authorized") is False,
            "unearned upstream authority")
    permitted(report.get("source_url"))
    permitted(report.get("final_url"))
    require(report.get("source_ancestry") == SOURCE_ANCESTRY,
            "GitHub ancestry must not be renamed independent")
    require(type(report.get("http_status")) is int
            and report["http_status"] == 200, "failed acquisition")
    fingerprints = archive_fingerprints(data, entries)
    require(report.get("archive_sha256") == fingerprints["archive_sha256"]
            and report.get("archive_byte_length") == len(data)
            and report.get("frozen_source_sha256")
                == fingerprints["source_sha256"],
            "HTTP receipt differs from exact replayed archive bytes")
    require(isinstance(claim, dict), "operator claim required")
    require(claim.get("source_receipt_sha256") == digest(report),
            "claimed source receipt not bound to observed record")
    operator_id = sha(claim.get("operator_pin"))
    nonce = sha(claim.get("acquisition_nonce_sha256"))
    ancestry = claim.get("ancestry")
    require(isinstance(ancestry, dict)
            and set(ancestry) == set(FIELDS),
            "complete operator / infrastructure ancestry required")
    for field in FIELDS:
        sha(ancestry[field])
    require(claim.get("independent_custody_verified") is False
            and claim.get("release_authorized") is False
            and claim.get("fork_selected") is False,
            "false custody or fork authority")
    return {
        "operator_pin": operator_id,
        "acquisition_nonce_sha256": nonce,
        "claimed_control_ancestry": {k: ancestry[k] for k in FIELDS},
        "report_sha256": digest(report),
        "archive_sha256": fingerprints["archive_sha256"],
        "archive_length": len(data),
        "frozen_source_sha256": fingerprints["source_sha256"],
        "observed_final_host": urlsplit(report["final_url"]).hostname,
    }

def assess(manifest, reports, archives, claims):
    entries = validate_manifest(manifest)
    require(all(isinstance(values, list) and len(values) == 2
                for values in (reports, archives, claims)),
            "exactly two report, byte and operator-claim triples required")
    rows = [inspect_one(manifest, entries, r, b, c)
            for r, b, c in zip(reports, archives, claims)]
    reasons = set()
    if rows[0]["operator_pin"] == rows[1]["operator_pin"]:
        reasons.add("REUSED_OPERATOR_PIN")
    if rows[0]["acquisition_nonce_sha256"]
            == rows[1]["acquisition_nonce_sha256"]:
        reasons.add("REUSED_ACQUISITION_NONCE")
    if rows[0]["report_sha256"] == rows[1]["report_sha256"]:
        reasons.add("REUSED_HTTP_RECEIPT")
    if rows[0]["archive_sha256"] == rows[1]["archive_sha256"]:
        reasons.add("IDENTICAL_ARCHIVE_BYTES")
    for field in FIELDS:
        if rows[0]["claimed_control_ancestry"][field] == (
                rows[1]["claimed_control_ancestry"][field]):
            reasons.add("SHARED_" + field.upper() + "_ANCESTRY")
    if rows[0]["observed_final_host"] == rows[1]["observed_final_host"]:
        reasons.add("SAME_GITHUB_DOWNLOAD_HOST")
    # Even distinct API/codeload hosts resolve to the same upstream source.
    reasons.add("SHARED_GITHUB_SOURCE_ANCESTRY")
    require(rows[0]["frozen_source_sha256"] == rows[1]["frozen_source_sha256"],
            "frozen source parity diverged")
    return {
        "phase": "RUST-104", "domain": DOMAIN, "status": HOLD,
        "century_checkpoint_sha256": manifest["checkpoint_sha256"],
        "source_bytes_parity": True,
        "retrieval_receipts": [
            {k: v for k, v in row.items()
             if k != "claimed_control_ancestry"}
            for row in rows],
        "claimed_operator_ancestry_sha256": [
            digest(row["claimed_control_ancestry"]) for row in rows],
        "correlation_reasons": sorted(reasons),
        "observed_independent_source_ancestries": 1,
        "independent_operator_control_authenticated": False,
        "independent_external_custody_verified": False,
        "global_anti_rollback_verified": False,
        "fork_selected": False, "recovery_authorized": False,
        "release_authorized": False, "live_gameplay_authorized": False,
    }

def missing():
    return {"phase": "RUST-104",
            "status": "HOLD_MISSING_DUAL_HTTP_RESPONSE_CUSTODY",
            "independent_operator_control_authenticated": False,
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("manifest", "report-a", "report-b", "archive-a",
                 "archive-b", "operator-claims"):
        p.add_argument("--" + name)
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    sources = (a.manifest, a.report_a, a.report_b,
               a.archive_a, a.archive_b, a.operator_claims)
    require(all(sources) or not any(sources),
            "partial operator custody bundle refused")
    if all(sources):
        read_json = lambda value: json.loads(
            Path(value).read_text(encoding="utf-8"))
        result = assess(read_json(a.manifest),
                        [read_json(a.report_a), read_json(a.report_b)],
                        [Path(a.archive_a).read_bytes(),
                         Path(a.archive_b).read_bytes()],
                        read_json(a.operator_claims))
    else:
        result = missing()
    target = Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-104 HOLD: independent external custody unverified")

if __name__ == "__main__":
    main()
