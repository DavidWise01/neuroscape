#!/usr/bin/env python3
"""RUST-090: bounded GitHub Actions artifact acquisition, not custody authority.

Read-only evidence fetch. Github HTTPS metadata plus exact ZIP bytes can
corroborate an observation, but neither proves independent external custody
nor permits recovery/release. No artifacts are extracted or executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

API = "https://api.github.com"
REPO = "DavidWise01/neuroscape"
MAX_BYTES = 25 * 1024 * 1024
HOLD = "HOLD_EXTERNAL_INDEPENDENT_CUSTODY_UNVERIFIED"
MISSING = "HOLD_MISSING_AUTHENTICATED_RUN_ARTIFACT"

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(blob):
    return hashlib.sha256(blob).hexdigest()

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def fetch(url, token, limit=MAX_BYTES):
    require(url.startswith(API + "/repos/" + REPO + "/actions/"),
            "only the exact repository GitHub Actions API is allowed")
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "neuroscape-rust090-readonly"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urlopen(Request(url, headers=headers), timeout=25) as response:
        data = response.read(limit + 1)
        require(len(data) <= limit, "remote body exceeds acquisition cap")
        return data

def acquire(run_id, artifact_id, token=None, fetcher=fetch):
    require(type(run_id) is int and run_id > 0
            and type(artifact_id) is int and artifact_id > 0,
            "positive run and artifact IDs required")
    base = API + "/repos/" + REPO + "/actions/"
    run_bytes = fetcher(base + "runs/" + str(run_id), token, 1024 * 1024)
    artifact_bytes = fetcher(base + "artifacts/" + str(artifact_id), token, 1024 * 1024)
    run = json.loads(run_bytes)
    artifact = json.loads(artifact_bytes)
    require(run.get("id") == run_id, "run ID mismatch")
    require(run.get("repository", {}).get("full_name") == REPO, "repository mismatch")
    require(run.get("event") in ("push", "workflow_dispatch"),
            "unexpected workflow event")
    require(run.get("head_sha") and len(run["head_sha"]) == 40,
            "missing run commit SHA")
    require(artifact.get("id") == artifact_id, "artifact ID mismatch")
    require(artifact.get("workflow_run", {}).get("id") == run_id,
            "artifact belongs to another run")
    require(artifact.get("expired") is False, "artifact expired")
    require(artifact.get("size_in_bytes", 0) > 0, "empty artifact declared")
    require(artifact["size_in_bytes"] <= MAX_BYTES, "declared archive exceeds cap")
    zip_bytes = fetcher(base + "artifacts/" + str(artifact_id) + "/zip", token, MAX_BYTES)
    require(len(zip_bytes) > 0 and zip_bytes.startswith(bytes((0x50,0x4b,0x03,0x04))),
            "not a ZIP archive")
    # GitHub artifact API returns archive size as metadata; compare if available.
    require(len(zip_bytes) == artifact["size_in_bytes"],
            "artifact archive byte length contradicts metadata")
    return {
        "phase": "RUST-090", "status": HOLD,
        "repository": REPO,
        "run_id": run_id, "artifact_id": artifact_id,
        "run_commit_sha": run["head_sha"],
        "run_event": run["event"],
        "run_conclusion": run.get("conclusion"),
        "run_metadata_sha256": sha(run_bytes),
        "artifact_metadata_sha256": sha(artifact_bytes),
        "archive_sha256": sha(zip_bytes), "archive_length": len(zip_bytes),
        "bytes_acquired_via_github_api": True,
        "independent_external_custody_verified": False,
        "global_anti_rollback_verified": False,
        "recovery_authorized": False, "release_authorized": False,
        "live_gameplay_authorized": False,
    }, zip_bytes

def hold(reason=MISSING):
    return {"phase": "RUST-090", "status": reason,
            "bytes_acquired_via_github_api": False,
            "independent_external_custody_verified": False,
            "global_anti_rollback_verified": False,
            "recovery_authorized": False,
            "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", type=int)
    p.add_argument("--artifact-id", type=int)
    p.add_argument("--output", required=True)
    p.add_argument("--archive-output")
    p.add_argument("--allow-hold-record", action="store_true")
    a = p.parse_args()
    require((a.run_id is None) == (a.artifact_id is None),
            "run and artifact must be supplied together")
    if a.run_id is None:
        result = hold()
    else:
        result, blob = acquire(a.run_id, a.artifact_id, os.environ.get("GITHUB_TOKEN"))
        require(a.archive_output, "archive output path required to retain exact ZIP")
        archive_path = Path(a.archive_output)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with archive_path.open("xb") as f:
            f.write(blob)
    dest = Path(a.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-090 HOLD: independent custody never authorized")

if __name__ == "__main__":
    main()
