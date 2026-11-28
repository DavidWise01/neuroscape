#!/usr/bin/env python3
"""RUST-100 — deterministic source freeze over RUST-086..099.

This is a *source* checkpoint, not a claim that historical executions,
independent witness custody, or GitHub Pages deployments are verified.
Pin against the RUST-099 final commit; never approve rollback or release.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

BASELINE = "80313da6a699b41922b72ea7abcb81e96c88cd7e"
DOMAIN = "NEUROSCAPE_RUST100_CENTURY_SOURCE_FREEZE_V1"
HOLD = "HOLD_CENTURY_EXTERNAL_CUSTODY_UNVERIFIED"
MODULES = {
  86:"custodian_quarantine_highwater",
  87:"custody_challenge_fence",
  88:"test_custody_challenge_replay",
  89:"cross_run_custody_evidence",
  90:"github_artifact_acquisition",
  91:"cross_run_acquisition_ledger",
  92:"contradiction_witness",
  93:"witness_byte_replay",
  94:"anti_mirror_custody",
  95:"persistent_anti_mirror",
  96:"quarantine_highwater",
  97:"external_highwater_witness",
  98:"highwater_custody_continuity",
  99:"fork_preservation",
}
PROTECTED = ("index.html", "rust/neuroscape-core/Cargo.toml",
             "assets/neuroscape-rust-wasm.generated.js")
PHASE_PATHS = tuple(
    "rust/tests/" + name + "_rust" + str(num).zfill(3) + ".py"
    for num,name in MODULES.items())
ALL_PATHS = PHASE_PATHS + PROTECTED

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(blob):
    return hashlib.sha256(blob).hexdigest()

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def git_baseline(repo, path):
    require(path in ALL_PATHS, "unlisted source path")
    return subprocess.check_output(
        ["git", "-C", str(repo), "show", BASELINE + ":" + path],
        stderr=subprocess.DEVNULL)

def freeze(repo, baseline_loader=git_baseline):
    repo = Path(repo)
    require(repo.is_dir(), "repository directory unavailable")
    entries = []
    for path in ALL_PATHS:
        observed = (repo / path).read_bytes()
        historical = baseline_loader(repo, path)
        require(isinstance(historical, bytes), "baseline must provide bytes")
        require(observed == historical,
                "frozen historical source changed: " + path)
        entries.append({"path":path, "sha256":sha(observed),
                        "length":len(observed)})
    require(len(entries) == len(ALL_PATHS)
            and len({r["path"] for r in entries}) == len(entries),
            "source freeze inventory incomplete")
    body = {"phase":"RUST-100", "domain":DOMAIN, "baseline_commit":BASELINE,
            "phase_range":"RUST-086..RUST-099",
            "source_entries":entries,
            "source_entry_count":len(entries),
            "source_manifest_sha256":sha(canonical(entries)),
            "fork_branches_preserved_in_source":True,
            "historical_execution_verified":False,
            "hosted_ci_verified":False,
            "independent_external_custody_verified":False,
            "global_anti_rollback_verified":False,
            "fork_selected":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}
    return {**body, "checkpoint_sha256":sha(canonical(body)),
            "status":HOLD}

def missing():
    return {"phase":"RUST-100",
            "status":"HOLD_MISSING_CENTURY_SOURCE_CHECKPOINT",
            "historical_execution_verified":False,
            "independent_external_custody_verified":False,
            "recovery_authorized":False, "release_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--repo", default=".")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-hold-record", action="store_true")
    p.add_argument("--verify-source", action="store_true")
    a=p.parse_args()
    result=freeze(a.repo) if a.verify_source else missing()
    dest=Path(a.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps(result, sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-100 HOLD: independently authenticated custody unavailable")

if __name__=="__main__":
    main()
