#!/usr/bin/env python3
"""RUST-018: three distinct observations, one repository ancestry.
Build, replay, and public readback must agree. This is not third-party custody.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

def fail(message):
    raise ValueError("HOLD: " + message)

def require(condition, message):
    if not condition:
        fail(message)

def load(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    require(isinstance(value, dict), "invalid receipt object")
    return value

def adjudicate(build, replay, public):
    commit = build.get("source_commit")
    wasm = build.get("wasm_sha256")
    replay_hash = replay.get("replay_sha256")
    run = str(build.get("github_run_id", ""))
    require(isinstance(commit, str) and re.fullmatch("[a-f0-9]{40}", commit), "source commit invalid")
    require(isinstance(wasm, str) and re.fullmatch("[a-f0-9]{64}", wasm), "WASM SHA-256 invalid")
    require(isinstance(replay_hash, str) and re.fullmatch("[a-f0-9]{64}", replay_hash), "replay SHA-256 invalid")
    require(run.isdecimal() and int(run)>0, "run ID invalid")
    require(build.get("reproducible_build") is True and build.get("cross_runner_reproducible") is True, "build reproduction missing")
    require(build.get("reproduction_wasm_sha256")==wasm and build.get("cross_runner_wasm_sha256")==wasm, "build fingerprints disagree")
    require(build.get("native_rust_gate")=="passed_in_deployment_job" and build.get("chromium_phase_and_combat_gate")=="passed_in_deployment_job", "build gate not passed")
    require(build.get("replay_sha256")==replay_hash and build.get("replay_steps")==3, "release/replay mismatch")
    require(replay.get("source_commit")==commit and replay.get("replay_steps")==3, "replay source/count mismatch")
    require(public.get("source_commit")==commit and str(public.get("github_run_id"))==run, "public source/run mismatch")
    require(public.get("wasm_sha256")==wasm and public.get("replay_sha256")==replay_hash, "public fingerprint mismatch")
    require(public.get("reproduced_wasm_sha256")==wasm and public.get("cross_runner_sha256")==wasm, "public build reproduction mismatch")
    require(public.get("public_manifest")=="MATCH" and public.get("public_browser_combat")=="PASS", "public verification not passed")
    require(build.get("live_gameplay_authority") is False and public.get("live_gameplay_authority") is False, "unauthorized game authority")
    observations=[
        {"role":"build","observed":"source and WASM bytes","source_commit":commit,"wasm_sha256":wasm},
        {"role":"replay","observed":"copied combat replay","source_commit":commit,"replay_sha256":replay_hash},
        {"role":"public","observed":"Pages manifest and Chromium execution","source_commit":commit,"wasm_sha256":wasm,"replay_sha256":replay_hash},
    ]
    verdict={
        "phase":"RUST-018", "status":"CONSISTENT_OBSERVATIONS",
        "source_commit":commit,"github_run_id":run,"wasm_sha256":wasm,
        "replay_sha256":replay_hash,"observations":observations,
        "unique_observation_classes":3,"independent_source_ancestries":1,
        "source_independence_certified":False,"external_custody_authenticated":False,
        "live_gameplay_authority":False,
    }
    canonical=json.dumps(verdict,sort_keys=True,separators=(",",":")).encode("utf-8")
    verdict["receipt_sha256"]=hashlib.sha256(canonical).hexdigest()
    return verdict

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("build","replay","public","output"):
        parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    verdict=adjudicate(load(args.build),load(args.replay),load(args.public))
    out=Path(args.output)
    require(not out.exists(),"refusing to overwrite immutable evidence")
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as handle:
        json.dump(verdict,handle,indent=2,sort_keys=True)
        handle.write("\n")
    print(json.dumps(verdict,sort_keys=True))
