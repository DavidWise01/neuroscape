#!/usr/bin/env python3
"""RUST-017: create or verify exact-commit cross-runner WASM receipts.

This detects byte-for-byte build differences between pinned-toolchain builds
on two GitHub-hosted runner images. It does NOT prove independent provenance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
WASM = ROOT / "rust/neuroscape-core/target/wasm32-unknown-unknown/release/neuroscape_core.wasm"
RECEIPT = ROOT / "rust/tests/.rust017-cross-build.json"
OUTPUT = ROOT / "assets/rust017-cross-environment.json"

def sha256(path):
    blob = path.read_bytes()
    if blob[:4] != bytes((0, 97, 115, 109)):
        raise ValueError("WASM magic invalid")
    return hashlib.sha256(blob).hexdigest(), len(blob)

def valid_sha(v, length):
    return isinstance(v, str) and bool(re.fullmatch("[0-9a-f]{" + str(length) + "}", v))

def run(*args):
    return subprocess.check_output(args, text=True, cwd=ROOT).strip()

def source():
    sha = os.getenv("GITHUB_SHA", "")
    if not valid_sha(sha, 40) or run("git", "rev-parse", "HEAD") != sha:
        raise SystemExit("RUST-017 HOLD: exact source commit mismatch")
    return sha

def record():
    sha = source()
    digest, size = sha256(WASM)
    return {
        "phase": "RUST-017",
        "source_commit": sha,
        "wasm_sha256": digest,
        "wasm_bytes": size,
        "rustc": run("rustc", "--version"),
        "cargo": run("cargo", "--version"),
        "runner_environment": os.environ.get("RUNNER_OS", "unknown") + "/" + os.environ.get("ImageOS", "unknown"),
        "source_ancestry": "single_repository",
        "independent_source_witness": False,
        "gameplay_authority": False,
    }

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "emit":
        if not os.environ.get("ImageOS", "").startswith("ubuntu22"):
            raise SystemExit("RUST-017 HOLD: expected Ubuntu 22.04 witness")
        receipt = record()
        RECEIPT.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True, indent=2))
    elif mode == "compare":
        if not RECEIPT.is_file():
            raise SystemExit("RUST-017 HOLD: independent runner receipt missing")
        witness = json.loads(RECEIPT.read_text(encoding="utf-8"))
        primary = record()
        if any(witness.get(k) != primary.get(k) for k in
               ("phase", "source_commit", "wasm_sha256", "wasm_bytes", "rustc", "cargo")):
            raise SystemExit("RUST-017 HOLD: cross-runner toolchain or WASM mismatch")
        if not str(witness.get("runner_environment", "")).startswith("Linux/ubuntu22"):
            raise SystemExit("RUST-017 HOLD: wrong witness environment")
        if not str(primary.get("runner_environment", "")).startswith("Linux/ubuntu24"):
            raise SystemExit("RUST-017 HOLD: wrong primary environment")
        receipt = {
            "phase": "RUST-017",
            "source_commit": primary["source_commit"],
            "wasm_sha256": primary["wasm_sha256"],
            "wasm_bytes": primary["wasm_bytes"],
            "rustc": primary["rustc"],
            "cargo": primary["cargo"],
            "witness_runner": witness["runner_environment"],
            "deployment_runner": primary["runner_environment"],
            "cross_runner_match": True,
            "single_source_ancestry": True,
            "independent_source_witness": False,
            "gameplay_authority": False,
        }
        OUTPUT.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True, indent=2))
    else:
        raise SystemExit("Usage: reproduce_cross_runner.py emit|compare")

if __name__ == "__main__":
    main()
