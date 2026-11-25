#!/usr/bin/env python3
"""RUST-016 — clean source checkout reproduction of the deployment WASM.

A second build from the same source ancestry is a reproducibility check,
not an independent witness to provenance or trustworthiness.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRIMARY = ROOT / "rust/neuroscape-core/target/wasm32-unknown-unknown/release/neuroscape_core.wasm"
REPORT = ROOT / "assets/rust016-reproduction.json"

def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)

def digest(path):
    blob = path.read_bytes()
    if blob[:4] != b"\x00asm":
        raise RuntimeError(f"Invalid WebAssembly magic: {path}")
    return hashlib.sha256(blob).hexdigest(), len(blob)

def main():
    source = os.environ.get("GITHUB_SHA")
    if not source or len(source) != 40 or any(ch not in "0123456789abcdef" for ch in source):
        raise SystemExit("RUST-016 HOLD: missing exact GITHUB_SHA")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != source:
        raise SystemExit(f"RUST-016 HOLD: source mismatch {actual} != {source}")
    if not PRIMARY.exists():
        raise SystemExit("RUST-016 HOLD: primary compiled WASM missing")
    primary_sha, primary_size = digest(PRIMARY)

    with tempfile.TemporaryDirectory(prefix="neuroscape-rust016-") as temp:
        isolated = Path(temp) / "source"
        isolated.mkdir()
        archive = subprocess.Popen(
            ["git", "archive", "--format=tar", source],
            cwd=ROOT, stdout=subprocess.PIPE,
        )
        try:
            subprocess.run(["tar", "-xf", "-", "-C", str(isolated)],
                           stdin=archive.stdout, check=True)
        finally:
            if archive.stdout:
                archive.stdout.close()
        if archive.wait() != 0:
            raise SystemExit("RUST-016 HOLD: exact-commit archive failed")

        manifest = isolated / "rust/neuroscape-core/Cargo.toml"
        isolated_target = Path(temp) / "isolated-target"
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(isolated_target)
        subprocess.run(
            ["cargo", "build", "--manifest-path", str(manifest),
             "--target", "wasm32-unknown-unknown", "--release", "--locked"],
            cwd=isolated, env=env, check=True,
        )
        reproduced = isolated_target / "wasm32-unknown-unknown/release/neuroscape_core.wasm"
        if not reproduced.is_file():
            raise SystemExit("RUST-016 HOLD: isolated WASM absent")
        second_sha, second_size = digest(reproduced)

    if primary_sha != second_sha or primary_size != second_size:
        raise SystemExit(
            f"RUST-016 HOLD: WASM nonreproducible: primary={primary_sha} "
            f"isolated={second_sha} ({primary_size}/{second_size} bytes)"
        )
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    cargo = subprocess.check_output(["cargo", "--version"], text=True).strip()
    receipt = {
        "phase": "RUST-016",
        "source_commit": source,
        "primary_wasm_sha256": primary_sha,
        "isolated_wasm_sha256": second_sha,
        "wasm_bytes": primary_size,
        "reproducible": True,
        "second_build": "fresh git archive / isolated cargo target",
        "same_source_ancestry": True,
        "independent_source_witness": False,
        "rustc": rustc,
        "cargo": cargo,
        "authority": "observation_only",
    }
    REPORT.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
