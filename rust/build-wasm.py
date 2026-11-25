#!/usr/bin/env python3
"""Encode the built wasm into a deterministic browser-loadable JS asset.

This avoids file:// fetch/CORS differences in the existing Chromium tests.
The generated JS is built fresh from Rust in Actions before testing/deploying.
The checked-in placeholder is explicitly NOT a compiled WASM binary.
"""
import base64
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent.parent
wasm = root / "rust/neuroscape-core/target/wasm32-unknown-unknown/release/neuroscape_core.wasm"
if not wasm.is_file():
    raise SystemExit(f"missing Rust WASM artifact: {wasm}")
data = wasm.read_bytes()
if data[:4] != b"\x00asm":
    raise SystemExit("invalid WASM magic")
sha = hashlib.sha256(data).hexdigest()
out = root / "assets/neuroscape-rust-wasm.generated.js"
out.write_text(
    "/* Generated from Rust source during CI. SHA-256: " + sha + " */\n"
    + "window.NEUROSCAPE_RUST_WASM_BASE64="
    + repr(base64.b64encode(data).decode("ascii")) + ";\n"
    + "window.NEUROSCAPE_RUST_WASM_SHA256='" + sha + "';\n",
    encoding="utf-8",
)
print(f"WASM binary: {len(data)} bytes, SHA-256: {sha}")
print(f"Embedded binary: {out}")
