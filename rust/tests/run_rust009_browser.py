#!/usr/bin/env python3
"""RUST-009 Chromium gate: checks the real compiled WASM in a browser."""
from pathlib import Path
from playwright.sync_api import sync_playwright

uri = (Path(__file__).resolve().parent / "rust009-browser.html").as_uri()
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()
        page.goto(uri, wait_until="load")
        page.wait_for_function(
            "() => window.RUST009_RESULT && (window.RUST009_RESULT.pass || window.RUST009_RESULT.error !== 'not started')",
            timeout=30000,
        )
        result = page.evaluate("window.RUST009_RESULT")
        print(result)
        if not result.get("pass") or result.get("steps") != 64 or not result.get("negativeTest"):
            raise SystemExit("RUST-009 FAIL: Chromium parity/rejection check")
        print("RUST-009 Chromium PASS: 64 transitions, deterministic replay, negative rejection")
    finally:
        browser.close()
