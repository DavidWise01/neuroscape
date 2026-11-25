#!/usr/bin/env python3
"""RUST-011 Chromium gate: certify phase and combat WASM replay fixtures."""
from pathlib import Path
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parent
fixtures = [
    ("rust009-browser.html", "RUST009_RESULT", 64),
    ("rust011-browser.html", "RUST011_RESULT", 3),
]
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        for filename, result_key, expected_steps in fixtures:
            page = browser.new_page()
            page.goto((root / filename).as_uri(), wait_until="load")
            page.wait_for_function(
                """key => window[key] && (window[key].pass || window[key].error !== 'not started')""",
                arg=result_key, timeout=30000,
            )
            result = page.evaluate("key => window[key]", result_key)
            print(filename, result)
            if not result.get("pass") or result.get("steps") != expected_steps:
                raise SystemExit(f"FAIL: {filename}")
            if result_key == "RUST009_RESULT" and not result.get("negativeTest"):
                raise SystemExit("FAIL: missing phase negative test")
            if result_key == "RUST011_RESULT" and not (
                result.get("repeat") and result.get("terminalRejected")
                and result.get("released") == [2, 3]
                and result.get("removed") == [1, 1]
                and result.get("winner") == 0
            ):
                raise SystemExit("FAIL: combat conservation/terminal evidence")
            page.close()
        print("PASS: phase and combat WASM browser parity.")
    finally:
        browser.close()
