#!/usr/bin/env python3
"""RUST-014: verify actual public GitHub Pages after deployment, fail closed.

Source metadata is self-reported by this repository's deployment workflow.
This probe checks public serving and parity; it is not independent custody.
"""
import hashlib
from pathlib import Path
import json
import os
import time
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright

BASE = os.environ.get("RUST014_PAGES_URL", "https://davidwise01.github.io/neuroscape").rstrip("/")
SHA = os.environ["GITHUB_SHA"]
RUN = os.environ["GITHUB_RUN_ID"]
ATTEMPTS = 8


def fetch(path):
    request = Request(f"{BASE}/{path}?rust014={SHA}", headers={"Cache-Control": "no-cache"})
    with urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"{path}: HTTP {response.status}")
        return response.read()


def verify_once(browser):
    manifest = json.loads(fetch("assets/rust013-release.json"))
    if manifest.get("source_commit") != SHA:
        raise RuntimeError(f"stale release source: {manifest.get('source_commit')} != {SHA}")
    if str(manifest.get("github_run_id")) != str(RUN):
        raise RuntimeError(f"stale release run: {manifest.get('github_run_id')} != {RUN}")
    if manifest.get("native_rust_gate") != "passed_in_deployment_job":
        raise RuntimeError("native Rust gate not attested")
    if manifest.get("chromium_phase_and_combat_gate") != "passed_in_deployment_job":
        raise RuntimeError("browser gate not attested")
    if manifest.get("live_gameplay_authority") is not False:
        raise RuntimeError("unauthorized gameplay authority in manifest")
    # A browser-loaded WASM asset is checked again by the publication page.
    page = browser.new_page()
    try:
        page.goto(f"{BASE}/rust/tests/rust013-release.html?rust014={SHA}", wait_until="load", timeout=30000)
        page.wait_for_function(
            """() => {
              const t = document.querySelector('#status')?.textContent || '';
              return t.startsWith('BUILD-MATCH PASS') ||
                (t.startsWith('HOLD') && !t.includes('waiting for published build evidence'));
            }""",
            timeout=30000,
        )
        status = page.locator("#status").inner_text()
        if not status.startswith("BUILD-MATCH PASS"):
            raise RuntimeError(f"publication witness: {status}")
        reported = page.locator("#digest").inner_text()
        if reported != manifest.get("wasm_sha256"):
            raise RuntimeError("publication witness digest disagrees with manifest")
        if page.locator("#commit").inner_text() != SHA:
            raise RuntimeError("publication witness commit disagrees")
    finally:
        page.close()

    # Run actual public copied-state combat replay, not just the presence of HTML.
    page = browser.new_page()
    try:
        page.goto(f"{BASE}/rust/tests/rust011-browser.html?rust014={SHA}", wait_until="load", timeout=30000)
        page.wait_for_function(
            """() => window.RUST011_RESULT
              && (window.RUST011_RESULT.pass || window.RUST011_RESULT.error !== 'not started')""",
            timeout=30000,
        )
        result = page.evaluate("window.RUST011_RESULT")
        if not (
            result.get("pass") is True
            and result.get("steps") == 3
            and result.get("removed") == [1, 1]
            and result.get("released") == [2, 3]
            and result.get("winner") == 0
            and result.get("repeat") is True
            and result.get("terminalRejected") is True
        ):
            raise RuntimeError(f"public combat witness HOLD: {result}")
    finally:
        page.close()

    # RUST-015: compare complete replay evidence against independent
    # CI-browser fingerprint produced before publication in this same run.
    receipt_file = Path(__file__).resolve().parent / ".rust015-local-evidence.json"
    if not receipt_file.is_file():
        raise RuntimeError("local CI replay fingerprint missing")
    expected = json.loads(receipt_file.read_text(encoding="utf-8"))
    if expected.get("source_commit") != SHA or expected.get("replay_steps") != 3:
        raise RuntimeError("local CI evidence ancestry/step count mismatch")
    evidence = result.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 3:
        raise RuntimeError("public full replay evidence absent")
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    replay_sha256 = hashlib.sha256(canonical).hexdigest()
    if replay_sha256 != expected.get("replay_sha256"):
        raise RuntimeError("CI/public replay SHA-256 mismatch")

    return {
        "phase": "RUST-015",
        "replay_sha256": replay_sha256,
        "source_commit": SHA,
        "github_run_id": RUN,
        "wasm_sha256": manifest["wasm_sha256"],
        "public_manifest": "MATCH",
        "public_browser_combat": "PASS",
        "live_gameplay_authority": False,
    }


def main():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            last = None
            for attempt in range(1, ATTEMPTS + 1):
                try:
                    result = verify_once(browser)
                    print(json.dumps(result, indent=2, sort_keys=True))
                    return
                except Exception as exc:
                    last = exc
                    print(f"RUST-014 attempt {attempt}/{ATTEMPTS}: HOLD - {exc}", flush=True)
                    if attempt < ATTEMPTS:
                        time.sleep(10)
            raise SystemExit(f"RUST-014 public Pages acceptance FAILED: {last}")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
