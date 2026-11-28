#!/usr/bin/env python3
"""RUST-103: bounded read-only GitHub archive acquisition and source ancestry.

Retrieves exact GitHub archive response bytes with a restricted redirect
policy. GitHub and its codeload endpoint share one source ancestry. Successful
network acquisition does NOT establish independent custody, global
anti-rollback, or release authority.
"""
import argparse
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from century_source_freeze_rust100 import BASELINE
from century_archive_replay_rust101 import (
    MAX_ARCHIVE, archive_fingerprints, validate_manifest)

DOMAIN = "NEUROSCAPE_RUST103_HTTP_ACQUISITION_V1"
HOLD = "HOLD_GITHUB_ARCHIVE_EXTERNAL_INDEPENDENCE_UNVERIFIED"
SOURCE = ("https://api.github.com/repos/DavidWise01/neuroscape/"
          "zipball/" + BASELINE)
ALLOWED_HOSTS = {"api.github.com", "codeload.github.com"}

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def permitted(url):
    require(isinstance(url, str) and len(url) <= 2048,
            "invalid acquisition URL")
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment,
            "unsafe redirect or origin")
    if parsed.hostname == "api.github.com":
        require(url == SOURCE, "unexpected API archive target")
    else:
        require(parsed.path.startswith("/DavidWise01/neuroscape/")
                and parsed.path.endswith("/" + BASELINE),
                "unexpected GitHub codeload archive")
    return parsed.hostname

class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(code in (301, 302, 303, 307, 308),
                "unsupported redirect status")
        permitted(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def network_fetch(url=SOURCE):
    permitted(url)
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": "neuroscape-rust103-readonly"},
        method="GET")
    opener = urllib.request.build_opener(RestrictedRedirect)
    with opener.open(req, timeout=20) as response:
        final_url = response.geturl()
        permitted(final_url)
        status = response.status
        headers = dict(response.headers.items())
        if headers.get("Content-Length"):
            require(int(headers["Content-Length"]) <= MAX_ARCHIVE,
                    "archive exceeds byte ceiling")
        content = response.read(MAX_ARCHIVE + 1)
    return {"url": final_url, "status": status,
            "headers": headers, "body": content}

def acquisition(manifest, fetcher=network_fetch):
    entries = validate_manifest(manifest)
    observed = fetcher(SOURCE)
    require(isinstance(observed, dict), "HTTP response evidence required")
    final = observed.get("url")
    hostname = permitted(final)
    require(type(observed.get("status")) is int and observed["status"] == 200,
            "unsuccessful GitHub archive fetch")
    headers = observed.get("headers")
    require(isinstance(headers, dict), "HTTP response headers required")
    header_map = {str(k).lower():str(v) for k,v in headers.items()}
    raw = observed.get("body")
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_ARCHIVE,
            "empty or oversized archive bytes")
    if "content-length" in header_map:
        try:
            announced = int(header_map["content-length"])
        except ValueError:
            raise ValueError("malformed Content-Length") from None
        require(announced == len(raw), "HTTP length disagrees with bytes")
    fingerprints = archive_fingerprints(raw, entries)
    return {
        "phase": "RUST-103", "domain": DOMAIN, "status": HOLD,
        "source_url": SOURCE, "final_url": final,
        "http_status": 200, "http_content_type_claim": header_map.get("content-type"),
        "archive_sha256": fingerprints["archive_sha256"],
        "archive_byte_length": len(raw),
        "frozen_source_sha256": fingerprints["source_sha256"],
        "century_checkpoint_sha256": manifest["checkpoint_sha256"],
        "source_ancestry": "github.com/api.github.com/codeload.github.com",
        "response_observed_by_this_process": True,
        "archive_bytes_locally_verified": True,
        "independent_external_custody_verified": False,
        "independent_source_count_verified": 0,
        "global_anti_rollback_verified": False,
        "fork_selected": False, "recovery_authorized": False,
        "release_authorized": False, "live_gameplay_authorized": False,
    }, raw

def missing():
    return {"phase": "RUST-103",
            "status": "HOLD_MISSING_AUTHENTICATED_HTTP_ARCHIVE_BYTES",
            "independent_external_custody_verified": False,
            "recovery_authorized": False, "release_authorized": False,
            "live_gameplay_authorized": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest")
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--archive-output")
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-hold-record", action="store_true")
    args = parser.parse_args()
    require(not args.acquire or (args.manifest and args.archive_output),
            "live acquisition needs manifest and byte archive destination")
    require(args.acquire or not args.archive_output,
            "archive output requires verified acquisition")
    if args.acquire:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        record, bytes_ = acquisition(manifest)
        archive_path = Path(args.archive_output)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with archive_path.open("xb") as out:
            out.write(bytes_)
    else:
        record = missing()
    outpath = Path(args.output)
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with outpath.open("x", encoding="utf-8") as out:
        json.dump(record, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps(record, sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-103 HOLD: external independent custody unverified")

if __name__ == "__main__":
    main()
