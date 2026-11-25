#!/usr/bin/env python3
"""RUST-019: append-only receipt lineage, with explicit externally retained anchor.

No global anti-rollback claim is possible when the predecessor is unavailable.
The unanchored result is HOLD, never an accepted chain.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

def require(condition, message):
    if not condition:
        raise ValueError("HOLD: " + message)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def validate_receipt(receipt):
    require(isinstance(receipt, dict), "receipt must be an object")
    require(receipt.get("phase") == "RUST-018", "source is not RUST-018 adjudication")
    require(receipt.get("status") == "CONSISTENT_OBSERVATIONS", "source not accepted")
    require(receipt.get("live_gameplay_authority") is False, "gameplay authority prohibited")
    require(receipt.get("source_independence_certified") is False, "unsupported ancestry claim")
    require(bool(HEX40.fullmatch(str(receipt.get("source_commit", "")))), "invalid source")
    for key in ("wasm_sha256", "replay_sha256", "receipt_sha256"):
        require(bool(HEX64.fullmatch(str(receipt.get(key, "")))), key + " invalid")
    raw = {k:v for k,v in receipt.items() if k != "receipt_sha256"}
    require(digest(raw) == receipt["receipt_sha256"], "RUST-018 receipt digest mismatch")
    return receipt

def validate_predecessor(prev):
    require(isinstance(prev, dict), "predecessor must be an object")
    require(prev.get("phase") == "RUST-019" and prev.get("status") == "ANCHORED", "predecessor not anchored")
    require(prev.get("live_gameplay_authority") is False, "predecessor gameplay authority")
    require(prev.get("source_independence_certified") is False, "predecessor ancestry claim")
    require(isinstance(prev.get("sequence"), int) and prev["sequence"] >= 1, "predecessor sequence invalid")
    require(bool(HEX40.fullmatch(str(prev.get("source_commit","")))), "predecessor commit invalid")
    require(bool(HEX64.fullmatch(str(prev.get("entry_sha256","")))), "predecessor hash invalid")
    require(digest({k:v for k,v in prev.items() if k != "entry_sha256"}) == prev["entry_sha256"], "predecessor tampered")
    return prev

def build(current, prev=None, commit_is_descendant=None):
    current=validate_receipt(current)
    if prev is None:
        return {
            "phase": "RUST-019", "status": "HOLD_UNANCHORED",
            "source_commit": current["source_commit"],
            "receipt_sha256": current["receipt_sha256"],
            "sequence": None, "predecessor_sha256": None,
            "live_gameplay_authority": False,
            "source_independence_certified": False,
            "reason": "No authenticated retained predecessor; global rollback protection unavailable",
        }
    prev=validate_predecessor(prev)
    require(callable(commit_is_descendant), "missing independent git ancestry check")
    require(current["source_commit"] != prev["source_commit"], "duplicate source commit")
    require(commit_is_descendant(prev["source_commit"], current["source_commit"]), "non-descendant source rollback")
    require(current["receipt_sha256"] != prev["receipt_sha256"], "reused evidence receipt")
    result={
        "phase": "RUST-019", "status": "ANCHORED",
        "sequence": prev["sequence"] + 1,
        "source_commit": current["source_commit"],
        "receipt_sha256": current["receipt_sha256"],
        "predecessor_sha256": prev["entry_sha256"],
        "predecessor_source_commit": prev["source_commit"],
        "live_gameplay_authority": False,
        "source_independence_certified": False,
    }
    result["entry_sha256"]=digest(result)
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--receipt", required=True)
    p.add_argument("--predecessor")
    p.add_argument("--output", required=True)
    p.add_argument("--allow-unanchored-report", action="store_true", help="Archive HOLD evidence without asserting a freeze")
    args=p.parse_args()
    current=json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    prev=json.loads(Path(args.predecessor).read_text(encoding="utf-8")) if args.predecessor else None
    if prev is not None:
        import subprocess
        def descendant(older, newer):
            result=subprocess.run(["git","merge-base","--is-ancestor",older,newer],check=False)
            return result.returncode == 0
    else:
        descendant=None
    result=build(current,prev,descendant)
    target=Path(args.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as writer:
        json.dump(result,writer,indent=2,sort_keys=True)
        writer.write("\n")
    print(json.dumps(result,sort_keys=True))
    if result["status"] != "ANCHORED" and not args.allow_unanchored_report:
        raise SystemExit("RUST-019 HOLD: lineage receipt recorded, no authenticated predecessor")
if __name__=="__main__":
    main()
