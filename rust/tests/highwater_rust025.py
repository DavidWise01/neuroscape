#!/usr/bin/env python3
"""RUST-025 external highwater witness: cryptographic check, not an oracle.

Verifies a retained Ed25519-signed latest checkpoint and one proposed
successor. A signed but stale checkpoint can still be replayed if the
verifier lacks an independently obtained latest highwater. No auto-release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, verify_key_and_signature

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

def check64(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None

def check_checkpoint(record):
    require(isinstance(record, dict), "highwater checkpoint absent")
    require(record.get("phase") == "RUST-025", "wrong highwater phase")
    require(record.get("status") == "HIGHWATER_CANDIDATE", "not checkpoint candidate")
    require(type(record.get("epoch")) is int and record["epoch"] >= 0, "invalid epoch")
    require(type(record.get("sequence")) is int and record["sequence"] >= 1, "invalid sequence")
    require(isinstance(record.get("source_commit"), str) and HEX40.fullmatch(record["source_commit"]), "invalid source")
    require(check64(record.get("entry_sha256")), "entry hash missing")
    require(check64(record.get("previous_highwater_sha256")), "previous highwater missing")
    require(record.get("live_gameplay_authority") is False, "gameplay authority prohibited")
    require(record.get("global_anti_rollback_certified") is False, "unsupported anti-rollback claim")
    require(check64(record.get("candidate_sha256")), "candidate hash missing")
    require(digest({k:v for k,v in record.items() if k != "candidate_sha256"}) ==
            record["candidate_sha256"], "checkpoint candidate tampered")
    return record

def make_candidate(epoch,sequence,source_commit,entry_sha256,previous_highwater_sha256):
    value={
        "phase":"RUST-025","status":"HIGHWATER_CANDIDATE",
        "epoch":epoch,"sequence":sequence,
        "source_commit":source_commit,"entry_sha256":entry_sha256,
        "previous_highwater_sha256":previous_highwater_sha256,
        "live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }
    value["candidate_sha256"]=digest(value)
    return check_checkpoint(value)

def validate_successor(prior, next_record):
    """Comparison presupposes externally fetched prior record and signature."""
    old=check_checkpoint(prior)
    new=check_checkpoint(next_record)
    require(new["previous_highwater_sha256"] == old["candidate_sha256"],
            "checkpoint fork or predecessor replay")
    require(new["sequence"] == old["sequence"] + 1, "sequence replay or skip")
    require(new["epoch"] >= old["epoch"], "epoch rollback")
    require(new["source_commit"] != old["source_commit"], "source replay")
    require(new["entry_sha256"] != old["entry_sha256"], "entry replay")
    return True

def verify_witness(record, key, signature, pinned):
    check_checkpoint(record)
    require(check64(pinned), "external witness SPKI pin missing")
    return verify_key_and_signature(key,signature,pinned,canonical(record))

def observe(prior, prior_key, prior_signature, external_pin, next_record=None):
    """Only verifies a signed snapshot. Does not prove globally latest."""
    signature_sha256=verify_witness(prior,prior_key,prior_signature,external_pin)
    if next_record is not None:
        validate_successor(prior,next_record)
    value={
        "phase":"RUST-025","status":"SIGNED_HIGHWATER_OBSERVED",
        "source_commit":prior["source_commit"],"epoch":prior["epoch"],
        "sequence":prior["sequence"],
        "candidate_sha256":prior["candidate_sha256"],
        "witness_spki_sha256":external_pin,
        "witness_signature_sha256":signature_sha256,
        "next_candidate_checked":next_record is not None,
        "external_latest_checkpoint_confirmed":False,
        "global_anti_rollback_certified":False,
        "live_gameplay_authority":False,
        "release_authorized":False,
    }
    value["receipt_sha256"]=digest(value)
    return value

def hold(reason):
    return {
        "phase":"RUST-025","status":"HOLD_EXTERNAL_HIGHWATER",
        "reason":reason,"release_authorized":False,
        "external_latest_checkpoint_confirmed":False,
        "global_anti_rollback_certified":False,
        "live_gameplay_authority":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--prior")
    p.add_argument("--prior-key")
    p.add_argument("--prior-signature")
    p.add_argument("--next")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    pin=os.environ.get("RUST025_WITNESS_SPKI_SHA256")
    if not (a.prior and a.prior_key and a.prior_signature and pin):
        result=hold("No externally retained signed highwater and pinned witness key")
    else:
        prior=json.loads(Path(a.prior).read_text())
        nxt=json.loads(Path(a.next).read_text()) if a.next else None
        result=observe(prior,a.prior_key,a.prior_signature,pin,nxt)
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if result["status"]!="SIGNED_HIGHWATER_OBSERVED" and not a.allow_hold_record:
        raise SystemExit("RUST-025 HOLD: no authenticated external highwater")

if __name__=="__main__":
    main()
