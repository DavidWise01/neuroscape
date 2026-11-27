#!/usr/bin/env python3
"""RUST-074 — signed custody highwater and exact external snapshot replay.

No external custody, global anti-rollback, or release authority is inferred
from supplied snapshots. Every structurally valid result remains HOLD.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from denial_custody_rust073 import checked_history

def highwater(previous):
    rows,heads=checked_history(previous)
    require(rows,"prior custody history must be nonempty")
    final=rows[-1]
    return {"phase":"RUST-074","kind":"DENIAL_CUSTODY_HIGHWATER_V1",
            "event_count":len(rows),"head_sha256":heads[-1],
            "events_sha256":digest(rows),
            "denials_sha256":final["denials_sha256"],
            "excluded_pins_sha256":final["excluded_pins_sha256"],
            "excluded_controllers_sha256":final["excluded_controllers_sha256"],
            "conflicts_sha256":digest(previous["custody_conflicts"]),
            "source_rust073_receipt_sha256":previous["receipt_sha256"],
            "recovery_authorized":False,"release_authorized":False}

def ancestry_conflicts(before,appended):
    witnessed=[]
    for e in before:
        witnessed.extend(e["witnesses"])
    findings=[]
    for e in appended:
        for w in e["witnesses"]:
            for prior in witnessed:
                if w["pin"]==prior["pin"] and any(w[k]!=prior[k] for k in
                        ("controller_sha256","source_root_sha256",
                         "acquisition_sha256")):
                    findings.append({"reason":"SAME_CUSTODIAN_CHANGED_ANCESTRY",
                                     "pin":w["pin"],"independent_custody_verified":False})
                    break
                if w["pin"]!=prior["pin"] and (
                        w["controller_sha256"]==prior["controller_sha256"] or
                        w["acquisition_sha256"]==prior["acquisition_sha256"]):
                    findings.append({"reason":"RENAMED_CUSTODIAN_REUSED_ANCESTRY",
                                     "pin":w["pin"],"independent_custody_verified":False})
                    break
    return findings

def audit(previous,current,checkpoint,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "successor denial custody must strictly extend prior custody")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historic custody snapshot prefix rewritten or truncated")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],
            "historical denial custody conflicts erased")
    for e in new:
        require(e["denials"][:len(old[-1]["denials"])]==old[-1]["denials"] and
                e["excluded_pins"][:len(old[-1]["excluded_pins"])]==
                old[-1]["excluded_pins"] and
                e["excluded_controllers"][:len(old[-1]["excluded_controllers"])]==
                old[-1]["excluded_controllers"],
                "historical recovery denial disappeared from snapshot")
    expected=highwater(previous)
    require(checkpoint==expected,"signed denial custody checkpoint substituted")
    check_sha(signer_pin,"highwater signing pin invalid")
    prohibited={w["pin"] for e in new for w in e["witnesses"]}
    prohibited.update(new[-1]["excluded_pins"])
    require(signer_pin not in prohibited,
            "excluded or custody witness cannot self-sign highwater")
    sig=verifier(key,signature,signer_pin,canonical(expected))
    check_sha(sig,"custody highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-074",
            "separately retained custody floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retained custody floor outside successor history")
    check_sha(floor.get("head_sha256"),"retained floor head missing")
    require(new_heads[n]==floor["head_sha256"],
            "retained custody floor contradicts exact prefix")
    recent=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(recent),
            "fresh external snapshot observation required per new epoch")
    old_nonces={w["nonce_sha256"] for e in new for w in e["witnesses"]}
    fresh=set();reviewed=[];conflicts=ancestry_conflicts(old,recent)
    seen_snapshots={digest(e["denials"]) for e in old}
    for event,obs in zip(recent,observations):
        require(isinstance(obs,dict) and obs.get("phase")=="RUST-074",
                "external snapshot observation missing")
        for field in ("custody_entry_sha256","snapshot_nonce_sha256",
                      "snapshot_denials_sha256","claimed_controller_sha256",
                      "claimed_acquisition_sha256"):
            check_sha(obs.get(field),"snapshot observation missing "+field)
        require(obs["custody_entry_sha256"]==event["entry_sha256"] and
                obs["snapshot_denials_sha256"]==event["denials_sha256"],
                "external snapshot not bound to exact denials")
        nonce=obs["snapshot_nonce_sha256"]
        require(nonce not in old_nonces and nonce not in fresh,
                "external custody nonce replay")
        fresh.add(nonce)
        require(obs.get("recovery_authorized") is False and
                obs.get("release_authorized") is False and
                obs.get("denials_retained") is True,
                "external snapshot attempted denial clearance")
        if obs["snapshot_denials_sha256"] in seen_snapshots:
            conflicts.append({"reason":"STALE_DENIAL_SNAPSHOT_DIGEST",
                              "entry_sha256":event["entry_sha256"],
                              "independent_custody_verified":False})
        seen_snapshots.add(obs["snapshot_denials_sha256"])
        reviewed.append({"entry_sha256":event["entry_sha256"],
                         "observation_sha256":digest(obs),
                         "nonce_sha256":nonce,
                         "denials_retained":True,
                         "independent_custody_verified":False})
    result={"phase":"RUST-074",
            "status":"HOLD_DENIAL_CUSTODY_HIGHWATER_REPLAY",
            "previous_rust073_receipt_sha256":previous["receipt_sha256"],
            "current_rust073_receipt_sha256":current["receipt_sha256"],
            "signed_checkpoint":expected,
            "checkpoint_signature_sha256":sig,
            "checkpoint_signer_pin":signer_pin,
            "retained_floor_claim_sha256":digest(floor),
            "previous_count":len(old),"current_count":len(new),
            "prior_denials_preserved":old[-1]["denials"],
            "current_denials_preserved":new[-1]["denials"],
            "prior_excluded_pins_preserved":old[-1]["excluded_pins"],
            "current_excluded_pins_preserved":new[-1]["excluded_pins"],
            "prior_excluded_controllers_preserved":old[-1]["excluded_controllers"],
            "current_excluded_controllers_preserved":new[-1]["excluded_controllers"],
            "historical_conflicts_preserved":previous["custody_conflicts"],
            "current_conflicts_preserved":current["custody_conflicts"],
            "snapshot_conflicts":conflicts,
            "snapshot_observations":reviewed,
            "all_denials_retained":True,
            "independent_custody_verified":False,
            "globally_latest_highwater_verified":False,
            "global_anti_rollback_certified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-074",
            "status":"HOLD_MISSING_DENIAL_CUSTODY_HIGHWATER",
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("previous","current","checkpoint","key","signature",
              "signer-pin","floor","observations"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    pieces=[a.previous,a.current,a.checkpoint,a.key,a.signature,
            a.signer_pin,a.floor,a.observations]
    require(all(pieces) or not any(pieces),"partial custody highwater bundle refused")
    if all(pieces):
        load=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        out=audit(load(a.previous),load(a.current),load(a.checkpoint),
                  a.key,a.signature,a.signer_pin,
                  load(a.floor),load(a.observations))
    else:out=hold()
    path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-074 HOLD: independently retained custody not verified")

if __name__=="__main__":
    main()
