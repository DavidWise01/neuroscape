#!/usr/bin/env python3
"""RUST-064: signed fork-registry highwater and cross-epoch witness continuity.

Checks exact ancestry, retained floors and claimed control separation.
All claims and signature verification remain non-authoritative: HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from fork_registry_rust063 import checked_history

FIELDS=("source_root_sha256","acquisition_sha256","operator_control_sha256")

def highwater(previous):
    events, heads=checked_history(previous)
    require(events,"previous RUST-063 registry must be nonempty")
    return {"phase":"RUST-064","kind":"FORK_REGISTRY_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "history_sha256":digest(events),
            "fork_keys_sha256":digest(previous["fork_keys"]),
            "conflicts_sha256":digest(previous["custody_conflicts"]),
            "source_rust063_receipt_sha256":previous["receipt_sha256"],
            "release_authorized":False}

def compare_witnesses(prior,successor):
    old={}
    by_root={}
    for event in prior:
        for witness in event["witnesses"]:
            pin=witness["pin"]
            ancestry=tuple(witness[k] for k in FIELDS)
            old.setdefault(pin,set()).add(ancestry)
            by_root.setdefault(witness["operator_control_sha256"],set()).add(pin)
    conflicts=[]
    for event in successor:
        for witness in event["witnesses"]:
            pin=witness["pin"]
            ancestry=tuple(witness[k] for k in FIELDS)
            if pin in old and ancestry not in old[pin]:
                conflicts.append({
                    "reason":"SIGNER_CLAIMED_ANCESTRY_CHANGED",
                    "pin":pin,"prior_claims":sorted(map(list,old[pin])),
                    "current_claim":list(ancestry),"independent_control_verified":False})
            previous_pins=by_root.get(witness["operator_control_sha256"],set())
            if previous_pins and pin not in previous_pins:
                conflicts.append({
                    "reason":"RENAMED_CUSTODIAN_REUSED_CONTROL_ROOT",
                    "pin":pin,"prior_pins":sorted(previous_pins),
                    "operator_control_sha256":witness["operator_control_sha256"],
                    "independent_control_verified":False})
    return conflicts

def audit(previous,current,checkpoint,checkpoint_key,checkpoint_signature,
          checkpoint_pin,floor,observations,verifier=verify_key_and_signature):
    prior,prior_heads=checked_history(previous)
    recent,recent_heads=checked_history(current)
    require(prior and len(recent)>len(prior),
            "new custody registry must strictly extend history")
    require(recent[:len(prior)]==prior and
            recent_heads[:len(prior_heads)]==prior_heads,
            "previous fork registry prefix rewritten")
    require(current["fork_keys"][:len(previous["fork_keys"])]==
            previous["fork_keys"],"historical fork keys removed")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],"historical custody conflicts erased")
    expected=highwater(previous)
    require(checkpoint==expected,"signed registry highwater substituted")
    check_sha(checkpoint_pin,"checkpoint signing pin invalid")
    require(checkpoint_pin not in {w["pin"] for event in recent
                                  for w in event["witnesses"]},
            "fork witness may not self-sign highwater")
    signature=verifier(checkpoint_key,checkpoint_signature,
                       checkpoint_pin,canonical(expected))
    check_sha(signature,"highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-064",
            "external retained highwater floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(prior)<=n<=len(recent),
            "retained highwater outside successor range")
    check_sha(floor.get("head_sha256"),"external floor head missing")
    require(recent_heads[n]==floor["head_sha256"],
            "retained fork registry head contradicts exact prefix")
    appended=recent[len(prior):]
    require(isinstance(observations,list) and len(observations)==len(appended),
            "one separate epoch observation per new registry event required")
    historical_nonces={w["nonce_sha256"] for e in recent for w in e["witnesses"]}
    fresh=set()
    rows=[]
    for event,observation in zip(appended,observations):
        require(isinstance(observation,dict) and
                observation.get("phase")=="RUST-064",
                "missing epoch observation")
        for key in ("fork_event_sha256","epoch_nonce_sha256",
                    "claimed_controller_sha256","acquisition_sha256"):
            check_sha(observation.get(key),"epoch observation missing "+key)
        require(observation["fork_event_sha256"]==event["entry_sha256"],
                "observation not bound to registry event")
        nonce=observation["epoch_nonce_sha256"]
        require(nonce not in historical_nonces and nonce not in fresh,
                "cross-epoch nonce replay")
        fresh.add(nonce)
        require(observation.get("fork_resolved") is False and
                observation.get("release_authorized") is False,
                "epoch observation asserted fork resolution")
        rows.append({"fork_entry_sha256":event["entry_sha256"],
                     "observation_sha256":digest(observation),
                     "nonce_sha256":nonce,
                     "independent_custody_verified":False})
    conflicts=compare_witnesses(prior,appended)
    result={
        "phase":"RUST-064",
        "status":"HOLD_FORK_REGISTRY_HIGHWATER_CONTINUITY",
        "previous_rust063_receipt_sha256":previous["receipt_sha256"],
        "current_rust063_receipt_sha256":current["receipt_sha256"],
        "signed_checkpoint":expected,"checkpoint_signature_sha256":signature,
        "checkpoint_pin":checkpoint_pin,
        "retained_floor_claim_sha256":digest(floor),
        "previous_count":len(prior),"current_count":len(recent),
        "previous_forks_preserved":previous["fork_keys"],
        "current_forks_preserved":current["fork_keys"],
        "historical_conflicts_preserved":previous["custody_conflicts"],
        "current_conflicts_preserved":current["custody_conflicts"],
        "cross_epoch_ancestry_conflicts":conflicts,
        "epoch_observations":rows,
        "independent_custody_verified":False,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "winner_selected":False,"fork_resolved":False,
        "release_authorized":False,"live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-064",
            "status":"HOLD_MISSING_FORK_REGISTRY_HIGHWATER",
            "independent_custody_verified":False,
            "globally_latest_highwater_verified":False,
            "winner_selected":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("previous","current","checkpoint","checkpoint-key",
              "checkpoint-signature","checkpoint-pin","floor","observations"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    vals=[a.previous,a.current,a.checkpoint,a.checkpoint_key,
          a.checkpoint_signature,a.checkpoint_pin,a.floor,a.observations]
    require(all(vals) or not any(vals),"partial registry highwater bundle refused")
    if all(vals):
        load=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(load(a.previous),load(a.current),load(a.checkpoint),
                  a.checkpoint_key,a.checkpoint_signature,a.checkpoint_pin,
                  load(a.floor),load(a.observations))
    else:out=hold()
    path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-064 HOLD: independently retained highwater unverified")
if __name__=="__main__":main()
