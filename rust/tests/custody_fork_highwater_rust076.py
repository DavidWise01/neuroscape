#!/usr/bin/env python3
"""RUST-076 — signed custody-fork highwater and cross-epoch branch persistence.

Every fork remains unresolved. This only checks internally supplied
signatures and snapshots; external custody and global latestness are HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from custody_fork_rust075 import checked_history

def checkpoint_payload(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty RUST-075 fork predecessor required")
    return {"phase":"RUST-076","kind":"CUSTODY_FORK_RETENTION_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "fork_pairs_sha256":digest(previous["fork_pairs"]),
            "custody_conflicts_sha256":digest(previous["custody_conflicts"]),
            "source_rust075_receipt_sha256":previous["receipt_sha256"],
            "fork_resolved":False,"winner_selected":False,
            "recovery_authorized":False,"release_authorized":False}

def audit(previous,current,checkpoint,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "new fork registry must strictly extend predecessor")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "fork registry prefix replaced")
    require(current["fork_pairs"][:len(previous["fork_pairs"])]==
            previous["fork_pairs"],"prior competing branches erased")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],"historical fork conflicts erased")
    require(current.get("winner_selected") is False and
            current.get("fork_resolved") is False and
            current.get("release_authorized") is False,
            "fork history falsely merged or promoted")
    payload=checkpoint_payload(previous)
    require(checkpoint==payload,"signed fork highwater substituted")
    check_sha(signer_pin,"checkpoint signer pin invalid")
    used={e[field] for e in new for field in ("witness_a_pin","witness_b_pin")}
    require(signer_pin not in used,"custody fork witness cannot self-sign highwater")
    signed=verifier(key,signature,signer_pin,canonical(payload))
    check_sha(signed,"invalid fork highwater signature")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-076",
            "separate retention floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retention floor outside known fork history")
    check_sha(floor.get("head_sha256"),"retention floor digest invalid")
    require(new_heads[n]==floor["head_sha256"],
            "retention floor contradicts exact prefix")
    added=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(added),
            "one new fork observation required per epoch")
    prior_nonces={e[f] for e in new for f in ("nonce_a_sha256","nonce_b_sha256")}
    fresh=set();observed=[];conflicts=[]
    prior_pairs={tuple(e["fork_pair"]) for e in old}
    prior_ancestry={e["base_rust073_receipt_sha256"] for e in old}
    for event,obs in zip(added,observations):
        require(isinstance(obs,dict) and obs.get("phase")=="RUST-076",
                "fork continuity observation missing")
        for field in ("fork_entry_sha256","observation_nonce_sha256",
                      "base_rust073_receipt_sha256",
                      "branch_a_head_sha256","branch_b_head_sha256"):
            check_sha(obs.get(field),"fork observation missing "+field)
        require(obs["fork_entry_sha256"]==event["entry_sha256"] and
                obs["base_rust073_receipt_sha256"]==
                event["base_rust073_receipt_sha256"] and
                [obs["branch_a_head_sha256"],obs["branch_b_head_sha256"]]==
                event["fork_pair"],"fork observation substituted a branch")
        nonce=obs["observation_nonce_sha256"]
        require(nonce not in prior_nonces and nonce not in fresh,
                "fork continuity observation nonce replay")
        fresh.add(nonce)
        require(obs.get("winner_selected") is False and
                obs.get("fork_resolved") is False and
                obs.get("recovery_authorized") is False and
                obs.get("release_authorized") is False,
                "fork observation attempted false merge")
        pair=tuple(event["fork_pair"])
        if pair in prior_pairs:
            conflicts.append({"reason":"REPEATED_FORK_PAIR_NEW_EPOCH",
                              "entry_sha256":event["entry_sha256"],
                              "independent_custody_verified":False})
        if event["base_rust073_receipt_sha256"] in prior_ancestry:
            conflicts.append({"reason":"REUSED_CUSTODY_ANCESTRY_WITH_NEW_FORK",
                              "entry_sha256":event["entry_sha256"],
                              "independent_custody_verified":False})
        observed.append({"fork_entry_sha256":event["entry_sha256"],
                         "observation_sha256":digest(obs),
                         "nonce_sha256":nonce,"both_branches_retained":True,
                         "independent_custody_verified":False})
    out={"phase":"RUST-076",
         "status":"HOLD_CUSTODY_FORK_HIGHWATER_RETENTION",
         "previous_rust075_receipt_sha256":previous["receipt_sha256"],
         "current_rust075_receipt_sha256":current["receipt_sha256"],
         "signed_checkpoint":payload,
         "checkpoint_signature_sha256":signed,
         "checkpoint_signer_pin":signer_pin,
         "retained_floor_claim_sha256":digest(floor),
         "previous_fork_count":len(old),"current_fork_count":len(new),
         "historical_fork_pairs_preserved":previous["fork_pairs"],
         "current_fork_pairs_preserved":current["fork_pairs"],
         "historical_conflicts_preserved":previous["custody_conflicts"],
         "current_conflicts_preserved":current["custody_conflicts"],
         "cross_epoch_conflicts":conflicts,
         "new_fork_observations":observed,
         "both_branches_retained":True,
         "winner_selected":False,"fork_resolved":False,
         "independent_custody_verified":False,
         "globally_latest_fork_highwater_verified":False,
         "global_anti_rollback_certified":False,
         "recovery_authorized":False,"release_authorized":False,
         "live_gameplay_authority":False}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-076",
            "status":"HOLD_MISSING_CUSTODY_FORK_HIGHWATER",
            "both_branches_retained":False,
            "winner_selected":False,"fork_resolved":False,
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","key","signature",
                 "signer-pin","floor","observations"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    args=[a.previous,a.current,a.checkpoint,a.key,a.signature,
          a.signer_pin,a.floor,a.observations]
    require(all(args) or not any(args),
            "partial custody fork highwater evidence refused")
    if all(args):
        load=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(load(a.previous),load(a.current),load(a.checkpoint),
                  a.key,a.signature,a.signer_pin,
                  load(a.floor),load(a.observations))
    else:
        out=hold()
    target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-076 HOLD: independent fork custody not verified")
if __name__=="__main__":
    main()
