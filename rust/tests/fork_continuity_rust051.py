#!/usr/bin/env python3
"""RUST-051 — cross-epoch fork continuity and branch witness accounting.

Consume exact RUST-050 fork registry and new RUST-049 receipt.
Classify every prior unresolved branch against both current branches:
EXTENDS, SAME, WITHHELD, CONTRADICTS, or UNREFERENCED.
An added signed provenance claim does not establish external custody;
historical forks never disappear and graduation/release remains HOLD.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import check_sha
from fork_registry_rust050 import checked_history, checked_observation


def classify(prior, current):
    old=prior["prefix_heads"]
    new=current["prefix_heads"]
    count=min(len(old),len(new))
    matching=old[:count]==new[:count]
    if not matching:
        return "CONTRADICTS"
    if len(new)>len(old):
        return "EXTENDS"
    if len(new)<len(old):
        return "WITHHELD"
    return "SAME"


def audit(history, observation, floor=None):
    entries, heads=checked_history(history)
    branches, fork, shared=checked_observation(observation)
    require(isinstance(entries,list) and entries,
            "at least one historical RUST-050 observation required")
    require(observation["receipt_sha256"] not in
            {x["upstream_rust049_receipt_sha256"] for x in entries},
            "source observation replay")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-051",
                "retained continuity floor missing")
        count=floor.get("entry_count")
        require(type(count) is int and 0<=count<len(heads),
                "retained continuity history truncated")
        check_sha(floor.get("head_sha256"),"retained continuity head invalid")
        require(heads[count]==floor["head_sha256"],
                "retained fork history forked or rewritten")
    # Every unresolved historical fork is tested against both current
    # branches independently. Comparing only to the current winner would
    # silently discard a historical branch.
    reviews=[]
    for entry in entries:
        oldfork=entry.get("fork_event")
        if oldfork is None:
            continue
        snapshots=entry.get("source_branch_snapshots")
        require(isinstance(snapshots,list) and len(snapshots)==2,
                "historical fork branch snapshots absent")
        roles=[]
        for i,prior in enumerate(snapshots):
            count=prior.get("denial_count")
            ph=prior.get("prefix_heads")
            require(type(count) is int and count>=1 and isinstance(ph,list)
                    and len(ph)==count+1 and prior.get("head_sha256")==ph[-1],
                    "historical fork ancestry invalid")
            matches=[]
            for j,current in enumerate(branches):
                status=classify(prior,current)
                matches.append({
                    "current_branch_index":j,
                    "current_branch_sha256":current["branch_sha256"],
                    "relation":status,
                    "same_claimed_signer":prior["signer_pin"]==current["signer_pin"],
                    "same_claimed_source_root":
                        prior["custody_root_sha256"]==current["custody_root_sha256"],
                    "same_claimed_acquisition":
                        prior["acquisition_sha256"]==current["acquisition_sha256"],
                })
            # Cryptographic ancestry extension and signer custody are
            # separate dimensions. A matching head alone never proves
            # independent witness continuity.
            relations={m["relation"] for m in matches}
            outcome=("EXTENDED" if "EXTENDS" in relations else
                     "PRESENT_UNEXTENDED" if "SAME" in relations else
                     "WITHHELD" if "WITHHELD" in relations else
                     "CONTRADICTED")
            roles.append({
                "historical_branch_index":i,
                "historical_branch_sha256":prior["branch_sha256"],
                "historical_denial_count":count,
                "current_comparisons":matches,
                "continuity_status":outcome,
                "independent_operator_custody_verified":False,
            })
        reviews.append({
            "historical_registry_ordinal":entry["ordinal"],
            "historical_registry_entry_sha256":entry["entry_sha256"],
            "historical_source_rust049_receipt_sha256":
                entry["upstream_rust049_receipt_sha256"],
            "historical_fork_sha256":digest(oldfork),
            "both_historical_branches_accounted_for":True,
            "branch_reviews":roles,
            "fork_resolved":False,
        })
    require(len(reviews)==len(history["fork_events"]),
            "historical forks omitted from continuity review")
    result={
        "phase":"RUST-051","status":"HOLD_UNRESOLVED_FORK_CONTINUITY",
        "upstream_rust050_receipt_sha256":history["receipt_sha256"],
        "new_rust049_receipt_sha256":observation["receipt_sha256"],
        "historical_fork_count":len(history["fork_events"]),
        "historical_fork_reviews":reviews,
        "historical_fork_events_preserved":history["fork_events"],
        "historical_ancestry_alerts_preserved":
            history["custody_ancestry_alerts"],
        "new_fork_evidence":fork,
        "new_shared_claimed_custody":shared,
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":
            digest(floor) if floor is not None else None,
        "independent_branch_witnessing_authenticated":False,
        "globally_latest_fork_registry_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result


def hold():
    return {
        "phase":"RUST-051","status":"HOLD_MISSING_FORK_CONTINUITY",
        "historical_fork_reviews":[],
        "independent_branch_witnessing_authenticated":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
        "reason":"Missing intact fork registry and separately acquired successor branch evidence",
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry")
    p.add_argument("--observation")
    p.add_argument("--floor")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.registry)==bool(a.observation),
            "partial continuity evidence refused")
    require(not a.floor or (a.registry and a.observation),
            "floor without full continuity record refused")
    if a.registry:
        registry=json.loads(Path(a.registry).read_text(encoding="utf-8"))
        observation=json.loads(Path(a.observation).read_text(encoding="utf-8"))
        floor=(json.loads(Path(a.floor).read_text(encoding="utf-8"))
               if a.floor else None)
        out=audit(registry,observation,floor)
    else:
        out=hold()
    dest=Path(a.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-051 HOLD: independent fork continuity not authenticated")


if __name__=="__main__":
    main()
