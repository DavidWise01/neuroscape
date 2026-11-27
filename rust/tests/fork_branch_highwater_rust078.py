#!/usr/bin/env python3
"""RUST-078 — branch custody highwater with immutable two-branch ancestry.

Structural signatures and retained-floor claims cannot establish independent
physical custody, global highwater, or fork resolution. All authority HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from fork_branch_custody_rust077 import checked_history

ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checkpoint_payload(previous):
    events,heads=checked_history(previous)
    require(events,"RUST-077 predecessor must be nonempty")
    return {"phase":"RUST-078","kind":"FORK_BRANCH_CUSTODY_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "branch_pairs_sha256":digest([
                [e["branch_a_sha256"],e["branch_b_sha256"]] for e in events]),
            "branch_claims_sha256":digest([e["claims_sha256"] for e in events]),
            "conflicts_sha256":digest(previous["custody_conflicts"]),
            "source_rust077_receipt_sha256":previous["receipt_sha256"],
            "fork_resolved":False,"winner_selected":False,
            "recovery_authorized":False,"release_authorized":False}

def ancestry_findings(prior,added):
    historic=[w for e in prior for w in e["branches"]]
    conflicts=[]
    for event in added:
        for w in event["branches"]:
            for earlier in historic:
                if w["pin"]==earlier["pin"] and any(
                    w[k]!=earlier[k] for k in ORIGINS):
                    conflicts.append({"reason":"CUSTODIAN_PIN_CHANGED_ANCESTRY",
                        "pin":w["pin"],"independent_custody_verified":False})
                    break
                if w["pin"]!=earlier["pin"] and any(
                    w[k]==earlier[k] for k in ("controller_sha256","acquisition_sha256")):
                    conflicts.append({"reason":"RENAMED_CUSTODIAN_REUSED_ANCESTRY",
                        "pin":w["pin"],"independent_custody_verified":False})
                    break
    return conflicts

def audit(previous,current,checkpoint,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "new custody branch ledger must strictly extend predecessor")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historical branch custody prefix replaced")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],
            "historical ancestry conflicts were erased")
    require(all(e["branch_a_sha256"]!=e["branch_b_sha256"] for e in new),
            "custody branches collapsed")
    for event in new:
        require(event["both_branches_retained"] is True and
                all(event[k] is False for k in
                    ("winner_selected","fork_resolved","release_authorized",
                     "recovery_authorized","independent_custody_verified")),
                "historical custody authority falsely promoted")
    expected=checkpoint_payload(previous)
    require(checkpoint==expected,"signed branch custody checkpoint substituted")
    check_sha(signer_pin,"custody highwater signer pin missing")
    prior_witnesses={w["pin"] for e in new for w in e["branches"]}
    require(signer_pin not in prior_witnesses,
            "branch custodian cannot self-sign highwater")
    signed=verifier(key,signature,signer_pin,canonical(expected))
    check_sha(signed,"custody highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-078",
            "retained custody floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retained custody floor outside successor")
    check_sha(floor.get("head_sha256"),"retained floor SHA invalid")
    require(new_heads[n]==floor["head_sha256"],
            "retained custody floor contradicts exact prefix")
    added=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(added),
            "one fresh pair observation required per appended custody event")
    witness_nonces={w["nonce_sha256"] for e in new for w in e["branches"]}
    seen=set();rows=[];conflicts=ancestry_findings(old,added)
    past_pairs={tuple([e["branch_a_sha256"],e["branch_b_sha256"]]) for e in old}
    for e,obs in zip(added,observations):
        require(isinstance(obs,dict) and obs.get("phase")=="RUST-078",
                "custody-pair observation missing")
        for field in ("custody_entry_sha256","observation_nonce_sha256",
                      "branch_a_sha256","branch_b_sha256","claims_sha256"):
            check_sha(obs.get(field),"custody-pair claim missing "+field)
        require(obs["custody_entry_sha256"]==e["entry_sha256"] and
                obs["branch_a_sha256"]==e["branch_a_sha256"] and
                obs["branch_b_sha256"]==e["branch_b_sha256"] and
                obs["claims_sha256"]==e["claims_sha256"],
                "custody observation substituted branch or witness claims")
        nonce=obs["observation_nonce_sha256"]
        require(nonce not in witness_nonces and nonce not in seen,
                "custody highwater nonce replay")
        seen.add(nonce)
        require(obs.get("both_branches_retained") is True and
                all(obs.get(k) is False for k in
                    ("winner_selected","fork_resolved","release_authorized",
                     "recovery_authorized")),
                "custody observation falsely reconciled fork")
        if (e["branch_a_sha256"],e["branch_b_sha256"]) in past_pairs:
            conflicts.append({"reason":"REPEATED_BRANCH_PAIR_NEW_EPOCH",
                "entry_sha256":e["entry_sha256"],
                "independent_custody_verified":False})
        rows.append({"custody_entry_sha256":e["entry_sha256"],
            "observation_sha256":digest(obs),
            "observation_nonce_sha256":nonce,
            "both_branches_retained":True,"independent_custody_verified":False})
    output={"phase":"RUST-078",
        "status":"HOLD_BRANCH_CUSTODY_HIGHWATER_ANCESTRY",
        "previous_rust077_receipt_sha256":previous["receipt_sha256"],
        "current_rust077_receipt_sha256":current["receipt_sha256"],
        "signed_checkpoint":expected,
        "checkpoint_signature_sha256":signed,
        "checkpoint_signer_pin":signer_pin,
        "retained_floor_claim_sha256":digest(floor),
        "previous_event_count":len(old),"current_event_count":len(new),
        "previous_branch_pairs":[[e["branch_a_sha256"],e["branch_b_sha256"]] for e in old],
        "current_branch_pairs":[[e["branch_a_sha256"],e["branch_b_sha256"]] for e in new],
        "previous_claim_digests":[e["claims_sha256"] for e in old],
        "current_claim_digests":[e["claims_sha256"] for e in new],
        "historical_conflicts":previous["custody_conflicts"],
        "current_conflicts":current["custody_conflicts"],
        "cross_epoch_conflicts":conflicts,
        "new_pair_observations":rows,
        "both_branches_retained":True,
        "winner_selected":False,"fork_resolved":False,
        "independent_custody_verified":False,
        "global_anti_rollback_certified":False,
        "globally_latest_highwater_verified":False,
        "recovery_authorized":False,"release_authorized":False,
        "live_gameplay_authority":False}
    output["receipt_sha256"]=digest(output)
    return output

def hold():
    return {"phase":"RUST-078",
            "status":"HOLD_MISSING_BRANCH_CUSTODY_HIGHWATER",
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
    args=p.parse_args()
    bundle=[args.previous,args.current,args.checkpoint,args.key,args.signature,
            args.signer_pin,args.floor,args.observations]
    require(all(bundle) or not any(bundle),
            "partial branch custody highwater evidence refused")
    if all(bundle):
        read=lambda value:json.loads(Path(value).read_text(encoding="utf-8"))
        result=audit(read(args.previous),read(args.current),read(args.checkpoint),
                     args.key,args.signature,args.signer_pin,
                     read(args.floor),read(args.observations))
    else:result=hold()
    dest=Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-078 HOLD: independently retained custody unverified")
if __name__=="__main__":main()
