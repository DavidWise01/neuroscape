#!/usr/bin/env python3
"""RUST-062: signed retention highwater and cross-custodian fork persistence.

Checks complete RUST-061 histories and separately signed custodian
observations. A signature proves only key possession; custody HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from reconciliation_retention_rust061 import checked_history

def highwater(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty retained reconciliation history required")
    return {"phase":"RUST-062","kind":"RETENTION_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "unresolved_disputes_sha256":digest(previous["unresolved_disputes"]),
            "source_rust061_receipt_sha256":previous["receipt_sha256"],
            "release_authorized":False}

def challenge(source,old_head,claim):
    keys=("signer_pin","source_root_sha256","acquisition_sha256",
          "operator_control_sha256","nonce_sha256")
    for k in keys:check_sha(claim.get(k),"custodian retention claim missing "+k)
    return {"phase":"RUST-062","kind":"CROSS_CUSTODY_FORK_PERSISTENCE_V1",
            "source_rust061_receipt_sha256":source["receipt_sha256"],
            "prior_reconciliation_head_sha256":old_head,
            "retained_branch_pair_sha256":digest([
                [e["left_branch_sha256"],e["right_branch_sha256"]]
                for e in source["events"]]),
            **{k:claim[k] for k in keys},
            "fork_resolved":False,"release_authorized":False}

def audit(previous,current,checkpoint,checkpoint_key,checkpoint_sig,
          checkpoint_pin,floor,claims,verifier=verify_key_and_signature):
    old,heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),"successor retention must strictly extend prior")
    require(new[:len(old)]==old and new_heads[:len(heads)]==heads,
            "prior reconciliation branch history truncated or rewritten")
    require(current["unresolved_disputes"][:len(previous["unresolved_disputes"])]==
            previous["unresolved_disputes"],"earlier reconciliation disputes erased")
    expected=highwater(previous)
    require(checkpoint==expected,"signed retention checkpoint substituted")
    check_sha(checkpoint_pin,"highwater signing pin missing")
    historical_pins={e["retention_pin"] for e in new}
    require(checkpoint_pin not in historical_pins,
            "retention witness cannot self-certify highwater")
    signed=verifier(checkpoint_key,checkpoint_sig,checkpoint_pin,canonical(expected))
    check_sha(signed,"checkpoint signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-062",
            "external retained floor missing")
    count=floor.get("event_count")
    require(type(count) is int and len(old)<=count<=len(new),
            "retained highwater outside available successor range")
    check_sha(floor.get("head_sha256"),"retained floor head invalid")
    require(new_heads[count]==floor["head_sha256"],
            "retained floor contradicts recovery history")
    require(isinstance(claims,list) and len(claims)==2,
            "two independently claimed custody observations required")
    pins=set();nonces=set();signed_claims=[]
    for c in claims:
        require(isinstance(c,dict),"custodian observation missing")
        message=challenge(current,heads[-1],c)
        require(c.get("fork_resolved") is False and
                c.get("release_authorized") is False,
                "custodian attempted fork clearance")
        pin=message["signer_pin"];nonce=message["nonce_sha256"]
        require(pin not in pins and pin!=checkpoint_pin,
                "custody signer duplicate or self-attesting")
        require(nonce not in nonces and
                nonce not in {e["retention_nonce_sha256"] for e in new},
                "retention challenge nonce replay")
        pins.add(pin);nonces.add(nonce)
        sig=verifier(c.get("public_key"),c.get("signature"),
                     pin,canonical(message))
        check_sha(sig,"custody challenge signature invalid")
        signed_claims.append({"pin":pin,"nonce_sha256":nonce,
                              "message_sha256":digest(message),
                              "signature_sha256":sig,
                              "source_root_sha256":message["source_root_sha256"],
                              "acquisition_sha256":message["acquisition_sha256"],
                              "operator_control_sha256":message["operator_control_sha256"],
                              "independent_custody_authenticated":False})
    conflict=[]
    for key in ("source_root_sha256","acquisition_sha256",
                "operator_control_sha256"):
        if signed_claims[0][key]==signed_claims[1][key]:
            conflict.append({"reason":"SHARED_CLAIMED_CUSTODIAN_ANCESTRY",
                             "shared_field":key,"independent_custody_verified":False})
    prior_forks=[{"left":e["left_branch_sha256"],"right":e["right_branch_sha256"],
                  "disagreements_sha256":digest(e["disagreements"])}
                 for e in old]
    current_forks=[{"left":e["left_branch_sha256"],"right":e["right_branch_sha256"],
                    "disagreements_sha256":digest(e["disagreements"])}
                   for e in new]
    require(current_forks[:len(prior_forks)]==prior_forks,
            "historical fork fingerprint removed")
    result={"phase":"RUST-062",
            "status":"HOLD_CROSS_CUSTODY_RETENTION_HIGHWATER",
            "previous_rust061_receipt_sha256":previous["receipt_sha256"],
            "current_rust061_receipt_sha256":current["receipt_sha256"],
            "signed_checkpoint":expected,"checkpoint_signature_sha256":signed,
            "checkpoint_pin":checkpoint_pin,
            "retained_floor_claim_sha256":digest(floor),
            "previous_count":len(old),"current_count":len(new),
            "history_prefix_preserved":True,
            "historical_forks_preserved":prior_forks,
            "current_forks_preserved":current_forks,
            "historical_disputes_preserved":previous["unresolved_disputes"],
            "current_disputes_preserved":current["unresolved_disputes"],
            "custody_challenges":signed_claims,
            "custody_ancestry_conflicts":conflict,
            "independent_custodians_authenticated":False,
            "globally_latest_highwater_verified":False,
            "global_anti_rollback_certified":False,
            "winner_selected":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-062","status":"HOLD_MISSING_CROSS_CUSTODY_RETENTION",
            "independent_custodians_authenticated":False,
            "winner_selected":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False,
            "reason":"No externally retained highwater and signed independent custody observations"}

def main():
    p=argparse.ArgumentParser()
    for name in ("previous","current","checkpoint","checkpoint-key",
                 "checkpoint-signature","checkpoint-pin","floor","claims"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    vals=[args.previous,args.current,args.checkpoint,args.checkpoint_key,
          args.checkpoint_signature,args.checkpoint_pin,args.floor,args.claims]
    require(all(vals) or not any(vals),"partial RUST-062 evidence refused")
    if all(vals):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(args.previous),read(args.current),read(args.checkpoint),
                  args.checkpoint_key,args.checkpoint_signature,args.checkpoint_pin,
                  read(args.floor),read(args.claims))
    else:out=hold()
    path=Path(args.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-062 HOLD: independent custodial retention not verified")
if __name__=="__main__":main()
