#!/usr/bin/env python3
"""RUST-080: Signed custodian ancestry highwater and cross-epoch exclusion.

This validates supplied structural lineage only. It does not independently
authenticate the custodian, control, global latestness, or custody.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from custodian_ancestry_rust079 import checked_history,ORIGINS

def checkpoint_payload(previous):
    events,heads=checked_history(previous)
    require(events,"nonempty RUST-079 ancestry predecessor required")
    return {"phase":"RUST-080","kind":"CUSTODIAN_ANCESTRY_HIGHWATER_V1",
        "event_count":len(events),"head_sha256":heads[-1],
        "events_sha256":digest(events),
        "claims_sha256":digest(previous["custodian_claims"]),
        "conflicts_sha256":digest(previous["custody_conflicts"]),
        "source_rust079_receipt_sha256":previous["receipt_sha256"],
        "independent_custody_verified":False,"fork_resolved":False,
        "recovery_authorized":False,"release_authorized":False}

def exclusion_findings(older,newer):
    """Conflicting fingerprints persist even when keys are renamed."""
    findings=[]
    for claim in newer:
        for prior in older:
            if claim["signer_pin"]==prior["signer_pin"]:
                changed=[f for f in ORIGINS if claim[f]!=prior[f]]
                if changed:
                    findings.append({"reason":"EXCLUDED_SIGNER_CHANGED_CLAIMED_CONTROL",
                        "new_pin":claim["signer_pin"],"prior_pin":prior["signer_pin"],
                        "fields":changed,"independent_custody_verified":False})
            else:
                overlap=[f for f in ORIGINS if claim[f]==prior[f]]
                if overlap:
                    findings.append({"reason":"RENAMED_SIGNER_REUSES_EXCLUDED_ANCESTRY",
                        "new_pin":claim["signer_pin"],"prior_pin":prior["signer_pin"],
                        "fields":overlap,"independent_custody_verified":False})
    return findings

def audit(previous,current,checkpoint,key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "ancestry successor must strictly extend predecessor")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historical ancestry event prefix erased or rewritten")
    for field in ("custodian_claims","custody_conflicts"):
        require(current[field][:len(previous[field])]==previous[field],
                "historical ancestry exclusion evidence erased: "+field)
    require(all(e["both_branches_retained"] is True and
                all(e[k] is False for k in
                    ("independent_custody_verified","fork_resolved",
                     "winner_selected","recovery_authorized","release_authorized"))
                for e in new),"fork ancestry promoted to authority")
    payload=checkpoint_payload(previous)
    require(checkpoint==payload,"signed ancestry highwater substituted")
    check_sha(signer_pin,"ancestry checkpoint signer invalid")
    prohibited={c["signer_pin"] for c in current["custodian_claims"]}
    prohibited.update(e["signer_pin"] for e in new)
    require(signer_pin not in prohibited,
            "source custodian/registrar cannot self-sign highwater")
    signed=verifier(key,signature,signer_pin,canonical(payload))
    check_sha(signed,"highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-080",
            "separately retained ancestry floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(old)<=n<=len(new),
            "retained ancestry floor outside successor ledger")
    check_sha(floor.get("head_sha256"),"retained ancestry floor hash invalid")
    require(new_heads[n]==floor["head_sha256"],
            "retained ancestry floor contradicts exact prefix")
    added=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(added),
            "one fresh ancestry observation per appended epoch required")
    used_nonces={e["observation_nonce_sha256"] for e in new}
    fresh=set();rows=[]
    conflicts=exclusion_findings(previous["custodian_claims"],
                                current["custodian_claims"][len(previous["custodian_claims"]):])
    past_conflict_pins={
        c[p] for c in previous["custody_conflicts"]
        for p in ("new_pin","prior_pin") if isinstance(c,dict) and isinstance(c.get(p),str)}
    past_controllers={c["controller_sha256"] for c in previous["custodian_claims"]}
    past_acquisitions={c["acquisition_sha256"] for c in previous["custodian_claims"]}
    for event,observation in zip(added,observations):
        require(isinstance(observation,dict) and
                observation.get("phase")=="RUST-080",
                "ancestry highwater observation missing")
        for f in ("ancestry_entry_sha256","observation_nonce_sha256",
                  "claims_sha256","branch_a_sha256","branch_b_sha256"):
            check_sha(observation.get(f),"ancestry highwater observation missing "+f)
        expected_pair=event["claims"]
        require(observation["ancestry_entry_sha256"]==event["entry_sha256"] and
                observation["claims_sha256"]==event["claims_sha256"] and
                observation["branch_a_sha256"]==expected_pair[0]["branch_sha256"] and
                observation["branch_b_sha256"]==expected_pair[1]["branch_sha256"],
                "ancestry highwater observation substituted claims or branch")
        nonce=observation["observation_nonce_sha256"]
        require(nonce not in used_nonces and nonce not in fresh,
                "ancestry highwater nonce replay")
        fresh.add(nonce)
        require(observation.get("both_branches_retained") is True and
                all(observation.get(k) is False for k in
                    ("fork_resolved","winner_selected",
                     "independent_custody_verified",
                     "recovery_authorized","release_authorized")),
                "ancestry highwater observation asserted authority")
        for claim in expected_pair:
            if claim["signer_pin"] in past_conflict_pins:
                conflicts.append({"reason":"PRIOR_CONFLICT_SIGNER_REENTERED",
                    "signer_pin":claim["signer_pin"],
                    "independent_custody_verified":False})
            if claim["controller_sha256"] in past_controllers or (
                    claim["acquisition_sha256"] in past_acquisitions):
                conflicts.append({"reason":"PAST_CONTROL_ANCESTRY_PERSISTS",
                    "signer_pin":claim["signer_pin"],
                    "independent_custody_verified":False})
        rows.append({"ancestry_entry_sha256":event["entry_sha256"],
            "observation_sha256":digest(observation),
            "observation_nonce_sha256":nonce,
            "both_branches_retained":True,"independent_custody_verified":False})
    out={"phase":"RUST-080",
         "status":"HOLD_CUSTODIAN_ANCESTRY_HIGHWATER_EXCLUSION",
         "previous_rust079_receipt_sha256":previous["receipt_sha256"],
         "current_rust079_receipt_sha256":current["receipt_sha256"],
         "signed_checkpoint":payload,"checkpoint_signature_sha256":signed,
         "checkpoint_signer_pin":signer_pin,
         "retained_floor_claim_sha256":digest(floor),
         "previous_count":len(old),"current_count":len(new),
         "historical_claims_preserved":previous["custodian_claims"],
         "current_claims_preserved":current["custodian_claims"],
         "historical_conflicts_preserved":previous["custody_conflicts"],
         "current_conflicts_preserved":current["custody_conflicts"],
         "cross_epoch_exclusion_conflicts":conflicts,
         "new_ancestry_observations":rows,
         "both_branches_retained":True,"winner_selected":False,
         "fork_resolved":False,"independent_custody_verified":False,
         "globally_latest_highwater_verified":False,
         "global_anti_rollback_certified":False,
         "recovery_authorized":False,"release_authorized":False,
         "live_gameplay_authority":False}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-080",
            "status":"HOLD_MISSING_CUSTODIAN_ANCESTRY_HIGHWATER",
            "both_branches_retained":False,"winner_selected":False,
            "fork_resolved":False,"independent_custody_verified":False,
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
            "partial custodian ancestry highwater bundle refused")
    if all(args):
        load=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        output=audit(load(a.previous),load(a.current),load(a.checkpoint),
                     a.key,a.signature,a.signer_pin,load(a.floor),
                     load(a.observations))
    else:output=hold()
    destination=Path(a.output)
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("x",encoding="utf-8") as stream:
        json.dump(output,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(output,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-080 HOLD: independent custodian control unverified")
if __name__=="__main__":main()
