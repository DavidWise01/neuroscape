#!/usr/bin/env python3
"""RUST-060 — signed external-control highwater and fork reconciliation.

Validates each RUST-059 history end to end, compares exact control-event
prefixes, and preserves both sides of a fork. Pinned signatures are
cryptographic proof of key possession, not independent custody. HOLD only.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import check_sha, canonical, verify_key_and_signature
from external_control_rust059 import checked_history

def checkpoint_payload(history):
    events, heads = checked_history(history)
    require(events, "nonempty control ledger required")
    return {
        "phase": "RUST-060", "kind": "EXTERNAL_CONTROL_HIGHWATER_V1",
        "control_count": len(events), "head_sha256": heads[-1],
        "history_sha256": digest(events),
        "conflicts_sha256": digest(history["control_conflicts"]),
        "source_rust059_receipt_sha256": history["receipt_sha256"],
        "release_authorized": False,
    }

def compare(left, right):
    left_events, left_heads = checked_history(left)
    right_events, right_heads = checked_history(right)
    common = 0
    for i in range(1, min(len(left_heads), len(right_heads))):
        if left_heads[i] != right_heads[i]:
            break
        common = i
    diverged = (left_heads[:min(len(left_heads),len(right_heads))] !=
                right_heads[:min(len(left_heads),len(right_heads))])
    left_suffix = left_events[common:]
    right_suffix = right_events[common:]
    disagreements = []
    if diverged:
        disagreements.append({
            "kind": "INCOMPATIBLE_CONTROL_HISTORY",
            "common_prefix_count": common,
            "left_first_divergence_sha256": left_heads[common+1],
            "right_first_divergence_sha256": right_heads[common+1],
        })
    by_key = {}
    by_claimed_controller = {}
    for e in left_events:
        by_key.setdefault(e["custodian_pin"], set()).add((
            e["claimed_controller_sha256"], e["claimed_operator_sha256"],
            e["claimed_acquisition_sha256"]))
        by_claimed_controller.setdefault(e["claimed_controller_sha256"],set()).add(e["custodian_pin"])
    for e in right_suffix:
        claim=(e["claimed_controller_sha256"],e["claimed_operator_sha256"],
               e["claimed_acquisition_sha256"])
        if e["custodian_pin"] in by_key and claim not in by_key[e["custodian_pin"]]:
            disagreements.append({
                "kind": "CROSS_BRANCH_KEY_CONTROL_ANCESTRY_CONFLICT",
                "pin": e["custodian_pin"], "new_claim": list(claim),
                "left_claims": sorted([list(x) for x in by_key[e["custodian_pin"]]]),
            })
        other=by_claimed_controller.get(e["claimed_controller_sha256"],set())
        if other and e["custodian_pin"] not in other:
            disagreements.append({
                "kind": "CROSS_BRANCH_SHARED_CLAIMED_CONTROLLER",
                "pin":e["custodian_pin"],"prior_pins":sorted(other),
                "claimed_controller_sha256":e["claimed_controller_sha256"],
            })
    return common, diverged, disagreements

def audit(left,right,checkpoint,checkpoint_key,checkpoint_signature,
          checkpoint_pin,retained_floor,left_custody,right_custody,
          verifier=verify_key_and_signature):
    a, a_heads = checked_history(left)
    b, b_heads = checked_history(right)
    require(a and b, "two nonempty external-control branches required")
    expected=checkpoint_payload(left)
    require(checkpoint == expected,"signed highwater checkpoint altered")
    check_sha(checkpoint_pin,"pinned highwater signer missing")
    require(checkpoint_pin not in {e["custodian_pin"] for e in a+b},
            "custodian may not self-sign highwater")
    signature=verifier(checkpoint_key,checkpoint_signature,
                       checkpoint_pin,canonical(expected))
    check_sha(signature,"highwater signature invalid")
    require(isinstance(retained_floor,dict) and
            retained_floor.get("phase")=="RUST-060",
            "retained highwater floor missing")
    count=retained_floor.get("control_count")
    require(type(count) is int and 0<=count<=len(a),
            "retained floor beyond signed branch")
    check_sha(retained_floor.get("head_sha256"),"retained head invalid")
    require(a_heads[count]==retained_floor["head_sha256"],
            "signed branch contradicts retained floor")
    for custody in (left_custody,right_custody):
        require(isinstance(custody,dict) and custody.get("phase")=="RUST-060",
                "claimed custody acquisition record missing")
        for field in ("claimed_source_root_sha256","acquisition_sha256",
                      "claimed_operator_sha256","control_nonce_sha256"):
            check_sha(custody.get(field),"custody acquisition claim incomplete")
        require(custody.get("independence_authenticated") is False and
                custody.get("release_authorized") is False,
                "custody claim asserted operational authority")
    require(left_custody["control_nonce_sha256"]!=
            right_custody["control_nonce_sha256"],
            "duplicate external custody nonce")
    common,diverged,disagreements=compare(left,right)
    shared=(left_custody["claimed_source_root_sha256"]==
            right_custody["claimed_source_root_sha256"] or
            left_custody["acquisition_sha256"]==right_custody["acquisition_sha256"] or
            left_custody["claimed_operator_sha256"]==
            right_custody["claimed_operator_sha256"])
    if shared:
        disagreements.append({
            "kind":"SHARED_CLAIMED_EXTERNAL_CUSTODY_ANCESTRY",
            "independent_custody_verified":False})
    result={
        "phase":"RUST-060",
        "status":"HOLD_EXTERNAL_CONTROL_RECONCILIATION",
        "signed_left_checkpoint":expected,
        "signature_sha256":signature,
        "highwater_signer_pin":checkpoint_pin,
        "retained_floor_claim_sha256":digest(retained_floor),
        "left_receipt_sha256":left["receipt_sha256"],
        "right_receipt_sha256":right["receipt_sha256"],
        "left_count":len(a),"right_count":len(b),
        "left_head_sha256":a_heads[-1],"right_head_sha256":b_heads[-1],
        "common_prefix_count":common,
        "incompatible_history_detected":diverged,
        "left_branch_events_preserved":a,
        "right_branch_events_preserved":b,
        "left_control_conflicts_preserved":left["control_conflicts"],
        "right_control_conflicts_preserved":right["control_conflicts"],
        "left_custody_claim":left_custody,"right_custody_claim":right_custody,
        "reconciliation_disagreements":disagreements,
        "independent_custodians_authenticated":False,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "winner_selected":False,"fork_resolved":False,
        "release_authorized":False,"live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-060","status":"HOLD_MISSING_INDEPENDENT_CONTROL_CUSTODY",
            "independent_custodians_authenticated":False,
            "winner_selected":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False,
            "reason":"No separately acquired signed external-control highwaters"}

def main():
    p=argparse.ArgumentParser()
    for name in ("left","right","checkpoint","checkpoint-key",
                 "checkpoint-signature","checkpoint-pin","floor",
                 "left-custody","right-custody"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    vals=[a.left,a.right,a.checkpoint,a.checkpoint_key,a.checkpoint_signature,
          a.checkpoint_pin,a.floor,a.left_custody,a.right_custody]
    require(all(vals) or not any(vals),
            "partial external-control reconciliation refused")
    if all(vals):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(a.left),read(a.right),read(a.checkpoint),a.checkpoint_key,
                  a.checkpoint_signature,a.checkpoint_pin,read(a.floor),
                  read(a.left_custody),read(a.right_custody))
    else: out=hold()
    dest=Path(a.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-060 HOLD: independent custody not certified")
if __name__=="__main__":main()
