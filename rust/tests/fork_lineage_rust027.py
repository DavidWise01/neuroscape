#!/usr/bin/env python3
"""RUST-027 — reconstruct signed highwater branches without majority promotion.

The checkpoint graph is supplied evidence, not a trusted oracle. Missing graph
nodes or ambiguous ancestry cannot be fabricated. Each witness's observation
must trace through the supplied graph by exact SHA-256 links.
"""
import argparse
import json
from pathlib import Path

from highwater_rust025 import check_checkpoint
from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES

def validate_observations(witness_record):
    require(isinstance(witness_record, dict), "witness record absent")
    require(witness_record.get("phase") == "RUST-026", "unexpected witness phase")
    require(witness_record.get("status") in ("HOLD_FORK_EVIDENCE", "CONSISTENT_SIGNED_SNAPSHOTS"),
            "unsigned or incomplete RUST-026 evidence")
    require(witness_record.get("release_authorized") is False, "witness must not grant authority")
    require(witness_record.get("independent_custody_ancestries_verified") is False,
            "unsupported independent custody claim")
    require(digest({k:v for k,v in witness_record.items() if k!="receipt_sha256"})
            == witness_record.get("receipt_sha256"), "witness receipt digest mismatch")
    observations = witness_record.get("observations")
    require(isinstance(observations, list) and len(observations)==3, "three witnesses required")
    require([x.get("role") for x in observations] == list(ROLES), "witness roles mismatch")
    require(all(x.get("signature_verified") is True for x in observations),
            "unsigned witness snapshot")
    require(len({x.get("key_spki_sha256") for x in observations}) == 3,
            "duplicated witness signing key")
    return observations

def reconstruct(witness_record, checkpoints):
    observations=validate_observations(witness_record)
    require(isinstance(checkpoints, list), "checkpoint graph must be an array")
    nodes={}
    for item in checkpoints:
        node=check_checkpoint(item)
        key=node["candidate_sha256"]
        require(key not in nodes, "duplicate candidate graph node")
        nodes[key]=node
    branches=[]
    for observed in observations:
        head=observed.get("candidate_sha256")
        require(head in nodes, "witness head missing from graph")
        node=nodes[head]
        require(all(observed.get(field)==node.get(field) for field in (
            "source_commit","sequence","epoch","entry_sha256","previous_highwater_sha256"
        )), "witness graph content mismatch")
        history=[]
        seen=set()
        current=head
        missing=None
        while current in nodes:
            require(current not in seen, "cycle in checkpoint graph")
            seen.add(current)
            item=nodes[current]
            if history:
                child=nodes[history[-1]]
                require(child["sequence"]==item["sequence"]+1, "sequence gap")
                require(child["epoch"]>=item["epoch"], "epoch rollback")
                require(child["source_commit"]!=item["source_commit"], "replayed source commit")
                require(child["entry_sha256"]!=item["entry_sha256"], "replayed entry digest")
            history.append(current)
            predecessor=item["previous_highwater_sha256"]
            if predecessor not in nodes:
                missing=predecessor
                break
            current=predecessor
        branches.append({
            "role":observed["role"],
            "head_sha256":head,
            "source_commit":node["source_commit"],
            "history_newest_first":history,
            "missing_predecessor_sha256":missing,
            "history_complete":missing is None,
            "signing_key_spki_sha256":observed["key_spki_sha256"],
            "signature_sha256":observed["signature_sha256"],
        })
    sets=[set(b["history_newest_first"]) for b in branches]
    shared=set.intersection(*sets)
    # A common ancestor is only *observed* if its node bytes are present;
    # the oldest shared link need not be an authenticated genesis.
    common=max(shared,key=lambda h:nodes[h]["sequence"]) if shared else None
    heads={b["head_sha256"] for b in branches}
    status="HOLD_FORK_EVIDENCE" if len(heads)>1 else "HOLD_UNVERIFIED_CUSTODY"
    if common is None:
        status="HOLD_NO_PROVEN_COMMON_ANCESTOR"
    elif any(b["missing_predecessor_sha256"] is not None for b in branches):
        status="HOLD_INCOMPLETE_ANCESTRY" if len(heads)==1 else "HOLD_FORK_INCOMPLETE_ANCESTRY"
    record={
        "phase":"RUST-027","status":status,
        "branches":branches,
        "supplied_checkpoint_count":len(nodes),
        "observed_common_ancestor_sha256":common,
        "observed_common_ancestor_sequence":nodes[common]["sequence"] if common else None,
        "fork_heads_sha256":sorted(heads),
        "fork_detected":len(heads)>1,
        "single_repository_source_ancestry":True,
        "independent_custody_ancestries_verified":False,
        "external_latest_checkpoint_confirmed":False,
        "global_anti_rollback_certified":False,
        "release_authorized":False,
        "live_gameplay_authority":False,
    }
    record["receipt_sha256"]=digest(record)
    return record

def hold():
    return {
        "phase":"RUST-027","status":"HOLD_MISSING_FORK_GRAPH",
        "branches":[],"release_authorized":False,
        "independent_custody_ancestries_verified":False,
        "live_gameplay_authority":False,
        "reason":"Three signed observations and checkpoint graph are not externally supplied",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--witness")
    p.add_argument("--checkpoints")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    require(bool(args.witness)==bool(args.checkpoints),"partial graph input not accepted")
    if args.witness:
        evidence=json.loads(Path(args.witness).read_text(encoding="utf-8"))
        graph=json.loads(Path(args.checkpoints).read_text(encoding="utf-8"))
        result=reconstruct(evidence,graph)
    else:
        result=hold()
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if result["status"].startswith("HOLD") and not args.allow_hold_record:
        raise SystemExit("RUST-027 HOLD: graph incomplete or fork disagreement")

if __name__=="__main__":
    main()
