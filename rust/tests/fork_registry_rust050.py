#!/usr/bin/env python3
"""RUST-050 — persistent fork registry and custody-evidence exchange.

Append-only registry of RUST-049 observations. Revalidates hash-linked
history and independently recalculates reported fork facts from both
branches. Prior conflicts never disappear when later checkpoints
converge. Evidence is not a second signature verification: upstream
RUST-049 is receipt-hash checked; live signatures require its source
material. No custody or release authority is inferred.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import check_sha

GENESIS = digest({"phase":"RUST-050","kind":"FORK_REGISTRY_GENESIS_V1"})
ALLOWED = ("HOLD_CONFLICTING_DENIAL_HIGHWATERS",
           "HOLD_SHARED_CUSTODY_ANCESTRY",
           "HOLD_EXTERNAL_CUSTODY_UNVERIFIED")


def checked_observation(obs):
    require(isinstance(obs, dict) and obs.get("phase") == "RUST-049"
            and obs.get("status") in ALLOWED, "RUST-049 evidence missing")
    require(obs.get("fork_resolved") is False and
            obs.get("release_authorized") is False and
            obs.get("independent_custodian_control_verified") is False,
            "upstream authority promotion")
    require(digest({k:v for k,v in obs.items() if k!="receipt_sha256"}) ==
            obs.get("receipt_sha256"), "RUST-049 receipt altered")
    branches = []
    for key in ("left_branch","right_branch"):
        branch = obs.get(key)
        require(isinstance(branch,dict), "missing evidence branch")
        count = branch.get("denial_count")
        heads = branch.get("prefix_heads")
        require(type(count) is int and count >= 1 and
                isinstance(heads,list) and len(heads)==count+1,
                "branch history count mismatch")
        for h in heads:
            check_sha(h,"branch prefix hash invalid")
        for field in ("branch_sha256","head_sha256","denial_history_sha256",
                      "rust047_receipt_sha256","custody_root_sha256",
                      "acquisition_sha256","signer_pin","signature_sha256"):
            check_sha(branch.get(field),"branch evidence fingerprint missing")
        require(branch["head_sha256"] == heads[-1],
                "branch terminal head altered")
        require(branch.get("independent_custody_authenticated") is False,
                "branch asserted independent custody")
        branches.append(branch)
    a,b = branches
    require(a["signer_pin"]!=b["signer_pin"],
            "duplicate custody signer key")
    shared = (a["custody_root_sha256"] == b["custody_root_sha256"]
              or a["acquisition_sha256"] == b["acquisition_sha256"])
    require(obs.get("shared_claimed_custody_ancestry") is shared,
            "shared custody ancestry misreported")
    n=min(a["denial_count"],b["denial_count"])
    common=0
    for i in range(n+1):
        if a["prefix_heads"][i]!=b["prefix_heads"][i]:
            break
        common=i
    conflict = a["prefix_heads"][n] != b["prefix_heads"][n]
    evidence=obs.get("same_count_fork_evidence")
    if conflict:
        require(isinstance(evidence,dict) and evidence.get("kind")==
                "INCOMPATIBLE_DENIAL_ANCESTRY",
                "conflicting branches not recorded")
        require(evidence.get("common_prefix_count")==common and
                evidence.get("compared_count")==n and
                evidence.get("left_prefix_sha256")==a["prefix_heads"][n] and
                evidence.get("right_prefix_sha256")==b["prefix_heads"][n] and
                evidence.get("left_branch_sha256")==a["branch_sha256"] and
                evidence.get("right_branch_sha256")==b["branch_sha256"] and
                evidence.get("winner_selected") is False and
                evidence.get("both_branches_preserved") is True,
                "conflict evidence rewritten")
        require(obs["status"]=="HOLD_CONFLICTING_DENIAL_HIGHWATERS",
                "fork status downgraded")
    else:
        require(evidence is None and obs["status"]==
                ("HOLD_SHARED_CUSTODY_ANCESTRY" if shared else
                 "HOLD_EXTERNAL_CUSTODY_UNVERIFIED"),
                "fork or custody status inconsistent")
    require(obs.get("highest_observed_denial_count")==
            max(a["denial_count"],b["denial_count"]),
            "reported highwater inconsistent")
    return branches,evidence,shared


def genesis():
    result={"phase":"RUST-050","status":"HOLD_PERSISTENT_FORK_REGISTRY",
            "entries":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
            "entry_count":0,"fork_events":[],
            "custody_ancestry_alerts":[],
            "release_authorized":False,"fork_resolved":False,
            "independent_custody_verified":False}
    result["receipt_sha256"]=digest(result)
    return result


def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-050"
            and history.get("status")=="HOLD_PERSISTENT_FORK_REGISTRY",
            "RUST-050 predecessor registry missing")
    require(history.get("release_authorized") is False and
            history.get("fork_resolved") is False,
            "previous registry promoted authority")
    entries=history.get("entries")
    heads=history.get("prefix_heads")
    require(isinstance(entries,list) and isinstance(heads,list)
            and len(heads)==len(entries)+1 and heads[0]==GENESIS,
            "registry history missing or truncated")
    chain=GENESIS
    receipts=set()
    observed_forks=[]
    observed_alerts=[]
    for i,entry in enumerate(entries,1):
        require(isinstance(entry,dict) and
                entry.get("phase")=="RUST-050" and
                entry.get("kind")=="FORK_REGISTRY_EVENT" and
                entry.get("ordinal")==i and
                entry.get("previous_entry_sha256")==chain,
                "registry entry order/prefix changed")
        check_sha(entry.get("upstream_rust049_receipt_sha256"),
                  "source receipt fingerprint missing")
        require(entry["upstream_rust049_receipt_sha256"] not in receipts,
                "historical RUST-049 evidence replay")
        receipts.add(entry["upstream_rust049_receipt_sha256"])
        require(entry.get("fork_event") is None or
                isinstance(entry.get("fork_event"),dict),
                "fork evidence missing")
        if entry["fork_event"] is not None:
            observed_forks.append(entry["fork_event"])
        if entry.get("shared_custody_alert") is not None:
            observed_alerts.append(entry["shared_custody_alert"])
        require(entry.get("release_authorized") is False and
                entry.get("fork_resolved") is False,
                "registry entry promoted authority")
        require(digest({k:v for k,v in entry.items()
                        if k!="entry_sha256"})==entry.get("entry_sha256"),
                "registry entry digest altered")
        chain=entry["entry_sha256"]
        require(heads[i]==chain,"registry prefix head modified")
    require(history.get("head_sha256")==chain and
            history.get("entry_count")==len(entries),
            "registry head/count modified")
    require(history.get("fork_events")==observed_forks and
            history.get("custody_ancestry_alerts")==observed_alerts,
            "historical fork/ancestry alerts discarded")
    require(digest({k:v for k,v in history.items()
                    if k!="receipt_sha256"})==history.get("receipt_sha256"),
            "registry receipt altered")
    return entries,heads


def audit(observation,history,floor=None):
    branches,fork,shared=checked_observation(observation)
    old,heads=checked_history(history)
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-050",
                "retained registry floor missing")
        count=floor.get("entry_count")
        require(type(count) is int and 0<=count<len(heads),
                "retained fork registry floor exceeds history")
        check_sha(floor.get("head_sha256"),"retained registry head invalid")
        require(heads[count]==floor["head_sha256"],
                "retained fork registry rewritten or withheld")
    require(observation["receipt_sha256"] not in {
            x["upstream_rust049_receipt_sha256"] for x in old},
            "cross-custody exchange receipt replay")
    event={
        "phase":"RUST-050","kind":"FORK_REGISTRY_EVENT",
        "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
        "upstream_rust049_receipt_sha256":observation["receipt_sha256"],
        "source_branch_snapshots":[{
            "branch_sha256":b["branch_sha256"],
            "denial_count":b["denial_count"],
            "head_sha256":b["head_sha256"],
            "prefix_heads":b["prefix_heads"],
            "custody_root_sha256":b["custody_root_sha256"],
            "acquisition_sha256":b["acquisition_sha256"],
            "signer_pin":b["signer_pin"],
        } for b in branches],
        "fork_event":({
            "source_receipt_sha256":observation["receipt_sha256"],
            "fork_evidence":fork,
            "left_branch_sha256":branches[0]["branch_sha256"],
            "right_branch_sha256":branches[1]["branch_sha256"],
            "winner_selected":False,
        } if fork is not None else None),
        "shared_custody_alert":({
            "source_receipt_sha256":observation["receipt_sha256"],
            "branch_fingerprints":[b["branch_sha256"] for b in branches],
            "shared_claimed_source":branches[0]["custody_root_sha256"]==
                                    branches[1]["custody_root_sha256"],
            "shared_acquisition_path":branches[0]["acquisition_sha256"]==
                                      branches[1]["acquisition_sha256"],
        } if shared else None),
        "fork_resolved":False,"release_authorized":False,
    }
    event["entry_sha256"]=digest(event)
    entries=old+[event]
    new_heads=heads+[event["entry_sha256"]]
    forks=list(history["fork_events"])
    alerts=list(history["custody_ancestry_alerts"])
    if event["fork_event"] is not None:
        forks.append(event["fork_event"])
    if event["shared_custody_alert"] is not None:
        alerts.append(event["shared_custody_alert"])
    result={
        "phase":"RUST-050","status":"HOLD_PERSISTENT_FORK_REGISTRY",
        "entries":entries,"prefix_heads":new_heads,
        "head_sha256":new_heads[-1],"entry_count":len(entries),
        "fork_events":forks,"custody_ancestry_alerts":alerts,
        "latest_source_receipt_sha256":observation["receipt_sha256"],
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
        "independent_evidence_custody_authenticated":False,
        "globally_latest_fork_registry_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result


def hold():
    return {"phase":"RUST-050","status":"HOLD_MISSING_EXTERNAL_FORK_CUSTODY",
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False,
            "independent_evidence_custody_authenticated":False,
            "reason":"RUST-049 signed exchange and retained fork registry not available"}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--observation")
    p.add_argument("--history")
    p.add_argument("--floor")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.observation)==bool(a.history),
            "partial fork registry material refused")
    require(not a.floor or (a.observation and a.history),
            "floor without registry observation refused")
    if a.observation:
        result=audit(json.loads(Path(a.observation).read_text(encoding="utf-8")),
                     json.loads(Path(a.history).read_text(encoding="utf-8")),
                     json.loads(Path(a.floor).read_text(encoding="utf-8"))
                     if a.floor else None)
    else:
        result=hold()
    destination=Path(a.output)
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-050 HOLD: independent custody and fork adjudication unverified")


if __name__=="__main__":
    main()
