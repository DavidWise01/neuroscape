#!/usr/bin/env python3
"""RUST-063: cross-custody fork registry with fresh retention replay fencing.

The verifier checks locally supplied hash-linked evidence and pinned
signatures. No external witness or independent custody is certified.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

GENESIS = digest({"phase": "RUST-063", "kind": "CROSS_CUSTODY_FORK_GENESIS_V1"})
KEYS = ("source_root_sha256", "acquisition_sha256", "operator_control_sha256")


def checked_source(source):
    require(isinstance(source, dict) and source.get("phase") == "RUST-062"
            and source.get("status") == "HOLD_CROSS_CUSTODY_RETENTION_HIGHWATER",
            "RUST-062 assessment missing")
    require(all(source.get(f) is False for f in (
            "independent_custodians_authenticated", "winner_selected",
            "fork_resolved", "release_authorized", "live_gameplay_authority")),
            "upstream assessment asserted authority")
    require(digest({k:v for k,v in source.items() if k != "receipt_sha256"}) ==
            source.get("receipt_sha256"), "RUST-062 receipt altered")
    forks = source.get("current_forks_preserved")
    prior = source.get("historical_forks_preserved")
    require(isinstance(forks, list) and forks and isinstance(prior, list) and
            forks[:len(prior)] == prior and
            len(forks) == source.get("current_count"), "fork history incomplete")
    disputes = source.get("current_disputes_preserved")
    old_disputes = source.get("historical_disputes_preserved")
    require(isinstance(disputes, list) and isinstance(old_disputes, list) and
            disputes[:len(old_disputes)] == old_disputes,
            "historical reconciliation disputes missing")
    for fork in forks:
        for field in ("left", "right", "disagreements_sha256"):
            check_sha(fork.get(field), "source fork hash invalid")
    observations = source.get("custody_challenges")
    require(isinstance(observations, list) and len(observations) == 2 and
            all(c.get("independent_custody_authenticated") is False
                for c in observations), "two unresolved custody observations required")
    return forks, observations


def genesis():
    record = {"phase": "RUST-063", "status": "HOLD_CROSS_CUSTODY_FORK_REGISTRY",
              "events": [], "prefix_heads": [GENESIS], "head_sha256": GENESIS,
              "event_count": 0, "fork_keys": [], "custody_conflicts": [],
              "winner_selected": False, "fork_resolved": False,
              "release_authorized": False, "independent_custody_verified": False}
    record["receipt_sha256"] = digest(record)
    return record


def checked_history(registry):
    require(isinstance(registry, dict) and registry.get("phase") == "RUST-063"
            and registry.get("status") == "HOLD_CROSS_CUSTODY_FORK_REGISTRY"
            and all(registry.get(f) is False for f in (
                "winner_selected", "fork_resolved", "release_authorized",
                "independent_custody_verified")), "RUST-063 registry missing")
    rows, heads = registry.get("events"), registry.get("prefix_heads")
    require(isinstance(rows, list) and isinstance(heads, list) and
            len(heads) == len(rows)+1 and heads[0] == GENESIS,
            "historical fork registry truncated")
    prior_head = GENESIS
    source_receipts, nonces, messages = set(), set(), set()
    all_forks, conflicts = [], []
    for ordinal, row in enumerate(rows, 1):
        require(isinstance(row, dict) and row.get("phase") == "RUST-063" and
                row.get("kind") == "CROSS_CUSTODY_FORK_ENTRY" and
                row.get("ordinal") == ordinal and
                row.get("previous_entry_sha256") == prior_head and
                all(row.get(f) is False for f in (
                    "winner_selected", "fork_resolved", "release_authorized")),
                "historical fork entry changed")
        receipt = row.get("source_rust062_receipt_sha256")
        check_sha(receipt, "fork source receipt invalid")
        require(receipt not in source_receipts, "historical source receipt replay")
        source_receipts.add(receipt)
        forks = row.get("forks")
        require(isinstance(forks, list) and forks, "historical forks missing")
        for fork in forks:
            check_sha(fork.get("fork_key_sha256"), "historical fork key missing")
            for key in ("left", "right", "disagreements_sha256"):
                check_sha(fork.get(key), "historical fork branch missing")
            require(fork["fork_key_sha256"] == digest({
                k: fork[k] for k in ("left", "right", "disagreements_sha256")}),
                "historical fork key substituted")
        require(row.get("historical_fork_keys") == all_forks and
                row.get("fork_keys") == [f["fork_key_sha256"] for f in forks],
                "earlier fork keys omitted")
        require(row["fork_keys"][:len(all_forks)] == all_forks,
                "historical fork continuity broken")
        all_forks = row["fork_keys"]
        witnesses = row.get("witnesses")
        require(isinstance(witnesses, list) and len(witnesses) == 2,
                "historical witness evidence incomplete")
        for w in witnesses:
            for field in ("pin", "nonce_sha256", "message_sha256",
                          "signature_sha256", *KEYS):
                check_sha(w.get(field), "historical witness field invalid")
            require(w["nonce_sha256"] not in nonces and
                    w["message_sha256"] not in messages,
                    "historical witness challenge replay")
            nonces.add(w["nonce_sha256"])
            messages.add(w["message_sha256"])
        require(isinstance(row.get("conflicts"), list),
                "historical custody conflicts missing")
        conflicts += row["conflicts"]
        require(digest({k:v for k,v in row.items() if k != "entry_sha256"}) ==
                row.get("entry_sha256"), "historical fork entry hash changed")
        prior_head = row["entry_sha256"]
        require(heads[ordinal] == prior_head, "historical prefix head changed")
    require(registry.get("event_count") == len(rows) and
            registry.get("head_sha256") == prior_head and
            registry.get("fork_keys") == all_forks and
            registry.get("custody_conflicts") == conflicts,
            "historical forks or conflicts erased")
    require(digest({k:v for k,v in registry.items() if k != "receipt_sha256"}) ==
            registry.get("receipt_sha256"), "registry receipt altered")
    return rows, heads


def payload(source, last_head, fork_hash, witness, nonce):
    check_sha(fork_hash, "fork snapshot hash missing")
    check_sha(nonce, "witness challenge nonce missing")
    for key in ("signer_pin", *KEYS):
        check_sha(witness.get(key), "witness claim field missing: "+key)
    return {"phase":"RUST-063", "kind":"FORK_RETENTION_CHALLENGE_V1",
            "source_rust062_receipt_sha256":source["receipt_sha256"],
            "prior_registry_head_sha256":last_head,
            "all_forks_sha256":fork_hash,
            "signer_pin":witness["signer_pin"],
            **{key:witness[key] for key in KEYS},
            "nonce_sha256":nonce,
            "fork_resolved":False, "release_authorized":False}


def audit(source, registry, witnesses, nonces, floor=None,
          verifier=verify_key_and_signature):
    forks, prior_claims = checked_source(source)
    rows, heads = checked_history(registry)
    require(source["receipt_sha256"] not in
            {e["source_rust062_receipt_sha256"] for e in rows},
            "upstream source receipt replay")
    require(isinstance(witnesses, list) and len(witnesses) == 2 and
            isinstance(nonces, list) and len(nonces) == 2,
            "two fresh custodian challenges required")
    prior_fork_keys = registry["fork_keys"]
    snapshot = [{**f, "fork_key_sha256":digest(f)} for f in forks]
    keys = [f["fork_key_sha256"] for f in snapshot]
    require(keys[:len(prior_fork_keys)] == prior_fork_keys,
            "earlier unresolved fork removed from new observation")
    if floor is not None:
        require(isinstance(floor, dict) and floor.get("phase") == "RUST-063",
                "retained highwater floor absent")
        ordinal = floor.get("event_count")
        require(type(ordinal) is int and 0 <= ordinal < len(heads),
                "retained floor exceeds prior registry")
        check_sha(floor.get("head_sha256"), "retained head invalid")
        require(heads[ordinal] == floor["head_sha256"],
                "retained registry fork or rollback")
    seen_nonces = {w["nonce_sha256"] for e in rows for w in e["witnesses"]}
    seen_messages = {w["message_sha256"] for e in rows for w in e["witnesses"]}
    seen_pins = set()
    witness_rows = []
    all_conflicts = []
    for w, nonce in zip(witnesses, nonces):
        require(isinstance(w, dict), "custodian witness missing")
        require(w.get("fork_resolved") is False and
                w.get("release_authorized") is False,
                "witness attempted to clear fork")
        msg = payload(source, heads[-1], digest(snapshot), w, nonce)
        pin = msg["signer_pin"]
        require(pin not in seen_pins and pin != source["checkpoint_pin"],
                "witness pin repeated or self-attesting")
        require(nonce not in seen_nonces and
                nonce not in {c["nonce_sha256"] for c in prior_claims},
                "retention challenge nonce replay")
        seen_nonces.add(nonce); seen_pins.add(pin)
        msg_hash = digest(msg)
        require(msg_hash not in seen_messages, "retention statement replay")
        seen_messages.add(msg_hash)
        signature = verifier(w.get("public_key"),w.get("signature"),
                             pin,canonical(msg))
        check_sha(signature, "custody signature invalid")
        witness_rows.append({"pin":pin, "nonce_sha256":nonce,
                             "message_sha256":msg_hash,"signature_sha256":signature,
                             **{key:msg[key] for key in KEYS},
                             "independent_custody_verified":False})
    for key in KEYS:
        if witness_rows[0][key] == witness_rows[1][key]:
            all_conflicts.append({"reason":"SHARED_CLAIMED_CUSTODY_ANCESTRY",
                                  "field":key,"independent_custody_verified":False})
    for e in rows:
        for old in e["witnesses"]:
            for new in witness_rows:
                if old["pin"] != new["pin"] and (
                    old["operator_control_sha256"] ==
                    new["operator_control_sha256"]):
                    all_conflicts.append({
                        "reason":"RENAMED_CUSTODIAN_REUSED_CONTROLLER",
                        "old_pin":old["pin"],"new_pin":new["pin"],
                        "independent_custody_verified":False})
    event = {"phase":"RUST-063", "kind":"CROSS_CUSTODY_FORK_ENTRY",
             "ordinal":len(rows)+1,"previous_entry_sha256":heads[-1],
             "source_rust062_receipt_sha256":source["receipt_sha256"],
             "historical_fork_keys":prior_fork_keys,"fork_keys":keys,
             "forks":snapshot,
             "source_disputes_sha256":digest(source["current_disputes_preserved"]),
             "witnesses":witness_rows,"conflicts":all_conflicts,
             "winner_selected":False,"fork_resolved":False,
             "release_authorized":False}
    event["entry_sha256"] = digest(event)
    result = {"phase":"RUST-063","status":"HOLD_CROSS_CUSTODY_FORK_REGISTRY",
              "events":rows+[event],"prefix_heads":heads+[event["entry_sha256"]],
              "event_count":len(rows)+1,"head_sha256":event["entry_sha256"],
              "fork_keys":keys,
              "custody_conflicts":registry["custody_conflicts"]+all_conflicts,
              "retained_floor_compared":floor is not None,
              "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
              "independent_custody_verified":False,
              "globally_latest_fork_highwater_verified":False,
              "winner_selected":False,"fork_resolved":False,
              "release_authorized":False,"live_gameplay_authority":False}
    result["receipt_sha256"] = digest(result)
    return result


def hold():
    return {"phase":"RUST-063","status":"HOLD_MISSING_FORK_RETENTION_CHALLENGES",
            "independent_custody_verified":False,"winner_selected":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False}


def main():
    parser=argparse.ArgumentParser()
    for name in ("source","registry","witnesses","nonces","floor"):
        parser.add_argument("--"+name)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-hold-record",action="store_true")
    a=parser.parse_args()
    required=[a.source,a.registry,a.witnesses,a.nonces]
    require(all(required) or not any(required),"partial custody registry input refused")
    require(not a.floor or all(required),"floor without complete witness input refused")
    if all(required):
        doc=lambda name:json.loads(Path(name).read_text(encoding="utf-8"))
        result=audit(doc(a.source),doc(a.registry),doc(a.witnesses),
                     doc(a.nonces),doc(a.floor) if a.floor else None)
    else:
        result=hold()
    target=Path(a.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-063 HOLD: independent retention unverified")


if __name__=="__main__":
    main()
