#!/usr/bin/env python3
"""RUST-057: cross-epoch recovery custody challenges and controller separation.

Evidence receipts are hash checked; live signature verification applies
to new challenges only. Distinct keys and claimed ancestry never confer
real-world independent custody. All results remain HOLD.
"""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from witness_recovery_rust055 import checked_recovery_history
from witness_revocation_rust054 import checked_history as checked_revocations

GENESIS=digest({"phase":"RUST-057","kind":"RECOVERY_CUSTODY_CHALLENGE_GENESIS_V1"})
ROLES=("ff","cf","rr")

def checked_source(source,recovery,revocations):
    require(isinstance(source,dict) and source.get("phase")=="RUST-056" and
            source.get("status")=="HOLD_RECOVERY_QUARANTINE_HIGHWATER_UNVERIFIED",
            "signed RUST-056 recovery highwater missing")
    require(source.get("release_authorized") is False and
            source.get("fork_resolved") is False and
            source.get("independent_external_custody_verified") is False,
            "RUST-056 claimed authority")
    require(digest({k:v for k,v in source.items() if k!="receipt_sha256"})==
            source.get("receipt_sha256"),"RUST-056 receipt altered")
    entries,_=checked_recovery_history(recovery)
    checked_revocations(revocations)
    require(entries and source.get("current_rust055_receipt_sha256")==
            recovery["receipt_sha256"] and
            source.get("current_rust054_receipt_sha256")==
            revocations["receipt_sha256"] and
            source.get("current_recovery_count")==len(entries) and
            source.get("historical_recovery_attempts_preserved")==entries and
            source.get("revoked_witnesses_preserved")==
            revocations["revoked_signer_pins"] and
            source.get("revoked_controllers_preserved")==
            revocations["revoked_claimed_controllers"],
            "RUST-056 source does not bind entire recovery ancestry")
    return entries

def genesis():
    record={"phase":"RUST-057","status":"HOLD_RECOVERY_CUSTODY_CHALLENGES",
            "entries":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
            "event_count":0,"custody_conflicts":[],
            "release_authorized":False,"fork_resolved":False,
            "independent_custody_authenticated":False}
    record["receipt_sha256"]=digest(record)
    return record

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-057" and
            history.get("status")=="HOLD_RECOVERY_CUSTODY_CHALLENGES" and
            history.get("release_authorized") is False and
            history.get("fork_resolved") is False,
            "RUST-057 historical challenge registry unavailable")
    events=history.get("entries")
    heads=history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "custody challenge history truncated")
    last=GENESIS
    conflicts=[]
    seen_nonces=set()
    seen_messages=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-057" and
                e.get("kind")=="RECOVERY_CUSTODY_CHALLENGE" and
                e.get("ordinal")==i and
                e.get("previous_entry_sha256")==last and
                e.get("quarantine_persists") is True and
                e.get("release_authorized") is False and
                e.get("independent_custody_authenticated") is False,
                "historical custody challenge rewritten or promoted")
        for field in ("recovery_entry_sha256","source_rust056_receipt_sha256",
                      "source_rust055_receipt_sha256"):
            check_sha(e.get(field),"historical recovery reference missing")
        claims=e.get("witnesses")
        require(isinstance(claims,list) and len(claims)==3 and
                [c.get("role") for c in claims]==list(ROLES),
                "three historical witness challenges missing")
        for c in claims:
            for field in ("signer_pin","nonce_sha256","message_sha256",
                          "signature_sha256","claimed_controller_sha256",
                          "claimed_source_root_sha256","acquisition_sha256"):
                check_sha(c.get(field),"historic witness field invalid")
            require(c["nonce_sha256"] not in seen_nonces and
                    c["message_sha256"] not in seen_messages,
                    "historical session replay")
            seen_nonces.add(c["nonce_sha256"])
            seen_messages.add(c["message_sha256"])
        require(digest(claims)==e.get("witness_claims_sha256"),
                "historical witness claims modified")
        alerts=e.get("custody_conflicts")
        require(isinstance(alerts,list),"historical conflicts missing")
        conflicts.extend(alerts)
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historic custody event modified")
        last=e["entry_sha256"]
        require(heads[i]==last,"historic custody prefix altered")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==last and
            history.get("custody_conflicts")==conflicts,
            "historical custody conflicts erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"historical custody receipt altered")
    return events,heads

def challenge_payload(source,recovery_entry,role,claim,nonce,previous_head):
    for field in ("signer_pin","claimed_controller_sha256",
                  "claimed_source_root_sha256","acquisition_sha256"):
        check_sha(claim.get(field),"custodian claim incomplete: "+field)
    check_sha(nonce,"challenge nonce missing")
    return {
        "phase":"RUST-057","kind":"RECOVERY_CUSTODY_CHALLENGE_V1",
        "source_rust056_receipt_sha256":source["receipt_sha256"],
        "previous_registry_head_sha256":previous_head,
        "recovery_entry_sha256":recovery_entry["entry_sha256"],
        "candidate_signer_pin":recovery_entry["candidate_signer_pin"],
        "role":role,"signer_pin":claim["signer_pin"],
        "claimed_controller_sha256":claim["claimed_controller_sha256"],
        "claimed_source_root_sha256":claim["claimed_source_root_sha256"],
        "acquisition_sha256":claim["acquisition_sha256"],
        "nonce_sha256":nonce,
        "quarantine_persists":True,"release_authorized":False,
    }

def audit(source,recovery,revocations,history,witness_sets,nonce_sets,
          floor=None,verifier=verify_key_and_signature):
    recovery_entries=checked_source(source,recovery,revocations)
    old,heads=checked_history(history)
    require(isinstance(witness_sets,list) and
            isinstance(nonce_sets,list) and len(witness_sets)==len(nonce_sets)
            and len(witness_sets)==len(recovery_entries),
            "one complete challenge set per recovery candidate required")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-057",
                "retained custody floor absent")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained custody floor beyond available history")
        check_sha(floor.get("head_sha256"),"floor head invalid")
        require(heads[n]==floor["head_sha256"],
                "retained custody history withheld or forked")
    nonce_seen={c["nonce_sha256"] for e in old for c in e["witnesses"]}
    messages_seen={c["message_sha256"] for e in old for c in e["witnesses"]}
    roots_seen={}
    for e in old:
        for c in e["witnesses"]:
            roots_seen.setdefault(c["signer_pin"],set()).add((
                c["claimed_controller_sha256"],c["claimed_source_root_sha256"],
                c["acquisition_sha256"]))
    all_events=list(old)
    all_heads=list(heads)
    all_conflicts=list(history["custody_conflicts"])
    revoked=set(revocations["revoked_signer_pins"])
    controllers=set(revocations["revoked_claimed_controllers"])
    for rec,group,nonces in zip(recovery_entries,witness_sets,nonce_sets):
        require(isinstance(group,list) and isinstance(nonces,list) and
                len(group)==len(nonces)==3 and
                [c.get("role") for c in group]==list(ROLES),
                "three ordered ff/cf/rr recovery witnesses required")
        require(len({c.get("signer_pin") for c in group})==3,
                "recovery witness signing keys not distinct")
        claims=[]
        conflicts=[]
        for claim,nonce in zip(group,nonces):
            role=claim["role"]
            message=challenge_payload(source,rec,role,claim,nonce,all_heads[-1])
            signer=message["signer_pin"]
            require(signer not in revoked and
                    signer!=rec["candidate_signer_pin"],
                    "revoked or candidate signer cannot independently witness")
            message_hash=digest(message)
            require(nonce not in nonce_seen and message_hash not in messages_seen,
                    "replayed recovery witness challenge")
            nonce_seen.add(nonce)
            messages_seen.add(message_hash)
            sig=verifier(claim.get("public_key"),claim.get("signature"),signer,
                         canonical(message))
            check_sha(sig,"recovery custody challenge signature invalid")
            ancestry=(message["claimed_controller_sha256"],
                      message["claimed_source_root_sha256"],
                      message["acquisition_sha256"])
            if roots_seen.get(signer) and ancestry not in roots_seen[signer]:
                conflicts.append({
                    "reason":"SIGNER_CLAIMED_ANCESTRY_CHANGED",
                    "signer_pin":signer,"historical_claims":sorted(
                        [list(x) for x in roots_seen[signer]]),
                    "new_claim":list(ancestry),
                    "independent_control_verified":False,
                })
            roots_seen.setdefault(signer,set()).add(ancestry)
            if ancestry[0] in controllers or ancestry[0]==rec["claimed_controller_sha256"]:
                conflicts.append({"reason":"WITNESS_SHARES_COMPROMISED_OR_CANDIDATE_CONTROLLER",
                                  "signer_pin":signer,
                                  "claimed_controller_sha256":ancestry[0],
                                  "independent_control_verified":False})
            claims.append({
                "role":role,"signer_pin":signer,
                "nonce_sha256":nonce,"message_sha256":message_hash,
                "signature_sha256":sig,
                "claimed_controller_sha256":ancestry[0],
                "claimed_source_root_sha256":ancestry[1],
                "acquisition_sha256":ancestry[2],
                "independent_custody_authenticated":False,
            })
        for field in ("claimed_controller_sha256","claimed_source_root_sha256",
                      "acquisition_sha256"):
            if len({c[field] for c in claims})!=3:
                conflicts.append({"reason":"SHARED_CLAIMED_WITNESS_ANCESTRY",
                                  "shared_field":field,
                                  "independent_control_verified":False})
        event={
            "phase":"RUST-057","kind":"RECOVERY_CUSTODY_CHALLENGE",
            "ordinal":len(all_events)+1,
            "previous_entry_sha256":all_heads[-1],
            "source_rust056_receipt_sha256":source["receipt_sha256"],
            "source_rust055_receipt_sha256":recovery["receipt_sha256"],
            "recovery_entry_sha256":rec["entry_sha256"],
            "candidate_signer_pin":rec["candidate_signer_pin"],
            "witnesses":claims,"witness_claims_sha256":digest(claims),
            "custody_conflicts":conflicts,
            "quarantine_persists":True,
            "independent_custody_authenticated":False,
            "release_authorized":False,
        }
        event["entry_sha256"]=digest(event)
        all_events.append(event)
        all_heads.append(event["entry_sha256"])
        all_conflicts.extend(conflicts)
    result={
        "phase":"RUST-057","status":"HOLD_RECOVERY_CUSTODY_CHALLENGES",
        "entries":all_events,"prefix_heads":all_heads,
        "event_count":len(all_events),"head_sha256":all_heads[-1],
        "custody_conflicts":all_conflicts,
        "source_rust056_receipt_sha256":source["receipt_sha256"],
        "revoked_witnesses_preserved":revocations["revoked_signer_pins"],
        "revoked_controllers_preserved":revocations["revoked_claimed_controllers"],
        "recovery_candidates_preserved":recovery_entries,
        "retained_floor_compared":floor is not None,
        "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
        "independent_external_custody_verified":False,
        "globally_latest_custody_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-057","status":"HOLD_MISSING_RECOVERY_CUSTODIAN_CHALLENGES",
            "independent_external_custody_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False,
            "reason":"No independently retained signed custodian challenges"}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","recovery","revocations","history",
                 "witnesses","nonces","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    values=[a.source,a.recovery,a.revocations,a.history,a.witnesses,a.nonces]
    require(all(values) or not any(values),"partial recovery custody evidence refused")
    require(not a.floor or all(values),"retained floor without custody evidence")
    if all(values):
        doc=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        result=audit(*[doc(x) for x in values],
                     floor=doc(a.floor) if a.floor else None)
    else:
        result=hold()
    path=Path(a.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-057 HOLD: independent recovery custodians unverified")

if __name__=="__main__":
    main()
