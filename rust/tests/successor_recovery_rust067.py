#!/usr/bin/env python3
"""RUST-067 — quarantined successor recovery attempt registry.

Records three pinned, fresh custody challenges per attempt, binds exact
RUST-065 ancestry to the RUST-066 highwater and permanently denies
recovery/release. Claims never establish independent physical custody.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from witness_rotation_rust065 import checked_history as checked_revocations

GENESIS=digest({"phase":"RUST-067","kind":"QUARANTINED_RECOVERY_GENESIS_V1"})
ROLES=("ff","cf","rr")
ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checked_source(highwater,revocations):
    require(isinstance(highwater,dict) and highwater.get("phase")=="RUST-066"
            and highwater.get("status")==
                "HOLD_REVOCATION_SUCCESSOR_QUARANTINE_HIGHWATER",
            "RUST-066 successor highwater missing")
    require(digest({k:v for k,v in highwater.items() if k!="receipt_sha256"})
            ==highwater.get("receipt_sha256"),"RUST-066 receipt altered")
    require(all(highwater.get(k) is False for k in
                ("independent_custody_verified","fork_resolved",
                 "release_authorized","live_gameplay_authority")),
            "highwater attempted recovery authorization")
    require(highwater.get("all_successors_quarantined") is True,
            "successor quarantine not preserved")
    events,_=checked_revocations(revocations)
    require(highwater.get("current_rust065_receipt_sha256")==
            revocations["receipt_sha256"] and
            highwater.get("current_revocation_count")==len(events) and
            highwater.get("revoked_signer_pins_preserved")==
            revocations["revoked_signer_pins"] and
            highwater.get("revoked_controller_roots_preserved")==
            revocations["revoked_controller_roots"] and
            highwater.get("current_conflicts_preserved")==
            revocations["rotation_conflicts"],"RUST-066 ancestry incomplete")
    newly=[e for e in events if e["entry_sha256"] in {
        o["revocation_entry_sha256"] for o in
        highwater.get("successor_observations",[])}]
    require(len(newly)==len(highwater.get("successor_observations",[])) and
            newly and all(e["quarantined"] is True for e in newly),
            "new quarantined successors unavailable")
    return newly

def genesis():
    result={"phase":"RUST-067","status":"HOLD_QUARANTINED_RECOVERY_ATTEMPTS",
            "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
            "event_count":0,"custody_conflicts":[],
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False}
    result["receipt_sha256"]=digest(result)
    return result

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-067"
            and history.get("status")=="HOLD_QUARANTINED_RECOVERY_ATTEMPTS"
            and all(history.get(k) is False for k in
                ("independent_custody_verified","recovery_authorized",
                 "release_authorized")),"recovery history missing or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "recovery ledger truncated")
    last=GENESIS; conflicts=[]; nonces=set(); messages=set(); references=set()
    for i,event in enumerate(events,1):
        require(isinstance(event,dict) and event.get("phase")=="RUST-067"
                and event.get("kind")=="QUARANTINED_RECOVERY_ATTEMPT"
                and event.get("ordinal")==i and
                event.get("previous_entry_sha256")==last and
                event.get("quarantine_persists") is True and
                all(event.get(k) is False for k in
                    ("independent_custody_verified","recovery_authorized",
                     "release_authorized")),"historical recovery attempt rewritten")
        for field in ("source_rust066_receipt_sha256","source_rust065_receipt_sha256",
                      "revocation_entry_sha256","candidate_pin",
                      "candidate_controller_sha256","candidate_source_root_sha256",
                      "candidate_acquisition_sha256"):
            check_sha(event.get(field),"historical attempt field invalid")
        reference=(event["source_rust066_receipt_sha256"],
                   event["revocation_entry_sha256"])
        require(reference not in references,"historical recovery attempt replay")
        references.add(reference)
        claims=event.get("witnesses")
        require(isinstance(claims,list) and len(claims)==3 and
                [c.get("role") for c in claims]==list(ROLES),
                "historical three-witness custody incomplete")
        for c in claims:
            for field in ("pin","nonce_sha256","message_sha256",
                          "signature_sha256",*ORIGINS):
                check_sha(c.get(field),"historical witness claim incomplete")
            require(c["nonce_sha256"] not in nonces and
                    c["message_sha256"] not in messages,
                    "historical custody challenge replay")
            nonces.add(c["nonce_sha256"]);messages.add(c["message_sha256"])
        require(digest(claims)==event.get("witnesses_sha256"),
                "historical custody witnesses substituted")
        require(isinstance(event.get("custody_conflicts"),list),
                "historical conflicts missing")
        conflicts+=event["custody_conflicts"]
        require(digest({k:v for k,v in event.items() if k!="entry_sha256"})==
                event.get("entry_sha256"),"historical recovery entry hash altered")
        last=event["entry_sha256"]
        require(heads[i]==last,"historical recovery prefix rewritten")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==last and
            history.get("custody_conflicts")==conflicts,
            "historic recovery conflicts erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"recovery registry receipt changed")
    return events,heads

def challenge(highwater,revocation,previous_head,claim,nonce):
    require(isinstance(claim,dict) and claim.get("role") in ROLES,
            "custody role missing")
    for field in ("signer_pin",*ORIGINS):
        check_sha(claim.get(field),"custody claim missing "+field)
    check_sha(nonce,"fresh custody nonce missing")
    return {
        "phase":"RUST-067","kind":"QUARANTINED_SUCCESSOR_CUSTODY_V1",
        "source_rust066_receipt_sha256":highwater["receipt_sha256"],
        "previous_recovery_head_sha256":previous_head,
        "revocation_entry_sha256":revocation["entry_sha256"],
        "replacement_pin":revocation["replacement_pin"],
        "role":claim["role"],"signer_pin":claim["signer_pin"],
        **{field:claim[field] for field in ORIGINS},
        "nonce_sha256":nonce,
        "quarantine_persists":True,
        "recovery_authorized":False,"release_authorized":False,
    }

def audit(highwater,revocations,history,witness_sets,nonce_sets,
          floor=None,verifier=verify_key_and_signature):
    newly=checked_source(highwater,revocations)
    old,heads=checked_history(history)
    require(isinstance(witness_sets,list) and isinstance(nonce_sets,list)
            and len(witness_sets)==len(nonce_sets)==len(newly),
            "three custody witnesses required per new quarantined successor")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-067",
                "retained recovery ledger floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "floor exceeds recorded recovery history")
        check_sha(floor.get("head_sha256"),"floor SHA invalid")
        require(heads[n]==floor["head_sha256"],"retained recovery floor forked")
    nonce_seen={c["nonce_sha256"] for e in old for c in e["witnesses"]}
    nonce_seen.update(e["nonce_sha256"] for e in revocations["events"])
    nonce_seen.update(c["observation_nonce_sha256"] for c in
                      highwater["successor_observations"])
    message_seen={c["message_sha256"] for e in old for c in e["witnesses"]}
    all_events=list(old);all_heads=list(heads);all_conflicts=list(history["custody_conflicts"])
    revoked_pins=set(revocations["revoked_signer_pins"])
    revoked_roots=set(revocations["revoked_controller_roots"])
    all_replacements={e["replacement_pin"] for e in revocations["events"]}
    prior_candidate_refs={(e["source_rust066_receipt_sha256"],
                           e["revocation_entry_sha256"]) for e in old}
    for rev,group,nonces in zip(newly,witness_sets,nonce_sets):
        require((highwater["receipt_sha256"],rev["entry_sha256"])
                not in prior_candidate_refs,"successor recovery replay")
        require(isinstance(group,list) and isinstance(nonces,list) and
                len(group)==len(nonces)==3 and
                [g.get("role") for g in group]==list(ROLES),
                "three ordered ff/cf/rr custody witnesses required")
        pins=[g.get("signer_pin") for g in group]
        require(len(set(pins))==3,"custodian signing pins not distinct")
        claims=[]; conflicts=[]
        for witness,nonce in zip(group,nonces):
            msg=challenge(highwater,rev,all_heads[-1],witness,nonce)
            pin=msg["signer_pin"]
            require(pin not in revoked_pins and pin not in all_replacements and
                    pin!=highwater["checkpoint_signer_pin"],
                    "revoked, replacement or checkpoint signer cannot attest")
            require(nonce not in nonce_seen,"successor custody nonce replay")
            nonce_seen.add(nonce)
            msg_sha=digest(msg)
            require(msg_sha not in message_seen,"replayed custody challenge")
            message_seen.add(msg_sha)
            signature=verifier(witness.get("public_key"),witness.get("signature"),
                               pin,canonical(msg))
            check_sha(signature,"invalid witness custody signature")
            row={"role":witness["role"],"pin":pin,
                 "nonce_sha256":nonce,"message_sha256":msg_sha,
                 "signature_sha256":signature,
                 **{field:msg[field] for field in ORIGINS},
                 "independent_custody_verified":False}
            claims.append(row)
            if msg["controller_sha256"] in revoked_roots or \
                    msg["controller_sha256"]==rev["replacement_controller_sha256"]:
                conflicts.append({"reason":"WITNESS_REUSES_REVOKED_OR_SUCCESSOR_CONTROLLER",
                                  "pin":pin,"independent_custody_verified":False})
            if msg["acquisition_sha256"]==rev["replacement_acquisition_sha256"]:
                conflicts.append({"reason":"WITNESS_REUSES_SUCCESSOR_ACQUISITION",
                                  "pin":pin,"independent_custody_verified":False})
        for key in ORIGINS:
            if len({c[key] for c in claims})!=3:
                conflicts.append({"reason":"WITNESSES_SHARE_CLAIMED_ANCESTRY",
                                  "field":key,"independent_custody_verified":False})
        event={"phase":"RUST-067","kind":"QUARANTINED_RECOVERY_ATTEMPT",
               "ordinal":len(all_events)+1,"previous_entry_sha256":all_heads[-1],
               "source_rust066_receipt_sha256":highwater["receipt_sha256"],
               "source_rust065_receipt_sha256":revocations["receipt_sha256"],
               "revocation_entry_sha256":rev["entry_sha256"],
               "candidate_pin":rev["replacement_pin"],
               "candidate_controller_sha256":rev["replacement_controller_sha256"],
               "candidate_source_root_sha256":rev["replacement_source_root_sha256"],
               "candidate_acquisition_sha256":rev["replacement_acquisition_sha256"],
               "witnesses":claims,"witnesses_sha256":digest(claims),
               "custody_conflicts":conflicts,"quarantine_persists":True,
               "independent_custody_verified":False,
               "recovery_authorized":False,"release_authorized":False}
        event["entry_sha256"]=digest(event)
        all_events.append(event);all_heads.append(event["entry_sha256"])
        all_conflicts+=conflicts
    result={"phase":"RUST-067","status":"HOLD_QUARANTINED_RECOVERY_ATTEMPTS",
            "events":all_events,"prefix_heads":all_heads,
            "event_count":len(all_events),"head_sha256":all_heads[-1],
            "custody_conflicts":all_conflicts,
            "source_rust066_receipt_sha256":highwater["receipt_sha256"],
            "revoked_pins_preserved":revocations["revoked_signer_pins"],
            "revoked_controllers_preserved":revocations["revoked_controller_roots"],
            "source_revocation_events_preserved":revocations["events"],
            "retained_floor_compared":floor is not None,
            "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
            "independent_custody_verified":False,
            "globally_latest_recovery_verified":False,
            "global_anti_rollback_certified":False,
            "fork_resolved":False,"recovery_authorized":False,
            "release_authorized":False,"live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-067","status":"HOLD_MISSING_INDEPENDENT_SUCCESSOR_CUSTODY",
            "independent_custody_verified":False,"fork_resolved":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("highwater","revocations","history","witnesses","nonces","floor"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.highwater,a.revocations,a.history,a.witnesses,a.nonces]
    require(all(required) or not any(required),
            "partial quarantined recovery evidence refused")
    require(not a.floor or all(required),"floor without recovery evidence refused")
    if all(required):
        load=lambda s:json.loads(Path(s).read_text(encoding="utf-8"))
        out=audit(load(a.highwater),load(a.revocations),load(a.history),
                  load(a.witnesses),load(a.nonces),
                  load(a.floor) if a.floor else None)
    else:out=hold()
    path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as stream:
        json.dump(out,stream,indent=2,sort_keys=True);stream.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-067 HOLD: independent successor recovery custody unverified")
if __name__=="__main__":main()
