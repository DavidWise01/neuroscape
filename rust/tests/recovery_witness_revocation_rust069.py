#!/usr/bin/env python3
"""RUST-069 — persistent recovery custody challenge and witness revocation.
Claims and signatures alone are never independent custody proof.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from successor_recovery_rust067 import checked_history as checked_recovery

GENESIS=digest({"phase":"RUST-069","kind":"RECOVERY_WITNESS_REVOCATION_GENESIS_V1"})
ROLES=("ff","cf","rr")
ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def source_checked(highwater,recovery):
    require(isinstance(highwater,dict) and highwater.get("phase")=="RUST-068" and
            highwater.get("status")=="HOLD_RECOVERY_HIGHWATER_QUARANTINE_PERSISTENCE",
            "RUST-068 source absent")
    require(digest({k:v for k,v in highwater.items() if k!="receipt_sha256"})==
            highwater.get("receipt_sha256"),"source receipt altered")
    require(all(highwater.get(k) is False for k in
            ("independent_custody_verified","recovery_authorized",
             "release_authorized","fork_resolved","live_gameplay_authority")) and
            highwater.get("all_successors_quarantined") is True,
            "source attempted authority promotion")
    events,_=checked_recovery(recovery)
    require(highwater.get("current_rust067_receipt_sha256")==recovery["receipt_sha256"] and
            highwater.get("current_recovery_count")==len(events) and
            highwater.get("current_conflicts_preserved")==recovery["custody_conflicts"] and
            highwater.get("current_quarantined_candidates_preserved")==[
                [e["revocation_entry_sha256"],e["candidate_pin"]] for e in events],
            "source not bound to complete recovery ledger")
    return events

def genesis():
    h={"phase":"RUST-069","status":"HOLD_RECOVERY_WITNESS_REVOCATION",
       "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
       "event_count":0,"revoked_witness_pins":[],
       "revoked_controller_roots":[],"custody_conflicts":[],
       "independent_custody_verified":False,"recovery_authorized":False,
       "release_authorized":False}
    h["receipt_sha256"]=digest(h)
    return h

def checked_history(h):
    require(isinstance(h,dict) and h.get("phase")=="RUST-069" and
            h.get("status")=="HOLD_RECOVERY_WITNESS_REVOCATION" and
            all(h.get(k) is False for k in
                ("independent_custody_verified","recovery_authorized","release_authorized")),
            "witness revocation ledger absent or elevated")
    events,heads=h.get("events"),h.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "revocation history truncated")
    prev=GENESIS; pins=[]; roots=[]; conflicts=[];nonces=set();source_refs=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-069" and
                e.get("kind")=="RECOVERY_CUSTODY_WITNESS_REVOCATION" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==prev and
                e.get("quarantine_persists") is True and
                all(e.get(k) is False for k in
                    ("independent_custody_verified","recovery_authorized","release_authorized")),
                "historical revocation promoted or rewritten")
        for key in ("source_rust068_receipt_sha256","source_rust067_receipt_sha256",
                    "compromised_pin","compromised_controller_sha256",
                    "compromised_recovery_entry_sha256","revocation_nonce_sha256"):
            check_sha(e.get(key),"historical revocation data missing")
        require(e["compromised_pin"] not in pins and
                e["revocation_nonce_sha256"] not in nonces and
                e["source_rust068_receipt_sha256"] not in source_refs,
                "historical revocation or nonce replay")
        pins.append(e["compromised_pin"]);nonces.add(e["revocation_nonce_sha256"])
        source_refs.add(e["source_rust068_receipt_sha256"])
        if e["compromised_controller_sha256"] not in roots:
            roots.append(e["compromised_controller_sha256"])
        witnesses=e.get("witnesses")
        require(isinstance(witnesses,list) and
                [w.get("role") for w in witnesses]==list(ROLES),
                "historic three-custodian evidence missing")
        require(len({w.get("pin") for w in witnesses})==3,"historical witness key duplication")
        for w in witnesses:
            for k in ("pin","nonce_sha256","message_sha256","signature_sha256",*ORIGINS):
                check_sha(w.get(k),"historic witness evidence invalid")
            require(w["nonce_sha256"] not in nonces,"historical witness nonce replay")
            nonces.add(w["nonce_sha256"])
            require(w.get("independent_custody_verified") is False,
                    "historical witness promoted")
        require(isinstance(e.get("custody_conflicts"),list),
                "historical ancestry conflicts missing")
        conflicts+=e["custody_conflicts"]
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historic revocation entry altered")
        prev=e["entry_sha256"]
        require(heads[i]==prev,"revocation prefix rewritten")
    require(h.get("event_count")==len(events) and h.get("head_sha256")==prev and
            h.get("revoked_witness_pins")==pins and
            h.get("revoked_controller_roots")==roots and
            h.get("custody_conflicts")==conflicts,"historic revocations erased")
    require(digest({k:v for k,v in h.items() if k!="receipt_sha256"})==
            h.get("receipt_sha256"),"revocation ledger receipt changed")
    return events,heads

def challenge(source,entry,head,revocation_nonce,claim,nonce):
    check_sha(revocation_nonce,"revocation nonce missing")
    check_sha(nonce,"custodian nonce missing")
    require(isinstance(claim,dict) and claim.get("role") in ROLES,"custodian role missing")
    for k in ("signer_pin",*ORIGINS):
        check_sha(claim.get(k),"custodian ancestry incomplete")
    return {"phase":"RUST-069","kind":"INDEPENDENT_RECOVERY_REVOCATION_CHALLENGE_V1",
            "source_rust068_receipt_sha256":source["receipt_sha256"],
            "prior_revocation_head_sha256":head,
            "compromised_recovery_entry_sha256":entry["entry_sha256"],
            "compromised_pin":entry["pin"],
            "revocation_nonce_sha256":revocation_nonce,
            "role":claim["role"],"signer_pin":claim["signer_pin"],
            **{k:claim[k] for k in ORIGINS},"nonce_sha256":nonce,
            "quarantine_persists":True,"recovery_authorized":False,
            "release_authorized":False}

def audit(source,recovery,history,compromised_pin,revocation_nonce,
          witnesses,nonces,floor=None,verifier=verify_key_and_signature):
    events=source_checked(source,recovery)
    prior,heads=checked_history(history)
    check_sha(compromised_pin,"compromised witness pin missing")
    check_sha(revocation_nonce,"fresh revocation nonce missing")
    require(source["receipt_sha256"] not in
            {e["source_rust068_receipt_sha256"] for e in prior},
            "source recovery highwater replay")
    require(compromised_pin not in history["revoked_witness_pins"],
            "witness already revoked")
    historic_claims=[(event,w) for event in events for w in event["witnesses"]]
    matching=[(e,w) for e,w in historic_claims if w["pin"]==compromised_pin]
    require(matching,"compromised pin not present in recovery history")
    event,compromised=matching[0]
    require(isinstance(witnesses,list) and isinstance(nonces,list) and
            len(witnesses)==len(nonces)==3 and
            [w.get("role") for w in witnesses]==list(ROLES),
            "exactly ff/cf/rr revocation challenges required")
    witness_pins={w["pin"] for _,w in historic_claims}
    candidate_pins={e["candidate_pin"] for e in events}
    previous_nonces={e["revocation_nonce_sha256"] for e in prior}
    previous_nonces.update(w["nonce_sha256"] for e in prior for w in e["witnesses"])
    previous_nonces.update(w["nonce_sha256"] for _,w in historic_claims)
    require(revocation_nonce not in previous_nonces,
            "revocation nonce replay")
    previous_nonces.add(revocation_nonce)
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-069",
                "external revocation floor absent")
        count=floor.get("event_count")
        require(type(count) is int and 0<=count<len(heads),
                "retained floor exceeds recorded revocations")
        check_sha(floor.get("head_sha256"),"external floor hash missing")
        require(heads[count]==floor["head_sha256"],
                "retained witness revocation floor forked")
    previous_origins=[w for _,w in historic_claims]
    claim_rows=[]; conflicts=[]; seen_pins=set()
    for w,nonce in zip(witnesses,nonces):
        msg=challenge(source,compromised,heads[-1],revocation_nonce,w,nonce)
        pin=msg["signer_pin"]
        require(pin not in seen_pins and pin not in witness_pins and
                pin not in candidate_pins and
                pin not in history["revoked_witness_pins"] and
                pin!=source["checkpoint_signer_pin"],
                "revoked or non-independent witness attempted attestation")
        require(nonce not in previous_nonces,"witness revocation challenge nonce replay")
        seen_pins.add(pin);previous_nonces.add(nonce)
        sig=verifier(w.get("public_key"),w.get("signature"),pin,canonical(msg))
        check_sha(sig,"invalid revocation witness signature")
        row={"role":w["role"],"pin":pin,"nonce_sha256":nonce,
             "message_sha256":digest(msg),"signature_sha256":sig,
             **{k:msg[k] for k in ORIGINS},
             "independent_custody_verified":False}
        claim_rows.append(row)
        if row["controller_sha256"]==compromised["controller_sha256"] or (
                row["controller_sha256"] in history["revoked_controller_roots"]):
            conflicts.append({"reason":"ATTESTOR_REUSES_REVOKED_CONTROLLER",
                              "role":row["role"],"independent_custody_verified":False})
        if any(row["acquisition_sha256"]==p["acquisition_sha256"] for p in previous_origins):
            conflicts.append({"reason":"ATTESTOR_REUSES_HISTORICAL_ACQUISITION",
                              "role":row["role"],"independent_custody_verified":False})
    for k in ORIGINS:
        if len({w[k] for w in claim_rows})!=3:
            conflicts.append({"reason":"NEW_ATTESTORS_SHARE_CLAIMED_ANCESTRY",
                              "field":k,"independent_custody_verified":False})
    ledger_event={
        "phase":"RUST-069","kind":"RECOVERY_CUSTODY_WITNESS_REVOCATION",
        "ordinal":len(prior)+1,"previous_entry_sha256":heads[-1],
        "source_rust068_receipt_sha256":source["receipt_sha256"],
        "source_rust067_receipt_sha256":recovery["receipt_sha256"],
        "compromised_pin":compromised_pin,
        "compromised_controller_sha256":compromised["controller_sha256"],
        "compromised_recovery_entry_sha256":event["entry_sha256"],
        "revocation_nonce_sha256":revocation_nonce,
        "witnesses":claim_rows,"custody_conflicts":conflicts,
        "quarantine_persists":True,"independent_custody_verified":False,
        "recovery_authorized":False,"release_authorized":False}
    ledger_event["entry_sha256"]=digest(ledger_event)
    roots=list(history["revoked_controller_roots"])
    if compromised["controller_sha256"] not in roots:
        roots.append(compromised["controller_sha256"])
    out={"phase":"RUST-069","status":"HOLD_RECOVERY_WITNESS_REVOCATION",
         "events":prior+[ledger_event],"prefix_heads":heads+[ledger_event["entry_sha256"]],
         "event_count":len(prior)+1,"head_sha256":ledger_event["entry_sha256"],
         "revoked_witness_pins":history["revoked_witness_pins"]+[compromised_pin],
         "revoked_controller_roots":roots,
         "custody_conflicts":history["custody_conflicts"]+conflicts,
         "source_recovery_candidates_preserved":source["current_quarantined_candidates_preserved"],
         "source_custody_conflicts_preserved":source["current_conflicts_preserved"],
         "retained_floor_compared":floor is not None,
         "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
         "quarantine_persists":True,"independent_custody_verified":False,
         "globally_latest_revocation_verified":False,
         "recovery_authorized":False,"release_authorized":False,
         "live_gameplay_authority":False}
    out["receipt_sha256"]=digest(out)
    return out

def hold():
    return {"phase":"RUST-069","status":"HOLD_MISSING_RECOVERY_CUSTODY_REVOCATION",
            "quarantine_persists":True,"independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("highwater","recovery","history","compromised-pin",
                 "revocation-nonce","witnesses","nonces","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.highwater,a.recovery,a.history,a.compromised_pin,
              a.revocation_nonce,a.witnesses,a.nonces]
    require(all(required) or not any(required),
            "partial recovery-witness revocation bundle refused")
    require(not a.floor or all(required),
            "retained floor without revocation evidence refused")
    if all(required):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(a.highwater),read(a.recovery),read(a.history),a.compromised_pin,
                  a.revocation_nonce,read(a.witnesses),read(a.nonces),
                  read(a.floor) if a.floor else None)
    else:out=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-069 HOLD: external recovery custody unverified")
if __name__=="__main__":main()
