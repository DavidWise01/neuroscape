#!/usr/bin/env python3
"""RUST-065: persistent witness revocation and rotation ancestry fence.

Revoked signing keys and declared control roots remain permanently fenced.
A fresh signing key is not evidence of a different controlling operator.
All structural outcomes remain HOLD.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from fork_registry_rust063 import checked_history as checked_forks

GENESIS=digest({"phase":"RUST-065","kind":"WITNESS_ROTATION_REVOCATION_GENESIS_V1"})
FIELDS=("compromised_pin","replacement_pin","compromised_controller_sha256",
        "replacement_controller_sha256","replacement_source_root_sha256",
        "replacement_acquisition_sha256","nonce_sha256","incident_sha256")

def checked_source(source,registry):
    require(isinstance(source,dict) and source.get("phase")=="RUST-064" and
            source.get("status")=="HOLD_FORK_REGISTRY_HIGHWATER_CONTINUITY",
            "RUST-064 assessment missing")
    for f in ("independent_custody_verified","globally_latest_highwater_verified",
              "winner_selected","fork_resolved","release_authorized",
              "live_gameplay_authority"):
        require(source.get(f) is False,"RUST-064 authority promotion")
    require(digest({k:v for k,v in source.items() if k!="receipt_sha256"})==
            source.get("receipt_sha256"),"RUST-064 receipt altered")
    entries,_=checked_forks(registry)
    require(source.get("current_rust063_receipt_sha256")==
            registry["receipt_sha256"] and
            source.get("current_count")==len(entries) and
            source.get("current_forks_preserved")==registry["fork_keys"] and
            source.get("current_conflicts_preserved")==registry["custody_conflicts"],
            "RUST-064 source not bound to fork registry")
    return entries

def genesis():
    x={"phase":"RUST-065","status":"HOLD_WITNESS_ROTATION_REVOCATION",
       "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
       "event_count":0,"revoked_signer_pins":[],
       "revoked_controller_roots":[],"rotation_conflicts":[],
       "independent_recovery_verified":False,"fork_resolved":False,
       "release_authorized":False}
    x["receipt_sha256"]=digest(x)
    return x

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-065" and
            history.get("status")=="HOLD_WITNESS_ROTATION_REVOCATION" and
            all(history.get(f) is False for f in (
                "independent_recovery_verified","fork_resolved","release_authorized")),
            "prior revocation history unavailable or promoted")
    events,heads=history.get("events"),history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "revocation history truncated")
    last=GENESIS
    pins=[]; roots=[]; conflicts=[]; nonces=set(); receipts=set()
    for i,e in enumerate(events,1):
        require(isinstance(e,dict) and e.get("phase")=="RUST-065" and
                e.get("kind")=="REVOKED_WITNESS_ROTATION_EVENT" and
                e.get("ordinal")==i and e.get("previous_entry_sha256")==last and
                e.get("recovery_authorized") is False and
                e.get("release_authorized") is False,
                "historical rotation changed")
        for k in ("source_rust064_receipt_sha256","registry_head_sha256",
                  "compromised_pin","replacement_pin",
                  "compromised_controller_sha256",
                  "replacement_controller_sha256","nonce_sha256",
                  "signature_sha256","revocation_payload_sha256"):
            check_sha(e.get(k),"historical rotation evidence missing "+k)
        require(e["source_rust064_receipt_sha256"] not in receipts and
                e["nonce_sha256"] not in nonces and
                e["compromised_pin"] not in pins,
                "historical revocation or nonce replay")
        receipts.add(e["source_rust064_receipt_sha256"])
        nonces.add(e["nonce_sha256"])
        pins.append(e["compromised_pin"])
        if e["compromised_controller_sha256"] not in roots:
            roots.append(e["compromised_controller_sha256"])
        if e["replacement_controller_sha256"] in roots and not e.get("quarantined"):
            raise ValueError("revoked controlling root escaped quarantine")
        require(e.get("quarantined") is True and
                isinstance(e.get("conflicts"),list),
                "historical rotation graduated")
        conflicts+=e["conflicts"]
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical revocation entry rewritten")
        last=e["entry_sha256"]
        require(heads[i]==last,"revocation prefix head altered")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==last and
            history.get("revoked_signer_pins")==pins and
            history.get("revoked_controller_roots")==roots and
            history.get("rotation_conflicts")==conflicts,
            "revoked history or conflicts erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"revocation receipt altered")
    return events,heads

def message(source,history_head,item):
    for k in FIELDS:
        check_sha(item.get(k),"revocation statement missing "+k)
    return {"phase":"RUST-065","kind":"WITNESS_ROTATION_REVOCATION_V1",
            "source_rust064_receipt_sha256":source["receipt_sha256"],
            "previous_revocation_head_sha256":history_head,
            **{k:item[k] for k in FIELDS},
            "recovery_authorized":False,"release_authorized":False}

def audit(source,registry,history,rotation,authority_pin,floor=None,
          verifier=verify_key_and_signature):
    source_entries=checked_source(source,registry)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in
            {e["source_rust064_receipt_sha256"] for e in old},
            "source highwater replay")
    require(isinstance(rotation,dict),"rotation statement missing")
    msg=message(source,heads[-1],rotation)
    bad=msg["compromised_pin"]; successor=msg["replacement_pin"]
    witness_claims=[w for e in source_entries for w in e["witnesses"]]
    known={w["pin"]:w for w in witness_claims}
    require(bad in known or bad in history["revoked_signer_pins"],
            "revoked key never observed in fork custody")
    require(bad not in history["revoked_signer_pins"],
            "duplicate revocation of old key")
    require(successor!=bad and successor not in history["revoked_signer_pins"],
            "replacement signing key revoked")
    require(msg["compromised_controller_sha256"]==
            (known[bad]["operator_control_sha256"] if bad in known else
             next(e["compromised_controller_sha256"] for e in old
                  if e["compromised_pin"]==bad)),
            "revoked controller does not match witness ancestry")
    check_sha(authority_pin,"revocation authority key missing")
    require(authority_pin not in (bad,successor) and
            authority_pin not in history["revoked_signer_pins"],
            "self-issued or revoked revocation authority")
    require(msg["nonce_sha256"] not in {e["nonce_sha256"] for e in old} and
            msg["nonce_sha256"] not in {w["nonce_sha256"] for w in witness_claims},
            "rotation nonce replay")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-065",
                "retained revocation floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained revocation floor beyond history")
        check_sha(floor.get("head_sha256"),"floor hash invalid")
        require(heads[n]==floor["head_sha256"],
                "retained revocation highwater forked")
    sig=verifier(rotation.get("authority_public_key"),
                 rotation.get("authority_signature"),authority_pin,
                 canonical(msg))
    check_sha(sig,"revocation authority signature invalid")
    revoked_roots=history["revoked_controller_roots"][:]
    root=msg["compromised_controller_sha256"]
    if root not in revoked_roots:
        revoked_roots.append(root)
    conflicts=[]
    if msg["replacement_controller_sha256"] in revoked_roots:
        conflicts.append({"reason":"REPLACEMENT_REUSES_REVOKED_CONTROLLER",
                          "replacement_pin":successor,
                          "controller_sha256":msg["replacement_controller_sha256"],
                          "independent_control_verified":False})
    prior_keys=[w for w in witness_claims if
                w["operator_control_sha256"]==msg["replacement_controller_sha256"]]
    if prior_keys:
        conflicts.append({"reason":"REPLACEMENT_REUSES_WITNESS_CONTROL_ANCESTRY",
                          "prior_witness_pins":[w["pin"] for w in prior_keys],
                          "independent_control_verified":False})
    if successor in known:
        conflicts.append({"reason":"REPLACEMENT_KEY_ALREADY_OBSERVED",
                          "replacement_pin":successor,
                          "independent_control_verified":False})
    event={"phase":"RUST-065","kind":"REVOKED_WITNESS_ROTATION_EVENT",
           "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
           "source_rust064_receipt_sha256":source["receipt_sha256"],
           "registry_head_sha256":registry["head_sha256"],
           **{k:msg[k] for k in FIELDS},
           "authority_pin":authority_pin,"signature_sha256":sig,
           "revocation_payload_sha256":digest(msg),
           "conflicts":conflicts,"quarantined":True,
           "recovery_authorized":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    result={"phase":"RUST-065","status":"HOLD_WITNESS_ROTATION_REVOCATION",
            "events":old+[event],"prefix_heads":heads+[event["entry_sha256"]],
            "event_count":len(old)+1,"head_sha256":event["entry_sha256"],
            "revoked_signer_pins":history["revoked_signer_pins"]+[bad],
            "revoked_controller_roots":revoked_roots,
            "rotation_conflicts":history["rotation_conflicts"]+conflicts,
            "source_fork_keys_preserved":registry["fork_keys"],
            "source_custody_conflicts_preserved":registry["custody_conflicts"],
            "retained_floor_compared":floor is not None,
            "retained_floor_claim_sha256":digest(floor) if floor is not None else None,
            "independent_recovery_verified":False,
            "globally_latest_revocation_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-065","status":"HOLD_MISSING_WITNESS_REVOCATION_CUSTODY",
            "independent_recovery_verified":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","registry","history","rotation","authority-pin","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.source,a.registry,a.history,a.rotation,a.authority_pin]
    require(all(required) or not any(required),"partial witness revocation bundle refused")
    require(not a.floor or all(required),"floor without revocation evidence refused")
    if all(required):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        out=audit(read(a.source),read(a.registry),read(a.history),read(a.rotation),
                  a.authority_pin,read(a.floor) if a.floor else None)
    else:out=hold()
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-065 HOLD: independent recovery not verified")
if __name__=="__main__":main()
