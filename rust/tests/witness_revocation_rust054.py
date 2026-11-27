#!/usr/bin/env python3
"""RUST-054: persistent witness ancestry conflicts and signed revocation HOLD."""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature

GENESIS = digest({"phase":"RUST-054","kind":"WITNESS_FENCE_GENESIS_V1"})

def checked_source(source):
    require(isinstance(source,dict) and source.get("phase")=="RUST-053" and
            source.get("status")=="HOLD_SIGNED_CHALLENGE_HIGHWATER_CUSTODY_UNVERIFIED",
            "RUST-053 source unavailable")
    require(source.get("release_authorized") is False and
            source.get("fork_resolved") is False and
            source.get("independent_external_custody_verified") is False,
            "source claims authority")
    require(digest({k:v for k,v in source.items() if k!="receipt_sha256"})==
            source.get("receipt_sha256"),"source receipt corrupted")
    sessions=source.get("new_session_evidence")
    conflicts=source.get("session_ancestry_conflicts")
    require(isinstance(sessions,list) and sessions and isinstance(conflicts,list),
            "session and ancestry evidence absent")
    for s in sessions:
        require(isinstance(s,dict) and s.get("independent_custody_verified") is False,
                "session asserted independence")
        for k in ("signer_pin","session_nonce_sha256","message_sha256",
                  "signature_sha256","claimed_source_root_sha256",
                  "operator_control_sha256","acquisition_sha256"):
            check_sha(s.get(k),"session field invalid")
    for c in conflicts:
        require(c.get("reason")=="SESSION_SIGNER_ANCESTRY_CHANGED" and
                c.get("independent_control_verified") is False,
                "unqualified conflict")
        check_sha(c.get("pin"),"conflict signer invalid")
        require(any(s["signer_pin"]==c["pin"] and
                    [s["claimed_source_root_sha256"],s["acquisition_sha256"],
                     s["operator_control_sha256"]]==c.get("current_claim")
                    for s in sessions),"ancestry conflict not in session")
    return sessions,conflicts

def genesis():
    out={"phase":"RUST-054","status":"HOLD_WITNESS_REVOCATION_REGISTRY",
         "events":[],"prefix_heads":[GENESIS],"head_sha256":GENESIS,
         "event_count":0,"conflicts":[],"revoked_signer_pins":[],
         "revoked_claimed_controllers":[],"release_authorized":False,
         "fork_resolved":False,"independent_custody_verified":False}
    out["receipt_sha256"]=digest(out)
    return out

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-054" and
            history.get("status")=="HOLD_WITNESS_REVOCATION_REGISTRY",
            "RUST-054 history absent")
    require(history.get("release_authorized") is False and
            history.get("fork_resolved") is False,"prior authority promotion")
    events=history.get("events")
    heads=history.get("prefix_heads")
    require(isinstance(events,list) and isinstance(heads,list) and
            len(heads)==len(events)+1 and heads[0]==GENESIS,
            "revocation registry truncated")
    last=GENESIS
    receipts=set()
    conflicts=[]
    revoked=[]
    roots=[]
    for i,event in enumerate(events,1):
        require(isinstance(event,dict) and event.get("phase")=="RUST-054" and
                event.get("kind")=="WITNESS_FENCE_EVENT" and
                event.get("ordinal")==i and event.get("previous_entry_sha256")==last,
                "witness registry ancestry changed")
        check_sha(event.get("source_rust053_receipt_sha256"),"source hash invalid")
        require(event["source_rust053_receipt_sha256"] not in receipts,
                "duplicate source receipt")
        receipts.add(event["source_rust053_receipt_sha256"])
        require(event.get("release_authorized") is False and
                event.get("fork_resolved") is False,"historical authority promotion")
        require(isinstance(event.get("sessions"),list) and
                isinstance(event.get("conflicts"),list) and
                isinstance(event.get("revocations"),list),"historical evidence missing")
        conflicts.extend(event["conflicts"])
        for item in event["revocations"]:
            pin=item.get("compromised_pin")
            root=item.get("claimed_controller_sha256")
            check_sha(pin,"revoked signer hash invalid")
            check_sha(root,"revoked control root invalid")
            require(pin not in revoked,"duplicate historical revocation")
            revoked.append(pin)
            if root not in roots: roots.append(root)
        require(digest({k:v for k,v in event.items() if k!="entry_sha256"})==
                event.get("entry_sha256"),"witness event rewritten")
        last=event["entry_sha256"]
        require(heads[i]==last,"witness prefix rewritten")
    require(history.get("event_count")==len(events) and
            history.get("head_sha256")==last and
            history.get("conflicts")==conflicts and
            history.get("revoked_signer_pins")==revoked and
            history.get("revoked_claimed_controllers")==roots,
            "previous revocations or conflicts erased")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"registry receipt tampered")
    return events,heads

def revocation_payload(source,head,item):
    for field in ("compromised_pin","claimed_controller_sha256",
                  "incident_evidence_sha256","nonce_sha256"):
        check_sha(item.get(field),"revocation payload incomplete")
    return {"phase":"RUST-054","kind":"WITNESS_REVOCATION_V1",
            "source_rust053_receipt_sha256":source["receipt_sha256"],
            "previous_registry_head_sha256":head,
            "compromised_pin":item["compromised_pin"],
            "claimed_controller_sha256":item["claimed_controller_sha256"],
            "incident_evidence_sha256":item["incident_evidence_sha256"],
            "nonce_sha256":item["nonce_sha256"],
            "release_authorized":False}

def audit(source,history,revocations,pins,floor=None,
          verifier=verify_key_and_signature):
    sessions,source_conflicts=checked_source(source)
    old,heads=checked_history(history)
    require(source["receipt_sha256"] not in
            {e["source_rust053_receipt_sha256"] for e in old},
            "source session replay")
    require(isinstance(revocations,list) and isinstance(pins,list) and
            len(revocations)==len(pins),"revocation authority pins mismatch")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-054",
                "external retained floor missing")
        count=floor.get("event_count")
        require(type(count) is int and 0<=count<len(heads),
                "floor exceeds recorded history")
        check_sha(floor.get("head_sha256"),"retained head invalid")
        require(heads[count]==floor["head_sha256"],
                "retained fork history rewritten")
    known=set(history["revoked_signer_pins"])
    roots=set(history["revoked_claimed_controllers"])
    previous_nonces={r["nonce_sha256"] for e in old for r in e["revocations"]}
    new=[]
    for item,authority in zip(revocations,pins):
        require(isinstance(item,dict),"malformed revocation")
        msg=revocation_payload(source,heads[-1],item)
        pin=msg["compromised_pin"]
        require(pin not in known,"already revoked witness key")
        known.add(pin)
        check_sha(authority,"independent authority key missing")
        require(authority not in known,"revoked/self-issued revocation authority")
        require(msg["nonce_sha256"] not in previous_nonces,"revocation nonce replay")
        previous_nonces.add(msg["nonce_sha256"])
        signature=verifier(item.get("authority_public_key"),
                           item.get("authority_signature"),authority,canonical(msg))
        check_sha(signature,"revocation signature invalid")
        new.append({"compromised_pin":pin,
                    "claimed_controller_sha256":msg["claimed_controller_sha256"],
                    "nonce_sha256":msg["nonce_sha256"],
                    "revocation_payload_sha256":digest(msg),
                    "authority_pin":authority,"signature_sha256":signature,
                    "independent_authority_authenticated":False})
    for item in new: roots.add(item["claimed_controller_sha256"])
    alerts=[]
    for s in sessions:
        if s["signer_pin"] in known or s["operator_control_sha256"] in roots:
            alerts.append({"reason":"REVOKED_KEY_OR_CONTROLLER_REAPPEARED",
                           "signer_pin":s["signer_pin"],
                           "claimed_controller_sha256":s["operator_control_sha256"],
                           "recovery_authorized":False})
    conflicts=[{"kind":"SESSION_ANCESTRY","evidence":c} for c in source_conflicts]+[
        {"kind":"REVOKED_CONTROLLER_REAPPEARANCE","evidence":a} for a in alerts]
    event={"phase":"RUST-054","kind":"WITNESS_FENCE_EVENT",
           "ordinal":len(old)+1,"previous_entry_sha256":heads[-1],
           "source_rust053_receipt_sha256":source["receipt_sha256"],
           "sessions":sessions,"conflicts":conflicts,"revocations":new,
           "fork_resolved":False,"release_authorized":False}
    event["entry_sha256"]=digest(event)
    old_roots=list(history["revoked_claimed_controllers"])
    for item in new:
        if item["claimed_controller_sha256"] not in old_roots:
            old_roots.append(item["claimed_controller_sha256"])
    result={"phase":"RUST-054","status":"HOLD_WITNESS_REVOCATION_REGISTRY",
            "events":old+[event],"prefix_heads":heads+[event["entry_sha256"]],
            "head_sha256":event["entry_sha256"],"event_count":len(old)+1,
            "conflicts":history["conflicts"]+conflicts,
            "revoked_signer_pins":history["revoked_signer_pins"]+[
                r["compromised_pin"] for r in new],
            "revoked_claimed_controllers":old_roots,
            "historical_source_ancestry_conflicts":
                source.get("historical_ancestry_conflicts",[]),
            "retained_floor_compared":floor is not None,
            "retained_floor_claim_sha256":digest(floor) if floor else None,
            "independent_custody_verified":False,
            "globally_latest_witness_highwater_verified":False,
            "fork_resolved":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-054","status":"HOLD_MISSING_WITNESS_REVOCATION_CUSTODY",
            "independent_custody_verified":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False,
            "reason":"No independent witness revocation registry or custody floor"}

def main():
    p=argparse.ArgumentParser()
    for name in ("source","history","revocations","pins","floor"):
        p.add_argument("--"+name)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.source,a.history,a.revocations,a.pins]
    require(all(required) or not any(required),"partial revocation bundle refused")
    require(not a.floor or all(required),"external floor without full bundle refused")
    if all(required):
        doc=lambda v:json.loads(Path(v).read_text(encoding="utf-8"))
        result=audit(doc(a.source),doc(a.history),doc(a.revocations),
                     doc(a.pins),doc(a.floor) if a.floor else None)
    else:
        result=hold()
    out=Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-054 HOLD: external witness custody unverified")

if __name__=="__main__":
    main()
