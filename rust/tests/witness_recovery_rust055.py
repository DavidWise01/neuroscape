#!/usr/bin/env python3
"""RUST-055: quarantined successor witness recovery; never authorize a revoked origin."""
import argparse
import json
from pathlib import Path
from lineage_rust019 import digest, require
from rotation_rust022 import canonical, check_sha, verify_key_and_signature
from witness_revocation_rust054 import checked_history

GENESIS=digest({"phase":"RUST-055","kind":"WITNESS_RECOVERY_QUARANTINE_GENESIS_V1"})

def genesis():
    x={"phase":"RUST-055","status":"HOLD_WITNESS_RECOVERY_QUARANTINE",
       "events":[],"prefix_heads":[GENESIS],"event_count":0,"head_sha256":GENESIS,
       "recovery_attempts":[],"release_authorized":False,"fork_resolved":False,
       "independent_custody_verified":False}
    x["receipt_sha256"]=digest(x)
    return x

def checked_recovery_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-055" and
            history.get("status")=="HOLD_WITNESS_RECOVERY_QUARANTINE",
            "prior recovery quarantine unavailable")
    require(history.get("release_authorized") is False and
            history.get("fork_resolved") is False,"prior recovery claimed authority")
    entries=history.get("events")
    heads=history.get("prefix_heads")
    require(isinstance(entries,list) and isinstance(heads,list) and
            len(heads)==len(entries)+1 and heads[0]==GENESIS,
            "recovery history truncated")
    previous=GENESIS
    attempts=[]
    seen=set()
    for i,e in enumerate(entries,1):
        require(e.get("phase")=="RUST-055" and
                e.get("kind")=="QUARANTINED_WITNESS_RECOVERY_EVENT" and
                e.get("ordinal")==i and
                e.get("previous_entry_sha256")==previous,
                "recovery predecessor rewritten")
        require(e.get("release_authorized") is False and
                e.get("recovery_authorized") is False,
                "recovery asserted authority")
        check_sha(e.get("source_rust054_receipt_sha256"),"source digest invalid")
        check_sha(e.get("candidate_nonce_sha256"),"nonce invalid")
        require(e["candidate_nonce_sha256"] not in seen,"replayed recovery nonce")
        seen.add(e["candidate_nonce_sha256"])
        require(e.get("independence_authenticated") is False,
                "unqualified independent control")
        require(digest({k:v for k,v in e.items() if k!="entry_sha256"})==
                e.get("entry_sha256"),"historical recovery entry changed")
        previous=e["entry_sha256"]
        require(heads[i]==previous,"historical prefix changed")
        attempts.append(e)
    require(history.get("event_count")==len(entries) and
            history.get("head_sha256")==previous and
            history.get("recovery_attempts")==attempts,
            "recovery attempt history altered")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"recovery receipt corrupted")
    return entries,heads

def candidate_message(registry, previous_head, candidate):
    required=("revoked_signer_pin","candidate_signer_pin",
              "claimed_controller_sha256","candidate_source_root_sha256",
              "candidate_acquisition_sha256","external_authority_root_sha256",
              "challenge_nonce_sha256","incident_evidence_sha256")
    for key in required:
        check_sha(candidate.get(key),"candidate evidence missing: "+key)
    return {"phase":"RUST-055","kind":"QUARANTINED_WITNESS_REPLACEMENT_V1",
            "source_rust054_receipt_sha256":registry["receipt_sha256"],
            "previous_recovery_head_sha256":previous_head,
            **{key:candidate[key] for key in required},
            "release_authorized":False,"recovery_authorized":False}

def audit(registry, history, candidates, candidate_pins, authority_pins,
          floor=None, verifier=verify_key_and_signature):
    checked_history(registry)
    previous,heads=checked_recovery_history(history)
    require(registry.get("release_authorized") is False and
            registry.get("fork_resolved") is False and
            registry.get("independent_custody_verified") is False,
            "revocation registry claims authority")
    require(isinstance(candidates,list) and candidates and
            isinstance(candidate_pins,list) and
            isinstance(authority_pins,list) and
            len(candidates)==len(candidate_pins)==len(authority_pins),
            "complete signed candidate and authority pairs required")
    if floor is not None:
        require(isinstance(floor,dict) and floor.get("phase")=="RUST-055",
                "retained recovery floor missing")
        n=floor.get("event_count")
        require(type(n) is int and 0<=n<len(heads),
                "retained recovery floor exceeds known history")
        check_sha(floor.get("head_sha256"),"floor head invalid")
        require(heads[n]==floor["head_sha256"],"recovery ancestry withheld or forked")
    revoked=set(registry["revoked_signer_pins"])
    revoked_roots=set(registry["revoked_claimed_controllers"])
    seen_nonces={e["candidate_nonce_sha256"] for e in previous}
    seen_pairs={(e["revoked_signer_pin"],e["candidate_signer_pin"]) for e in previous}
    created=[]
    for item,candidate_pin,authority_pin in zip(candidates,candidate_pins,authority_pins):
        require(isinstance(item,dict),"malformed witness replacement")
        msg=candidate_message(registry,heads[-1],item)
        old=msg["revoked_signer_pin"]
        new=msg["candidate_signer_pin"]
        require(old in revoked,"replacement not anchored to revoked witness")
        require(new not in revoked and new!=old,
                "replacement key already revoked")
        require(candidate_pin==new,"replacement signer pin mismatch")
        check_sha(authority_pin,"external authority signing pin absent")
        require(authority_pin not in revoked and authority_pin not in (new,old),
                "self-issued or revoked recovery authority")
        require(msg["challenge_nonce_sha256"] not in seen_nonces,
                "replacement challenge nonce replay")
        seen_nonces.add(msg["challenge_nonce_sha256"])
        require((old,new) not in seen_pairs,"duplicate compromised-to-successor pair")
        seen_pairs.add((old,new))
        require(msg["external_authority_root_sha256"] not in revoked_roots and
                msg["external_authority_root_sha256"]!=
                msg["claimed_controller_sha256"],
                "recovery authority inherits compromised controller")
        candidate_sig=verifier(item.get("candidate_public_key"),
                               item.get("candidate_signature"),
                               candidate_pin,canonical(msg))
        authority_sig=verifier(item.get("authority_public_key"),
                               item.get("authority_signature"),
                               authority_pin,canonical(msg))
        check_sha(candidate_sig,"replacement signature invalid")
        check_sha(authority_sig,"authority signature invalid")
        collision=msg["claimed_controller_sha256"] in revoked_roots
        entry={"phase":"RUST-055","kind":"QUARANTINED_WITNESS_RECOVERY_EVENT",
               "ordinal":len(previous)+len(created)+1,
               "previous_entry_sha256":heads[-1] if not created else
                     created[-1]["entry_sha256"],
               "source_rust054_receipt_sha256":registry["receipt_sha256"],
               "revoked_signer_pin":old,"candidate_signer_pin":new,
               "candidate_nonce_sha256":msg["challenge_nonce_sha256"],
               "claimed_controller_sha256":msg["claimed_controller_sha256"],
               "candidate_source_root_sha256":msg["candidate_source_root_sha256"],
               "candidate_acquisition_sha256":msg["candidate_acquisition_sha256"],
               "external_authority_root_sha256":msg["external_authority_root_sha256"],
               "recovery_payload_sha256":digest(msg),
               "candidate_signature_sha256":candidate_sig,
               "authority_signature_sha256":authority_sig,
               "authority_pin":authority_pin,
               "reuses_revoked_controller":collision,
               "quarantine_persists":True,"independence_authenticated":False,
               "recovery_authorized":False,"release_authorized":False}
        entry["entry_sha256"]=digest(entry)
        created.append(entry)
    combined=previous+created
    new_heads=heads+[e["entry_sha256"] for e in created]
    result={"phase":"RUST-055","status":"HOLD_WITNESS_RECOVERY_QUARANTINE",
            "events":combined,"prefix_heads":new_heads,
            "event_count":len(combined),"head_sha256":new_heads[-1],
            "recovery_attempts":combined,
            "revoked_signer_pins_preserved":registry["revoked_signer_pins"],
            "revoked_claimed_controllers_preserved":
                registry["revoked_claimed_controllers"],
            "earlier_ancestry_conflicts_preserved":registry["conflicts"],
            "retained_floor_compared":floor is not None,
            "retained_floor_claim_sha256":digest(floor) if floor else None,
            "independent_custody_verified":False,
            "global_anti_rollback_certified":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-055","status":"HOLD_MISSING_INDEPENDENT_RECOVERY_CUSTODY",
            "independent_custody_verified":False,"fork_resolved":False,
            "release_authorized":False,"live_gameplay_authority":False,
            "reason":"No separately held recovery ancestry and successor signatures"}

def main():
    p=argparse.ArgumentParser()
    for key in ("registry","history","candidates","candidate-pins","authority-pins","floor"):
        p.add_argument("--"+key)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    inputs=[a.registry,a.history,a.candidates,a.candidate_pins,a.authority_pins]
    require(all(inputs) or not any(inputs),"partial recovery material refused")
    require(not a.floor or all(inputs),"floor without recovery inputs refused")
    if all(inputs):
        data=[json.loads(Path(x).read_text(encoding="utf-8")) for x in inputs]
        floor=json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None
        result=audit(*data,floor=floor)
    else:
        result=hold()
    dest=Path(a.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-055 HOLD: recovery not independently authenticated")

if __name__=="__main__":
    main()
