#!/usr/bin/env python3
"""RUST-042: append-only challenge sessions and attestor key continuity.

Consumes a digest-checked RUST-041 receipt, previous RUST-042 ledger and
a separately supplied retained prefix floor. Detects replay, missing epochs,
attestor-key substitutions and rewritten historical challenges. Neither an
in-repository ledger nor a caller-supplied floor authenticates custody.
"""
import argparse
import json
from pathlib import Path

from lineage_rust019 import digest, require
from multiwitness_rust026 import ROLES
from rotation_rust022 import check_sha

GENESIS = digest({"phase":"RUST-042","kind":"CHALLENGE_GENESIS_V1"})
HEX_FIELDS = (
    "externally_issued_nonce_sha256","retrieval_session_sha256",
    "custodian_signature_sha256","attestor_signature_sha256",
    "attestor_key_spki_sha256","external_attestor_root_sha256",
    "source_root_sha256","acquisition_path_sha256",
)

def checked_upstream(receipt):
    require(isinstance(receipt,dict) and receipt.get("phase")=="RUST-041",
            "RUST-041 receipt required")
    require(receipt.get("status") in ("HOLD_SHARED_ATTESTATION_ANCESTRY",
                                     "HOLD_INDEPENDENT_CONTROL_UNVERIFIED"),
            "unexpected attestation status")
    require(receipt.get("release_authorized") is False and
            receipt.get("fork_resolved") is False,
            "upstream authority escalation")
    require(digest({k:v for k,v in receipt.items() if k!="receipt_sha256"})==
            receipt.get("receipt_sha256"),"RUST-041 receipt altered")
    obs=receipt.get("observations")
    require(isinstance(obs,list) and len(obs)==3 and
            [x.get("role") for x in obs]==list(ROLES),
            "three ordered signed observations required")
    for x in obs:
        require(x.get("dual_signature_checked") is True,
                "upstream unverified dual signature")
        for name in HEX_FIELDS:
            check_sha(x.get(name),"invalid upstream "+name)
    require([x["externally_issued_nonce_sha256"] for x in obs] ==
            receipt.get("new_nonce_fingerprints"),"nonce list differs from upstream observations")
    return obs

def checked_history(history):
    require(isinstance(history,dict) and history.get("phase")=="RUST-042" and
            history.get("status") in ("HOLD_EXTERNAL_LEDGER_UNVERIFIED",
                                          "HOLD_ATTESTOR_IDENTITY_SUBSTITUTION"),
            "RUST-042 predecessor ledger missing")
    require(history.get("release_authorized") is False,
            "historical release promotion")
    require(type(history.get("epoch")) is int and history["epoch"]>=0,
            "invalid previous epoch")
    entries=history.get("entries")
    heads=history.get("prefix_heads")
    require(isinstance(entries,list) and isinstance(heads,list),"historical entries missing")
    require(len(entries)==history["epoch"]*3 and len(heads)==len(entries)+1,
            "historical ledger truncated")
    require(heads[0]==GENESIS,"incorrect genesis")
    last=GENESIS
    seen_nonce=set()
    seen_session=set()
    for index,entry in enumerate(entries):
        require(isinstance(entry,dict) and
                entry.get("ordinal")==index+1 and
                entry.get("epoch")==index//3+1 and
                entry.get("role")==ROLES[index%3],
                "historical epoch or role gap")
        require(entry.get("previous_entry_sha256")==last,
                "historical predecessor link changed")
        check_sha(entry.get("attestor_key_spki_sha256"),"missing attestor pin")
        check_sha(entry.get("external_attestor_root_sha256"),"missing attestor root")
        nonce=entry.get("nonce_sha256")
        session=entry.get("retrieval_session_sha256")
        check_sha(nonce,"historical nonce invalid")
        check_sha(session,"historical session invalid")
        require(nonce not in seen_nonce and session not in seen_session,
                "historical challenge replay")
        seen_nonce.add(nonce)
        seen_session.add(session)
        require(digest({k:v for k,v in entry.items() if k!="entry_sha256"})==
                entry.get("entry_sha256"),"historical entry digest altered")
        last=entry["entry_sha256"]
        require(heads[index+1]==last,"historical prefix head differs")
    require(history.get("head_sha256")==last,"historical head mismatch")
    require(digest({k:v for k,v in history.items() if k!="receipt_sha256"})==
            history.get("receipt_sha256"),"historical ledger receipt altered")
    return entries,heads

def genesis():
    result={
        "phase":"RUST-042","status":"HOLD_EXTERNAL_LEDGER_UNVERIFIED",
        "epoch":0,"entries":[],"prefix_heads":[GENESIS],
        "head_sha256":GENESIS,
        "release_authorized":False,
        "external_custody_verified":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def check_floor(floor,heads):
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-042",
            "externally retained floor absent")
    require(type(floor.get("entry_count")) is int and floor["entry_count"]>=0,
            "floor entry count invalid")
    check_sha(floor.get("head_sha256"),"floor head missing")
    require(floor["entry_count"]<len(heads),"retained floor beyond proposed history")
    require(heads[floor["entry_count"]]==floor["head_sha256"],
            "withheld or substituted challenge history")
    return True

def audit(upstream,history,retained_floor=None):
    observations=checked_upstream(upstream)
    old,old_heads=checked_history(history)
    seen_nonces={x["nonce_sha256"] for x in old}
    seen_sessions={x["retrieval_session_sha256"] for x in old}
    last_attestor={}
    for entry in old:
        last_attestor[entry["role"]]=(
            entry["attestor_key_spki_sha256"],
            entry["external_attestor_root_sha256"])
    epoch=history["epoch"]+1
    entries=list(old)
    heads=list(old_heads)
    new=[]
    collisions=[]
    for role,obs in zip(ROLES,observations):
        nonce=obs["externally_issued_nonce_sha256"]
        session=obs["retrieval_session_sha256"]
        require(nonce not in seen_nonces,"challenge nonce replay")
        require(session not in seen_sessions,"retrieval session replay")
        seen_nonces.add(nonce)
        seen_sessions.add(session)
        identity=(obs["attestor_key_spki_sha256"],obs["external_attestor_root_sha256"])
        if role in last_attestor and last_attestor[role]!=identity:
            collisions.append({
                "role":role,"reason":"ATTESTOR_IDENTITY_CHANGED_WITHOUT_AUTHENTICATED_ROTATION",
                "prior_pin":last_attestor[role][0],
                "new_pin":identity[0],
                "prior_root":last_attestor[role][1],
                "new_root":identity[1],
            })
        last_attestor[role]=identity
        entry={
            "phase":"RUST-042","kind":"ATTESTED_CHALLENGE_ENTRY",
            "ordinal":len(entries)+1,"epoch":epoch,"role":role,
            "previous_entry_sha256":heads[-1],
            "source_rust041_receipt_sha256":upstream["receipt_sha256"],
            "source_observation_sha256":digest(obs),
            "nonce_sha256":nonce,
            "retrieval_session_sha256":session,
            "attestor_key_spki_sha256":identity[0],
            "external_attestor_root_sha256":identity[1],
            "custodian_signature_sha256":obs["custodian_signature_sha256"],
            "attestor_signature_sha256":obs["attestor_signature_sha256"],
            "release_authorized":False,
        }
        entry["entry_sha256"]=digest(entry)
        entries.append(entry)
        heads.append(entry["entry_sha256"])
        new.append(entry)
    if retained_floor is not None:
        check_floor(retained_floor,heads)
    result={
        "phase":"RUST-042","status":"HOLD_ATTESTOR_IDENTITY_SUBSTITUTION" if collisions or
            history.get("status")=="HOLD_ATTESTOR_IDENTITY_SUBSTITUTION"
            else "HOLD_EXTERNAL_LEDGER_UNVERIFIED",
        "epoch":epoch,"entries":entries,"prefix_heads":heads,
        "head_sha256":heads[-1],
        "new_epoch_entries":new,
        "attestor_continuity_conflicts":
            history.get("attestor_continuity_conflicts",[])+collisions,
        "upstream_rust041_receipt_sha256":upstream["receipt_sha256"],
        "retained_floor_compared":retained_floor is not None,
        "retained_floor_claim_sha256":digest(retained_floor) if retained_floor is not None else None,
        "preserved_upstream_collisions":upstream.get("attestation_ancestry_collisions",[]),
        "external_custody_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"release_authorized":False,
        "live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {
        "phase":"RUST-042","status":"HOLD_MISSING_RETAINED_CHALLENGE_LEDGER",
        "release_authorized":False,"fork_resolved":False,
        "external_custody_verified":False,
        "live_gameplay_authority":False,
        "reason":"No independently retained history, current signed challenges and external floor",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream")
    p.add_argument("--history")
    p.add_argument("--floor")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    require(bool(a.upstream)==bool(a.history),"partial ledger evidence refused")
    require(not a.floor or (a.upstream and a.history),"floor without history refused")
    if a.upstream:
        result=audit(json.loads(Path(a.upstream).read_text(encoding="utf-8")),
                     json.loads(Path(a.history).read_text(encoding="utf-8")),
                     json.loads(Path(a.floor).read_text(encoding="utf-8")) if a.floor else None)
    else:
        result=hold()
    out=Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("
")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-042 HOLD: independent challenge custody not authenticated")

if __name__=="__main__":
    main()
