#!/usr/bin/env python3
"""RUST-068 — signed recovery-attempt highwater; quarantines survive epochs.

Observation only. Signatures and retention-floor claims are not proof of
independent physical custody, global latest history, or release authority.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import canonical,check_sha,verify_key_and_signature
from successor_recovery_rust067 import checked_history

ORIGINS=("controller_sha256","source_root_sha256","acquisition_sha256")

def checkpoint_payload(history):
    events,heads=checked_history(history)
    require(events,"predecessor recovery history must be nonempty")
    return {"phase":"RUST-068","kind":"RECOVERY_QUARANTINE_HIGHWATER_V1",
            "recovery_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "quarantined_candidates_sha256":digest([
                [e["revocation_entry_sha256"],e["candidate_pin"]] for e in events]),
            "custody_conflicts_sha256":digest(history["custody_conflicts"]),
            "source_rust067_receipt_sha256":history["receipt_sha256"],
            "recovery_authorized":False,"release_authorized":False}

def compare_ancestry(prior,appended):
    pins={};roots={};acquisitions={}
    for event in prior:
        for w in event["witnesses"]:
            origin=tuple(w[k] for k in ORIGINS)
            pins.setdefault(w["pin"],set()).add(origin)
            roots.setdefault(w["controller_sha256"],set()).add(w["pin"])
            acquisitions.setdefault(w["acquisition_sha256"],set()).add(w["pin"])
    conflicts=[]
    for event in appended:
        for w in event["witnesses"]:
            origin=tuple(w[k] for k in ORIGINS)
            if w["pin"] in pins and origin not in pins[w["pin"]]:
                conflicts.append({"reason":"SAME_WITNESS_PIN_CHANGED_ANCESTRY",
                                  "pin":w["pin"],"independent_custody_verified":False})
            for field,index,reason in (
                ("controller_sha256",roots,"RENAMED_WITNESS_SHARED_CONTROLLER"),
                ("acquisition_sha256",acquisitions,"RENAMED_WITNESS_SHARED_ACQUISITION")):
                other=index.get(w[field],set())
                if other and w["pin"] not in other:
                    conflicts.append({"reason":reason,"pin":w["pin"],
                                      "prior_pins":sorted(other),
                                      "independent_custody_verified":False})
    return conflicts

def audit(previous,current,checkpoint,public_key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    old,old_heads=checked_history(previous)
    new,new_heads=checked_history(current)
    require(old and len(new)>len(old),
            "recovery successor must strictly advance")
    require(new[:len(old)]==old and new_heads[:len(old_heads)]==old_heads,
            "historical recovery prefix rewritten or withheld")
    require(current["custody_conflicts"][:len(previous["custody_conflicts"])]==
            previous["custody_conflicts"],"historical custody conflicts erased")
    for event in new:
        require(event["quarantine_persists"] is True and
                event["recovery_authorized"] is False and
                event["release_authorized"] is False,
                "historical candidate graduated from quarantine")
    expected=checkpoint_payload(previous)
    require(checkpoint==expected,"signed recovery checkpoint substituted")
    check_sha(signer_pin,"recovery checkpoint pin invalid")
    prohibited={w["pin"] for e in new for w in e["witnesses"]}
    prohibited.update(e["candidate_pin"] for e in new)
    require(signer_pin not in prohibited,
            "candidate or custody witness cannot self-sign highwater")
    signed=verifier(public_key,signature,signer_pin,canonical(expected))
    check_sha(signed,"recovery checkpoint signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-068",
            "independently presented retained floor missing")
    count=floor.get("recovery_count")
    require(type(count) is int and len(old)<=count<=len(new),
            "retained recovery highwater outside successor history")
    check_sha(floor.get("head_sha256"),"retained floor head invalid")
    require(new_heads[count]==floor["head_sha256"],
            "retained recovery floor contradicts exact prefix")
    appended=new[len(old):]
    require(isinstance(observations,list) and len(observations)==len(appended),
            "fresh observation required per new recovery attempt")
    historic_nonces={w["nonce_sha256"] for e in new for w in e["witnesses"]}
    fresh=set(); reviewed=[]
    for event,claim in zip(appended,observations):
        require(isinstance(claim,dict) and claim.get("phase")=="RUST-068",
                "recovery epoch claim missing")
        for field in ("recovery_entry_sha256","epoch_nonce_sha256",
                      "candidate_pin","revocation_entry_sha256",
                      "claimed_controller_sha256","claimed_acquisition_sha256"):
            check_sha(claim.get(field),"recovery observation missing "+field)
        require(claim["recovery_entry_sha256"]==event["entry_sha256"] and
                claim["candidate_pin"]==event["candidate_pin"] and
                claim["revocation_entry_sha256"]==event["revocation_entry_sha256"],
                "recovery observation not bound to quarantined successor")
        require(claim["claimed_controller_sha256"]==
                event["candidate_controller_sha256"] and
                claim["claimed_acquisition_sha256"]==
                event["candidate_acquisition_sha256"],
                "recovery observation substituted ancestry")
        nonce=claim["epoch_nonce_sha256"]
        require(nonce not in historic_nonces and nonce not in fresh,
                "recovery highwater observation nonce replay")
        fresh.add(nonce)
        require(claim.get("quarantine_persists") is True and
                claim.get("recovery_authorized") is False and
                claim.get("release_authorized") is False,
                "recovery observation promoted authority")
        reviewed.append({"entry_sha256":event["entry_sha256"],
                         "claim_sha256":digest(claim),
                         "nonce_sha256":nonce,"quarantine_persists":True,
                         "independent_custody_verified":False})
    ancestry=compare_ancestry(old,appended)
    result={
        "phase":"RUST-068",
        "status":"HOLD_RECOVERY_HIGHWATER_QUARANTINE_PERSISTENCE",
        "previous_rust067_receipt_sha256":previous["receipt_sha256"],
        "current_rust067_receipt_sha256":current["receipt_sha256"],
        "signed_checkpoint":expected,"checkpoint_signer_pin":signer_pin,
        "checkpoint_signature_sha256":signed,
        "retained_floor_claim_sha256":digest(floor),
        "previous_recovery_count":len(old),"current_recovery_count":len(new),
        "prior_quarantined_candidates_preserved":[
            [e["revocation_entry_sha256"],e["candidate_pin"]] for e in old],
        "current_quarantined_candidates_preserved":[
            [e["revocation_entry_sha256"],e["candidate_pin"]] for e in new],
        "historical_conflicts_preserved":previous["custody_conflicts"],
        "current_conflicts_preserved":current["custody_conflicts"],
        "cross_epoch_ancestry_conflicts":ancestry,
        "new_epoch_observations":reviewed,
        "all_successors_quarantined":True,
        "independent_custody_verified":False,
        "globally_latest_highwater_verified":False,
        "global_anti_rollback_certified":False,
        "fork_resolved":False,"recovery_authorized":False,
        "release_authorized":False,"live_gameplay_authority":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-068",
            "status":"HOLD_MISSING_RECOVERY_HIGHWATER_EVIDENCE",
            "all_successors_quarantined":True,
            "independent_custody_verified":False,
            "fork_resolved":False,"recovery_authorized":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("previous","current","checkpoint","public-key","signature",
              "signer-pin","floor","observations"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    required=[a.previous,a.current,a.checkpoint,a.public_key,a.signature,
              a.signer_pin,a.floor,a.observations]
    require(all(required) or not any(required),
            "partial recovery highwater evidence rejected")
    if all(required):
        read=lambda x:json.loads(Path(x).read_text(encoding="utf-8"))
        result=audit(read(a.previous),read(a.current),read(a.checkpoint),
                     a.public_key,a.signature,a.signer_pin,
                     read(a.floor),read(a.observations))
    else:result=hold()
    output=Path(a.output);output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(result,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-068 HOLD: independent recovery authority unavailable")
if __name__=="__main__":main()
