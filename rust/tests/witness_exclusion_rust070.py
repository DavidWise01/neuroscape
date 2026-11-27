#!/usr/bin/env python3
"""RUST-070 signed witness-revocation highwater and custodian exclusion fence.
All records are observational. Signatures never grant independent custody.
"""
import argparse,json
from pathlib import Path
from lineage_rust019 import digest,require
from rotation_rust022 import check_sha,canonical,verify_key_and_signature
from recovery_witness_revocation_rust069 import checked_history

def checkpoint_payload(history):
    events,heads=checked_history(history)
    require(events,"signed predecessor revocation ledger must be nonempty")
    return {"phase":"RUST-070","kind":"RECOVERY_WITNESS_REVOCATION_HIGHWATER_V1",
            "event_count":len(events),"head_sha256":heads[-1],
            "events_sha256":digest(events),
            "revoked_pins_sha256":digest(history["revoked_witness_pins"]),
            "revoked_controllers_sha256":digest(history["revoked_controller_roots"]),
            "conflicts_sha256":digest(history["custody_conflicts"]),
            "source_rust069_receipt_sha256":history["receipt_sha256"],
            "release_authorized":False}

def audit(previous,current,checkpoint,public_key,signature,signer_pin,
          floor,observations,verifier=verify_key_and_signature):
    before,before_heads=checked_history(previous)
    after,after_heads=checked_history(current)
    require(before and len(after)>len(before),
            "successor revocation ledger must strictly extend predecessor")
    require(after[:len(before)]==before and
            after_heads[:len(before_heads)]==before_heads,
            "historic revocation prefix rewritten or truncated")
    for key in ("revoked_witness_pins","revoked_controller_roots",
                "custody_conflicts"):
        require(current[key][:len(previous[key])]==previous[key],
                "historical exclusion or conflicts erased: "+key)
    expected=checkpoint_payload(previous)
    require(checkpoint==expected,"signed revocation checkpoint substituted")
    check_sha(signer_pin,"checkpoint signing key missing")
    excluded=set(current["revoked_witness_pins"])
    all_attestors={w["pin"] for e in after for w in e["witnesses"]}
    require(signer_pin not in excluded and signer_pin not in all_attestors,
            "revoked or historical witness may not self-sign highwater")
    sig=verifier(public_key,signature,signer_pin,canonical(expected))
    check_sha(sig,"highwater signature invalid")
    require(isinstance(floor,dict) and floor.get("phase")=="RUST-070",
            "external retained revocation floor missing")
    n=floor.get("event_count")
    require(type(n) is int and len(before)<=n<=len(after),
            "floor outside known successor history")
    check_sha(floor.get("head_sha256"),"retained floor head invalid")
    require(after_heads[n]==floor["head_sha256"],
            "retained revocation highwater contradicts exact prefix")
    recent=after[len(before):]
    require(isinstance(observations,list) and len(observations)==len(recent),
            "one cross-epoch custodian observation required per revocation")
    historical_nonces={e["revocation_nonce_sha256"] for e in after}
    historical_nonces.update(w["nonce_sha256"] for e in after for w in e["witnesses"])
    fresh=set(); rows=[]; conflicts=[]
    revoked_roots=set(current["revoked_controller_roots"])
    old_acquisition={w["acquisition_sha256"] for e in before for w in e["witnesses"]}
    old_roots={w["controller_sha256"] for e in before for w in e["witnesses"]}
    for event,obs in zip(recent,observations):
        require(isinstance(obs,dict) and obs.get("phase")=="RUST-070",
                "new custodian observation missing")
        for k in ("revocation_entry_sha256","observation_nonce_sha256",
                  "signer_pin","controller_sha256","acquisition_sha256",
                  "source_root_sha256"):
            check_sha(obs.get(k),"custodian continuity claim missing "+k)
        require(obs["revocation_entry_sha256"]==event["entry_sha256"],
                "observation not bound to new revocation event")
        nonce=obs["observation_nonce_sha256"]
        require(nonce not in historical_nonces and nonce not in fresh,
                "revocation observation nonce replay")
        fresh.add(nonce)
        require(obs.get("quarantine_persists") is True and
                obs.get("recovery_authorized") is False and
                obs.get("release_authorized") is False,
                "observation attempted quarantine release")
        if obs["signer_pin"] in excluded:
            conflicts.append({"reason":"REVOKED_SIGNER_REENTRY",
                              "pin":obs["signer_pin"],"independence_verified":False})
        if obs["controller_sha256"] in revoked_roots:
            conflicts.append({"reason":"RENAMED_KEY_REVOKED_CONTROLLER",
                              "pin":obs["signer_pin"],"independence_verified":False})
        if obs["controller_sha256"] in old_roots:
            conflicts.append({"reason":"CROSS_EPOCH_REUSED_CONTROLLER",
                              "pin":obs["signer_pin"],"independence_verified":False})
        if obs["acquisition_sha256"] in old_acquisition:
            conflicts.append({"reason":"CROSS_EPOCH_REUSED_ACQUISITION",
                              "pin":obs["signer_pin"],"independence_verified":False})
        rows.append({"revocation_entry_sha256":event["entry_sha256"],
                     "observation_sha256":digest(obs),
                     "nonce_sha256":nonce,
                     "excluded_from_recovery":True,
                     "independent_custody_verified":False})
    result={"phase":"RUST-070",
            "status":"HOLD_REVOCATION_HIGHWATER_CUSTODIAN_EXCLUSION",
            "previous_rust069_receipt_sha256":previous["receipt_sha256"],
            "current_rust069_receipt_sha256":current["receipt_sha256"],
            "signed_checkpoint":expected,"checkpoint_signature_sha256":sig,
            "checkpoint_signer_pin":signer_pin,
            "retained_floor_claim_sha256":digest(floor),
            "previous_count":len(before),"current_count":len(after),
            "prior_revoked_pins_preserved":previous["revoked_witness_pins"],
            "current_revoked_pins_preserved":current["revoked_witness_pins"],
            "prior_revoked_roots_preserved":previous["revoked_controller_roots"],
            "current_revoked_roots_preserved":current["revoked_controller_roots"],
            "historical_conflicts_preserved":previous["custody_conflicts"],
            "current_conflicts_preserved":current["custody_conflicts"],
            "custodian_exclusion_conflicts":conflicts,
            "cross_epoch_observations":rows,
            "all_successors_quarantined":True,
            "independent_custody_verified":False,
            "globally_latest_highwater_verified":False,
            "global_anti_rollback_certified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authority":False}
    result["receipt_sha256"]=digest(result)
    return result

def hold():
    return {"phase":"RUST-070",
            "status":"HOLD_MISSING_WITNESS_REVOCATION_HIGHWATER",
            "independent_custody_verified":False,"recovery_authorized":False,
            "release_authorized":False,"live_gameplay_authority":False}

def main():
    p=argparse.ArgumentParser()
    for k in ("previous","current","checkpoint","public-key","signature",
              "signer-pin","floor","observations"):
        p.add_argument("--"+k)
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    a=p.parse_args()
    args=[a.previous,a.current,a.checkpoint,a.public_key,a.signature,
          a.signer_pin,a.floor,a.observations]
    require(all(args) or not any(args),"partial cross-epoch exclusion bundle refused")
    if all(args):
        load=lambda path:json.loads(Path(path).read_text(encoding="utf-8"))
        out=audit(load(a.previous),load(a.current),load(a.checkpoint),
                  a.public_key,a.signature,a.signer_pin,load(a.floor),
                  load(a.observations))
    else:out=hold()
    target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(out,f,indent=2,sort_keys=True);f.write("\n")
    print(json.dumps(out,sort_keys=True))
    if not a.allow_hold_record:
        raise SystemExit("RUST-070 HOLD: independent external witness custody unverified")
if __name__=="__main__":main()
