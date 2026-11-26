import copy
import unittest
from lineage_rust019 import digest
from custodian_continuity_rust035 import audit, hold

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]

def observation(role, epoch, pin, ledger=None):
    return {
        "role":role,"epoch":epoch,"position":epoch,
        "ledger_sha256":ledger or str(epoch+3)*64,
        "checkpoint_sha256":str(epoch+5)*64,
        "witness_key_spki_sha256":pin,
        "witness_signature_sha256":"a"*64,
        "signed_checkpoint_verified":True,
    }

def parent(rotation=False, fork=False):
    items=[]
    for role,pin in zip(ROLES,PINS):
        items.append(observation(role,1,pin))
        items.append(observation(role,2,("4"*64 if role=="ff" and rotation else pin)))
    if fork:
        items.append(observation("rr",2,PINS[2],"b"*64))
    result={
        "phase":"RUST-034",
        "status":"HOLD_SIGNED_EQUIVOCATION" if fork else "HOLD_LATEST_CUSTODY_UNVERIFIED",
        "ordered_signed_observations":items,"equivocation_detected":fork,
        "epoch_equivocation_evidence":[{"epoch":2,"ledger_sha256_variants":["5"*64,"b"*64]}] if fork else [],
        "release_authorized":False,"fork_resolved":False,
    }
    result["receipt_sha256"]=digest(result)
    return result

def rotation_claim(data):
    ff=[x for x in data["ordered_signed_observations"] if x["role"]=="ff"]
    return [{
        "role":"ff",
        "from_checkpoint_sha256":ff[0]["checkpoint_sha256"],
        "to_checkpoint_sha256":ff[1]["checkpoint_sha256"],
        "old_public_key":"old.pem","old_signature":"old.sig",
        "new_public_key":"new.pem","new_signature":"new.sig",
    }]

def fake(*args):
    return "e"*64

class CustodyContinuityTests(unittest.TestCase):
    def test_no_custody_evidence_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_CONTINUITY")
        self.assertFalse(hold()["release_authorized"])
    def test_no_rotation_still_unqualified(self):
        record=audit(parent(),[],verifier=fake)
        self.assertEqual(record["status"],"HOLD_CUSTODIAN_CONTINUITY_UNPROVEN")
        self.assertEqual(len(record["custodian_history_heads"]),3)
        self.assertFalse(record["independent_custody_continuity_verified"])
    def test_rotation_needs_both_signatures(self):
        evidence=parent(rotation=True)
        calls=[]
        def witness(*args):
            calls.append(args)
            return "f"*64
        record=audit(evidence,rotation_claim(evidence),verifier=witness)
        self.assertEqual(len(calls),2)
        self.assertEqual(len(record["custodian_key_transitions"]),1)
        self.assertFalse(record["release_authorized"])
    def test_missing_or_extra_rotation_fails(self):
        evidence=parent(rotation=True)
        with self.assertRaisesRegex(ValueError,"missing or extra"):
            audit(evidence,[],verifier=fake)
        with self.assertRaisesRegex(ValueError,"missing or extra"):
            audit(parent(),rotation_claim(evidence),verifier=fake)
    def test_untrusted_signature_fails(self):
        evidence=parent(rotation=True)
        def bad(*args):
            raise ValueError("invalid signature")
        with self.assertRaises(ValueError):
            audit(evidence,rotation_claim(evidence),verifier=bad)
    def test_identity_substitution_fails(self):
        evidence=parent(rotation=True)
        claim=rotation_claim(evidence)
        claim[0]["role"]="rr"
        with self.assertRaises(ValueError):
            audit(evidence,claim,verifier=fake)
    def test_wrong_checkpoint_in_rotation_fails(self):
        evidence=parent(rotation=True)
        claim=rotation_claim(evidence)
        claim[0]["from_checkpoint_sha256"]="0"*64
        with self.assertRaises(ValueError):
            audit(evidence,claim,verifier=fake)
    def test_existing_equivocation_remains_hold(self):
        record=audit(parent(fork=True),[],verifier=fake)
        self.assertEqual(record["status"],"HOLD_CROSS_EPOCH_CONTRADICTION")
        self.assertFalse(record["fork_resolved"])
        self.assertTrue(record["preserved_upstream_equivocation"])
    def test_replay_and_epoch_gap_detected(self):
        evidence=parent()
        evidence["ordered_signed_observations"][1]["epoch"]=4
        evidence["receipt_sha256"]=digest({k:v for k,v in evidence.items() if k!="receipt_sha256"})
        out=audit(evidence,[],verifier=fake)
        self.assertEqual(out["status"],"HOLD_CROSS_EPOCH_CONTRADICTION")
        self.assertTrue(out["cross_epoch_conflicts"])
    def test_parent_digest_tampering_fails(self):
        evidence=parent()
        evidence["ordered_signed_observations"][0]["epoch"]=99
        with self.assertRaises(ValueError):
            audit(evidence,[],verifier=fake)

if __name__=="__main__":
    unittest.main()
