import copy
import unittest

from lineage_rust019 import digest
from challenge_ledger_rust042 import audit as ledger_audit, genesis
from attestor_rotation_rust043 import audit, highwater_payload, rotation_payload, hold

ROLES=("ff","cf","rr")
PIN="a"*64

def h(n):
    return format(n%16,"x")*64

def upstream(epoch,rotation=False,changed_root=False):
    observations=[]
    for i,role in enumerate(ROLES):
        observations.append({
            "role":role,"externally_issued_nonce_sha256":h(epoch*3+i),
            "retrieval_session_sha256":h(epoch*3+i+6),
            "custodian_signature_sha256":h(10+i),
            "attestor_signature_sha256":h(13+i),
            "attestor_key_spki_sha256":h(1+i+(4 if rotation and i==0 else 0)),
            "external_attestor_root_sha256":h(4+i+(5 if changed_root and i==0 else 0)),
            "source_root_sha256":h(7+i),
            "acquisition_path_sha256":h(10+i),
            "dual_signature_checked":True,
        })
    data={
        "phase":"RUST-041","status":"HOLD_INDEPENDENT_CONTROL_UNVERIFIED",
        "observations":observations,
        "new_nonce_fingerprints":[x["externally_issued_nonce_sha256"] for x in observations],
        "release_authorized":False,"fork_resolved":False,
    }
    data["receipt_sha256"]=digest(data)
    return data

def ledgers(rotation=False,root=False):
    first=ledger_audit(upstream(1),genesis())
    second=ledger_audit(upstream(2,rotation,root),first)
    return first,second

def floor(prior):
    return {"phase":"RUST-042","entry_count":len(prior["entries"]),
            "head_sha256":prior["head_sha256"]}

def fake(*args):
    return "f"*64

def transition(prior,current):
    old=[x for x in prior["entries"] if x["role"]=="ff"][-1]
    new=[x for x in current["entries"] if x["role"]=="ff"][-1]
    value=rotation_payload(prior,current,"ff",
                           old["attestor_key_spki_sha256"],
                           new["attestor_key_spki_sha256"])
    return [{
        "role":"ff",
        "old_attestor_spki_sha256":value["old_attestor_spki_sha256"],
        "new_attestor_spki_sha256":value["new_attestor_spki_sha256"],
        "payload":value,
        "old_public_key":"old.pem","old_signature":"old.sig",
        "new_public_key":"new.pem","new_signature":"new.sig",
    }]

class AttestorRotationTests(unittest.TestCase):
    def test_missing_material_remains_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_SIGNED_CHALLENGE_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_signed_highwater_without_rotation_still_hold(self):
        a,b=ledgers()
        seen=[]
        def verifier(*args):
            seen.append(args)
            return "f"*64
        out=audit(a,b,highwater_payload(a),"highwater.pem","hw.sig",PIN,[],
                  floor(a),verifier=verifier)
        self.assertEqual(len(seen),1)
        self.assertTrue(out["historical_prefix_preserved"])
        self.assertEqual(out["status"],"HOLD_EXTERNAL_HIGHWATER_UNVERIFIED")
        self.assertFalse(out["release_authorized"])

    def test_dual_signed_rotation_preserves_hold(self):
        a,b=ledgers(rotation=True)
        out=audit(a,b,highwater_payload(a),"highwater.pem","hw.sig",PIN,
                  transition(a,b),floor(a),verifier=fake)
        self.assertEqual(len(out["verified_rotation_signatures"]),1)
        self.assertTrue(out["preserved_attestor_conflicts"])
        self.assertFalse(out["attestor_identity_independently_verified"])
        self.assertEqual(out["status"],"HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED")

    def test_rotation_without_two_proofs_rejected(self):
        a,b=ledgers(rotation=True)
        with self.assertRaisesRegex(ValueError,"missing or extra"):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,[],
                  floor(a),verifier=fake)

    def test_bad_old_or_new_signature_rejected(self):
        a,b=ledgers(rotation=True)
        for fail_at in (2,3):
            counter=[0]
            def verifier(*args):
                counter[0]+=1
                if counter[0]==fail_at:
                    raise ValueError("invalid Ed25519")
                return "f"*64
            with self.assertRaises(ValueError):
                audit(a,b,highwater_payload(a),"key.pem","sig",PIN,
                      transition(a,b),floor(a),verifier=verifier)

    def test_mismatched_highwater_checkpoint_rejected(self):
        a,b=ledgers()
        checkpoint=highwater_payload(a)
        checkpoint["head_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"checkpoint does not match"):
            audit(a,b,checkpoint,"key.pem","sig",PIN,[],floor(a),verifier=fake)

    def test_old_retained_floor_conflict_rejected(self):
        a,b=ledgers()
        retained=floor(a)
        retained["head_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"substituted"):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,[],retained,
                  verifier=fake)

    def test_floor_must_cover_full_prior_epoch(self):
        a,b=ledgers()
        retained={"phase":"RUST-042","entry_count":1,
                  "head_sha256":a["prefix_heads"][1]}
        with self.assertRaisesRegex(ValueError,"complete prior epoch"):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,[],retained,
                  verifier=fake)

    def test_wrong_rotation_payload_rejected(self):
        a,b=ledgers(rotation=True)
        item=transition(a,b)
        item[0]["payload"]["from_epoch"]=999
        with self.assertRaisesRegex(ValueError,"rotation message differs"):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,item,floor(a),
                  verifier=fake)

    def test_changed_root_without_changed_key_stays_unqualified(self):
        a,b=ledgers(root=True)
        with self.assertRaisesRegex(ValueError,"same key is not a rotation"):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,
                  [{"role":"ff","old_attestor_spki_sha256":h(1),
                    "new_attestor_spki_sha256":h(1)}],floor(a),verifier=fake)

    def test_tampered_history_rejected(self):
        a,b=ledgers()
        b["entries"][0]["nonce_sha256"]="0"*64
        with self.assertRaises(ValueError):
            audit(a,b,highwater_payload(a),"key.pem","sig",PIN,[],floor(a),
                  verifier=fake)

if __name__=="__main__":
    unittest.main()
