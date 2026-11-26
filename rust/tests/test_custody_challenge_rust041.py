import copy
import unittest
from lineage_rust019 import digest
from custody_challenge_rust041 import audit, hold

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]
ATTESTORS=["4"*64,"5"*64,"6"*64]
NONCES=["7"*64,"8"*64,"9"*64]

def h(n):\n    return format(n%16,"x")*64\n\ndef parent(common=False):
    rows=[]
    for i,(role,pin) in enumerate(zip(ROLES,PINS)):
        rows.append({
            "role":role,"key_spki_sha256":pin,
            "source_root_sha256":("a"*64 if common else h(i+10)),
            "acquisition_path_sha256":h(i+13),
            "custody_controller_sha256":h(i+16),
            "operator_registry_sha256":h(i+19),
        })
    value={
        "phase":"RUST-040",
        "status":"HOLD_POTENTIAL_COMMON_CONTROL" if common else "HOLD_IDENTITY_ANCESTRY_UNPROVEN",
        "custodian_claims":rows,
        "pairwise_ancestry_collisions":[{"roles":["ff","cf"]}] if common else [],
        "suspected_replacement_lineages":[],
        "fork_resolved":False,"release_authorized":False,
    }
    value["receipt_sha256"]=digest(value)
    return value

def challenges(source=None):
    source=source or parent()
    return [{
        "role":row["role"],
        "source_root_sha256":row["source_root_sha256"],
        "acquisition_path_sha256":row["acquisition_path_sha256"],
        "custody_controller_sha256":row["custody_controller_sha256"],
        "operator_registry_sha256":row["operator_registry_sha256"],
        "retrieved_archive_sha256":h(i+22),
        "retrieval_session_sha256":h(i+25),
        "external_attestor_root_sha256":h(i+28),
        "custodian_public_key":role+".pem","custodian_signature":role+".sig",
        "attestor_public_key":role+"-attestor.pem",
        "attestor_signature":role+"-attestor.sig",
    } for i,(role,row) in enumerate(zip(ROLES,source["custodian_claims"]))]

def fake(*args):
    return "f"*64

class CustodyChallengeTests(unittest.TestCase):
    def test_missing_external_evidence_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_CONTROL_CHALLENGES")
        self.assertFalse(hold()["release_authorized"])
    def test_six_signatures_are_still_hold(self):
        source=parent()
        calls=[]
        def verifier(*args):
            calls.append(args)
            return "f"*64
        result=audit(source,challenges(source),ATTESTORS,NONCES,[],verifier=verifier)
        self.assertEqual(len(calls),6)
        self.assertEqual(len(result["observations"]),3)
        self.assertFalse(result["real_world_operator_control_verified"])
        self.assertFalse(result["independent_source_ancestry_verified"])
        self.assertFalse(result["release_authorized"])
    def test_replayed_nonce_against_history_fails(self):
        with self.assertRaisesRegex(ValueError,"replayed"):
            audit(parent(),challenges(),ATTESTORS,NONCES,[NONCES[0]],verifier=fake)
    def test_same_nonce_in_batch_fails(self):
        with self.assertRaisesRegex(ValueError,"replay"):
            audit(parent(),challenges(),ATTESTORS,[NONCES[0],NONCES[0],NONCES[2]],[],verifier=fake)
    def test_duplicate_attestor_or_self_attestation_fails(self):
        with self.assertRaises(ValueError):
            audit(parent(),challenges(),[ATTESTORS[0],ATTESTORS[0],ATTESTORS[2]],NONCES,[],verifier=fake)
        with self.assertRaisesRegex(ValueError,"self-attestation"):
            audit(parent(),challenges(),[PINS[0],ATTESTORS[1],ATTESTORS[2]],NONCES,[],verifier=fake)
    def test_claimed_root_substitution_fails(self):
        items=challenges()
        items[1]["source_root_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"ancestry substitution"):
            audit(parent(),items,ATTESTORS,NONCES,[],verifier=fake)
    def test_shared_attestor_root_is_collision_not_independence(self):
        items=challenges()
        items[2]["external_attestor_root_sha256"]=items[0]["external_attestor_root_sha256"]
        result=audit(parent(),items,ATTESTORS,NONCES,[],verifier=fake)
        self.assertEqual(result["status"],"HOLD_SHARED_ATTESTATION_ANCESTRY")
        self.assertIn("external_attestor_root_sha256",result["attestation_ancestry_collisions"][0]["shared_fields"])
    def test_prior_conflict_never_cleared(self):
        source=parent(True)
        result=audit(source,challenges(source),ATTESTORS,NONCES,[],verifier=fake)
        self.assertEqual(result["status"],"HOLD_SHARED_ATTESTATION_ANCESTRY")
        self.assertTrue(result["preserved_upstream_collisions"])
    def test_invalid_signature_fails(self):
        def reject(*args):
            raise ValueError("signature invalid")
        with self.assertRaises(ValueError):
            audit(parent(),challenges(),ATTESTORS,NONCES,[],verifier=reject)
    def test_role_swap_rejected(self):
        items=challenges()
        items[0],items[1]=items[1],items[0]
        with self.assertRaisesRegex(ValueError,"role mismatch"):
            audit(parent(),items,ATTESTORS,NONCES,[],verifier=fake)
    def test_tampered_parent_and_missing_nonce_ledger_fail(self):
        source=parent()
        source["custodian_claims"][0]["key_spki_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"receipt altered"):
            audit(source,challenges(),ATTESTORS,NONCES,[],verifier=fake)
        with self.assertRaisesRegex(ValueError,"history missing"):
            audit(parent(),challenges(),ATTESTORS,NONCES,None,verifier=fake)

if __name__=="__main__":
    unittest.main()
