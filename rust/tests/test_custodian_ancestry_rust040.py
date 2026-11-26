import copy
import unittest

from lineage_rust019 import digest
from custodian_ancestry_rust040 import audit, hold

P1="1"*64
P2="2"*64
P3="3"*64

def parent(shared=False):
    data={
        "phase":"RUST-039",
        "status":"HOLD_SHARED_CUSTODY_LINEAGE" if shared else "HOLD_EXTERNAL_CUSTODY_UNPROVEN",
        "inherited_revocations":[{"role":"ff","revoked_pin":P1,"source_sha256":"a"*64}],
        "custodian_lineage_claims":[
            {"role":"ff","key_spki_sha256":P1,
             "claimed_custody_controller":"controller-A","independently_verified":False},
            {"role":"cf","key_spki_sha256":P2,
             "claimed_custody_controller":"controller-B","independently_verified":False},
            {"role":"rr","key_spki_sha256":P3,
             "claimed_custody_controller":"controller-C","independently_verified":False},
        ],
        "suspected_same_custodian_replacements":(
            [{"revoked_role":"ff","replacement_role":"cf"}] if shared else []),
        "preserved_upstream_equivocation":[],
        "fork_resolved":False,"release_authorized":False,
    }
    data["receipt_sha256"]=digest(data)
    return data

def claims():
    return [
        {"role":role,"key_spki_sha256":pin,
         "source_root_sha256":str(i+4)*64,
         "acquisition_path_sha256":str(i+7)*64,
         "custody_controller_sha256":str(i+10)*64,
         "operator_registry_sha256":str(i+13)*64,
         "aliases":["operator-"+role]} for i,(role,pin) in
         enumerate((("ff",P1),("cf",P2),("rr",P3)))
    ]

class CustodianAncestryTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_ANCESTRY")
        self.assertFalse(hold()["release_authorized"])

    def test_disjoint_declarations_do_not_certify_independence(self):
        out=audit(parent(),claims())
        self.assertEqual(out["status"],"HOLD_IDENTITY_ANCESTRY_UNPROVEN")
        self.assertFalse(out["independent_custodian_roots_verified"])
        self.assertFalse(out["release_authorized"])
        self.assertEqual(len(out["custodian_claims"]),3)

    def test_duplicate_source_root_catches_claimed_mirror(self):
        values=claims()
        values[1]["source_root_sha256"]=values[0]["source_root_sha256"]
        out=audit(parent(),values)
        self.assertEqual(out["status"],"HOLD_POTENTIAL_COMMON_CONTROL")
        self.assertIn("source_root_sha256",out["pairwise_ancestry_collisions"][0]["shared_fields"])

    def test_alias_relabel_with_different_roots_still_conflicts(self):
        values=claims()
        values[1]["aliases"]=["operator-ff"]
        out=audit(parent(),values)
        match=out["pairwise_ancestry_collisions"][0]
        self.assertTrue(match["different_declared_roots"])
        self.assertIn("operator-ff",match["shared_aliases"])
        self.assertEqual(len(out["suspected_replacement_lineages"]),1)

    def test_shared_acquisition_path_exposes_common_control(self):
        values=claims()
        values[2]["acquisition_path_sha256"]=values[0]["acquisition_path_sha256"]
        out=audit(parent(),values)
        self.assertEqual(out["status"],"HOLD_POTENTIAL_COMMON_CONTROL")
        self.assertIn("acquisition_path_sha256",out["pairwise_ancestry_collisions"][0]["shared_fields"])

    def test_parent_suspicion_never_disappears(self):
        out=audit(parent(shared=True),claims())
        self.assertEqual(out["status"],"HOLD_POTENTIAL_COMMON_CONTROL")
        self.assertTrue(out["preserved_upstream_suspicions"])

    def test_withheld_claims_rejected(self):
        with self.assertRaisesRegex(ValueError,"withheld"):
            audit(parent(),claims()[:2])

    def test_unknown_signer_or_duplicate_claim_rejected(self):
        values=claims()
        values[0]["key_spki_sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"unbound"):
            audit(parent(),values)
        values=claims()
        with self.assertRaisesRegex(ValueError,"duplicate signer"):
            audit(parent(),values+[copy.deepcopy(values[0])])

    def test_invalid_alias_or_root_rejected(self):
        values=claims()
        values[0]["aliases"]=["same","same"]
        with self.assertRaisesRegex(ValueError,"repeated alias"):
            audit(parent(),values)
        values=claims()
        values[0]["source_root_sha256"]="not-sha"
        with self.assertRaises(ValueError):
            audit(parent(),values)

    def test_upstream_tamper_or_false_release_rejected(self):
        source=parent()
        source["release_authorized"]=True
        with self.assertRaises(ValueError):
            audit(source,claims())
        source=parent()
        source["inherited_revocations"][0]["revoked_pin"]="f"*64
        with self.assertRaisesRegex(ValueError,"digest altered"):
            audit(source,claims())

    def test_preserves_all_claims_without_source_vote(self):
        values=claims()
        values[1]["operator_registry_sha256"]=values[0]["operator_registry_sha256"]
        out=audit(parent(),values)
        self.assertEqual(len(out["custodian_claims"]),3)
        self.assertTrue(out["pairwise_ancestry_collisions"])
        self.assertFalse(out["fork_resolved"])

if __name__=="__main__":
    unittest.main()
