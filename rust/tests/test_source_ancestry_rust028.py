import copy
import unittest
from lineage_rust019 import digest
from source_ancestry_rust028 import audit, hold, validate_fork

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]

def fork(split=False):
    heads=["a"*64,"a"*64,("b"*64 if split else "a"*64)]
    x={
        "phase":"RUST-027",
        "status":"HOLD_FORK_EVIDENCE" if split else "HOLD_UNVERIFIED_CUSTODY",
        "branches":[{"role":r,"head_sha256":h} for r,h in zip(ROLES,heads)],
        "fork_heads_sha256":sorted(set(heads)),
        "fork_detected":split,
        "observed_common_ancestor_sha256":"c"*64,
        "release_authorized":False,
    }
    x["receipt_sha256"]=digest(x)
    return x

def claims(shared=False):
    return [
        {
            "role":role,
            "source_root":f"archive-{i}",
            "source_family":("github-repo-A" if shared else f"independent-archive-{i}"),
            "custody_controller":f"operator-{i}",
            "capture_sha256":str(i+4)*64,
            "public_key":f"key-{i}.pem",
            "signature":f"sig-{i}.bin",
        } for i,role in enumerate(ROLES)
    ]

class AncestryAudit(unittest.TestCase):
    def verify(self,*args):
        return "d"*64

    def test_missing_external_custody_hold(self):
        self.assertEqual(hold()["status"],"HOLD_NO_EXTERNAL_PROVENANCE")
        self.assertFalse(hold()["release_authorized"])

    def test_shared_source_family_not_three_roots(self):
        result=audit(fork(),claims(shared=True),PINS,verify=self.verify)
        self.assertEqual(result["status"],"HOLD_SHARED_SOURCE_ANCESTRY")
        self.assertEqual(result["unique_declared_families"],1)
        self.assertEqual(len(result["provenance_assertions"]),3)
        self.assertTrue(result["shared_ancestry_collisions"])
        self.assertFalse(result["independent_source_roots_certified"])

    def test_distinct_claims_do_not_prove_independence(self):
        result=audit(fork(),claims(),PINS,verify=self.verify)
        self.assertEqual(result["status"],"HOLD_INDEPENDENCE_UNPROVEN")
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["independent_custody_ancestries_verified"])

    def test_fork_preserved_even_with_three_distinct_keys(self):
        result=audit(fork(split=True),claims(shared=True),PINS,verify=self.verify)
        self.assertEqual(result["status"],"HOLD_FORK_AND_SHARED_ANCESTRY")
        self.assertEqual(len(result["fork_heads_sha256"]),2)
        self.assertFalse(result["fork_resolved"])

    def test_duplicate_capture_does_not_count_as_independent(self):
        items=claims()
        items[1]["capture_sha256"]=items[0]["capture_sha256"]
        result=audit(fork(),items,PINS,verify=self.verify)
        self.assertIn("capture_sha256",result["shared_ancestry_collisions"][0]["shared_fields"])

    def test_rejects_mismatched_roles_signers_and_tampering(self):
        data=fork()
        broken=copy.deepcopy(data)
        broken["branches"][1]["role"]="ff"
        broken["receipt_sha256"]=digest({k:v for k,v in broken.items() if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            validate_fork(broken)
        with self.assertRaises(ValueError):
            audit(data,claims(),[PINS[0],PINS[0],PINS[2]],verify=self.verify)
        altered=copy.deepcopy(data)
        altered["status"]="QUALIFIED"
        with self.assertRaises(ValueError):
            audit(altered,claims(),PINS,verify=self.verify)

    def test_invalid_signature_is_hard_error(self):
        def reject(*args):
            raise ValueError("Ed25519 signature invalid")
        with self.assertRaises(ValueError):
            audit(fork(),claims(),PINS,verify=reject)

if __name__=="__main__":
    unittest.main()
