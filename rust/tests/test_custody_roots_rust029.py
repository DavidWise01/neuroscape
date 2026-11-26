import copy
import unittest
from lineage_rust019 import digest
from custody_roots_rust029 import audit, hold, check_upstream

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]
NONCES=["4"*64,"5"*64,"6"*64]

def upstream(shared=False):
    claims=[]
    for i,role in enumerate(ROLES):
        claims.append({
            "role":role,"source_root":f"root-{i}",
            "source_family":"single-git-family" if shared else f"family-{i}",
            "custody_controller":f"controller-{i}",
            "capture_sha256":str(i+7)*64,"head_sha256":str(i+10 if i<0 else i+1)*64,
        })
    result={
        "phase":"RUST-028","status":"HOLD_SHARED_SOURCE_ANCESTRY" if shared else "HOLD_INDEPENDENCE_UNPROVEN",
        "release_authorized":False,"fork_resolved":False,
        "independent_source_roots_certified":False,
        "provenance_assertions":claims,
        "fork_heads_sha256":["e"*64,"f"*64],
        "shared_ancestry_collisions":[],
    }
    result["receipt_sha256"]=digest(result)
    return result

def declarations(u,shared_operator=False,shared_path=False):
    result=[]
    for i,source in enumerate(u["provenance_assertions"]):
        result.append({
            "role":source["role"],"source_root":source["source_root"],
            "source_family":source["source_family"],
            "custody_controller":source["custody_controller"],
            "archive_digest_sha256":source["capture_sha256"],
            "archive_origin":f"archive-endpoint-{i}",
            "archive_operator":"same-owner" if shared_operator else f"operator-{i}",
            "operator_registry_sha256":str(i+10)*64,
            "acquisition_path_sha256":("b"*64 if shared_path else str(i+11)*64),
            "acquisition_method":"direct-collection",
            "acquisition_controller":f"collector-{i}",
            "public_key":f"custodian-{i}.pem","signature":f"response-{i}.sig",
        })
    return result

def fake_verify(*args):
    return "c"*64

class CustodyRoots(unittest.TestCase):
    def test_missing_external_evidence_remains_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_CUSTODY_ROOTS")
        self.assertFalse(hold()["release_authorized"])
    def test_distinct_challenge_responses_are_not_independence(self):
        source=upstream()
        result=audit(source,declarations(source),PINS,NONCES,verify=fake_verify)
        self.assertEqual(result["status"],"HOLD_CUSTODY_CONTROL_UNPROVEN")
        self.assertFalse(result["archive_control_independently_verified"])
        self.assertFalse(result["fork_resolved"])
        self.assertEqual(len(result["witness_custody_claims"]),3)
    def test_shared_source_family_and_operator_exposed(self):
        source=upstream(shared=True)
        result=audit(source,declarations(source,shared_operator=True),PINS,NONCES,verify=fake_verify)
        self.assertEqual(result["status"],"HOLD_SHARED_CUSTODY_OR_ACQUISITION")
        fields={field for row in result["shared_custody_or_acquisition"]
                for field in row["matching_ancestry_fields"]}
        self.assertIn("source_family",fields)
        self.assertIn("archive_operator",fields)
    def test_duplicate_acquisition_path_is_one_origin(self):
        source=upstream()
        result=audit(source,declarations(source,shared_path=True),PINS,NONCES,verify=fake_verify)
        self.assertIn("acquisition_path_sha256",result["shared_custody_or_acquisition"][0]["matching_ancestry_fields"])
        self.assertFalse(result["independent_source_roots_certified"])
    def test_capture_mismatch_is_rejected(self):
        source=upstream()
        claims=declarations(source)
        claims[1]["archive_digest_sha256"]="0"*64
        with self.assertRaises(ValueError):
            audit(source,claims,PINS,NONCES,verify=fake_verify)
    def test_replayed_nonce_and_key_rejected(self):
        source=upstream()
        for pins,nonces in [
            ([PINS[0],PINS[0],PINS[2]],NONCES),
            (PINS,[NONCES[0],NONCES[0],NONCES[2]]),
        ]:
            with self.assertRaises(ValueError):
                audit(source,declarations(source),pins,nonces,verify=fake_verify)
    def test_altered_upstream_and_false_release_rejected(self):
        source=upstream()
        source["release_authorized"]=True
        with self.assertRaises(ValueError):
            audit(source,declarations(source),PINS,NONCES,verify=fake_verify)
        source=upstream()
        source["provenance_assertions"][0]["source_root"]="tampered"
        with self.assertRaises(ValueError):
            check_upstream(source)
    def test_invalid_signature_rejected(self):
        source=upstream()
        def reject(*args):
            raise ValueError("invalid Ed25519 response")
        with self.assertRaises(ValueError):
            audit(source,declarations(source),PINS,NONCES,verify=reject)
    def test_role_swapping_cannot_impersonate_custodian(self):
        source=upstream()
        claims=declarations(source)
        claims[0],claims[1]=claims[1],claims[0]
        with self.assertRaises(ValueError):
            audit(source,claims,PINS,NONCES,verify=fake_verify)

if __name__=="__main__":
    unittest.main()
