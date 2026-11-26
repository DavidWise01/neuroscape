import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from lineage_rust019 import digest
from acquisition_rust030 import audit, challenge, hold, check_upstream

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]
NONCES=["4"*64,"5"*64,"6"*64]

def upstream(contents, shared=False):
    claims=[]
    for i,(role,data) in enumerate(zip(ROLES,contents)):
        claims.append({
            "role":role,
            "archive_digest_sha256":hashlib.sha256(data).hexdigest(),
            "custody_controller":"shared-controller" if shared else f"controller-{i}",
            "archive_operator":f"operator-{i}",
            "acquisition_controller":f"acquirer-{i}",
            "acquisition_path_sha256":str(i+7)*64,
        })
    out={
        "phase":"RUST-029","status":"HOLD_CUSTODY_CONTROL_UNPROVEN",
        "witness_custody_claims":claims,"release_authorized":False,
        "fork_resolved":False,"independent_source_roots_certified":False,
        "preserved_fork_heads_sha256":["a"*64,"b"*64],
    }
    out["receipt_sha256"]=digest(out)
    return out

def sample_paths(folder, contents):
    entries=[]
    for i,(role,data) in enumerate(zip(ROLES,contents)):
        path=folder/f"archive-{i}.bin"
        path.write_bytes(data)
        entries.append({
            "role":role,"archive_path":str(path),
            "public_key":str(folder/f"{role}.pem"),
            "signature":str(folder/f"{role}.sig"),
        })
    return entries

class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.contents=[b"alpha"*30,b"bravo"*30,b"charlie"*30]
    def fake(self,*args):
        return "f"*64
    def test_no_external_archive_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_ACQUISITION")
        self.assertFalse(hold()["release_authorized"])
    def test_exact_bytes_and_slices_are_bound_to_nonces(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries=sample_paths(Path(tmp),self.contents)
            result=audit(upstream(self.contents),entries,PINS,NONCES,verify=self.fake)
        self.assertEqual(result["archive_possession_samples_verified"],3)
        self.assertEqual(result["status"],"HOLD_INDEPENDENT_CONTROL_UNPROVEN")
        self.assertEqual(len(result["observations"]),3)
        self.assertFalse(result["operator_control_independently_verified"])
        self.assertFalse(result["nonce_freshness_independently_verified"])
        self.assertFalse(result["release_authorized"])
    def test_shared_operator_detected_not_quorum(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=audit(upstream(self.contents,shared=True),
                         sample_paths(Path(tmp),self.contents),PINS,NONCES,verify=self.fake)
        self.assertEqual(result["status"],"HOLD_SHARED_ACQUISITION")
        self.assertTrue(any("custody_controller" in c["shared_fields"]
                            for c in result["shared_custody_collisions"]))
        self.assertEqual(len(result["preserved_fork_heads_sha256"]),2)
    def test_archive_content_mismatch_hard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries=sample_paths(Path(tmp),self.contents)
            Path(entries[1]["archive_path"]).write_bytes(b"tampered"*20)
            with self.assertRaisesRegex(ValueError,"archive content mismatch"):
                audit(upstream(self.contents),entries,PINS,NONCES,verify=self.fake)
    def test_missing_or_reused_nonce_pin_hard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries=sample_paths(Path(tmp),self.contents)
            for pins,nonces in [
                ([PINS[0],PINS[0],PINS[2]],NONCES),
                (PINS,[NONCES[0],NONCES[0],NONCES[2]]),
                (PINS,["bad",NONCES[1],NONCES[2]]),
            ]:
                with self.assertRaises(ValueError):
                    audit(upstream(self.contents),entries,pins,nonces,verify=self.fake)
    def test_upstream_forgery_and_role_swap_rejected(self):
        src=upstream(self.contents)
        src["release_authorized"]=True
        with self.assertRaises(ValueError):
            check_upstream(src)
        src=upstream(self.contents)
        with tempfile.TemporaryDirectory() as tmp:
            entries=sample_paths(Path(tmp),self.contents)
            entries[0],entries[1]=entries[1],entries[0]
            with self.assertRaisesRegex(ValueError,"sample role mismatch"):
                audit(src,entries,PINS,NONCES,verify=self.fake)
    def test_short_archive_rejected(self):
        with self.assertRaises(ValueError):
            challenge({"role":"ff","archive_digest_sha256":"a"*64},
                      "ff",b"short",NONCES[0])
    def test_invalid_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries=sample_paths(Path(tmp),self.contents)
            def reject(*args):
                raise ValueError("invalid signature")
            with self.assertRaises(ValueError):
                audit(upstream(self.contents),entries,PINS,NONCES,verify=reject)

if __name__=="__main__":
    unittest.main()
