import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from lineage_rust019 import digest
from operator_control_rust031 import audit, hold, checked_upstream

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]
NONCES=["4"*64,"5"*64,"6"*64]
DATA=[b"alpha"*35,b"bravo"*35,b"charlie"*35]

def upstream(shared=False):
    observations=[]
    for i,(role,raw) in enumerate(zip(ROLES,DATA)):
        observations.append({
            "role":role,
            "archive_digest_sha256":hashlib.sha256(raw).hexdigest(),
            "archive_operator":"one-operator" if shared else f"operator-{i}",
            "custody_controller":f"controller-{i}",
            "acquisition_controller":f"acquirer-{i}",
        })
    result={
        "phase":"RUST-030","status":"HOLD_INDEPENDENT_CONTROL_UNPROVEN",
        "observations":observations,
        "release_authorized":False,"fork_resolved":False,
        "preserved_fork_heads_sha256":["a"*64,"b"*64],
    }
    result["receipt_sha256"]=digest(result)
    return result

def retrieved(folder,shared_session=False):
    rows=[]
    for i,(role,data) in enumerate(zip(ROLES,DATA)):
        file=folder/(role+".bin")
        file.write_bytes(data)
        rows.append({
            "role":role,"retrieved_archive_path":str(file),
            "retrieval_session_sha256":"a"*64 if shared_session else str(i+7)*64,
            "retrieval_endpoint_sha256":str(i+8)*64,
            "operator_registry_sha256":str(i+9)*64,
            "operator_account_sha256":str(i+10)*64,
            "archive_operator":f"operator-{i}",
            "custody_controller":f"controller-{i}",
            "acquisition_controller":f"acquirer-{i}",
            "operator_public_key":str(folder/(role+".pem")),
            "operator_signature":str(folder/(role+".sig")),
        })
    return rows

def simulated_signature(*args):
    return "f"*64

class OperatorControlTests(unittest.TestCase):
    def test_missing_external_retrieval_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_OPERATOR_CONTROL_EVIDENCE")
        self.assertFalse(hold()["release_authorized"])
    def test_exact_retrieval_observation_still_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            r=audit(upstream(),retrieved(Path(temp)),PINS,NONCES,verifier=simulated_signature)
        self.assertEqual(r["status"],"HOLD_OPERATOR_CONTROL_UNPROVEN")
        self.assertEqual(len(r["observations"]),3)
        self.assertFalse(r["independent_archive_custody_verified"])
        self.assertFalse(r["release_authorized"])
    def test_same_retrieval_session_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            r=audit(upstream(),retrieved(Path(temp),True),PINS,NONCES,verifier=simulated_signature)
        self.assertEqual(r["status"],"HOLD_DUPLICATED_RETRIEVAL_ANCESTRY")
        self.assertTrue(any("retrieval_session_sha256" in x["shared_fields"] for x in r["shared_retrieval_ancestry"]))
    def test_changed_archive_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rows=retrieved(Path(temp))
            Path(rows[0]["retrieved_archive_path"]).write_bytes(b"forged"*50)
            with self.assertRaisesRegex(ValueError,"does not match"):
                audit(upstream(),rows,PINS,NONCES,verifier=simulated_signature)
    def test_mismatched_operator_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rows=retrieved(Path(temp))
            rows[1]["archive_operator"]="not-the-same"
            with self.assertRaises(ValueError):
                audit(upstream(),rows,PINS,NONCES,verifier=simulated_signature)
    def test_duplicate_nonce_and_pin_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rows=retrieved(Path(temp))
            for pins,nonces in [
                ([PINS[0],PINS[0],PINS[2]],NONCES),
                (PINS,[NONCES[0],NONCES[0],NONCES[2]]),
            ]:
                with self.assertRaises(ValueError):
                    audit(upstream(),rows,pins,nonces,verifier=simulated_signature)
    def test_invalid_signature_and_role_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rows=retrieved(Path(temp))
            def reject(*args):
                raise ValueError("invalid signature")
            with self.assertRaises(ValueError):
                audit(upstream(),rows,PINS,NONCES,verifier=reject)
            rows[0],rows[1]=rows[1],rows[0]
            with self.assertRaises(ValueError):
                audit(upstream(),rows,PINS,NONCES,verifier=simulated_signature)
    def test_modified_upstream_receipt_rejected(self):
        row=upstream()
        row["observations"][0]["archive_digest_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"digest mismatch"):
            checked_upstream(row)

if __name__=="__main__":
    unittest.main()
