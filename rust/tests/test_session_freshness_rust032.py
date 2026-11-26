import copy
import unittest

from lineage_rust019 import digest
from session_freshness_rust032 import audit, checked_history, genesis_history, hold

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]

def upstream():
    items=[]
    for i,role in enumerate(ROLES):
        items.append({
            "role":role,
            "retrieval_session_sha256":str(i+4)*64,
            "retrieval_endpoint_sha256":str(i+7)*64,
            "retrieved_archive_sha256":str(i+10)*64,
        })
    obj={
        "phase":"RUST-031",
        "status":"HOLD_OPERATOR_CONTROL_UNPROVEN",
        "observations":items,"release_authorized":False,"fork_resolved":False,
    }
    obj["receipt_sha256"]=digest(obj)
    return obj

def challenges(upstream_record=None):
    obj=upstream_record or upstream()
    return [{
        "role":role,"nonce_sha256":str(i+13)*64,
        "retrieval_session_sha256":obs["retrieval_session_sha256"],
        "retrieval_endpoint_sha256":obs["retrieval_endpoint_sha256"],
        "issuer_public_key":role+".pem","issuer_signature":role+".sig",
    } for i,(role,obs) in enumerate(zip(ROLES,obj["observations"]))]

def fake(*args):
    return "f"*64

class FreshnessTests(unittest.TestCase):
    def test_missing_evidence_remains_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_SESSION_LEDGER")
        self.assertFalse(hold()["release_authorized"])
    def test_three_distinct_signed_snapshots_still_hold(self):
        source=upstream()
        result=audit(source,challenges(source),PINS,genesis_history(),verifier=fake)
        self.assertEqual(result["epoch"],1)
        self.assertEqual(result["status"],"HOLD_RETRIEVAL_FRESHNESS")
        self.assertEqual(len(result["entries"]),3)
        self.assertFalse(result["external_latest_ledger_confirmed"])
        self.assertFalse(result["release_authorized"])
    def test_replayed_nonce_rejected_from_history(self):
        source=upstream()
        prev=audit(source,challenges(source),PINS,genesis_history(),verifier=fake)
        new=challenges(source)
        new[0]["nonce_sha256"]=prev["entries"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            audit(source,new,PINS,prev,verifier=fake)
    def test_replayed_session_rejected_from_history(self):
        source=upstream()
        prev=audit(source,challenges(source),PINS,genesis_history(),verifier=fake)
        newer=challenges(source)
        for i,c in enumerate(newer):
            c["nonce_sha256"]=str(i+20)*64
        with self.assertRaisesRegex(ValueError,"session replay"):
            audit(source,newer,PINS,prev,verifier=fake)
    def test_duplicate_nonce_inside_batch_rejected(self):
        items=challenges()
        items[1]["nonce_sha256"]=items[0]["nonce_sha256"]
        with self.assertRaises(ValueError):
            audit(upstream(),items,PINS,genesis_history(),verifier=fake)
    def test_issuer_key_reuse_rejected(self):
        with self.assertRaises(ValueError):
            audit(upstream(),challenges(),[PINS[0],PINS[0],PINS[2]],genesis_history(),verifier=fake)
    def test_tampered_history_rejected(self):
        row=genesis_history()
        row["epoch"]=4
        with self.assertRaisesRegex(ValueError,"history altered"):
            checked_history(row)
    def test_wrong_endpoint_rejected(self):
        items=challenges()
        items[1]["retrieval_endpoint_sha256"]="0"*64
        with self.assertRaises(ValueError):
            audit(upstream(),items,PINS,genesis_history(),verifier=fake)
    def test_false_authority_and_signature_failure_rejected(self):
        source=upstream()
        source["release_authorized"]=True
        with self.assertRaises(ValueError):
            audit(source,challenges(),PINS,genesis_history(),verifier=fake)
        def reject(*args):
            raise ValueError("invalid signature")
        with self.assertRaises(ValueError):
            audit(upstream(),challenges(),PINS,genesis_history(),verifier=reject)
    def test_missing_session_claim_rejected(self):
        items=challenges()
        del items[0]["retrieval_session_sha256"]
        with self.assertRaises(ValueError):
            audit(upstream(),items,PINS,genesis_history(),verifier=fake)

if __name__=="__main__":
    unittest.main()
