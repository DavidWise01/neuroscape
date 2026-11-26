import copy
import unittest

from lineage_rust019 import digest
from session_freshness_rust032 import genesis_history
from session_highwater_rust033 import (
    checkpoint_payload, compare_with_retained_floor, hold, verify
)

PIN="a"*64

def ledger():
    entries=[]
    for i,role in enumerate(("ff","cf","rr")):
        entries.append({
            "role":role,"epoch":1,
            "nonce_sha256":str(i+1)*64,
            "retrieval_session_sha256":str(i+4)*64,
            "challenge_signature_sha256":str(i+7)*64,
        })
    result={
        "phase":"RUST-032","status":"HOLD_RETRIEVAL_FRESHNESS",
        "epoch":1,"entries":entries,"release_authorized":False,
    }
    result["ledger_sha256"]=digest(result)
    return result

def fake_verify(*args):
    return "f"*64

class SessionHighwaterTests(unittest.TestCase):
    def test_missing_external_witness_remains_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_SIGNED_SESSION_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_signature_binds_complete_history_but_not_global_freshness(self):
        history=ledger()
        report=verify(history,checkpoint_payload(history),"highwater.pem",
                      "highwater.sig",PIN,signature_verifier=fake_verify)
        self.assertTrue(report["retained_entry_count_matches"])
        self.assertEqual(report["entry_count"],3)
        self.assertFalse(report["latest_highwater_independently_verified"])
        self.assertFalse(report["release_authorized"])

    def test_withheld_history_disagrees_with_signed_checkpoint(self):
        full=ledger()
        shortened=copy.deepcopy(full)
        shortened["entries"].pop()
        shortened["ledger_sha256"]=digest({k:v for k,v in shortened.items() if k!="ledger_sha256"})
        with self.assertRaises(ValueError):
            verify(shortened,checkpoint_payload(full),"pub.pem","sig.bin",PIN,
                   signature_verifier=fake_verify)

    def test_historical_nonce_replay_rejected(self):
        history=ledger()
        history["entries"][1]["nonce_sha256"]=history["entries"][0]["nonce_sha256"]
        history["ledger_sha256"]=digest({k:v for k,v in history.items() if k!="ledger_sha256"})
        with self.assertRaisesRegex(ValueError,"nonce reuse"):
            checkpoint_payload(history)

    def test_session_replay_rejected(self):
        history=ledger()
        history["entries"][2]["retrieval_session_sha256"]=history["entries"][0]["retrieval_session_sha256"]
        history["ledger_sha256"]=digest({k:v for k,v in history.items() if k!="ledger_sha256"})
        with self.assertRaisesRegex(ValueError,"session reuse"):
            checkpoint_payload(history)

    def test_signed_checkpoint_tampering_rejected(self):
        history=ledger()
        signed=checkpoint_payload(history)
        signed["entries_sha256"]="0"*64
        with self.assertRaises(ValueError):
            verify(history,signed,"pub.pem","sig.bin",PIN,signature_verifier=fake_verify)

    def test_external_retained_floor_rejects_rollback(self):
        signed=checkpoint_payload(ledger())
        with self.assertRaisesRegex(ValueError,"rollback"):
            compare_with_retained_floor(signed,2,"b"*64)
        with self.assertRaisesRegex(ValueError,"equivocated"):
            compare_with_retained_floor(signed,1,"c"*64)
        self.assertTrue(compare_with_retained_floor(signed,1,signed["ledger_sha256"]))

    def test_wrong_epoch_ordering_rejected(self):
        history=ledger()
        history["entries"][1]["role"]="rr"
        history["ledger_sha256"]=digest({k:v for k,v in history.items() if k!="ledger_sha256"})
        with self.assertRaisesRegex(ValueError,"ordering"):
            checkpoint_payload(history)

    def test_invalid_signature_rejected(self):
        def reject(*args):
            raise ValueError("bad Ed25519 signature")
        history=ledger()
        with self.assertRaises(ValueError):
            verify(history,checkpoint_payload(history),"pub.pem","sig.bin",PIN,
                   signature_verifier=reject)

    def test_untrusted_empty_genesis_not_authority(self):
        value=genesis_history()
        signed=checkpoint_payload(value)
        self.assertEqual(signed["entry_count"],0)
        self.assertFalse(signed["release_authorized"])

if __name__=="__main__":
    unittest.main()
