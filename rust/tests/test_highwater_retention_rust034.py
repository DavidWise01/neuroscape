import copy
import unittest

from highwater_retention_rust034 import audit, hold

ROLES = ("ff", "cf", "rr")
PINS = ["1"*64, "2"*64, "3"*64]

def checkpoint(epoch, ledger):
    return {
        "phase":"RUST-033","kind":"SIGNED_SESSION_HIGHWATER",
        "ledger_sha256":ledger,"epoch":epoch,"entry_count":epoch*3,
        "entries_sha256":"a"*64,"last_entry_sha256":"b"*64,
        "release_authorized":False,"global_anti_rollback_certified":False,
    }

def histories(overrides=None):
    items=[]
    for role in ROLES:
        items.append({
            "role":role,
            "snapshots":[{
                "checkpoint":checkpoint(1,"c"*64),
                "public_key":role+".pem","signature":role+".sig"
            }],
        })
    for index, payload in (overrides or {}).items():
        items[index]["snapshots"] = payload
    return items

def fake(*args):
    return "f"*64

class HighwaterRetentionTests(unittest.TestCase):
    def test_missing_histories_is_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_RETAINED_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_matching_history_is_not_independent_custody(self):
        result=audit(histories(),PINS,verifier=fake)
        self.assertEqual(result["status"],"HOLD_LATEST_CUSTODY_UNVERIFIED")
        self.assertFalse(result["equivocation_detected"])
        self.assertEqual(len(result["ordered_signed_observations"]),3)
        self.assertFalse(result["independent_witness_ownership_verified"])
        self.assertFalse(result["release_authorized"])

    def test_two_to_one_fork_preserves_all_signatures(self):
        fork=[{"checkpoint":checkpoint(1,"d"*64),
               "public_key":"rr.pem","signature":"fork.sig"}]
        result=audit(histories({2:fork}),PINS,verifier=fake)
        self.assertEqual(result["status"],"HOLD_SIGNED_EQUIVOCATION")
        self.assertEqual(len(result["epoch_equivocation_evidence"]),1)
        self.assertEqual(len(result["epoch_equivocation_evidence"][0]["claims"]),3)
        self.assertEqual(len(result["epoch_equivocation_evidence"][0]["ledger_sha256_variants"]),2)
        self.assertFalse(result["fork_resolved"])

    def test_same_witness_two_distinct_signed_claims_at_same_epoch(self):
        claims=[
            {"checkpoint":checkpoint(1,"c"*64),"public_key":"ff.pem","signature":"one.sig"},
            {"checkpoint":checkpoint(1,"d"*64),"public_key":"ff.pem","signature":"two.sig"},
        ]
        result=audit(histories({0:claims}),PINS,verifier=fake)
        self.assertTrue(result["equivocation_detected"])
        self.assertEqual(len(result["ordered_signed_observations"]),4)

    def test_exact_signature_replay_is_rejected(self):
        one=histories()[0]["snapshots"][0]
        with self.assertRaisesRegex(ValueError,"replayed identical"):
            audit(histories({0:[one,copy.deepcopy(one)]}),PINS,verifier=fake)

    def test_epoch_gap_is_rejected(self):
        a=histories()[0]["snapshots"][0]
        b={"checkpoint":checkpoint(3,"e"*64),"public_key":"ff.pem","signature":"third.sig"}
        with self.assertRaisesRegex(ValueError,"withheld epoch"):
            audit(histories({0:[a,b]}),PINS,verifier=fake)

    def test_epoch_rollback_is_rejected(self):
        first={"checkpoint":checkpoint(2,"e"*64),"public_key":"ff.pem","signature":"later.sig"}
        second={"checkpoint":checkpoint(1,"c"*64),"public_key":"ff.pem","signature":"older.sig"}
        with self.assertRaisesRegex(ValueError,"rolled back"):
            audit(histories({0:[first,second]}),PINS,verifier=fake)

    def test_duplicate_pins_and_missing_witness_rejected(self):
        with self.assertRaises(ValueError):
            audit(histories(),[PINS[0],PINS[0],PINS[2]],verifier=fake)
        with self.assertRaises(ValueError):
            audit(histories()[:2],PINS,verifier=fake)

    def test_tampered_checkpoint_and_role_rejected(self):
        rows=histories()
        rows[0]["snapshots"][0]["checkpoint"]["release_authorized"]=True
        with self.assertRaises(ValueError):
            audit(rows,PINS,verifier=fake)
        rows=histories()
        rows[0]["role"]="rr"
        with self.assertRaises(ValueError):
            audit(rows,PINS,verifier=fake)

    def test_bad_signature_rejected(self):
        def reject(*args):
            raise ValueError("signature failed")
        with self.assertRaises(ValueError):
            audit(histories(),PINS,verifier=reject)

if __name__=="__main__":
    unittest.main()
