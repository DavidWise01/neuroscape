import copy
import unittest
from unittest.mock import patch

from lineage_rust019 import digest
from rotation_rust022 import proposal, qualify, check_anchor, hold

OLD="a"*40
NEW="b"*40
PIN="c"*64
NEXT_PIN="d"*64

def previous():
    row={
        "phase":"RUST-021","status":"FIRST_SUCCESSOR_OF_SIGNED_GENESIS",
        "sequence":1,"source_commit":OLD,"receipt_sha256":"e"*64,
        "source_independence_certified":False,"live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }
    row["entry_sha256"]=digest(row)
    return row

def receipt():
    row={
        "phase":"RUST-018","status":"CONSISTENT_OBSERVATIONS",
        "source_commit":NEW,"receipt_sha256":"f"*64,
        "wasm_sha256":"1"*64,"replay_sha256":"2"*64,
        "source_independence_certified":False,"live_gameplay_authority":False,
    }
    row["receipt_sha256"]=digest({k:v for k,v in row.items() if k!="receipt_sha256"})
    return row

class Rotation(unittest.TestCase):
    def test_missing_external_custody_hold(self):
        self.assertEqual(hold(receipt())["status"],"HOLD_CUSTODIAN_CONTINUITY")

    def test_continuity_requires_existing_key_signature(self):
        with patch("rotation_rust022.verify_key_and_signature",return_value="3"*64) as verify:
            result=qualify(previous(),receipt(),PIN,"old.pem","old.sig",
                           descendant=lambda a,b:a==OLD and b==NEW)
            self.assertEqual(result["kind"],"CONTINUITY")
            self.assertEqual(result["sequence"],2)
            self.assertEqual(verify.call_count,1)
            self.assertFalse(result["global_anti_rollback_certified"])

    def test_rotation_requires_dual_signature(self):
        with patch("rotation_rust022.verify_key_and_signature",return_value="3"*64) as verify:
            result=qualify(previous(),receipt(),PIN,"old.pem","old.sig",
                           NEXT_PIN,"new.pem","new.sig",
                           descendant=lambda a,b:True)
            self.assertEqual(result["kind"],"ROTATION")
            self.assertEqual(result["new_key_spki_sha256"],NEXT_PIN)
            self.assertEqual(verify.call_count,2)

    def test_rotation_rejects_missing_new_signature_and_rollback(self):
        with patch("rotation_rust022.verify_key_and_signature",return_value="3"*64):
            with self.assertRaises(ValueError):
                qualify(previous(),receipt(),PIN,"old.pem","old.sig",NEXT_PIN,
                        descendant=lambda a,b:True)
            with self.assertRaises(ValueError):
                qualify(previous(),receipt(),PIN,"old.pem","old.sig",
                        descendant=lambda a,b:False)

    def test_tamper_and_reuse_rejected(self):
        bad=copy.deepcopy(previous())
        bad["sequence"]=5
        with self.assertRaises(ValueError):
            check_anchor(bad)
        bad=copy.deepcopy(previous())
        bad["entry_sha256"]="0"*64
        with self.assertRaises(ValueError):
            check_anchor(bad)
        duplicate=receipt()
        duplicate["source_commit"]=OLD
        duplicate["receipt_sha256"]=digest({k:v for k,v in duplicate.items() if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            proposal(previous(),duplicate,PIN)
        with self.assertRaises(ValueError):
            proposal(previous(),receipt(),"short")

if __name__=="__main__":
    unittest.main()
