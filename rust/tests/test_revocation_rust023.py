import copy
import unittest
from unittest.mock import patch

from lineage_rust019 import digest
from revocation_rust023 import (
    deny_if_revoked, hold_record, qualify, revocation_proposal,
    validate_revocation,
)

OLD="a"*40
PIN="b"*64
RECOVERY="c"*64

def predecessor():
    value={
        "phase":"RUST-022","status":"CUSTODIAN_CONTINUITY",
        "sequence":2,"source_commit":OLD,"receipt_sha256":"d"*64,
        "new_key_spki_sha256":PIN,
        "source_independence_certified":False,
        "live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }
    value["entry_sha256"]=digest(value)
    return value

class RevocationTests(unittest.TestCase):
    def test_no_external_evidence_hold(self):
        self.assertEqual(hold_record("unknown")["status"],"HOLD_REVOCATION_CUSTODY_UNVERIFIED")
        self.assertTrue(hold_record("unknown")["frozen"])
    def test_signed_recovery_freeze_and_denylist(self):
        with patch("revocation_rust023.verify_key_and_signature",return_value="e"*64) as signed:
            receipt=qualify(predecessor(),PIN,RECOVERY,"COMPROMISE","recovery.pem","recovery.sig",RECOVERY)
            self.assertEqual(signed.call_count,1)
            self.assertEqual(receipt["status"],"REVOKED_EMERGENCY_FREEZE")
            self.assertEqual(receipt["sequence"],3)
            self.assertTrue(validate_revocation(receipt,predecessor())["frozen"])
            with self.assertRaisesRegex(ValueError,"revoked key"):
                deny_if_revoked(PIN,[receipt],predecessor())
            self.assertTrue(deny_if_revoked(RECOVERY,[receipt],predecessor()))
    def test_mismatched_keys_and_reason_rejected(self):
        for revoked,recovery,reason,pin in [
            (PIN,PIN,"COMPROMISE",PIN),
            (RECOVERY,PIN,"COMPROMISE",PIN),
            (PIN,RECOVERY,"REPLACE_WITHOUT_CAUSE",RECOVERY),
            (PIN,RECOVERY,"COMPROMISE",PIN),
            (PIN,RECOVERY,"COMPROMISE",None),
        ]:
            with self.subTest(reason=reason,revoked=revoked,pin=pin):
                with self.assertRaises(ValueError):
                    qualify(predecessor(),revoked,recovery,reason,"a.pem","a.sig",pin)
    def test_tampering_and_wrong_predecessor_rejected(self):
        with patch("revocation_rust023.verify_key_and_signature",return_value="e"*64):
            original=qualify(predecessor(),PIN,RECOVERY,"LOSS","recovery.pem","recovery.sig",RECOVERY)
        for field,value in [
            ("sequence",11),("predecessor_sha256","f"*64),
            ("frozen",False),("entry_sha256","0"*64),
        ]:
            row=copy.deepcopy(original)
            row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_revocation(row,predecessor())
    def test_unsigned_early_predecessor_is_not_trusted(self):
        bad=predecessor()
        bad["phase"]="RUST-021"
        bad["status"]="FIRST_SUCCESSOR_OF_SIGNED_GENESIS"
        bad["entry_sha256"]=digest({k:v for k,v in bad.items() if k!="entry_sha256"})
        with self.assertRaises(ValueError):
            revocation_proposal(bad,PIN,RECOVERY,"COMPROMISE")

if __name__=="__main__":
    unittest.main()
