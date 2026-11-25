import copy
import unittest
from unittest.mock import patch

from lineage_rust019 import digest
from recovery_epoch_rust024 import (
    hold, validate_highwater, recovery_proposal, qualify
)
OLD="a"*40
REVOKED="b"*64
RECOVERY="c"*64
NEXT="d"*64

def previous():
    x={
        "phase":"RUST-022","status":"CUSTODIAN_CONTINUITY",
        "sequence":2,"source_commit":OLD,"receipt_sha256":"e"*64,
        "new_key_spki_sha256":REVOKED,
        "source_independence_certified":False,"live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }
    x["entry_sha256"]=digest(x)
    return x

def revoked(prev):
    x={
        "phase":"RUST-023","status":"REVOKED_EMERGENCY_FREEZE",
        "sequence":3,"predecessor_sha256":prev["entry_sha256"],
        "revoked_key_spki_sha256":REVOKED,
        "recovery_key_spki_sha256":RECOVERY,
        "frozen":True,"recovery_key_externally_pinned":True,
        "live_gameplay_authority":False,
        "global_anti_rollback_certified":False,
    }
    x["entry_sha256"]=digest(x)
    return x

def highwater(prev):
    x={
        "phase":"RUST-024","status":"EXTERNAL_HIGHWATER",
        "sequence":2,"epoch":0,
        "checkpoint_sha256":prev["entry_sha256"],
        "key_spki_sha256":REVOKED,
        "live_gameplay_authority":False,
    }
    x["highwater_sha256"]=digest(x)
    return x

class RecoveryEpochTests(unittest.TestCase):
    def test_missing_authority_is_hold(self):
        self.assertEqual(hold("not held")["status"],"HOLD_QUARANTINED")
        self.assertFalse(hold("not held")["custody_resume_authorized"])
    def test_monotonic_proposal_and_quarantine(self):
        prev=previous()
        p=recovery_proposal(prev,revoked(prev),highwater(prev),[REVOKED],NEXT)
        self.assertEqual(p["epoch"],1)
        self.assertEqual(p["sequence"],4)
        self.assertIn(REVOKED,p["quarantined_key_spki_sha256"])
    def test_replayed_or_compromised_key_rejected(self):
        prev=previous()
        for quarantine,new_key in [
            ([REVOKED],REVOKED), ([],NEXT), ([RECOVERY],NEXT),
            ([REVOKED,REVOKED],NEXT), ([REVOKED],RECOVERY),
        ]:
            with self.subTest(quarantine=quarantine,new_key=new_key):
                with self.assertRaises(ValueError):
                    recovery_proposal(prev,revoked(prev),highwater(prev),quarantine,new_key)
    def test_missing_highwater_and_forgery_rejected(self):
        prev=previous()
        for key,value in [("epoch",-1),("sequence",1),("checkpoint_sha256","0"*64),
                          ("key_spki_sha256",NEXT),("highwater_sha256","f"*64)]:
            h=copy.deepcopy(highwater(prev))
            h[key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):
                recovery_proposal(prev,revoked(prev),h,[REVOKED],NEXT)
    def test_no_self_issued_authentication(self):
        prev=previous()
        with self.assertRaisesRegex(ValueError,"external prior custody"):
            qualify(prev,revoked(prev),highwater(prev),[REVOKED],NEXT,
                    "recovery.pem","recovery.sig","new.pem","new.sig",
                    RECOVERY,NEXT,prior_authenticated=False)
    def test_qualified_dual_signature_is_not_release_authority(self):
        prev=previous()
        with patch("recovery_epoch_rust024.verify_key_and_signature",return_value="f"*64) as verify:
            result=qualify(prev,revoked(prev),highwater(prev),[REVOKED],NEXT,
                "recovery.pem","recovery.sig","new.pem","new.sig",
                RECOVERY,NEXT,prior_authenticated=True)
        self.assertEqual(verify.call_count,2)
        self.assertEqual(result["status"],"RECOVERY_EPOCH_SIGNATURES_VERIFIED")
        self.assertFalse(result["custody_resume_authorized"])
        self.assertFalse(result["global_anti_rollback_certified"])

if __name__=="__main__":
    unittest.main()
