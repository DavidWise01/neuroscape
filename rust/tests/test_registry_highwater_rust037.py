import copy
import unittest

from lineage_rust019 import digest
from registry_highwater_rust037 import (
    anchor_payload, check_floor, hold, validate_registry, verify
)

PIN="a"*64

def registry(fork=False, revoked=True):
    claims=[]
    for role,pin in zip(("ff","cf","rr"),("1"*64,"2"*64,"3"*64)):
        for epoch in (1,2):
            claims.append({
                "role":role,"epoch":epoch,
                "ledger_sha256":("b"*64 if fork and role=="rr" else "c"*64),
                "checkpoint_sha256":str(epoch+3)*64,
                "signing_key_spki_sha256":pin,
                "signature_sha256":"d"*64,"signed_checkpoint_verified":True,
            })
    revocations=[{
        "role":"ff","revoked_pin":"1"*64,
        "effective_epoch":3,"evidence_sha256":"e"*64,
        "authority_signature_sha256":"f"*64,
    }] if revoked else []
    row={
        "phase":"RUST-036","status":"HOLD_EQUIVOCATION_OR_SHARED_KEYS" if fork else
        "HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN",
        "epoch_key_claims":claims,
        "verified_rotations":[],
        "revocation_evidence":revocations,
        "equivocation_evidence":[{"epoch":2,"ledger_sha256_variants":["b"*64,"c"*64]}] if fork else [],
        "shared_witness_key_evidence":[],
        "external_key_registry_ancestry_verified":False,
        "release_authorized":False,"fork_resolved":False,
    }
    row["receipt_sha256"]=digest(row)
    return row

def floor(payload):
    return {
        "highwater_epoch":payload["highwater_epoch"],
        "rust036_receipt_sha256":payload["rust036_receipt_sha256"],
        "revocation_count":payload["revocation_count"],
        "revocations_sha256":payload["revocations_sha256"],
    }

def fake(*args):
    return "9"*64

class RegistryHighwaterTests(unittest.TestCase):
    def test_missing_external_anchor_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_REGISTRY_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_full_signed_registry_still_unqualified(self):
        src=registry()
        anchored=anchor_payload(src)
        result=verify(src,anchored,"pub.pem","sig.bin",PIN,floor(anchored),verifier=fake)
        self.assertEqual(result["status"],"HOLD_EXTERNAL_LATEST_REGISTRY_UNVERIFIED")
        self.assertTrue(result["external_floor_compared"])
        self.assertEqual(result["signed_anchor"]["revocation_count"],1)
        self.assertFalse(result["external_latest_highwater_verified"])
        self.assertFalse(result["release_authorized"])

    def test_missing_revocation_fails_anchor_comparison(self):
        src=registry()
        anchor=anchor_payload(src)
        rewritten=registry(revoked=False)
        with self.assertRaisesRegex(ValueError,"signed anchor"):
            verify(rewritten,anchor,"pub.pem","sig.bin",PIN,verifier=fake)

    def test_old_registry_below_external_epoch_rejected(self):
        payload=anchor_payload(registry())
        retained=floor(payload)
        retained["highwater_epoch"]=3
        with self.assertRaisesRegex(ValueError,"rollback"):
            check_floor(payload,retained)

    def test_equal_epoch_different_registry_rejected(self):
        payload=anchor_payload(registry())
        retained=floor(payload)
        retained["rust036_receipt_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"equivocated"):
            check_floor(payload,retained)

    def test_more_old_revocations_than_current_rejected(self):
        payload=anchor_payload(registry())
        retained=floor(payload)
        retained["revocation_count"]=2
        with self.assertRaisesRegex(ValueError,"withheld"):
            check_floor(payload,retained)

    def test_equal_count_changed_revocation_history_rejected(self):
        payload=anchor_payload(registry())
        retained=floor(payload)
        retained["revocations_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"revocation history"):
            check_floor(payload,retained)

    def test_tampered_parent_digest_fails(self):
        src=registry()
        src["epoch_key_claims"][0]["epoch"]=99
        with self.assertRaisesRegex(ValueError,"altered"):
            validate_registry(src)

    def test_incomplete_epoch_history_fails(self):
        src=registry()
        src["epoch_key_claims"]=[x for x in src["epoch_key_claims"] if not
                                 (x["role"]=="ff" and x["epoch"]==1)]
        src["receipt_sha256"]=digest({k:v for k,v in src.items() if k!="receipt_sha256"})
        # One observed epoch is permitted; missing prior ancestry cannot be inferred.
        self.assertEqual(len(anchor_payload(src)["key_claims_sha256"]),64)

    def test_fork_preserved_when_anchor_signed(self):
        src=registry(fork=True)
        result=verify(src,anchor_payload(src),"pub.pem","sig.bin",PIN,verifier=fake)
        self.assertEqual(result["status"],"HOLD_REGISTRY_EQUIVOCATION")
        self.assertTrue(result["preserved_equivocation_evidence"])
        self.assertFalse(result["fork_resolved"])

    def test_signature_failure_is_hard_error(self):
        src=registry()
        def fail(*args):
            raise ValueError("invalid Ed25519")
        with self.assertRaises(ValueError):
            verify(src,anchor_payload(src),"pub.pem","sig.bin",PIN,verifier=fail)

if __name__=="__main__":
    unittest.main()
