import copy
import unittest

from lineage_rust019 import digest
from challenge_ledger_rust042 import audit, check_floor, genesis, hold

ROLES=("ff","cf","rr")

def hex64(number):
    return format(number%16,"x")*64

def upstream(seed=0, changed_attestor=False, collision=False):
    observations=[]
    for i,role in enumerate(ROLES):
        o={
            "role":role,
            "externally_issued_nonce_sha256":hex64(i+1+seed*3),
            "retrieval_session_sha256":hex64(i+4+seed*3),
            "custodian_signature_sha256":hex64(i+7),
            "attestor_signature_sha256":hex64(i+10),
            "attestor_key_spki_sha256":hex64(i+13+(4 if changed_attestor and i==0 else 0)),
            "external_attestor_root_sha256":hex64(i+2+(5 if changed_attestor and i==0 else 0)),
            "source_root_sha256":hex64(i+5),
            "acquisition_path_sha256":hex64(i+8),
            "dual_signature_checked":True,
        }
        observations.append(o)
    if collision:
        observations[2]["external_attestor_root_sha256"]=observations[0]["external_attestor_root_sha256"]
    record={
        "phase":"RUST-041",
        "status":"HOLD_SHARED_ATTESTATION_ANCESTRY" if collision else "HOLD_INDEPENDENT_CONTROL_UNVERIFIED",
        "observations":observations,
        "new_nonce_fingerprints":[o["externally_issued_nonce_sha256"] for o in observations],
        "attestation_ancestry_collisions":[{"roles":["ff","rr"]}] if collision else [],
        "release_authorized":False,"fork_resolved":False,
    }
    record["receipt_sha256"]=digest(record)
    return record

def floor(history,count):
    return {
        "phase":"RUST-042","entry_count":count,
        "head_sha256":history["prefix_heads"][count],
    }

class ChallengeLedgerTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_RETAINED_CHALLENGE_LEDGER")
        self.assertFalse(hold()["release_authorized"])
    def test_genesis_first_epoch(self):
        first=audit(upstream(),genesis())
        self.assertEqual(first["epoch"],1)
        self.assertEqual(len(first["entries"]),3)
        self.assertFalse(first["release_authorized"])
    def test_second_epoch_preserves_exact_prefix(self):
        first=audit(upstream(),genesis())
        second=audit(upstream(1),first,floor(first,3))
        self.assertEqual(second["epoch"],2)
        self.assertEqual(second["entries"][:3],first["entries"])
        self.assertEqual(second["prefix_heads"][:4],first["prefix_heads"])
        self.assertFalse(second["external_custody_verified"])
    def test_repeated_nonce_fails(self):
        first=audit(upstream(),genesis())
        next_challenge=upstream(1)
        next_challenge["observations"][0]["externally_issued_nonce_sha256"]=first["entries"][0]["nonce_sha256"]
        next_challenge["new_nonce_fingerprints"][0]=first["entries"][0]["nonce_sha256"]
        next_challenge["receipt_sha256"]=digest({k:v for k,v in next_challenge.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            audit(next_challenge,first)
    def test_repeated_session_fails(self):
        first=audit(upstream(),genesis())
        next_challenge=upstream(1)
        next_challenge["observations"][0]["retrieval_session_sha256"]=first["entries"][0]["retrieval_session_sha256"]
        next_challenge["receipt_sha256"]=digest({k:v for k,v in next_challenge.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"session replay"):
            audit(next_challenge,first)
    def test_changed_attestor_key_preserved_as_hold(self):
        first=audit(upstream(),genesis())
        second=audit(upstream(1,changed_attestor=True),first)
        self.assertEqual(second["status"],"HOLD_ATTESTOR_IDENTITY_SUBSTITUTION")
        self.assertEqual(second["attestor_continuity_conflicts"][0]["role"],"ff")
        self.assertFalse(second["fork_resolved"])
    def test_forged_historical_entry_rejected(self):
        first=audit(upstream(),genesis())
        first["entries"][0]["nonce_sha256"]="0"*64
        with self.assertRaises(ValueError):
            audit(upstream(1),first)
    def test_missing_historical_entry_fails(self):
        first=audit(upstream(),genesis())
        first["entries"].pop(1)
        with self.assertRaisesRegex(ValueError,"truncated"):
            audit(upstream(1),first)
    def test_retained_floor_rejects_changed_prefix(self):
        first=audit(upstream(),genesis())
        with self.assertRaisesRegex(ValueError,"substituted"):
            check_floor({"phase":"RUST-042","entry_count":2,"head_sha256":"f"*64},first["prefix_heads"])
    def test_upstream_collisions_preserved(self):
        out=audit(upstream(collision=True),genesis())
        self.assertTrue(out["preserved_upstream_collisions"])
        self.assertFalse(out["release_authorized"])
    def test_wrong_upstream_digest_or_unsigned_claim_fails(self):
        current=upstream()
        current["observations"][0]["dual_signature_checked"]=False
        current["receipt_sha256"]=digest({k:v for k,v in current.items() if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            audit(current,genesis())
        current=upstream()
        current["observations"][0]["role"]="cf"
        with self.assertRaises(ValueError):
            audit(current,genesis())

if __name__=="__main__":
    unittest.main()
