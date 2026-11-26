import copy
import unittest

from graduation_denial_rust047 import genesis, audit as denial_audit
from denial_highwater_rust048 import audit, checkpoint_payload, verify_floor, hold
from test_graduation_denial_rust047 import review, sha

PIN = "a" * 64

def histories():
    first = denial_audit(review(), genesis())
    second = denial_audit(review(4, "second", source="review-2"), first)
    third = denial_audit(review(5, "third", source="review-3"), second)
    return first, second, third

def floor(ledger, count=None):
    n = ledger["entry_count"] if count is None else count
    return {"phase":"RUST-048", "denial_count":n,
            "head_sha256":ledger["prefix_heads"][n]}

def fake(*args):
    return "f" * 64

class SignedDenialHighwaterTests(unittest.TestCase):
    def test_missing_external_evidence_holds(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_SIGNED_DENIAL_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_valid_signed_prefix_remains_hold(self):
        old, new, _ = histories()
        calls=[]
        def verifier(*args):
            calls.append(args)
            return "f"*64
        result=audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                     PIN,floor(old),verifier=verifier)
        self.assertEqual(len(calls),1)
        self.assertEqual(result["current_denial_count"],2)
        self.assertTrue(result["historical_prefix_preserved"])
        self.assertTrue(result["all_graduations_denied"])
        self.assertFalse(result["globally_latest_denial_highwater_verified"])
        self.assertFalse(result["release_authorized"])

    def test_newer_retained_floor_must_match_exact_prefix(self):
        old, new, latest = histories()
        result=audit(old,latest,checkpoint_payload(old),"key.pem","sig.bin",
                     PIN,floor(new),verifier=fake)
        self.assertEqual(result["retained_denial_count"],2)

    def test_no_progress_from_old_snapshot_rejected(self):
        old, _, _ = histories()
        with self.assertRaisesRegex(ValueError,"no new denial"):
            audit(old,old,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(old),verifier=fake)

    def test_rollback_under_retained_denial_count_rejected(self):
        old,new,latest=histories()
        with self.assertRaisesRegex(ValueError,"history withheld"):
            audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(latest),verifier=fake)

    def test_false_retained_head_rejected(self):
        old,new,_=histories()
        retained=floor(old)
        retained["head_sha256"]=sha("fork")
        with self.assertRaisesRegex(ValueError,"replaced or forked"):
            audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,retained,verifier=fake)

    def test_substituted_highwater_checkpoint_rejected(self):
        old,new,_=histories()
        cp=checkpoint_payload(old)
        cp["head_sha256"]=sha("other")
        with self.assertRaisesRegex(ValueError,"checkpoint does not match"):
            audit(old,new,cp,"key.pem","sig.bin",PIN,floor(old),verifier=fake)

    def test_invalid_external_signature_rejected(self):
        old,new,_=histories()
        def reject(*args):
            raise ValueError("bad Ed25519")
        with self.assertRaises(ValueError):
            audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(old),verifier=reject)

    def test_prefix_rewrite_rejected_even_if_rehashed(self):
        old,new,_=histories()
        new=copy.deepcopy(new)
        new["entries"][0]["replacement_pin"]=sha("alternate")
        with self.assertRaises(ValueError):
            audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(old),verifier=fake)

    def test_same_count_other_history_is_rejected(self):
        old,new,_=histories()
        alternative=denial_audit(review(4,"other",source="alternate"),old)
        with self.assertRaisesRegex(ValueError,"replaced or forked"):
            audit(old,alternative,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(new),verifier=fake)

    def test_unauthorized_graduation_rejected(self):
        old,new,_=histories()
        bad=copy.deepcopy(new)
        bad["entries"][1]["graduation_approved"]=True
        with self.assertRaises(ValueError):
            audit(old,bad,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,floor(old),verifier=fake)

    def test_retained_floor_requires_nonzero_denial(self):
        old,new,_=histories()
        with self.assertRaisesRegex(ValueError,"count invalid"):
            audit(old,new,checkpoint_payload(old),"key.pem","sig.bin",
                  PIN,{"phase":"RUST-048","denial_count":0,
                       "head_sha256":old["prefix_heads"][0]},verifier=fake)

    def test_signed_genesis_is_not_denial_highwater(self):
        with self.assertRaisesRegex(ValueError,"recorded denial"):
            checkpoint_payload(genesis())

if __name__=="__main__":
    unittest.main()
