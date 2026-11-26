import copy
import hashlib
import unittest
from lineage_rust019 import digest
from fork_challenge_ledger_rust052 import audit, hold, genesis, checked_history, GENESIS
from fork_continuity_rust051 import audit as continuity_audit
from test_fork_continuity_rust051 import scenario


def h(t):
    return hashlib.sha256(t.encode()).hexdigest()


def bundle(tag="one", changed=False, shared=False):
    history, observation=scenario()
    review=continuity_audit(history,observation)
    groups=[]
    pins=[]
    nonces=[]
    for row in review["historical_fork_reviews"]:
        groups.append([{
            "role":role,"source_root_sha256":h(("alias" if changed else "root")+role),
            "acquisition_sha256":h(("alias" if changed else "acq")+role),
            "operator_control_sha256":h(("same" if shared else "control"+role)),
            "public_key":role+".pem","signature":role+".sig"
        } for role in ("ff","cf","rr")])
        pins.append([h("pin"+role) for role in ("ff","cf","rr")])
        nonces.append([h(tag+"nonce"+role) for role in ("ff","cf","rr")])
    return review,groups,pins,nonces


def verifier(*args):
    return h("verified")


class ForkChallengeLedgerTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_WITNESS_CHALLENGES")
        self.assertFalse(hold()["release_authorized"])

    def test_first_signed_review_is_still_hold(self):
        review,groups,pins,nonces=bundle()
        out=audit(review,genesis(),groups,pins,nonces,verifier=verifier)
        self.assertEqual(out["entry_count"],1)
        self.assertEqual(out["prefix_heads"][0],GENESIS)
        self.assertFalse(out["release_authorized"])
        self.assertFalse(out["independent_witness_custody_verified"])

    def test_successor_preserves_prior_entries(self):
        review,groups,pins,nonces=bundle()
        first=audit(review,genesis(),groups,pins,nonces,verifier=verifier)
        next_review,groups,pins,nonces=bundle("two")
        # A second RUST-051 observation may differ by its receipt, including
        # different external assessment identifiers, while keeping fork roots.
        next_review["retained_floor_claim_sha256"]=h("different-review")
        next_review["receipt_sha256"]=digest({k:v for k,v in next_review.items()
                                             if k!="receipt_sha256"})
        next_out=audit(next_review,first,groups,pins,nonces,verifier=verifier)
        self.assertEqual(next_out["entries"][:1],first["entries"])
        self.assertEqual(next_out["prefix_heads"][:2],first["prefix_heads"])
        self.assertFalse(next_out["fork_resolved"])

    def test_same_nonce_rejected(self):
        r,g,p,n=bundle()
        first=audit(r,genesis(),g,p,n,verifier=verifier)
        different=copy.deepcopy(r)
        different["retained_floor_claim_sha256"]=h("new")
        different["receipt_sha256"]=digest({k:v for k,v in different.items()
                                           if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"replayed witness"):
            audit(different,first,g,p,n,verifier=verifier)

    def test_same_pin_changed_ancestry_flagged(self):
        r,g,p,n=bundle()
        first=audit(r,genesis(),g,p,n,verifier=verifier)
        later,g,p,n=bundle("later",changed=True)
        later["new_rust049_receipt_sha256"]=h("later-source")
        later["receipt_sha256"]=digest({k:v for k,v in later.items()
                                       if k!="receipt_sha256"})
        out=audit(later,first,g,p,n,verifier=verifier)
        self.assertTrue(out["source_ancestry_conflicts"])

    def test_shared_control_root_flagged(self):
        r,g,p,n=bundle(shared=True)
        out=audit(r,genesis(),g,p,n,verifier=verifier)
        self.assertEqual(out["source_ancestry_conflicts"][0]["reason"],
                         "SHARED_CLAIMED_WITNESS_ANCESTRY")

    def test_duplicate_pins_rejected(self):
        r,g,p,n=bundle()
        p[0][1]=p[0][0]
        with self.assertRaisesRegex(ValueError,"pin reused"):
            audit(r,genesis(),g,p,n,verifier=verifier)

    def test_missing_witness_rejected(self):
        r,g,p,n=bundle()
        g[0].pop()
        with self.assertRaisesRegex(ValueError,"three ordered"):
            audit(r,genesis(),g,p,n,verifier=verifier)

    def test_invalid_signature_rejected(self):
        r,g,p,n=bundle()
        def bad(*args):
            raise ValueError("Ed25519 invalid")
        with self.assertRaises(ValueError):
            audit(r,genesis(),g,p,n,verifier=bad)

    def test_false_review_authority_rejected(self):
        r,g,p,n=bundle()
        r["fork_resolved"]=True
        with self.assertRaises(ValueError):
            audit(r,genesis(),g,p,n,verifier=verifier)

    def test_floor_mismatch_rejected(self):
        r,g,p,n=bundle()
        first=audit(r,genesis(),g,p,n,verifier=verifier)
        later=copy.deepcopy(r)
        later["new_rust049_receipt_sha256"]=h("different")
        later["receipt_sha256"]=digest({k:v for k,v in later.items()
                                       if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"substituted"):
            audit(later,first,g,p,[[h("changed"+role) for role in ("ff","cf","rr")]],
                  {"phase":"RUST-052","entry_count":1,"head_sha256":h("wrong")},
                  verifier=verifier)

    def test_historical_tampering_rejected(self):
        r,g,p,n=bundle()
        first=audit(r,genesis(),g,p,n,verifier=verifier)
        first["entries"][0]["witness_claims"][0]["signature_sha256"]=h("fraud")
        with self.assertRaises(ValueError):
            checked_history(first)

    def test_historical_conflict_erasure_rejected(self):
        r,g,p,n=bundle(shared=True)
        first=audit(r,genesis(),g,p,n,verifier=verifier)
        first["source_ancestry_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"conflict erased"):
            checked_history(first)

    def test_all_historical_forks_must_be_reviewed(self):
        r,g,p,n=bundle()
        r["historical_fork_count"]=2
        r["receipt_sha256"]=digest({k:v for k,v in r.items()
                                   if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"unaccounted historical fork"):
            audit(r,genesis(),g,p,n,verifier=verifier)


if __name__=="__main__":
    unittest.main()
