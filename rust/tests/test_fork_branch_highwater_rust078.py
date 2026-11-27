import unittest
from fork_branch_highwater_rust078 import audit,checkpoint_payload,hold
from test_fork_branch_custody_rust077 import run as custody_run,materials,h,verify

def fixture():
    previous=custody_run()
    current=custody_run(materials("two"),history=previous)
    e=current["events"][-1]
    claim={"phase":"RUST-078",
           "custody_entry_sha256":e["entry_sha256"],
           "observation_nonce_sha256":h("fresh-078-nonce"),
           "branch_a_sha256":e["branch_a_sha256"],
           "branch_b_sha256":e["branch_b_sha256"],
           "claims_sha256":e["claims_sha256"],
           "both_branches_retained":True,"winner_selected":False,
           "fork_resolved":False,"recovery_authorized":False,
           "release_authorized":False}
    floor={"phase":"RUST-078","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,checkpoint_payload(previous),floor,[claim]]

def run(bundle=None,pin=None,verifier=verify):
    prev,cur,cp,floor,claims=bundle or fixture()
    return audit(prev,cur,cp,"highwater.pem","highwater.sig",
                 pin or h("external-078-signing-pin"),floor,claims,
                 verifier=verifier)

class BranchCustodyHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_BRANCH_CUSTODY_HIGHWATER")
        self.assertFalse(hold()["fork_resolved"])
    def test_signed_extension_still_hold(self):
        x=run()
        self.assertEqual((x["previous_event_count"],x["current_event_count"]),(1,2))
        self.assertTrue(x["both_branches_retained"])
        self.assertFalse(x["recovery_authorized"])
    def test_previous_branch_pairs_preserved(self):
        x=run()
        self.assertEqual(x["current_branch_pairs"][:len(x["previous_branch_pairs"])],
                         x["previous_branch_pairs"])
    def test_previous_claims_preserved(self):
        x=run()
        self.assertEqual(x["current_claim_digests"][:len(x["previous_claim_digests"])],
                         x["previous_claim_digests"])
    def test_historical_conflicts_preserved(self):
        x=run()
        self.assertEqual(x["current_conflicts"][:len(x["historical_conflicts"])],
                         x["historical_conflicts"])
    def test_branch_heads_distinct(self):
        self.assertTrue(all(a!=b for a,b in run()["current_branch_pairs"]))
    def test_repeat_branch_pair_detected(self):
        x=run()
        self.assertIn("REPEATED_BRANCH_PAIR_NEW_EPOCH",
                      [c["reason"] for c in x["cross_epoch_conflicts"]])
    def test_existing_signing_pin_changed_ancestry_not_authority(self):
        x=run()
        self.assertFalse(x["independent_custody_verified"])
        self.assertFalse(x["fork_resolved"])
    def test_stale_history_rejected(self):
        a=fixture();a[1]=a[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(a)
    def test_history_event_rewrite_rejected(self):
        a=fixture();a[1]["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):run(a)
    def test_history_conflict_erase_rejected(self):
        a=fixture();a[1]["custody_conflicts"]=[{"fake":"conflict"}]
        with self.assertRaises(ValueError):run(a)
    def test_checkpoint_substitution_rejected(self):
        a=fixture();a[2]["head_sha256"]=h("different")
        with self.assertRaisesRegex(ValueError,"substituted"):run(a)
    def test_wrong_retention_floor_rejected(self):
        a=fixture();a[3]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(a)
    def test_floor_ahead_rejected(self):
        a=fixture();a[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(a)
    def test_custodian_cannot_self_sign(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(a,pin=a[1]["events"][0]["branches"][0]["pin"])
    def test_missing_observation_rejected(self):
        a=fixture();a[4]=[]
        with self.assertRaisesRegex(ValueError,"one fresh pair observation"):run(a)
    def test_swapped_branches_rejected(self):
        a=fixture()
        x=a[4][0]
        x["branch_a_sha256"],x["branch_b_sha256"]=x["branch_b_sha256"],x["branch_a_sha256"]
        with self.assertRaisesRegex(ValueError,"substituted branch"):run(a)
    def test_substituted_claim_digest_rejected(self):
        a=fixture();a[4][0]["claims_sha256"]=h("different")
        with self.assertRaisesRegex(ValueError,"substituted branch"):run(a)
    def test_observation_wrong_entry_rejected(self):
        a=fixture();a[4][0]["custody_entry_sha256"]=h("different")
        with self.assertRaisesRegex(ValueError,"substituted branch"):run(a)
    def test_replayed_witness_nonce_rejected(self):
        a=fixture()
        a[4][0]["observation_nonce_sha256"]=a[1]["events"][0]["branches"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(a)
    def test_false_merge_rejected(self):
        a=fixture();a[4][0]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"falsely reconciled"):run(a)
    def test_false_release_rejected(self):
        a=fixture();a[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"falsely reconciled"):run(a)
    def test_invalid_signature_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=invalid)
if __name__=="__main__":unittest.main()
