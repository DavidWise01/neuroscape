import unittest
from custody_fork_highwater_rust076 import audit,checkpoint_payload,hold
from test_custody_fork_rust075 import run as fork_run,sample,h,verify

def fixture():
    previous=fork_run()
    current=fork_run(sample("second"),history=previous)
    e=current["events"][-1]
    observation={"phase":"RUST-076",
                 "fork_entry_sha256":e["entry_sha256"],
                 "observation_nonce_sha256":h("076-nonce"),
                 "base_rust073_receipt_sha256":e["base_rust073_receipt_sha256"],
                 "branch_a_head_sha256":e["branch_a_head_sha256"],
                 "branch_b_head_sha256":e["branch_b_head_sha256"],
                 "winner_selected":False,"fork_resolved":False,
                 "recovery_authorized":False,"release_authorized":False}
    floor={"phase":"RUST-076","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,checkpoint_payload(previous),floor,[observation]]

def run(args=None,pin=None,verifier=verify):
    before,after,checkpoint,floor,observations=args or fixture()
    return audit(before,after,checkpoint,"checkpoint.pem","checkpoint.sig",
                 pin or h("076-independent-checkpoint-key"),
                 floor,observations,verifier=verifier)

class CustodyForkHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODY_FORK_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])
    def test_signed_extension_still_hold(self):
        result=run()
        self.assertEqual((result["previous_fork_count"],result["current_fork_count"]),(1,2))
        self.assertTrue(result["both_branches_retained"])
        self.assertFalse(result["winner_selected"])
        self.assertFalse(result["fork_resolved"])
    def test_pair_history_exact_prefix(self):
        result=run()
        self.assertEqual(result["current_fork_pairs_preserved"][:len(
            result["historical_fork_pairs_preserved"])],
            result["historical_fork_pairs_preserved"])
    def test_conflicts_exact_prefix(self):
        result=run()
        self.assertEqual(result["current_conflicts_preserved"][:len(
            result["historical_conflicts_preserved"])],
            result["historical_conflicts_preserved"])
    def test_historical_fork_heads_distinct(self):
        for pair in run()["current_fork_pairs_preserved"]:
            self.assertNotEqual(pair[0],pair[1])
    def test_new_fork_pair_not_misclassified_as_replay(self):
        self.assertNotIn("REPEATED_FORK_PAIR_NEW_EPOCH",
                         [x["reason"] for x in run()["cross_epoch_conflicts"]])
    def test_repeated_fork_pair_is_recorded(self):
        first=fork_run()
        material=sample("second")
        material[3]=sample()[3]
        second=fork_run(material,history=first)
        args=fixture()
        args[1]=second
        new_event=second["events"][-1]
        args[4][0]["fork_entry_sha256"]=new_event["entry_sha256"]
        args[4][0]["branch_b_head_sha256"]=new_event["branch_b_head_sha256"]
        result=run(args)
        self.assertIn("REPEATED_FORK_PAIR_NEW_EPOCH",
                      [x["reason"] for x in result["cross_epoch_conflicts"]])
    def test_reused_source_ancestry_recorded(self):
        self.assertIn("REUSED_CUSTODY_ANCESTRY_WITH_NEW_FORK",
                      [x["reason"] for x in run()["cross_epoch_conflicts"]])
    def test_stale_ledger_rejected(self):
        a=fixture();a[1]=a[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(a)
    def test_prior_fork_mutation_rejected(self):
        a=fixture();a[1]["events"][0]["winner_selected"]=True
        with self.assertRaises(ValueError):run(a)
    def test_prior_conflicts_erased_rejected(self):
        a=fixture();a[1]["custody_conflicts"]=[]
        with self.assertRaises(ValueError):run(a)
    def test_checkpoint_changed_rejected(self):
        a=fixture();a[2]["head_sha256"]=h("fake")
        with self.assertRaisesRegex(ValueError,"substituted"):run(a)
    def test_floor_branch_rejected(self):
        a=fixture();a[3]["head_sha256"]=h("another-branch")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(a)
    def test_floor_ahead_rejected(self):
        a=fixture();a[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside known"):run(a)
    def test_fork_witness_cannot_self_sign(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(a,pin=a[1]["events"][0]["witness_a_pin"])
    def test_missing_observation_rejected(self):
        a=fixture();a[4]=[]
        with self.assertRaisesRegex(ValueError,"one new fork observation"):run(a)
    def test_swapped_branch_claim_rejected(self):
        a=fixture()
        a[4][0]["branch_a_head_sha256"],a[4][0]["branch_b_head_sha256"]=(
            a[4][0]["branch_b_head_sha256"],a[4][0]["branch_a_head_sha256"])
        with self.assertRaisesRegex(ValueError,"substituted a branch"):run(a)
    def test_wrong_fork_event_rejected(self):
        a=fixture();a[4][0]["fork_entry_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"substituted a branch"):run(a)
    def test_replayed_nonce_rejected(self):
        a=fixture()
        a[4][0]["observation_nonce_sha256"]=a[1]["events"][0]["nonce_a_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(a)
    def test_fabricated_merge_rejected(self):
        a=fixture();a[4][0]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"false merge"):run(a)
    def test_release_claim_rejected(self):
        a=fixture();a[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"false merge"):run(a)
    def test_invalid_signature_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=invalid)

if __name__=="__main__":
    unittest.main()
