import copy
import unittest

from lineage_rust019 import digest
from fork_registry_rust050 import genesis, audit as register
from fork_continuity_rust051 import audit, hold, classify
from test_fork_registry_rust050 import observation, floor
from test_cross_custody_highwater_rust049 import sha


def scenario():
    first=register(observation(fork=True),genesis())
    newer=observation(newer=True)
    return first,newer


class ForkContinuityTests(unittest.TestCase):
    def test_no_material_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_FORK_CONTINUITY")
        self.assertFalse(hold()["release_authorized"])

    def test_successor_does_not_erase_old_fork(self):
        old,new=scenario()
        result=audit(old,new)
        self.assertEqual(result["historical_fork_count"],1)
        self.assertEqual(len(result["historical_fork_reviews"][0]["branch_reviews"]),2)
        self.assertTrue(result["historical_fork_reviews"][0]["both_historical_branches_accounted_for"])
        self.assertFalse(result["fork_resolved"])
        self.assertFalse(result["release_authorized"])

    def test_first_branch_extended_second_contradicted(self):
        old,new=scenario()
        statuses=[v["continuity_status"] for v in
                  audit(old,new)["historical_fork_reviews"][0]["branch_reviews"]]
        self.assertEqual(statuses,["EXTENDED","CONTRADICTED"])

    def test_claimed_same_signer_does_not_grant_independence(self):
        old,new=scenario()
        review=audit(old,new)["historical_fork_reviews"][0]["branch_reviews"][0]
        self.assertTrue(review["current_comparisons"][0]["same_claimed_signer"])
        self.assertFalse(review["independent_operator_custody_verified"])

    def test_repeating_upstream_observation_fails(self):
        obs=observation(fork=True)
        old=register(obs,genesis())
        with self.assertRaisesRegex(ValueError,"replay"):
            audit(old,obs)

    def test_wrong_floor_rejected(self):
        old,new=scenario()
        bad=floor(old)
        bad["phase"]="RUST-051"
        bad["head_sha256"]=sha("forged")
        with self.assertRaisesRegex(ValueError,"forked or rewritten"):
            audit(old,new,bad)

    def test_correct_floor_is_not_custody(self):
        old,new=scenario()
        supplied=floor(old)
        supplied["phase"]="RUST-051"
        result=audit(old,new,supplied)
        self.assertTrue(result["retained_floor_compared"])
        self.assertFalse(result["independent_branch_witnessing_authenticated"])

    def test_withheld_shorter_history(self):
        prior={"prefix_heads":[sha("genesis"),sha("one"),sha("two")]}
        current={"prefix_heads":[sha("genesis"),sha("one")]}
        self.assertEqual(classify(prior,current),"WITHHELD")

    def test_equal_history_is_not_resolution(self):
        same={"prefix_heads":[sha("genesis"),sha("one")]}
        self.assertEqual(classify(same,same),"SAME")

    def test_wrong_history_is_contradiction(self):
        a={"prefix_heads":[sha("genesis"),sha("one")]}
        b={"prefix_heads":[sha("genesis"),sha("two")]}
        self.assertEqual(classify(a,b),"CONTRADICTS")

    def test_empty_historical_registry_rejected(self):
        with self.assertRaisesRegex(ValueError,"historical"):
            audit(genesis(),observation())

    def test_removed_historical_fork_is_detected(self):
        old,new=scenario()
        old["fork_events"]=[]
        old["receipt_sha256"]=digest({k:v for k,v in old.items()
                                     if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"alerts discarded"):
            audit(old,new)

    def test_altered_historical_branch_detected(self):
        old,new=scenario()
        old["entries"][0]["source_branch_snapshots"][0]["prefix_heads"][1]=sha("substituted")
        with self.assertRaises(ValueError):
            audit(old,new)

    def test_new_observation_authority_claim_rejected(self):
        old,new=scenario()
        new["fork_resolved"]=True
        new["receipt_sha256"]=digest({k:v for k,v in new.items()
                                    if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"authority promotion"):
            audit(old,new)

    def test_multi_fork_registry_all_accounted(self):
        old,new=scenario()
        from cross_custody_highwater_rust049 import audit as pair
        from test_cross_custody_highwater_rust049 import branch,histories,PINS,verifier
        _,second,other,third=histories()
        extra=pair(branch(third),branch(other,1),PINS,verifier=verifier)
        older=register(extra,old)
        result=audit(older,new)
        self.assertEqual(result["historical_fork_count"],2)
        self.assertEqual(len(result["historical_fork_reviews"]),2)
        self.assertFalse(result["fork_resolved"])


if __name__=="__main__":
    unittest.main()
