import copy
import unittest
from test_dual_response_custody_rust104 import fixture
from dual_response_custody_rust104 import assess
from operator_continuity_rust105 import (
    append, audit, validate, missing, HOLD, ZERO, LIMIT)

def sample():
    temp,manifest,reports,archives,claims=fixture()
    report=assess(manifest,reports,archives,claims)
    ancestry=[copy.deepcopy(c["ancestry"]) for c in claims]
    return temp,report,ancestry

class OperatorContinuityRUST105(unittest.TestCase):
    def case(self):
        t,r,a=sample()
        self.addCleanup(t.cleanup)
        return r,a
    def history(self):
        r,a=self.case()
        first=append([],r,a)
        return first,r,a
    def test_missing_hold(self):
        self.assertEqual(missing()["status"],"HOLD_MISSING_OPERATOR_CONTINUITY_LEDGER")
    def test_initial_zero_head(self):
        self.assertEqual(validate([]),ZERO)
    def test_first_epoch_valid(self):
        first,_,_=self.history()
        self.assertEqual(len(first),1)
        self.assertEqual(first[0]["previous_sha256"],ZERO)
    def test_exact_repeat_detected(self):
        first,r,a=self.history()
        second=append(first,r,a)
        self.assertIn("REPLAYED_RUST104_REPORT",second[-1]["cross_epoch_conflicts"])
    def test_rotated_operator_pin_cannot_clear_network(self):
        first,r,a=self.history()
        changed=copy.deepcopy(r)
        new_ancestry=copy.deepcopy(a)
        for i,op in enumerate(changed["retrieval_receipts"]):
            op["operator_pin"]=("%064x" % (100+i))
            new_ancestry[i]["operator"]=("%064x" % (200+i))
            changed["claimed_operator_ancestry_sha256"][i]=__import__(
                "operator_continuity_rust105").digest(new_ancestry[i])
        second=append(first,changed,new_ancestry)
        self.assertIn("REUSED_NETWORK_ANCESTRY",
                      second[-1]["cross_epoch_conflicts"])
        self.assertIn("REUSED_ARCHIVE_BYTES",
                      second[-1]["cross_epoch_conflicts"])
    def test_replayed_nonce_detected(self):
        first,r,a=self.history()
        second=append(first,r,a)
        self.assertIn("REPLAYED_ACQUISITION_NONCE",
                      second[-1]["cross_epoch_conflicts"])
    def test_reused_report_detected(self):
        first,r,a=self.history()
        self.assertIn("REUSED_RETRIEVAL_REPORT",
                      append(first,r,a)[-1]["cross_epoch_conflicts"])
    def test_reused_operator_detected(self):
        first,r,a=self.history()
        self.assertIn("REUSED_OPERATOR_PIN",append(first,r,a)[-1]["cross_epoch_conflicts"])
    def test_reused_controller_detected(self):
        first,r,a=self.history()
        self.assertIn("REUSED_CONTROLLER_ANCESTRY",
                      append(first,r,a)[-1]["cross_epoch_conflicts"])
    def test_monotone_extension_hold(self):
        first,r,a=self.history()
        second=append(first,r,a)
        out=audit(first,second)
        self.assertEqual(out["status"],HOLD)
        self.assertEqual(out["epoch_count"],2)
        self.assertFalse(out["release_authorized"])
    def test_no_extension_refused(self):
        first,_,_=self.history()
        with self.assertRaises(ValueError):audit(first,first)
    def test_rollback_refused(self):
        first,r,a=self.history()
        second=append(first,r,a)
        with self.assertRaises(ValueError):audit(second,first)
    def test_rewrite_old_event_refused(self):
        first,r,a=self.history()
        second=append(first,r,a)
        tampered=copy.deepcopy(second)
        tampered[0]["observation"]["operators"][0]["operator_pin"]="f"*64
        with self.assertRaises(ValueError):validate(tampered)
    def test_erase_conflict_refused(self):
        first,r,a=self.history()
        second=append(first,r,a)
        second[-1]["cross_epoch_conflicts"]=[]
        with self.assertRaises(ValueError):validate(second)
    def test_release_forgery_refused(self):
        first,_,_=self.history()
        first[0]["release_authorized"]=True
        with self.assertRaises(ValueError):validate(first)
    def test_malformed_ancestry_refused(self):
        r,a=self.case()
        a[0].pop("network")
        with self.assertRaises(ValueError):append([],r,a)
    def test_wrong_ancestry_binding_refused(self):
        r,a=self.case()
        a[0]["network"]="f"*64
        with self.assertRaises(ValueError):append([],r,a)
    def test_upstream_release_refused(self):
        r,a=self.case()
        r["release_authorized"]=True
        with self.assertRaises(ValueError):append([],r,a)
    def test_capacity_no_overwrite(self):
        first,r,a=self.history()
        import operator_continuity_rust105 as module
        original=module.LIMIT
        try:
            module.LIMIT=1
            with self.assertRaises(ValueError):append(first,r,a)
        finally:module.LIMIT=original
        self.assertEqual(len(first),1)
    def test_deterministic_replay(self):
        first,r,a=self.history()
        self.assertEqual(append(first,r,a),append(first,r,a))
    def test_retained_conflicts_across_third_epoch(self):
        first,r,a=self.history()
        second=append(first,r,a)
        third=append(second,r,a)
        self.assertEqual(third[1],second[1])
        self.assertTrue(audit(second,third)["retained_cross_epoch_conflicts"])
    def test_no_input_mutation(self):
        first,r,a=self.history()
        frozen=copy.deepcopy((first,r,a))
        append(first,r,a)
        self.assertEqual((first,r,a),frozen)

if __name__=="__main__":
    unittest.main()
