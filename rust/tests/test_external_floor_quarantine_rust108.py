import copy
import unittest
from test_external_highwater_floor_rust107 import sample, check
from external_floor_quarantine_rust108 import (
    append, audit, validate, observation, missing, HOLD, ZERO)

def report_fixture():
    tmp, old, now, copies = sample()
    return tmp, check(old,now,copies)

class ExternalFloorQuarantineRUST108(unittest.TestCase):
    def case(self):
        t,r=report_fixture();self.addCleanup(t.cleanup)
        return r
    def history(self):
        report=self.case()
        return append([],report),report
    def invalid(self,mutate):
        report=self.case()
        mutate(report)
        with self.assertRaises((ValueError,KeyError,TypeError)):
            append([],report)
    def test_missing_is_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_EXTERNAL_FLOOR_QUARANTINE_HISTORY")
    def test_empty_head(self):
        self.assertEqual(validate([]),ZERO)
    def test_first_epoch(self):
        first,report=self.history()
        self.assertEqual(first[0]["index"],0)
        self.assertEqual(first[0]["previous_sha256"],ZERO)
    def test_stale_floor_retained(self):
        first,_=self.history()
        self.assertIn("STALE_COPY_RETAINED",
                      first[0]["observation"]["derived_conflicts"])
    def test_conflicting_floor_retained(self):
        first,_=self.history()
        self.assertIn("INTRA_EPOCH_FLOOR_CONFLICT",
                      first[0]["observation"]["derived_conflicts"])
    def test_replayed_report_recorded(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertIn("REPLAYED_RUST107_REPORT",next_[-1]["quarantine_reasons"])
    def test_reintroduced_copy_recorded(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertIn("REINTRODUCED_HIGHWATER_COPY",
                      next_[-1]["quarantine_reasons"])
    def test_nonce_reuse_recorded(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertIn("REUSED_ACQUISITION_NONCE",
                      next_[-1]["quarantine_reasons"])
    def test_signer_reuse_recorded(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertIn("REUSED_HIGHWATER_SIGNER",
                      next_[-1]["quarantine_reasons"])
    def test_ancestry_reuse_recorded(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertIn("REUSED_CUSTODY_ANCESTRY",
                      next_[-1]["quarantine_reasons"])
    def test_append_preserves_prefix(self):
        first,report=self.history()
        next_=append(first,report)
        self.assertEqual(next_[:len(first)],first)
    def test_audit_holds(self):
        first,report=self.history()
        next_=append(first,report)
        result=audit(first,next_)
        self.assertEqual(result["status"],HOLD)
        self.assertFalse(result["global_latest_floor_authenticated"])
        self.assertFalse(result["release_authorized"])
    def test_replay_determinism(self):
        first,report=self.history()
        self.assertEqual(append(first,report),append(first,report))
    def test_no_extension_rejected(self):
        first,_=self.history()
        with self.assertRaises(ValueError):audit(first,first)
    def test_rollback_rejected(self):
        first,report=self.history()
        next_=append(first,report)
        with self.assertRaises(ValueError):audit(next_,first)
    def test_erased_cross_epoch_conflict_rejected(self):
        first,report=self.history()
        next_=append(first,report)
        next_[-1]["quarantine_reasons"]=[]
        with self.assertRaises(ValueError):validate(next_)
    def test_erased_derived_stale_conflict_rejected(self):
        first,_=self.history()
        first[0]["observation"]["derived_conflicts"]=[]
        with self.assertRaises(ValueError):validate(first)
    def test_rewritten_head_rejected(self):
        first,_=self.history()
        first[0]["observation"]["local_head_sha256"]="f"*64
        with self.assertRaises(ValueError):validate(first)
    def test_forged_release_rejected(self):
        first,_=self.history()
        first[0]["release_authorized"]=True
        with self.assertRaises(ValueError):validate(first)
    def test_forged_external_acquisition_rejected(self):
        self.invalid(lambda r:r.update(external_acquisition_authenticated=True))
    def test_forged_latest_floor_rejected(self):
        self.invalid(lambda r:r.update(global_latest_floor_authenticated=True))
    def test_missing_copy_rejected(self):
        self.invalid(lambda r:r["copies"].pop())
    def test_malformed_custody_digest_rejected(self):
        self.invalid(lambda r:r["custody_ancestry_sha256"].__setitem__(0,"bad"))
    def test_limit_fails_without_overwrite(self):
        import external_floor_quarantine_rust108 as mod
        first,report=self.history()
        original=mod.MAX_EPOCHS
        try:
            mod.MAX_EPOCHS=1
            with self.assertRaises(ValueError):append(first,report)
        finally:mod.MAX_EPOCHS=original
        self.assertEqual(len(first),1)
    def test_third_epoch_retains_second(self):
        first,report=self.history()
        second=append(first,report)
        third=append(second,report)
        self.assertEqual(third[1],second[1])
        self.assertTrue(audit(second,third)["retained_quarantine"])
    def test_no_input_mutation(self):
        first,report=self.history()
        old=copy.deepcopy((first,report))
        append(first,report)
        self.assertEqual((first,report),old)

if __name__=="__main__":
    unittest.main()
