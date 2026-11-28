import copy
import hashlib
import unittest
from cross_run_acquisition_ledger_rust091 import (
    append, audit, verify_ledger, missing, ZERO)

def h(value):
    return hashlib.sha256(value.encode()).hexdigest()

def observation(i):
    return {"phase": "RUST-090",
        "status": "HOLD_EXTERNAL_INDEPENDENT_CUSTODY_UNVERIFIED",
        "repository": "DavidWise01/neuroscape",
        "run_id": 100000 + i, "artifact_id": 200000 + i,
        "run_commit_sha": h("commit-" + str(i))[:40],
        "archive_length": 64 + i,
        "archive_sha256": h("archive-" + str(i)),
        "run_metadata_sha256": h("run-" + str(i)),
        "artifact_metadata_sha256": h("artifact-" + str(i)),
        "bytes_acquired_via_github_api": True,
        "independent_external_custody_verified": False,
        "global_anti_rollback_verified": False,
        "recovery_authorized": False, "release_authorized": False,
        "live_gameplay_authorized": False}

def history():
    a = append([], observation(1))
    return a, append(a, observation(2))

class AcquisitionLedgerRUST091(unittest.TestCase):
    def rejects(self, old, new):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            audit(old, new)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"], "HOLD_MISSING_ACQUISITION_LEDGER")
    def test_zero_head(self):
        self.assertEqual(verify_ledger([]), ZERO)
    def test_append_preserves_previous(self):
        before, after = history()
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(audit(before, after)["entry_count"], 2)
    def test_valid_ledger_stays_hold(self):
        before, after = history()
        result = audit(before, after)
        self.assertEqual(result["status"], "HOLD_CROSS_RUN_ANCESTRY_UNVERIFIED")
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["independent_external_custody_verified"])
    def test_deterministic_replay(self):
        self.assertEqual(history(), history())
    def test_no_extension_refused(self):
        before, _ = history()
        self.rejects(before, before)
    def test_history_rewrite_refused(self):
        before, after = history()
        altered = copy.deepcopy(after)
        altered[0]["observation"]["archive_length"] += 1
        self.rejects(before, altered)
    def test_previous_hash_refused(self):
        before, after = history()
        altered = copy.deepcopy(after)
        altered[1]["previous_sha256"] = h("wrong")
        self.rejects(before, altered)
    def test_removed_entry_refused(self):
        before, after = history()
        self.rejects(after, before)
    def test_duplicate_run_retained(self):
        before, _ = history()
        ob = observation(2); ob["run_id"] = observation(1)["run_id"]
        new = append(before, ob)
        self.assertIn("REUSED_RUN", new[-1]["contradictions"])
        self.assertTrue(audit(before, new)["contradictions_retained"])
    def test_duplicate_artifact_retained(self):
        before, _ = history()
        ob = observation(2); ob["artifact_id"] = observation(1)["artifact_id"]
        self.assertIn("REUSED_ARTIFACT", append(before, ob)[-1]["contradictions"])
    def test_duplicate_bytes_retained(self):
        before, _ = history()
        ob = observation(2); ob["archive_sha256"] = observation(1)["archive_sha256"]
        self.assertIn("REUSED_ARCHIVE_BYTES", append(before, ob)[-1]["contradictions"])
    def test_duplicate_metadata_retained(self):
        before, _ = history()
        ob = observation(2); ob["run_metadata_sha256"] = observation(1)["run_metadata_sha256"]
        self.assertIn("REUSED_METADATA_ANCESTRY", append(before, ob)[-1]["contradictions"])
    def test_run_commit_conflict_retained(self):
        before, _ = history()
        ob = observation(2); ob["run_id"] = observation(1)["run_id"]
        self.assertIn("CONTRADICTORY_RUN_COMMIT", append(before, ob)[-1]["contradictions"])
    def test_erase_contradiction_refused(self):
        before, _ = history()
        ob = observation(2); ob["artifact_id"] = observation(1)["artifact_id"]
        altered = append(before, ob)
        altered[-1]["contradictions"] = []
        self.rejects(before, altered)
    def test_release_promotion_refused(self):
        ob = observation(1); ob["release_authorized"] = True
        with self.assertRaises(ValueError):
            append([], ob)
    def test_custody_promotion_refused(self):
        ob = observation(1); ob["independent_external_custody_verified"] = True
        with self.assertRaises(ValueError):
            append([], ob)
    def test_bad_observation_source_refused(self):
        ob = observation(1); ob["repository"] = "thirdparty/mirror"
        with self.assertRaises(ValueError):
            append([], ob)
    def test_invalid_archive_digest_refused(self):
        ob = observation(1); ob["archive_sha256"] = "bad"
        with self.assertRaises(ValueError):
            append([], ob)
    def test_claims_are_not_independent_sources(self):
        before, after = history()
        self.assertFalse(audit(before, after)["live_gameplay_authorized"])

if __name__ == "__main__":
    unittest.main()
