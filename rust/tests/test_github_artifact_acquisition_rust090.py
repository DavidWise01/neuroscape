import json
import unittest
from github_artifact_acquisition_rust090 import acquire, hold, API, REPO, MAX_BYTES

RUN = 802103
ARTIFACT = 790201
SHA = "a" * 40
ZIP = bytes((0x50, 0x4b, 0x03, 0x04)) + b"synthetic-zip-test"
BASE = API + "/repos/" + REPO + "/actions/"
def bodies():
    return {
        BASE + "runs/" + str(RUN): json.dumps({
            "id": RUN, "repository": {"full_name": REPO},
            "event": "push", "head_sha": SHA, "conclusion": "success"
        }).encode(),
        BASE + "artifacts/" + str(ARTIFACT): json.dumps({
            "id": ARTIFACT, "workflow_run": {"id": RUN},
            "expired": False, "size_in_bytes": len(ZIP)
        }).encode(),
        BASE + "artifacts/" + str(ARTIFACT) + "/zip": ZIP
    }
def attempt(data=None):
    records = bodies() if data is None else data
    def fake_fetch(url, token, limit):
        value = records[url]
        if len(value) > limit:
            raise ValueError("over cap")
        return value
    return acquire(RUN, ARTIFACT, token=None, fetcher=fake_fetch)

class ArtifactAcquisitionRUST090(unittest.TestCase):
    def rejected(self, edit):
        data = bodies()
        edit(data)
        with self.assertRaises((ValueError, KeyError, UnicodeError, json.JSONDecodeError)):
            attempt(data)
    def change_run(self, edit):
        def change(data):
            url = BASE + "runs/" + str(RUN)
            record = json.loads(data[url])
            edit(record)
            data[url] = json.dumps(record).encode()
        self.rejected(change)
    def change_artifact(self, edit):
        def change(data):
            url = BASE + "artifacts/" + str(ARTIFACT)
            record = json.loads(data[url])
            edit(record)
            data[url] = json.dumps(record).encode()
        self.rejected(change)
    def test_holding_pattern(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_AUTHENTICATED_RUN_ARTIFACT")
        self.assertFalse(hold()["release_authorized"])
    def test_acquired_bytes_still_hold(self):
        row, data = attempt()
        self.assertEqual(row["status"], "HOLD_EXTERNAL_INDEPENDENT_CUSTODY_UNVERIFIED")
        self.assertEqual(data, ZIP)
        self.assertTrue(row["bytes_acquired_via_github_api"])
        self.assertFalse(row["release_authorized"])
        self.assertFalse(row["independent_external_custody_verified"])
    def test_deterministic_byte_digest(self):
        self.assertEqual(attempt()[0], attempt()[0])
    def test_reject_run_id_mismatch(self):
        self.change_run(lambda r: r.update(id=999))
    def test_reject_wrong_repository(self):
        self.change_run(lambda r: r.update(repository={"full_name": "other/repo"}))
    def test_reject_wrong_event(self):
        self.change_run(lambda r: r.update(event="pull_request"))
    def test_reject_missing_commit(self):
        self.change_run(lambda r: r.update(head_sha=None))
    def test_reject_artifact_id_mismatch(self):
        self.change_artifact(lambda r: r.update(id=999))
    def test_reject_cross_run_artifact(self):
        self.change_artifact(lambda r: r.update(workflow_run={"id": RUN + 1}))
    def test_reject_expired_artifact(self):
        self.change_artifact(lambda r: r.update(expired=True))
    def test_reject_unbounded_metadata(self):
        self.change_artifact(lambda r: r.update(size_in_bytes=MAX_BYTES + 1))
    def test_reject_empty_metadata(self):
        self.change_artifact(lambda r: r.update(size_in_bytes=0))
    def test_reject_archive_size_mismatch(self):
        self.change_artifact(lambda r: r.update(size_in_bytes=len(ZIP) + 1))
    def test_reject_invalid_zip_signature(self):
        self.rejected(lambda d: d.update({BASE + "artifacts/" + str(ARTIFACT) + "/zip": b"NOTAZIP" + ZIP[7:]}))
    def test_reject_missing_zip(self):
        self.rejected(lambda d: d.update({BASE + "artifacts/" + str(ARTIFACT) + "/zip": b""}))
    def test_require_positive_ids(self):
        with self.assertRaises(ValueError):
            acquire(0, ARTIFACT)
    def test_rerun_does_not_grant_authority(self):
        for _ in range(3):
            row, _ = attempt()
            self.assertFalse(row["global_anti_rollback_verified"])
            self.assertFalse(row["recovery_authorized"])
            self.assertFalse(row["live_gameplay_authorized"])
if __name__ == "__main__":
    unittest.main()
