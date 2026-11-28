import base64
import copy
import hashlib
import unittest
from cross_run_custody_evidence_rust089 import audit, hold, DOMAIN, record_digest

def h(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

CP = {"phase": "RUST-086", "kind": "CROSS_CUSTODIAN_QUARANTINE_HIGHWATER_V1",
      "head_sha256": h("frozen-head")}
DENIED = [{"denial": h("denied-release")}]
QUARANTINED = [{"quarantined": h("witness")}]

def item(i):
    blob = ("immutable-archive-" + str(i)).encode()
    return {"domain": DOMAIN, "checkpoint_sha256": record_digest(CP),
            "run_id": 80000 + i, "custodian_pin": h("pin-" + str(i)),
            "acquisition_nonce_sha256": h("nonce-" + str(i)),
            "control_ancestry": {k: h(k + "-" + str(i)) for k in (
                "controller", "root", "source", "acquisition")},
            "artifact_base64": base64.b64encode(blob).decode(),
            "artifact_sha256": hashlib.sha256(blob).hexdigest(),
            "external_custody_verified": False, "release_authorized": False}

def pair():
    return [item(1), item(2)]

def run(rows=None):
    return audit(CP, pair() if rows is None else rows, DENIED, QUARANTINED)

class CrossRunEvidenceTests(unittest.TestCase):
    def rejected(self, rows):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            run(rows)
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_CROSS_RUN_CUSTODY_EVIDENCE")
    def test_valid_supplied_bytes_still_hold(self):
        result = run()
        self.assertEqual(result["status"], "HOLD_EXTERNAL_CUSTODY_NOT_AUTHENTICATED")
        self.assertTrue(result["locally_supplied_bytes_hash_verified"])
        for key in ("independent_external_custody_verified",
                    "github_run_provenance_authenticated", "recovery_authorized",
                    "release_authorized", "live_gameplay_authorized"):
            self.assertFalse(result[key])
    def test_deterministic_replay(self):
        self.assertEqual(run(), run())
    def test_single_observation(self):
        self.rejected([item(1)])
    def test_extra_observation(self):
        self.rejected([item(1), item(2), item(3)])
    def test_duplicate_run_id(self):
        rows = pair(); rows[1]["run_id"] = rows[0]["run_id"]
        self.rejected(rows)
    def test_duplicate_custodian(self):
        rows = pair(); rows[1]["custodian_pin"] = rows[0]["custodian_pin"]
        self.rejected(rows)
    def test_replayed_nonce(self):
        rows = pair(); rows[1]["acquisition_nonce_sha256"] = rows[0]["acquisition_nonce_sha256"]
        self.rejected(rows)
    def test_shared_controller(self):
        self.shared("controller")
    def test_shared_root(self):
        self.shared("root")
    def test_shared_source(self):
        self.shared("source")
    def test_shared_acquisition(self):
        self.shared("acquisition")
    def shared(self, key):
        rows = pair(); rows[1]["control_ancestry"][key] = rows[0]["control_ancestry"][key]
        self.rejected(rows)
    def test_altered_artifact_bytes(self):
        rows = pair(); rows[1]["artifact_base64"] = base64.b64encode(b"altered").decode()
        self.rejected(rows)
    def test_invalid_base64(self):
        rows = pair(); rows[1]["artifact_base64"] = "!not base64"
        self.rejected(rows)
    def test_empty_artifact(self):
        rows = pair(); rows[1]["artifact_base64"] = ""
        rows[1]["artifact_sha256"] = hashlib.sha256(b"").hexdigest()
        self.rejected(rows)
    def test_wrong_checkpoint(self):
        rows = pair(); rows[0]["checkpoint_sha256"] = h("forged")
        self.rejected(rows)
    def test_forged_release(self):
        rows = pair(); rows[0]["release_authorized"] = True
        self.rejected(rows)
    def test_forged_custody(self):
        rows = pair(); rows[0]["external_custody_verified"] = True
        self.rejected(rows)
    def test_missing_ancestry(self):
        rows = pair(); del rows[1]["control_ancestry"]["root"]
        self.rejected(rows)
    def test_history_digest_changes(self):
        a = run()
        b = audit(CP, pair(), DENIED + [{"deny": "another"}], QUARANTINED)
        self.assertNotEqual(a["denial_history_sha256"], b["denial_history_sha256"])

if __name__ == "__main__":
    unittest.main()
