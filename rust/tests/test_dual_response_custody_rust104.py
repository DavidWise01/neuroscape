import copy
import hashlib
import unittest

from century_source_freeze_rust100 import canonical
from test_century_archive_replay_rust101 import bundle
from http_archive_acquisition_rust103 import acquisition, SOURCE, BASELINE
from dual_response_custody_rust104 import assess, missing, HOLD, digest

def h(text):
    return hashlib.sha256(text.encode()).hexdigest()

def fixture():
    temporary, manifest, archives, _, _ = bundle()
    reports = []
    for i, archive in enumerate(archives):
        def fetch(_url, archive=archive):
            return {
                "url": "https://codeload.github.com/DavidWise01/neuroscape/legacy.zip/" + BASELINE,
                "status": 200,
                "headers": {"Content-Length": str(len(archive))},
                "body": archive,
            }
        report, observed = acquisition(manifest, fetch)
        assert observed == archive
        reports.append(report)
    claims = []
    for i, report in enumerate(reports):
        claims.append({
            "operator_pin": h("operator-"+str(i)),
            "acquisition_nonce_sha256": h("nonce-"+str(i)),
            "source_receipt_sha256": digest(report),
            "ancestry": {k: h(k+"-"+str(i)) for k in
                         ("controller","operator","root","network","acquisition")},
            "independent_custody_verified": False,
            "release_authorized": False, "fork_selected": False,
        })
    return temporary, manifest, reports, archives, claims

class DualResponseCustodyRUST104(unittest.TestCase):
    def case(self):
        t, m, r, b, c = fixture()
        self.addCleanup(t.cleanup)
        return m,r,b,c
    def rejected(self, mutation):
        m,r,b,c = self.case()
        mutation(m,r,b,c)
        with self.assertRaises((ValueError,KeyError,TypeError)):
            assess(m,r,b,c)
    def test_missing_is_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_DUAL_HTTP_RESPONSE_CUSTODY")
    def test_distinct_operator_claims_still_hold(self):
        m,r,b,c=self.case()
        result=assess(m,r,b,c)
        self.assertEqual(result["status"],HOLD)
        self.assertTrue(result["source_bytes_parity"])
        self.assertEqual(result["observed_independent_source_ancestries"],1)
        self.assertFalse(result["independent_external_custody_verified"])
        self.assertFalse(result["release_authorized"])
    def test_github_common_ancestry_is_recorded(self):
        m,r,b,c=self.case()
        self.assertIn("SHARED_GITHUB_SOURCE_ANCESTRY",
                      assess(m,r,b,c)["correlation_reasons"])
    def test_deterministic_replay(self):
        m,r,b,c=self.case()
        self.assertEqual(assess(m,r,b,c),assess(m,r,b,c))
    def test_identical_archive_detected(self):
        m,r,b,c=self.case()
        b[1]=b[0]
        r[1]=copy.deepcopy(r[0])
        c[1]["source_receipt_sha256"]=digest(r[1])
        result=assess(m,r,b,c)
        self.assertIn("IDENTICAL_ARCHIVE_BYTES",result["correlation_reasons"])
    def test_same_operator_pin_detected(self):
        m,r,b,c=self.case()
        c[1]["operator_pin"]=c[0]["operator_pin"]
        self.assertIn("REUSED_OPERATOR_PIN",assess(m,r,b,c)["correlation_reasons"])
    def test_same_nonce_detected(self):
        m,r,b,c=self.case()
        c[1]["acquisition_nonce_sha256"]=c[0]["acquisition_nonce_sha256"]
        self.assertIn("REUSED_ACQUISITION_NONCE",assess(m,r,b,c)["correlation_reasons"])
    def test_shared_controller_detected(self):
        self.shared("controller")
    def test_shared_root_detected(self):
        self.shared("root")
    def test_shared_network_detected(self):
        self.shared("network")
    def test_shared_acquisition_detected(self):
        self.shared("acquisition")
    def shared(self, field):
        m,r,b,c=self.case()
        c[1]["ancestry"][field]=c[0]["ancestry"][field]
        result=assess(m,r,b,c)
        self.assertIn("SHARED_"+field.upper()+"_ANCESTRY",
                      result["correlation_reasons"])
        self.assertFalse(result["independent_operator_control_authenticated"])
    def test_altered_zip_rejected(self):
        self.rejected(lambda m,r,b,c:b.__setitem__(0,b[0][:-1]+b"?"))
    def test_forged_archive_digest_rejected(self):
        self.rejected(lambda m,r,b,c:r[0].update(archive_sha256="f"*64))
    def test_forged_source_parity_rejected(self):
        self.rejected(lambda m,r,b,c:r[0].update(frozen_source_sha256="f"*64))
    def test_forged_custody_rejected(self):
        self.rejected(lambda m,r,b,c:c[0].update(independent_custody_verified=True))
    def test_release_authority_rejected(self):
        self.rejected(lambda m,r,b,c:c[1].update(release_authorized=True))
    def test_report_rebinding_rejected(self):
        self.rejected(lambda m,r,b,c:c[0].update(source_receipt_sha256="f"*64))
    def test_missing_second_record_rejected(self):
        self.rejected(lambda m,r,b,c:r.pop())
    def test_missing_network_ancestry_rejected(self):
        self.rejected(lambda m,r,b,c:c[0]["ancestry"].pop("network"))
    def test_upstream_authority_rejected(self):
        self.rejected(lambda m,r,b,c:r[0].update(release_authorized=True))
    def test_no_input_mutation(self):
        m,r,b,c=self.case()
        before=copy.deepcopy((m,r,b,c))
        assess(m,r,b,c)
        self.assertEqual((m,r,b,c),before)

if __name__ == "__main__":
    unittest.main()
