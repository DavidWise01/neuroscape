import copy
import hashlib
import unittest
from test_century_archive_replay_rust101 import bundle
from http_archive_acquisition_rust103 import (
    acquisition, permitted, missing, SOURCE, BASELINE, HOLD, MAX_ARCHIVE)

def fixture():
    temporary, manifest, archives, _, _ = bundle()
    response = {"url": "https://codeload.github.com/DavidWise01/neuroscape/legacy.zip/" + BASELINE,
                "status": 200,
                "headers": {"Content-Length": str(len(archives[0])),
                            "Content-Type": "application/zip"},
                "body": archives[0]}
    return temporary, manifest, response

def fetch(response):
    def mock(url):
        if url != SOURCE:
            raise ValueError("source URL changed")
        return response
    return mock

class HTTPArchiveAcquisitionRUST103(unittest.TestCase):
    def case(self):
        t, m, r = fixture()
        self.addCleanup(t.cleanup)
        return m, r
    def rejected(self, edit):
        m, r = self.case()
        edit(m,r)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            acquisition(m, fetch(r))
    def test_missing_acquisition_stays_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_AUTHENTICATED_HTTP_ARCHIVE_BYTES")
    def test_exact_acquisition_records_hold(self):
        m,r = self.case()
        result, body = acquisition(m, fetch(r))
        self.assertEqual(result["status"], HOLD)
        self.assertEqual(body,r["body"])
        self.assertTrue(result["archive_bytes_locally_verified"])
        self.assertFalse(result["independent_external_custody_verified"])
        self.assertFalse(result["release_authorized"])
    def test_deterministic_replay(self):
        m,r=self.case()
        self.assertEqual(acquisition(m,fetch(r)),acquisition(m,fetch(r)))
    def test_github_api_url_accepted(self):
        self.assertEqual(permitted(SOURCE),"api.github.com")
    def test_codeload_url_accepted(self):
        _,r=self.case()
        self.assertEqual(permitted(r["url"]),"codeload.github.com")
    def test_arbitrary_redirect_host_refused(self):
        self.rejected(lambda m,r:r.update(url="https://example.net/fake.zip"))
    def test_unexpected_codeload_commit_refused(self):
        self.rejected(lambda m,r:r.update(
            url="https://codeload.github.com/DavidWise01/neuroscape/legacy.zip/deadbeef"))
    def test_http_url_refused(self):
        self.rejected(lambda m,r:r.update(url="http://api.github.com/a"))
    def test_embedded_credentials_refused(self):
        self.rejected(lambda m,r:r.update(
            url="https://u:p@codeload.github.com/DavidWise01/neuroscape/legacy.zip/"+BASELINE))
    def test_failed_http_status_refused(self):
        self.rejected(lambda m,r:r.update(status=404))
    def test_malformed_status_refused(self):
        self.rejected(lambda m,r:r.update(status="200"))
    def test_empty_body_refused(self):
        self.rejected(lambda m,r:r.update(body=b""))
    def test_oversized_body_refused(self):
        self.rejected(lambda m,r:r.update(body=b"a"*(MAX_ARCHIVE+1)))
    def test_content_length_mismatch_refused(self):
        self.rejected(lambda m,r:r["headers"].update({"Content-Length":"3"}))
    def test_bad_content_length_refused(self):
        self.rejected(lambda m,r:r["headers"].update({"Content-Length":"bad"}))
    def test_changed_archive_bytes_refused(self):
        self.rejected(lambda m,r:r.update(body=r["body"][:-4]+b"BAD!"))
    def test_changed_baseline_digest_refused(self):
        self.rejected(lambda m,r:m["source_entries"][0].update(sha256="f"*64))
    def test_missing_headers_refused(self):
        self.rejected(lambda m,r:r.update(headers=None))
    def test_absent_content_length_permitted(self):
        m,r=self.case()
        r["headers"].pop("Content-Length")
        self.assertEqual(acquisition(m,fetch(r))[0]["status"],HOLD)
    def test_no_mutation(self):
        m,r=self.case()
        snapshot=copy.deepcopy((m,r))
        acquisition(m,fetch(r))
        self.assertEqual((m,r),snapshot)

if __name__=="__main__":
    unittest.main()
