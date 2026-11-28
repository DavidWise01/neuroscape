import copy
import hashlib
import unittest
from test_century_archive_replay_rust101 import bundle
from archive_acquisition_receipts_rust102 import (
    verify_receipts, missing, HOLD, DOMAIN)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def sample():
    temp, manifest, archives, _, _ = bundle()
    receipts = []
    for i, data in enumerate(archives):
        receipts.append({
            "phase": "RUST-102", "domain": DOMAIN,
            "method": "GET", "http_status": 200,
            "content_type": "application/zip",
            "content_length": len(data),
            "archive_sha256": sha(data),
            "response_sha256": sha(data),
            "source_url": "https://origin%d.example/archives/source.zip" % i,
            "retrieval_id": "retrieval-%d" % i,
            "ancestry": {k: sha((k+str(i)).encode()) for k in
                         ("controller", "root", "source", "acquisition")},
            "independent_custody_verified": False,
            "release_authorized": False})
    return temp, manifest, archives, receipts

class ArchiveAcquisitionReceiptsRUST102(unittest.TestCase):
    def entry(self):
        tmp, manifest, archives, receipts = sample()
        self.addCleanup(tmp.cleanup)
        return manifest, archives, receipts
    def reject(self, mutation):
        m, a, r = self.entry()
        mutation(m,a,r)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            verify_receipts(m,a,r)
    def test_missing_fails_closed(self):
        self.assertEqual(missing()["status"],
            "HOLD_MISSING_EXTERNAL_ARCHIVE_ACQUISITION_RECEIPTS")
    def test_two_receipts_still_hold(self):
        m,a,r=self.entry(); result=verify_receipts(m,a,r)
        self.assertEqual(result["status"],HOLD)
        self.assertTrue(result["snapshot_byte_parity"])
        self.assertFalse(result["external_custody_independence_verified"])
        self.assertFalse(result["release_authorized"])
    def test_deterministic_replay(self):
        m,a,r=self.entry()
        self.assertEqual(verify_receipts(m,a,r),verify_receipts(m,a,r))
    def test_same_origin_is_conflict(self):
        m,a,r=self.entry()
        r[1]["source_url"]=r[0]["source_url"]
        self.assertIn("SAME_DECLARED_ORIGIN_HOST",
                      verify_receipts(m,a,r)["provenance_conflicts"])
    def test_same_retrieval_id_is_conflict(self):
        m,a,r=self.entry()
        r[1]["retrieval_id"]=r[0]["retrieval_id"]
        self.assertIn("REUSED_RETRIEVAL_ID",
                      verify_receipts(m,a,r)["provenance_conflicts"])
    def test_shared_root_is_conflict(self):
        m,a,r=self.entry()
        r[1]["ancestry"]["root"]=r[0]["ancestry"]["root"]
        self.assertIn("SHARED_ROOT_ANCESTRY",
                      verify_receipts(m,a,r)["provenance_conflicts"])
    def test_bytes_replaced_rejected(self):
        self.reject(lambda m,a,r: a.__setitem__(1,b"not an archive"))
    def test_archive_digest_forgery_rejected(self):
        self.reject(lambda m,a,r:r[1].update(archive_sha256="f"*64))
    def test_response_digest_conflict_rejected(self):
        self.reject(lambda m,a,r:r[1].update(response_sha256="f"*64))
    def test_response_length_mismatch_rejected(self):
        self.reject(lambda m,a,r:r[1].update(content_length=1))
    def test_missing_second_receipt_rejected(self):
        self.reject(lambda m,a,r:r.pop())
    def test_http_failure_rejected(self):
        self.reject(lambda m,a,r:r[0].update(http_status=404))
    def test_non_https_rejected(self):
        self.reject(lambda m,a,r:r[0].update(source_url="http://origin.example/x"))
    def test_embedded_credentials_rejected(self):
        self.reject(lambda m,a,r:r[0].update(source_url="https://u:p@origin.example/x"))
    def test_wrong_content_type_rejected(self):
        self.reject(lambda m,a,r:r[0].update(content_type="text/html"))
    def test_missing_ancestry_rejected(self):
        self.reject(lambda m,a,r:r[0]["ancestry"].pop("source"))
    def test_claimed_custody_promoted_rejected(self):
        self.reject(lambda m,a,r:r[1].update(independent_custody_verified=True))
    def test_claimed_release_rejected(self):
        self.reject(lambda m,a,r:r[1].update(release_authorized=True))
    def test_no_mutation(self):
        m,a,r=self.entry()
        frozen=copy.deepcopy((m,a,r))
        verify_receipts(m,a,r)
        self.assertEqual((m,a,r),frozen)
    def test_distinct_hosts_not_verified_as_independent(self):
        m,a,r=self.entry()
        result=verify_receipts(m,a,r)
        self.assertFalse(result["source_urls_independently_authenticated"])

if __name__=="__main__":
    unittest.main()
