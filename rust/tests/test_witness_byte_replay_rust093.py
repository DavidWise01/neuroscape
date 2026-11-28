import base64
import copy
import hashlib
import unittest
from witness_byte_replay_rust093 import check, missing, DOMAIN, HOLD

def h(value):
    return hashlib.sha256(value.encode()).hexdigest()

def fixture():
    receipts = [{"signer_pin": h("pin"+str(i)),
                 "signed_payload_sha256": h("payload"+str(i))}
                for i in (1, 2)]
    prior = {"phase": "RUST-092",
             "status": "HOLD_INDEPENDENT_CONTRADICTION_CUSTODY_UNVERIFIED",
             "ledger_head_sha256": h("head"),
             "retained_contradictions_sha256": h("conflicts"),
             "witness_receipts": receipts,
             "independent_external_custody_verified": False,
             "release_authorized": False}
    rows = []
    for i, receipt in enumerate(receipts, 1):
        blob = ("distinct signed observation " + str(i)).encode()
        rows.append({"domain": DOMAIN, "signer_pin": receipt["signer_pin"],
            "signed_payload_sha256": receipt["signed_payload_sha256"],
            "nonce_sha256": h("nonce"+str(i)),
            "ledger_head_sha256": prior["ledger_head_sha256"],
            "contradictions_sha256": prior["retained_contradictions_sha256"],
            "control_ancestry": {k: h(k+str(i))
                for k in ("controller","root","source","acquisition")},
            "evidence_sha256": hashlib.sha256(blob).hexdigest(),
            "evidence_base64": base64.b64encode(blob).decode(),
            "independent_external_custody_verified": False,
            "release_authorized": False})
    return prior, rows

class WitnessByteReplayRUST093(unittest.TestCase):
    def reject(self, mutate):
        p, rows = fixture()
        mutate(p, rows)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            check(p, rows)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"], "HOLD_MISSING_EXTERNAL_WITNESS_BYTES")
    def test_valid_local_bytes_still_hold(self):
        p, rows = fixture()
        result = check(p, rows)
        self.assertEqual(result["status"], HOLD)
        self.assertTrue(result["submitted_byte_digests_verified"])
        self.assertFalse(result["independent_external_custody_verified"])
        self.assertFalse(result["release_authorized"])
    def test_deterministic_replay(self):
        p, rows = fixture()
        self.assertEqual(check(p, rows), check(p, rows))
    def test_missing_witness(self):
        self.reject(lambda p,r: r.pop())
    def test_reversed_witness(self):
        self.reject(lambda p,r: r.reverse())
    def test_replayed_signer(self):
        self.reject(lambda p,r: r[1].update(signer_pin=r[0]["signer_pin"]))
    def test_replayed_nonce(self):
        self.reject(lambda p,r: r[1].update(nonce_sha256=r[0]["nonce_sha256"]))
    def test_reused_bytes(self):
        self.reject(lambda p,r: r[1].update(evidence_sha256=r[0]["evidence_sha256"],
                                            evidence_base64=r[0]["evidence_base64"]))
    def test_modified_bytes(self):
        self.reject(lambda p,r: r[1].update(
            evidence_base64=base64.b64encode(b"altered").decode()))
    def test_invalid_base64(self):
        self.reject(lambda p,r: r[0].update(evidence_base64="!bad!"))
    def test_shared_controller(self):
        self.shared("controller")
    def test_shared_root(self):
        self.shared("root")
    def test_shared_source(self):
        self.shared("source")
    def test_shared_acquisition(self):
        self.shared("acquisition")
    def shared(self, field):
        self.reject(lambda p,r: r[1]["control_ancestry"].update(
            {field: r[0]["control_ancestry"][field]}))
    def test_wrong_head(self):
        self.reject(lambda p,r: r[1].update(ledger_head_sha256=h("other")))
    def test_contradiction_digest_replaced(self):
        self.reject(lambda p,r: r[1].update(contradictions_sha256=h("other")))
    def test_fake_release(self):
        self.reject(lambda p,r: r[1].update(release_authorized=True))
    def test_fake_custody(self):
        self.reject(lambda p,r: r[0].update(independent_external_custody_verified=True))
    def test_prior_custody_promoted(self):
        self.reject(lambda p,r: p.update(independent_external_custody_verified=True))
    def test_payload_substituted(self):
        self.reject(lambda p,r: r[1].update(signed_payload_sha256=h("fake")))

if __name__ == "__main__":
    unittest.main()
