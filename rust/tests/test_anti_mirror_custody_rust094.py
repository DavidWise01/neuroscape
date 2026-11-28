import base64
import copy
import hashlib
import json
import unittest

from anti_mirror_custody_rust094 import analyze, canonical_evidence, missing, HOLD, DOMAIN

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def setup():
    receipts = [{"signer_pin": h("pin"+str(i)),
                 "signed_payload_sha256": h("signed"+str(i))}
                for i in (1, 2)]
    prior = {"phase": "RUST-092",
             "status": "HOLD_INDEPENDENT_CONTRADICTION_CUSTODY_UNVERIFIED",
             "ledger_head_sha256": h("head"),
             "retained_contradictions_sha256": h("contradictions"),
             "witness_receipts": receipts,
             "independent_external_custody_verified": False,
             "release_authorized": False}
    rows = []
    for i, receipt in enumerate(receipts, 1):
        raw = json.dumps({"value": i, "kind":"sample"},sort_keys=True).encode()
        rows.append({
            "domain": "NEUROSCAPE_RUST093_WITNESS_BYTE_REPLAY_V1",
            "signer_pin": receipt["signer_pin"],
            "signed_payload_sha256": receipt["signed_payload_sha256"],
            "nonce_sha256": h("nonce"+str(i)),
            "ledger_head_sha256": prior["ledger_head_sha256"],
            "contradictions_sha256": prior["retained_contradictions_sha256"],
            "control_ancestry": {k: h(k+str(i)) for k in
                ("controller", "root", "source", "acquisition")},
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_base64": base64.b64encode(raw).decode(),
            "independent_external_custody_verified": False,
            "release_authorized": False})
    return prior, rows

def put_bytes(row, data):
    row["evidence_base64"] = base64.b64encode(data).decode()
    row["evidence_sha256"] = hashlib.sha256(data).hexdigest()

class AntiMirrorRUST094(unittest.TestCase):
    def rejected(self, modify):
        p, rows = setup()
        modify(p, rows)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            analyze(p, rows)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"], "HOLD_MISSING_ANTI_MIRROR_BYTES")
    def test_distinct_evidence_still_hold(self):
        p, rows = setup()
        result = analyze(p, rows)
        self.assertEqual(result["status"], HOLD)
        self.assertFalse(result["independent_external_custody_verified"])
        self.assertEqual(result["new_mirror_conflict_count"], 0)
    def test_exact_bytes_mirror_quarantined(self):
        p, rows = setup()
        data = base64.b64decode(rows[0]["evidence_base64"])
        put_bytes(rows[1],data)
        result = analyze(p,rows)
        self.assertIn("IDENTICAL_BYTES", result["quarantine_log"][0]["reasons"])
    def test_json_repackaging_quarantined(self):
        p, rows = setup()
        put_bytes(rows[1], b'{ "kind" : "sample", "value": 1 }')
        result=analyze(p,rows)
        self.assertIn("EQUIVALENT_JSON_CONTENT",
                      result["quarantine_log"][0]["reasons"])
        self.assertNotIn("IDENTICAL_BYTES",
                         result["quarantine_log"][0]["reasons"])
    def test_shared_controller_quarantined(self):
        self.shared("controller")
    def test_shared_root_quarantined(self):
        self.shared("root")
    def test_shared_source_quarantined(self):
        self.shared("source")
    def test_shared_acquisition_quarantined(self):
        self.shared("acquisition")
    def shared(self, field):
        p, rows = setup()
        rows[1]["control_ancestry"][field] = rows[0]["control_ancestry"][field]
        result = analyze(p, rows)
        self.assertIn("SHARED_"+field.upper()+"_ANCESTRY",
                      result["quarantine_log"][0]["reasons"])
    def test_same_custodian_quarantined(self):
        p,rows=setup()
        for row in rows:row["acquisition_custodian_id"]="same"
        self.assertIn("SAME_DECLARED_CUSTODIAN",
                      analyze(p,rows)["quarantine_log"][0]["reasons"])
    def test_prior_quarantine_retained(self):
        p,rows=setup()
        previous=[{"phase":"RUST-094","status":"QUARANTINED",
                   "reasons":["PRIOR_CONFLICT"]}]
        result=analyze(p,rows,previous)
        self.assertEqual(result["quarantine_log"],previous)
        self.assertEqual(previous[0]["reasons"],["PRIOR_CONFLICT"])
    def test_replay_deterministic(self):
        p,rows=setup()
        self.assertEqual(analyze(p,rows),analyze(p,rows))
    def test_modified_bytes_rejected(self):
        self.rejected(lambda p,r:r[1].update(evidence_base64=base64.b64encode(b"tamper").decode()))
    def test_forged_release_rejected(self):
        self.rejected(lambda p,r:r[1].update(release_authorized=True))
    def test_wrong_ledger_rejected(self):
        self.rejected(lambda p,r:r[1].update(ledger_head_sha256=h("other")))
    def test_duplicate_nonce_rejected(self):
        self.rejected(lambda p,r:r[1].update(nonce_sha256=r[0]["nonce_sha256"]))
    def test_invalid_prior_quarantine_rejected(self):
        p,rows=setup()
        with self.assertRaises(ValueError):
            analyze(p,rows,[{"phase":"RUST-094","status":"CLEARED","reasons":[]}])
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):
            canonical_evidence(b'{"a":1,"a":2}')
    def test_non_json_evidence_not_semantically_equal(self):
        self.assertIsNone(canonical_evidence(b"binary-content"))
    def test_prior_authority_promotion_rejected(self):
        self.rejected(lambda p,r:p.update(release_authorized=True))

if __name__ == "__main__":
    unittest.main()
