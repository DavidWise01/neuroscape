import base64
import copy
import json
import unittest

from persistent_anti_mirror_rust095 import (
    append, compare, validate, missing, ZERO, HOLD)
from test_anti_mirror_custody_rust094 import setup, put_bytes

def start():
    prior, witnesses = setup()
    first = append([], prior, witnesses)
    return first, prior, witnesses

class PersistentAntiMirrorRUST095(unittest.TestCase):
    def test_missing_hold(self):
        self.assertEqual(missing()["status"],
            "HOLD_MISSING_PERSISTENT_ANTI_MIRROR_QUARANTINE")
    def test_zero_head(self):
        self.assertEqual(validate([]), ZERO)
    def test_first_epoch(self):
        first, _, _ = start()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["previous_sha256"], ZERO)
    def test_two_epoch_stays_hold(self):
        first, p, w = start()
        second = append(first, p, w)
        report = compare(first, second)
        self.assertEqual(report["status"], HOLD)
        for key in ("independent_external_custody_verified",
                    "release_authorized","recovery_authorized",
                    "live_gameplay_authorized"):
            self.assertFalse(report[key])
    def test_deterministic_replay(self):
        self.assertEqual(start()[0],start()[0])
    def test_identical_reintroduction(self):
        first, p, w = start()
        second = append(first, p, w)
        self.assertIn("REINTRODUCED_IDENTICAL_BYTES",
                      second[-1]["cross_epoch_reasons"])
    def test_repackaged_json(self):
        first,p,w=start()
        put_bytes(w[0],b'{ "kind": "sample", "value" : 1 }')
        second=append(first,p,w)
        self.assertIn("REINTRODUCED_REPACKAGED_JSON",
                      second[-1]["cross_epoch_reasons"])
    def test_renamed_same_controller(self):
        first,p,w=start()
        for row in w:
            put_bytes(row,b'{"completely":"different","seq":1}')
            row["signer_pin"]="a"*64 if row is w[0] else "b"*64
            row["nonce_sha256"]="c"*64 if row is w[0] else "d"*64
        # receipt signer must remain bound, so change receipts too
        p["witness_receipts"][0]["signer_pin"]="a"*64
        p["witness_receipts"][1]["signer_pin"]="b"*64
        second=append(first,p,w)
        self.assertIn("REINTRODUCED_CONTROLLER_ANCESTRY",
                      second[-1]["cross_epoch_reasons"])
    def test_within_epoch_mirror_retained(self):
        first,p,w=start()
        raw=base64.b64decode(w[0]["evidence_base64"])
        put_bytes(w[1],raw)
        second=append(first,p,w)
        self.assertIn("IDENTICAL_BYTES",second[-1]["within_epoch_reasons"])
    def test_prior_prefix_exact(self):
        first,p,w=start()
        second=append(first,p,w)
        self.assertEqual(second[:len(first)],first)
    def test_no_extension_refused(self):
        first,_,_=start()
        with self.assertRaises(ValueError):
            compare(first,first)
    def test_rewritten_predecessor_refused(self):
        first,p,w=start()
        second=append(first,p,w)
        second[1]["previous_sha256"]="f"*64
        with self.assertRaises(ValueError):
            compare(first,second)
    def test_rewritten_historical_fingerprint_refused(self):
        first,p,w=start()
        second=append(first,p,w)
        second[0]["fingerprints"][0]["raw_sha256"]="e"*64
        with self.assertRaises(ValueError):
            compare(first,second)
    def test_erased_cross_epoch_quarantine_refused(self):
        first,p,w=start()
        second=append(first,p,w)
        second[-1]["cross_epoch_reasons"]=[]
        with self.assertRaises(ValueError):
            validate(second)
    def test_forged_release_refused(self):
        first,p,w=start()
        second=append(first,p,w)
        second[-1]["release_authorized"]=True
        with self.assertRaises(ValueError):
            validate(second)
    def test_removed_epoch_refused(self):
        first,p,w=start()
        second=append(first,p,w)
        with self.assertRaises(ValueError):
            compare(second,first)
    def test_prior_head_changes(self):
        first,p,w=start()
        second=append(first,p,w)
        result=compare(first,second)
        self.assertNotEqual(result["previous_head_sha256"],
                            result["head_sha256"])
    def test_new_anomalies_retained_on_later_epoch(self):
        first,p,w=start()
        second=append(first,p,w)
        third=append(second,p,w)
        self.assertTrue(compare(second,third)["quarantine_conflicts_retained"])
    def test_upstream_release_claim_refused(self):
        first,p,w=start()
        p["release_authorized"]=True
        with self.assertRaises(ValueError):
            append(first,p,w)

if __name__=="__main__":
    unittest.main()
