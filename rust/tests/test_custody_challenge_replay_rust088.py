import copy
import hashlib
import unittest

from lineage_rust019 import digest
from custody_challenge_fence_rust087 import fence, challenge_payload, HOLD

def h(v):
    return hashlib.sha256(v.encode("utf-8")).hexdigest()

CHECKPOINT = {"phase": "RUST-086",
              "kind": "CROSS_CUSTODIAN_QUARANTINE_HIGHWATER_V1",
              "head_sha256": h("historical-head")}
DENIALS = [{"deny": "release", "receipt": h("denial-0")}]
QUARANTINES = [{"pin": h("quarantined"), "reason": "shared ancestry"}]

def verify(key, signature, pin, message):
    if signature != "signed:" + pin:
        raise ValueError("signature mismatch")
    return h("signature-receipt:" + pin)

def make(i):
    pin = h("custodian-signing-pin-" + str(i))
    lineage = {name: h("owner-" + str(i) + "-" + name)
               for name in ("controller", "root", "source", "acquisition")}
    nonce = h("fresh-nonce-" + str(i))
    return {"signer_pin": pin, "nonce_sha256": nonce,
            "control_ancestry": lineage, "public_key": "mock-public-key",
            "signature": "signed:" + pin,
            "payload": challenge_payload(CHECKPOINT, nonce, pin, lineage)}

def run(challenges=None, denials=None, quarantines=None):
    return fence(CHECKPOINT, [make(1), make(2)] if challenges is None else challenges,
                 DENIALS if denials is None else denials,
                 QUARANTINES if quarantines is None else quarantines,
                 verifier=verify)

class CustodyChallengeReplayRUST088(unittest.TestCase):
    def assert_rejected(self, challenges):
        with self.assertRaises((ValueError, AssertionError, TypeError, KeyError)):
            run(challenges)
    def test_two_submitted_signatures_still_hold(self):
        result = run()
        self.assertEqual(result["status"], HOLD)
        self.assertFalse(result["independent_external_custody_verified"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["recovery_authorized"])
        self.assertFalse(result["live_gameplay_authorized"])
    def test_replay_identical_output(self):
        self.assertEqual(run(), run())
    def test_retention_digests_stable(self):
        self.assertEqual(run()["denial_retention_sha256"], digest(DENIALS))
        self.assertEqual(run()["quarantine_retention_sha256"], digest(QUARANTINES))
    def test_missing_challenge(self):
        self.assert_rejected([make(1)])
    def test_extra_challenge(self):
        self.assert_rejected([make(1), make(2), make(3)])
    def test_replayed_signer(self):
        self.assert_rejected([make(1), make(1)])
    def test_replayed_nonce(self):
        a, b = make(1), make(2)
        b["nonce_sha256"] = a["nonce_sha256"]
        b["payload"] = challenge_payload(CHECKPOINT, b["nonce_sha256"],
                                         b["signer_pin"], b["control_ancestry"])
        self.assert_rejected([a, b])
    def test_shared_controller_ancestry(self):
        self._shared("controller")
    def test_shared_root_ancestry(self):
        self._shared("root")
    def test_shared_source_ancestry(self):
        self._shared("source")
    def test_shared_acquisition_ancestry(self):
        self._shared("acquisition")
    def _shared(self, field):
        a, b = make(1), make(2)
        b["control_ancestry"][field] = a["control_ancestry"][field]
        b["payload"] = challenge_payload(CHECKPOINT, b["nonce_sha256"],
                                         b["signer_pin"], b["control_ancestry"])
        self.assert_rejected([a, b])
    def test_missing_fingerprint(self):
        a, b = make(1), make(2)
        del b["control_ancestry"]["root"]
        self.assert_rejected([a, b])
    def test_payload_substitution(self):
        a, b = make(1), make(2)
        b["payload"]["highwater_sha256"] = h("other-highwater")
        self.assert_rejected([a, b])
    def test_forged_release(self):
        a, b = make(1), make(2)
        b["payload"]["release_authorized"] = True
        self.assert_rejected([a, b])
    def test_forged_independence(self):
        a, b = make(1), make(2)
        b["payload"]["custody_independence_verified"] = True
        self.assert_rejected([a, b])
    def test_invalid_signature(self):
        a, b = make(1), make(2)
        b["signature"] = "bad-signature"
        self.assert_rejected([a, b])
    def test_missing_retention_lists(self):
        with self.assertRaises((ValueError, AssertionError, TypeError)):
            run(denials=None if False else "not-a-list")
    def test_retention_changes_are_observable(self):
        self.assertNotEqual(run()["denial_retention_sha256"],
                            run(denials=DENIALS + [{"deny": "new"}])["denial_retention_sha256"])
    def test_checkpoint_domain_fence(self):
        with self.assertRaises((ValueError, AssertionError, TypeError)):
            challenge_payload({"phase": "RUST-085"}, h("nonce"), h("pin"),
                              make(1)["control_ancestry"])

if __name__ == "__main__":
    unittest.main()
