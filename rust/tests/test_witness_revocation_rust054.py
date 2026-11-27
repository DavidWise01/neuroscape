import copy
import unittest

from lineage_rust019 import digest
from witness_revocation_rust054 import audit, genesis, hold, checked_history
from test_challenge_highwater_rust053 import (
    histories, floor, session, verify, h)
from challenge_highwater_rust053 import audit as source_audit, highwater


def source(tag="first", pin=None, controller=None):
    old, current = histories()
    s = session(tag)
    if controller:
        s["operator_control_sha256"] = controller
    key = pin or h("session-pin")
    return source_audit(
        old, current, highwater(old), "checkpoint.pem",
        "checkpoint.sig", h("checkpoint-pin"), floor(old),
        [s], [key], verifier=verify)


def revoke(pin=None, controller=None, nonce="one"):
    return {
        "compromised_pin": pin or h("session-pin"),
        "claimed_controller_sha256": controller or h("session-control"),
        "incident_evidence_sha256": h("incident-" + nonce),
        "nonce_sha256": h("revoke-" + nonce),
        "authority_public_key": "independent.pem",
        "authority_signature": "independent.sig",
    }


def fresh_source(label):
    x = source(label)
    return x


class WitnessRevocationTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_WITNESS_REVOCATION_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_first_signed_revocation_remains_hold(self):
        out = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        self.assertEqual(out["event_count"], 1)
        self.assertEqual(len(out["revoked_signer_pins"]), 1)
        self.assertFalse(out["independent_custody_verified"])
        self.assertFalse(out["release_authorized"])

    def test_revoked_signer_reappearance_persistently_flagged(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        next_ = audit(fresh_source("next"), first, [], [], verifier=verify)
        self.assertTrue(any(c["kind"] == "REVOKED_CONTROLLER_REAPPEARANCE"
                            for c in next_["conflicts"]))
        self.assertEqual(next_["revoked_signer_pins"], first["revoked_signer_pins"])

    def test_replacement_key_with_same_controller_flagged(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        next_ = audit(source("replacement", pin=h("replacement-pin")), first, [], [],
                      verifier=verify)
        self.assertEqual(next_["conflicts"][-1]["kind"],
                         "REVOKED_CONTROLLER_REAPPEARANCE")
        self.assertFalse(next_["fork_resolved"])

    def test_replacement_key_new_controller_still_hold(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        next_ = audit(source("clean", pin=h("replacement-pin"),
                             controller=h("different-controller")),
                      first, [], [], verifier=verify)
        self.assertFalse(next_["release_authorized"])
        self.assertFalse(next_["independent_custody_verified"])

    def test_same_revoked_key_cannot_be_revoked_twice(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        with self.assertRaisesRegex(ValueError, "already revoked"):
            audit(source("next"), first, [revoke(nonce="two")],
                  [h("authority")], verifier=verify)

    def test_self_issued_revocation_rejected(self):
        with self.assertRaisesRegex(ValueError, "self-issued"):
            audit(source(), genesis(), [revoke()], [h("session-pin")],
                  verifier=verify)

    def test_revoked_authority_rejected(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        with self.assertRaisesRegex(ValueError, "self-issued"):
            audit(source("next"), first, [revoke(h("other-pin"), nonce="other")],
                  [h("session-pin")], verifier=verify)

    def test_invalid_signature_fails_closed(self):
        def reject(*_args):
            raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            audit(source(), genesis(), [revoke()], [h("authority")],
                  verifier=reject)

    def test_tampered_prior_revocation_rejected(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        first["events"][0]["revocations"][0]["compromised_pin"] = h("forged")
        with self.assertRaises(ValueError):
            checked_history(first)

    def test_prior_revocation_erasure_rejected(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        first["revoked_signer_pins"] = []
        first["receipt_sha256"] = digest({k:v for k,v in first.items()
                                         if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "erased"):
            checked_history(first)

    def test_external_floor_mismatch_rejected(self):
        first = audit(source(), genesis(), [revoke()], [h("authority")], verifier=verify)
        with self.assertRaisesRegex(ValueError, "rewritten"):
            audit(source("next"), first, [], [],
                  {"phase":"RUST-054", "event_count":1,
                   "head_sha256":h("false-floor")}, verifier=verify)

    def test_source_authority_escalation_rejected(self):
        forged = source()
        forged["fork_resolved"] = True
        forged["receipt_sha256"] = digest({
            k:v for k,v in forged.items() if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "source claims authority"):
            audit(forged, genesis(), [], [], verifier=verify)

    def test_source_replay_rejected(self):
        old = source()
        first = audit(old, genesis(), [], [], verifier=verify)
        with self.assertRaisesRegex(ValueError, "source session replay"):
            audit(old, first, [], [], verifier=verify)

    def test_genesis_floor_matches(self):
        first = audit(source(), genesis(), [], [],
                      {"phase":"RUST-054", "event_count":0,
                       "head_sha256":genesis()["head_sha256"]}, verifier=verify)
        self.assertTrue(first["retained_floor_compared"])


if __name__=="__main__":
    unittest.main()
