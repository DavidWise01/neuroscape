import copy
import unittest
from lineage_rust019 import digest
from witness_recovery_rust055 import audit, genesis, hold, checked_recovery_history
from witness_revocation_rust054 import audit as revoke_audit, genesis as revoked_genesis
from test_witness_revocation_rust054 import source, revoke, verify, h


def registry():
    return revoke_audit(source(), revoked_genesis(), [revoke()],
                        [h("authority")], verifier=verify)


def candidate(nonce="first", new=None, controller=None):
    return {
        "revoked_signer_pin": h("session-pin"),
        "candidate_signer_pin": new or h("successor-pin"),
        "claimed_controller_sha256": controller or h("session-control"),
        "candidate_source_root_sha256": h("new-root"),
        "candidate_acquisition_sha256": h("new-acquisition"),
        "external_authority_root_sha256": h("separate-authority-root"),
        "challenge_nonce_sha256": h("challenge-" + nonce),
        "incident_evidence_sha256": h("incident-" + nonce),
        "candidate_public_key": "candidate.pem",
        "candidate_signature": "candidate.sig",
        "authority_public_key": "authority.pem",
        "authority_signature": "authority.sig",
    }


def run(reg=None, history=None, item=None, auth=None, pin=None, floor=None, verifier=verify):
    item = item if item is not None else candidate()
    return audit(reg if reg is not None else registry(),
                 history if history is not None else genesis(), [item],
                 [pin or item["candidate_signer_pin"]],
                 [auth or h("authority-pin")], floor=floor, verifier=verifier)


class WitnessRecoveryTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_INDEPENDENT_RECOVERY_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_two_signatures_still_quarantined(self):
        out = run()
        self.assertEqual(out["event_count"], 1)
        self.assertTrue(out["events"][0]["quarantine_persists"])
        self.assertTrue(out["events"][0]["reuses_revoked_controller"])
        self.assertFalse(out["independent_custody_verified"])
        self.assertFalse(out["release_authorized"])

    def test_new_controller_still_no_authority(self):
        out = run(item=candidate(controller=h("other-controller")))
        self.assertFalse(out["events"][0]["reuses_revoked_controller"])
        self.assertFalse(out["events"][0]["recovery_authorized"])

    def test_reissued_revoked_key_denied(self):
        with self.assertRaisesRegex(ValueError, "already revoked"):
            run(item=candidate(new=h("session-pin")))

    def test_unknown_revoked_witness_denied(self):
        item = candidate()
        item["revoked_signer_pin"] = h("never-revoked")
        with self.assertRaisesRegex(ValueError, "not anchored"):
            run(item=item)

    def test_self_issued_recovery_denied(self):
        with self.assertRaisesRegex(ValueError, "self-issued"):
            run(auth=h("successor-pin"))

    def test_compromised_authority_denied(self):
        with self.assertRaisesRegex(ValueError, "self-issued"):
            run(auth=h("session-pin"))

    def test_recovery_authority_shared_controller_denied(self):
        item = candidate()
        item["external_authority_root_sha256"] = h("session-control")
        with self.assertRaisesRegex(ValueError, "inherits compromised"):
            run(item=item)

    def test_wrong_replacement_pin_denied(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            run(pin=h("different-key"))

    def test_invalid_candidate_signature_denied(self):
        def reject(*_args):
            raise ValueError("invalid signature")
        with self.assertRaisesRegex(ValueError, "invalid signature"):
            run(verifier=reject)

    def test_replayed_recovery_pair_denied(self):
        reg=registry()
        prior=run(reg=reg)
        with self.assertRaisesRegex(ValueError, "duplicate compromised-to-successor"):
            run(reg=reg, history=prior, item=candidate(nonce="second"))

    def test_replayed_recovery_nonce_denied(self):
        reg=registry()
        prior=run(reg=reg)
        with self.assertRaisesRegex(ValueError, "nonce replay"):
            run(reg=reg, history=prior, item=candidate(new=h("another-successor")))

    def test_prior_registry_forgery_denied(self):
        prior=run()
        prior["events"][0]["recovery_authorized"] = True
        with self.assertRaises(ValueError):
            checked_recovery_history(prior)

    def test_retained_floor_mismatch_denied(self):
        reg=registry()
        prior=run(reg=reg)
        with self.assertRaisesRegex(ValueError, "withheld or forked"):
            run(reg=reg,history=prior,
                item=candidate(nonce="new",new=h("second-successor")),
                floor={"phase":"RUST-055","event_count":1,
                       "head_sha256":h("false-head")})

    def test_genesis_floor_accepted_without_graduation(self):
        out=run(floor={"phase":"RUST-055","event_count":0,
                       "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(out["retained_floor_compared"])
        self.assertFalse(out["release_authorized"])

    def test_compromised_history_preserved(self):
        reg=registry()
        out=run(reg=reg)
        self.assertEqual(out["revoked_signer_pins_preserved"],
                         reg["revoked_signer_pins"])
        self.assertEqual(out["earlier_ancestry_conflicts_preserved"],
                         reg["conflicts"])


if __name__=="__main__":
    unittest.main()
