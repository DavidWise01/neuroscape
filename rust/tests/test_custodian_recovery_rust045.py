import copy
import unittest

from lineage_rust019 import digest
from custodian_recovery_rust045 import audit, hold
from test_attestor_revocation_rust044 import fixture, revocation, fake, h
from attestor_revocation_rust044 import audit as revocation_audit


def sample():
    ledger, rotation = fixture()
    prior = revocation_audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)
    floor = {"phase": "RUST-044", "entry_count": 1,
             "head_sha256": prior["revocation_head_sha256"]}
    claim = {
        "role": "ff",
        "revoked_attestor_spki_sha256": h(1),
        "replacement_attestor_spki_sha256": h(8),
        "recovery_authority_root_sha256": h(10),
        "independent_acquisition_sha256": h(11),
        "challenge_nonce_sha256": h(15),
        "recovery_public_key": "external.pub",
        "recovery_signature": "external.sig",
        "successor_public_key": "successor.pub",
        "successor_signature": "successor.sig",
    }
    return ledger, prior, claim, floor


class CustodianRecoveryTests(unittest.TestCase):
    def test_no_material_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_INDEPENDENT_RECOVERY")
        self.assertFalse(hold()["release_authorized"])

    def test_dual_signed_recovery_still_quarantined(self):
        ledger, report, claim, floor = sample()
        calls = []
        def witness(*args):
            calls.append(args)
            return h(15)
        out = audit(report, ledger, [claim], [h(12)], floor, verifier=witness)
        self.assertEqual(len(calls), 2)
        self.assertEqual(out["status"], "HOLD_QUARANTINED_RECOVERY_CANDIDATES")
        self.assertEqual(len(out["recovery_candidates"]), 1)
        self.assertFalse(out["real_world_independent_recovery_verified"])
        self.assertFalse(out["release_authorized"])
        self.assertTrue(out["revoked_key_history_retained"])

    def test_revoked_attestor_cannot_self_recover(self):
        ledger, report, claim, floor = sample()
        claim["replacement_attestor_spki_sha256"] = h(1)
        with self.assertRaises(ValueError):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_revoked_or_successor_authority_key_rejected(self):
        ledger, report, claim, floor = sample()
        for pin in (h(1), h(8)):
            with self.assertRaisesRegex(ValueError, "self-issued or revoked"):
                audit(report, ledger, [claim], [pin], floor, verifier=fake)

    def test_same_root_as_compromised_attestor_rejected(self):
        ledger, report, claim, floor = sample()
        ledger["entries"][3]["external_attestor_root_sha256"] = h(4)
        with self.assertRaises(ValueError):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_recovery_authority_same_as_compromised_root_rejected(self):
        ledger, report, claim, floor = sample()
        claim["recovery_authority_root_sha256"] = h(4)
        with self.assertRaisesRegex(ValueError, "root matches|inherits revoked"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_external_floor_mismatch_rejected(self):
        ledger, report, claim, floor = sample()
        floor["head_sha256"] = h(0)
        with self.assertRaisesRegex(ValueError, "contradicts"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_incomplete_floor_rejected(self):
        ledger, report, claim, floor = sample()
        floor["entry_count"] = 0
        with self.assertRaisesRegex(ValueError, "all known"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_unknown_or_unrevoked_recovery_rejected(self):
        ledger, report, claim, floor = sample()
        claim["revoked_attestor_spki_sha256"] = h(2)
        with self.assertRaisesRegex(ValueError, "unrevoked"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_missing_successor_challenge_rejected(self):
        ledger, report, claim, floor = sample()
        claim["replacement_attestor_spki_sha256"] = h(3)
        with self.assertRaisesRegex(ValueError, "replacement lacks later"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_recovery_nonce_replay_rejected(self):
        ledger, report, claim, floor = sample()
        claim["challenge_nonce_sha256"] = ledger["entries"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError, "nonce replay"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)

    def test_false_recovery_signature_rejected(self):
        ledger, report, claim, floor = sample()
        def reject(*args):
            raise ValueError("invalid external signature")
        with self.assertRaises(ValueError):
            audit(report, ledger, [claim], [h(12)], floor, verifier=reject)

    def test_forged_revocation_receipt_rejected(self):
        ledger, report, claim, floor = sample()
        report["revocation_events"][0]["effective_epoch"] = 999
        with self.assertRaisesRegex(ValueError, "receipt modified"):
            audit(report, ledger, [claim], [h(12)], floor, verifier=fake)


if __name__ == "__main__":
    unittest.main()
