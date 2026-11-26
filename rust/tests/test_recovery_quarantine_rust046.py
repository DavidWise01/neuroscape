import copy
import hashlib
import unittest

from lineage_rust019 import digest
from recovery_quarantine_rust046 import audit, hold
from test_custodian_recovery_rust045 import sample
from custodian_recovery_rust045 import audit as recovery_audit
from attestor_revocation_rust044 import audit as revocation_audit
from test_attestor_revocation_rust044 import revocation, fake, h


def fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_bundle():
    previous_ledger, old_revocation, proposal, old_floor = sample()
    recovery = recovery_audit(old_revocation, previous_ledger, [proposal], [h(12)],
                              old_floor, verifier=fake)
    ledger = copy.deepcopy(previous_ledger)
    for role in ("ff", "cf", "rr"):
        old = next(x for x in reversed(ledger["entries"]) if x["role"] == role)
        entry = copy.deepcopy(old)
        entry["ordinal"] = len(ledger["entries"]) + 1
        entry["epoch"] = previous_ledger["epoch"] + 1
        entry["previous_entry_sha256"] = ledger["prefix_heads"][-1]
        entry["nonce_sha256"] = fingerprint("r046-nonce-" + role)
        entry["retrieval_session_sha256"] = fingerprint("r046-session-" + role)
        entry["entry_sha256"] = digest({k: v for k, v in entry.items()
                                          if k != "entry_sha256"})
        ledger["entries"].append(entry)
        ledger["prefix_heads"].append(entry["entry_sha256"])
    ledger["epoch"] += 1
    ledger["head_sha256"] = ledger["prefix_heads"][-1]
    ledger["new_epoch_entries"] = ledger["entries"][-3:]
    ledger["receipt_sha256"] = digest({k: v for k, v in ledger.items()
                                       if k != "receipt_sha256"})
    # RUST-044 only uses this RUST-043 signature receipt to validate lineage
    # structurally; no new externally authenticated event is fabricated.
    rotation = {
        "phase": "RUST-043",
        "status": "HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED",
        "current_rust042_receipt_sha256": ledger["receipt_sha256"],
        "verified_rotation_signatures": [],
        "historical_prefix_preserved": True,
        "release_authorized": False,
        "fork_resolved": False,
        "preserved_attestor_conflicts": [{"role": "ff", "reason": "OLD_CONFLICT"}],
    }
    rotation["receipt_sha256"] = digest(rotation)
    current_revocation = revocation_audit(
        ledger, rotation, [revocation()], [h(6)], verifier=fake)
    floor = {"phase": "RUST-044", "entry_count": current_revocation["revocation_count"],
             "head_sha256": current_revocation["revocation_head_sha256"]}
    witness_group = [
        {"role": role, "source_root_sha256": fingerprint("root-" + role),
         "acquisition_sha256": fingerprint("acq-" + role),
         "public_key": role + ".pub", "signature": role + ".sig"}
        for role in ("ff", "cf", "rr")
    ]
    witness_pins = [fingerprint("key-" + role) for role in ("ff", "cf", "rr")]
    nonces = [fingerprint("review-" + role) for role in ("ff", "cf", "rr")]
    return [recovery, old_revocation, current_revocation,
            previous_ledger, ledger, [witness_group], [witness_pins],
            [nonces], floor]


class RecoveryQuarantineTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_GRADUATION_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_three_signatures_still_quarantined(self):
        bundle = make_bundle()
        calls = []
        def verify(*args):
            calls.append(args)
            return h(15)
        report = audit(*bundle, verifier=verify)
        self.assertEqual(len(calls), 3)
        self.assertEqual(report["status"], "HOLD_GRADUATION_NOT_AUTHORIZED")
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["independent_operator_custody_verified"])
        self.assertFalse(report["quarantined_recovery_reviews"][0]["graduation_approved"])
        self.assertTrue(report["revocation_prefix_preserved"])

    def test_no_new_epoch_rejected(self):
        b = make_bundle()
        b[4] = b[3]
        b[2] = b[1]
        with self.assertRaisesRegex(ValueError, "no successor challenge epoch"):
            audit(*b, verifier=fake)

    def test_historical_challenge_rewrite_rejected(self):
        b = make_bundle()
        b[4]["entries"][0]["nonce_sha256"] = h(0)
        with self.assertRaises(ValueError):
            audit(*b, verifier=fake)

    def test_prior_revocation_dropped_rejected(self):
        b = make_bundle()
        b[2]["revocation_events"] = []
        with self.assertRaises(ValueError):
            audit(*b, verifier=fake)

    def test_retention_floor_mismatch_rejected(self):
        b = make_bundle()
        b[-1]["head_sha256"] = h(0)
        with self.assertRaisesRegex(ValueError, "floor does not cover"):
            audit(*b, verifier=fake)

    def test_replayed_review_nonce_rejected(self):
        b = make_bundle()
        b[7][0][0] = b[4]["entries"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError, "nonce replay"):
            audit(*b, verifier=fake)

    def test_duplicate_review_keys_rejected(self):
        b = make_bundle()
        b[6][0][1] = b[6][0][0]
        with self.assertRaisesRegex(ValueError, "duplicated review witness"):
            audit(*b, verifier=fake)

    def test_claimed_shared_root_rejected(self):
        b = make_bundle()
        b[5][0][1]["source_root_sha256"] = b[5][0][0]["source_root_sha256"]
        with self.assertRaisesRegex(ValueError, "ancestry collision"):
            audit(*b, verifier=fake)

    def test_compromised_witness_pin_rejected(self):
        b = make_bundle()
        b[6][0][0] = h(1)
        with self.assertRaisesRegex(ValueError, "compromised or self-issued"):
            audit(*b, verifier=fake)

    def test_successor_key_revoked_rejected(self):
        b = make_bundle()
        b[2]["revocation_events"][0]["revoked_attestor_spki_sha256"] = h(8)
        with self.assertRaises(ValueError):
            audit(*b, verifier=fake)

    def test_false_witness_signature_rejected(self):
        b = make_bundle()
        def reject(*args):
            raise ValueError("invalid Ed25519")
        with self.assertRaises(ValueError):
            audit(*b, verifier=reject)

    def test_tampered_recovery_candidate_rejected(self):
        b = make_bundle()
        b[0]["recovery_candidates"][0]["replacement_pin"] = h(2)
        with self.assertRaisesRegex(ValueError, "RUST-045 receipt altered"):
            audit(*b, verifier=fake)


if __name__ == "__main__":
    unittest.main()
