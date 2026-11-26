import copy
import unittest

from lineage_rust019 import digest
from challenge_ledger_rust042 import GENESIS as LEDGER_GENESIS, checked_history
from attestor_revocation_rust044 import audit, hold, GENESIS, revocation_payload

ROLES = ("ff", "cf", "rr")


def h(num):
    return format(num % 16, "x") * 64


def fixture(key_reuse=False, shared_root=False, epoch=2):
    entries = []
    heads = [LEDGER_GENESIS]
    for step in range(1, epoch + 1):
        for i, role in enumerate(ROLES):
            pin = h(1 + i)
            if step >= 2 and i == 0 and not key_reuse:
                pin = h(8)
            root = h(4 + i)
            if step >= 2 and i == 0 and not shared_root:
                root = h(9)
            entry = {
                "phase": "RUST-042", "kind": "ATTESTED_CHALLENGE_ENTRY",
                "ordinal": len(entries) + 1, "epoch": step,
                "role": role, "previous_entry_sha256": heads[-1],
                "source_rust041_receipt_sha256": h(10),
                "source_observation_sha256": h(11),
                "nonce_sha256": h(2 + step * 3 + i),
                "retrieval_session_sha256": h(9 + step * 3 + i),
                "attestor_key_spki_sha256": pin,
                "external_attestor_root_sha256": root,
                "custodian_signature_sha256": h(12),
                "attestor_signature_sha256": h(13),
                "release_authorized": False,
            }
            # Nonces must remain unique across all epochs.
            entry["entry_sha256"] = digest(entry)
            entries.append(entry)
            heads.append(entry["entry_sha256"])
    ledger = {
        "phase": "RUST-042",
        "status": "HOLD_ATTESTOR_IDENTITY_SUBSTITUTION" if not key_reuse else
                  "HOLD_EXTERNAL_LEDGER_UNVERIFIED",
        "epoch": epoch, "entries": entries, "prefix_heads": heads,
        "head_sha256": heads[-1],
        "release_authorized": False,
        "external_custody_verified": False,
    }
    ledger["receipt_sha256"] = digest(ledger)
    rotation = {
        "phase": "RUST-043",
        "status": "HOLD_ATTESTOR_ROTATION_IDENTITY_UNVERIFIED",
        "current_rust042_receipt_sha256": ledger["receipt_sha256"],
        "verified_rotation_signatures": [{
            "role": "ff", "dual_signature_verified": True,
            "old_attestor_spki_sha256": h(1),
            "new_attestor_spki_sha256": h(8),
            "transition_sha256": h(10),
            "old_signature_sha256": h(11),
            "new_signature_sha256": h(12),
        }],
        "preserved_attestor_conflicts": [{"role": "ff", "reason": "ROTATED"}],
        "historical_prefix_preserved": True,
        "release_authorized": False, "fork_resolved": False,
    }
    rotation["receipt_sha256"] = digest(rotation)
    return ledger, rotation


def revocation(pin=None, epoch=2, root=None):
    return {
        "role": "ff",
        "revoked_attestor_spki_sha256": pin or h(1),
        "revoked_attestor_root_sha256": root or h(4),
        "effective_epoch": epoch,
        "evidence_sha256": h(14),
        "authority_public_key": "authority.pem",
        "authority_signature": "authority.sig",
    }


def fake(*args):
    return h(15)


class AttestorRevocationTests(unittest.TestCase):
    def test_missing_custody_is_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_ATTESTOR_REVOCATION_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_new_key_after_revocation_is_still_hold(self):
        ledger, rotation = fixture()
        result = audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)
        self.assertEqual(result["status"], "HOLD_EXTERNAL_REVOCATION_CUSTODY_UNVERIFIED")
        self.assertEqual(result["revocation_count"], 1)
        self.assertFalse(result["release_authorized"])

    def test_revoked_key_reused_after_effective_epoch_rejected(self):
        ledger, rotation = fixture(key_reuse=True)
        with self.assertRaisesRegex(ValueError, "revoked attestor signed"):
            audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)

    def test_replacement_sharing_compromised_root_flagged(self):
        ledger, rotation = fixture(shared_root=True)
        result = audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)
        self.assertEqual(result["status"], "HOLD_POTENTIAL_COMPROMISED_CONTROL")
        self.assertEqual(len(result["suspected_root_equivalent_replacements"]), 1)
        self.assertFalse(result["real_world_control_verified"])

    def test_invalid_revocation_authority_signature_rejected(self):
        ledger, rotation = fixture()
        def reject(*args):
            raise ValueError("Ed25519 invalid")
        with self.assertRaises(ValueError):
            audit(ledger, rotation, [revocation()], [h(6)], verifier=reject)

    def test_revoked_key_cannot_sign_own_revocation(self):
        ledger, rotation = fixture()
        with self.assertRaisesRegex(ValueError, "self-authorize"):
            audit(ledger, rotation, [revocation()], [h(1)], verifier=fake)

    def test_repeated_revocation_rejected(self):
        ledger, rotation = fixture()
        with self.assertRaisesRegex(ValueError, "duplicated"):
            audit(ledger, rotation, [revocation(), revocation()], [h(6), h(6)], verifier=fake)

    def test_retained_prefix_conflict_rejected(self):
        ledger, rotation = fixture()
        floor = {"phase": "RUST-044", "entry_count": 1, "head_sha256": h(0)}
        with self.assertRaisesRegex(ValueError, "rewritten"):
            audit(ledger, rotation, [revocation()], [h(6)], floor, verifier=fake)

    def test_empty_event_chain_and_genesis_floor(self):
        ledger, rotation = fixture()
        result = audit(ledger, rotation, [], [], {"phase": "RUST-044",
                      "entry_count": 0, "head_sha256": GENESIS}, verifier=fake)
        self.assertEqual(result["revocation_head_sha256"], GENESIS)
        self.assertEqual(result["revocation_events"], [])

    def test_upstream_ledger_forgery_rejected(self):
        ledger, rotation = fixture()
        ledger["entries"][0]["attestor_key_spki_sha256"] = h(0)
        with self.assertRaises(ValueError):
            audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)

    def test_transition_substitution_rejected(self):
        ledger, rotation = fixture()
        rotation["current_rust042_receipt_sha256"] = h(0)
        rotation["receipt_sha256"] = digest({k: v for k, v in rotation.items()
                                             if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "another challenge ledger"):
            audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)

    def test_rotation_conflicts_preserved(self):
        ledger, rotation = fixture()
        result = audit(ledger, rotation, [revocation()], [h(6)], verifier=fake)
        self.assertEqual(result["preserved_attestor_conflicts"][0]["role"], "ff")
        self.assertFalse(result["fork_resolved"])


if __name__ == "__main__":
    unittest.main()
