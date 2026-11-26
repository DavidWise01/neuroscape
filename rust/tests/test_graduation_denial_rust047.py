import copy
import hashlib
import unittest

from lineage_rust019 import digest
from graduation_denial_rust047 import audit, genesis, hold, validate_history, GENESIS


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def review(epoch=3, nonce_tag="first", root_suffix="", source="review-1"):
    claims = []
    for role in ("ff", "cf", "rr"):
        claims.append({
            "role": role,
            "pin": sha("pin-" + role),
            "source_root_sha256": sha("root-" + role + root_suffix),
            "acquisition_sha256": sha("acq-" + role + root_suffix),
            "nonce_sha256": sha(nonce_tag + "-nonce-" + role),
            "message_sha256": sha(nonce_tag + "-message-" + role),
            "signature_sha256": sha(nonce_tag + "-signature-" + role),
            "real_world_independence_authenticated": False,
        })
    row = {
        "role": "ff",
        "recovery_proposal_sha256": sha("recovery-a"),
        "replacement_pin": sha("replacement-a"),
        "latest_challenge_entry_sha256": sha("challenge-" + source),
        "latest_challenge_epoch": epoch,
        "signed_review_claims": claims,
        "quarantine_persists": True,
        "graduation_approved": False,
    }
    report = {
        "phase": "RUST-046", "status": "HOLD_GRADUATION_NOT_AUTHORIZED",
        "quarantined_recovery_reviews": [row],
        "historical_challenge_prefix_preserved": True,
        "revocation_prefix_preserved": True,
        "witness_evidence_sha256": digest(claims),
        "preserved_attestor_conflicts": [],
        "preserved_root_equivalent_replacements": [],
        "release_authorized": False,
        "fork_resolved": False,
        "independent_operator_custody_verified": False,
    }
    report["receipt_sha256"] = digest(report)
    return report


class GraduationDenialTests(unittest.TestCase):
    def test_missing_material_is_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_INDEPENDENT_DENIAL_LEDGER")
        self.assertFalse(hold()["release_authorized"])

    def test_first_denial_keeps_quarantine(self):
        out = audit(review(), genesis())
        self.assertEqual(out["entry_count"], 1)
        self.assertEqual(out["prefix_heads"][0], GENESIS)
        self.assertFalse(out["entries"][0]["graduation_approved"])
        self.assertFalse(out["release_authorized"])
        self.assertFalse(out["independent_external_retention_verified"])

    def test_successive_denials_preserve_exact_prefix(self):
        first = audit(review(), genesis())
        second = audit(review(4, "next", source="review-2"), first,
                       {"phase": "RUST-047", "entry_count": 1,
                        "head_sha256": first["head_sha256"]})
        self.assertEqual(second["entry_count"], 2)
        self.assertEqual(second["entries"][:1], first["entries"])
        self.assertEqual(second["prefix_heads"][:2], first["prefix_heads"])
        self.assertFalse(second["release_authorized"])

    def test_same_review_receipt_cannot_be_appended_twice(self):
        sample = review()
        first = audit(sample, genesis())
        with self.assertRaisesRegex(ValueError, "review replayed"):
            audit(sample, first)

    def test_reused_nonce_with_new_review_is_rejected(self):
        first = audit(review(), genesis())
        with self.assertRaisesRegex(ValueError, "nonce"):
            audit(review(4, "first", source="review-2"), first)

    def test_reused_signed_statement_with_new_nonces_rejected(self):
        first = audit(review(), genesis())
        second = review(4, "other", source="review-2")
        second["quarantined_recovery_reviews"][0]["signed_review_claims"][0]["message_sha256"] = (
            first["entries"][0]["witness_claims"][0]["message_sha256"])
        second["witness_evidence_sha256"] = digest(
            second["quarantined_recovery_reviews"][0]["signed_review_claims"])
        second["receipt_sha256"] = digest({k: v for k, v in second.items()
                                           if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "signed review statement"):
            audit(second, first)

    def test_same_witness_pin_changes_declared_ancestry(self):
        first = audit(review(), genesis())
        second = audit(review(4, "next", root_suffix="-alias", source="review-2"), first)
        self.assertTrue(second["witness_ancestry_conflicts"])
        self.assertFalse(second["review_source_ancestry_authenticated"])

    def test_floor_conflict_is_fail_closed(self):
        first = audit(review(), genesis())
        with self.assertRaisesRegex(ValueError, "substituted or withheld"):
            audit(review(4, "next", source="review-2"), first,
                  {"phase": "RUST-047", "entry_count": 1, "head_sha256": sha("false")})

    def test_tampered_history_denied(self):
        first = audit(review(), genesis())
        first["entries"][0]["graduation_approved"] = True
        with self.assertRaises(ValueError):
            audit(review(4, "next", source="review-2"), first)

    def test_graduation_approval_cannot_be_imported(self):
        sample = review()
        sample["quarantined_recovery_reviews"][0]["graduation_approved"] = True
        sample["receipt_sha256"] = digest({k: v for k, v in sample.items()
                                           if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "quarantine"):
            audit(sample, genesis())

    def test_unverified_witness_is_never_certified(self):
        sample = review()
        sample["quarantined_recovery_reviews"][0]["signed_review_claims"][1][
            "real_world_independence_authenticated"] = True
        claims = sample["quarantined_recovery_reviews"][0]["signed_review_claims"]
        sample["witness_evidence_sha256"] = digest(claims)
        sample["receipt_sha256"] = digest({k: v for k, v in sample.items()
                                           if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "unsupported witness independence"):
            audit(sample, genesis())

    def test_false_witness_claim_digest_rejected(self):
        sample = review()
        sample["witness_evidence_sha256"] = sha("incorrect")
        sample["receipt_sha256"] = digest({k: v for k, v in sample.items()
                                           if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "witness review evidence"):
            audit(sample, genesis())

    def test_historical_prefix_hash_cannot_be_changed(self):
        first = audit(review(), genesis())
        first["prefix_heads"][1] = sha("fake")
        with self.assertRaises(ValueError):
            validate_history(first)


if __name__ == "__main__":
    unittest.main()
