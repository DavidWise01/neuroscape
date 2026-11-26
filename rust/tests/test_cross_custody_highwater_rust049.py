import copy
import unittest

from graduation_denial_rust047 import genesis, audit as denial_audit
from denial_highwater_rust048 import checkpoint_payload
from cross_custody_highwater_rust049 import audit, hold
from test_graduation_denial_rust047 import review, sha


PINS = [sha("signer-A"), sha("signer-B")]


def histories():
    first = denial_audit(review(), genesis())
    second = denial_audit(review(4, "next", source="second"), first)
    other = denial_audit(review(4, "fork", source="alternative"), first)
    third = denial_audit(review(5, "third", source="third"), second)
    return first, second, other, third


def branch(ledger, index=0, root=None, acquisition=None):
    return {
        "ledger": ledger,
        "checkpoint": checkpoint_payload(ledger),
        "public_key": "custodian-" + str(index) + ".pem",
        "signature": "custodian-" + str(index) + ".sig",
        "custody_root_sha256": root or sha("source-" + str(index)),
        "acquisition_sha256": acquisition or sha("acquisition-" + str(index)),
    }


def verifier(*_args):
    return sha("signed")


class CrossCustodyHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_CROSS_CUSTODY_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_matching_equal_count_keeps_hold(self):
        _, second, _, _ = histories()
        out = audit(branch(second), branch(second, 1), PINS, verifier=verifier)
        self.assertEqual(out["status"], "HOLD_EXTERNAL_CUSTODY_UNVERIFIED")
        self.assertIsNone(out["same_count_fork_evidence"])
        self.assertFalse(out["independent_custodian_control_verified"])

    def test_same_count_divergent_head_preserved(self):
        _, second, other, _ = histories()
        out = audit(branch(second), branch(other, 1), PINS, verifier=verifier)
        self.assertEqual(out["status"], "HOLD_CONFLICTING_DENIAL_HIGHWATERS")
        self.assertEqual(out["same_count_fork_evidence"]["common_prefix_count"], 1)
        self.assertFalse(out["same_count_fork_evidence"]["winner_selected"])
        self.assertNotEqual(out["left_branch"]["head_sha256"], out["right_branch"]["head_sha256"])

    def test_fork_at_shorter_prefix_is_detected(self):
        _, second, other, third = histories()
        out = audit(branch(third), branch(other, 1), PINS, verifier=verifier)
        self.assertEqual(out["status"], "HOLD_CONFLICTING_DENIAL_HIGHWATERS")
        self.assertEqual(out["same_count_fork_evidence"]["compared_count"], 2)

    def test_valid_extension_of_shorter_branch(self):
        _, second, _, third = histories()
        out = audit(branch(second), branch(third, 1), PINS, verifier=verifier)
        self.assertEqual(out["status"], "HOLD_EXTERNAL_CUSTODY_UNVERIFIED")
        self.assertEqual(out["highest_observed_denial_count"], 3)

    def test_identical_custody_roots_are_not_independent(self):
        _, second, _, _ = histories()
        out = audit(branch(second), branch(second, 1, root=sha("source-0")),
                    PINS, verifier=verifier)
        self.assertEqual(out["status"], "HOLD_SHARED_CUSTODY_ANCESTRY")

    def test_identical_acquisition_paths_are_not_independent(self):
        _, second, _, _ = histories()
        out = audit(branch(second), branch(second, 1,
                    acquisition=sha("acquisition-0")), PINS, verifier=verifier)
        self.assertTrue(out["shared_claimed_custody_ancestry"])

    def test_duplicate_signing_pin_rejected(self):
        _, second, _, _ = histories()
        with self.assertRaisesRegex(ValueError, "same signing key"):
            audit(branch(second), branch(second, 1), [PINS[0], PINS[0]],
                  verifier=verifier)

    def test_invalid_signature_rejected(self):
        _, second, _, _ = histories()
        def fail(*args):
            raise ValueError("Ed25519 rejected")
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            audit(branch(second), branch(second, 1), PINS, verifier=fail)

    def test_substituted_checkpoint_rejected(self):
        _, second, _, _ = histories()
        right = branch(second, 1)
        right["checkpoint"]["head_sha256"] = sha("substitution")
        with self.assertRaisesRegex(ValueError, "checkpoint differs"):
            audit(branch(second), right, PINS, verifier=verifier)

    def test_external_floor_missing_from_one_branch_rejected(self):
        _, second, _, third = histories()
        floor = {"phase": "RUST-049", "denial_count": 3,
                 "head_sha256": third["head_sha256"]}
        with self.assertRaisesRegex(ValueError, "omitted"):
            audit(branch(second), branch(third, 1), PINS, floor, verifier=verifier)

    def test_neither_branch_matches_retained_floor_rejected(self):
        _, second, other, _ = histories()
        floor = {"phase": "RUST-049", "denial_count": 2,
                 "head_sha256": sha("another-history")}
        with self.assertRaisesRegex(ValueError, "neither branch"):
            audit(branch(second), branch(other, 1), PINS, floor, verifier=verifier)

    def test_retained_floor_reports_each_branch_match(self):
        _, second, other, _ = histories()
        floor = {"phase": "RUST-049", "denial_count": 2,
                 "head_sha256": second["head_sha256"]}
        out = audit(branch(second), branch(other, 1), PINS, floor, verifier=verifier)
        self.assertEqual(out["floor_match_by_branch"], [True, False])
        self.assertFalse(out["fork_resolved"])

    def test_tampered_denial_branch_rejected(self):
        _, second, _, _ = histories()
        right = branch(copy.deepcopy(second), 1)
        right["ledger"]["entries"][0]["graduation_approved"] = True
        with self.assertRaises(ValueError):
            audit(branch(second), right, PINS, verifier=verifier)


if __name__ == "__main__":
    unittest.main()
