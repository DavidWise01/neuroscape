import copy
import unittest
from unittest.mock import patch

from highwater_rust025 import make_candidate
from multiwitness_rust026 import ROLES, adjudicate, hold, verify_observations

PINS = ["1"*64,"2"*64,"3"*64]
CHECKPOINT = make_candidate(2, 18, "a"*40, "b"*64, "c"*64)
FORK = make_candidate(2, 18, "d"*40, "e"*64, "c"*64)

def bundle(checkpoints=None):
    points = checkpoints or [CHECKPOINT]*3
    return [
        {"role": role, "checkpoint": cp, "key": role + ".pem",
         "signature": role + ".sig", "external_pin": pin}
        for role, cp, pin in zip(ROLES, points, PINS)
    ]

class ThreeWitnessTests(unittest.TestCase):
    def test_missing_witness_is_hold(self):
        self.assertEqual(hold("no witness")["status"],"HOLD_MISSING_THREE_WITNESSES")
        self.assertFalse(hold("no witness")["release_authorized"])

    def test_matching_signed_snapshots_are_not_independent_custody(self):
        with patch("multiwitness_rust026.verify_witness", return_value="f"*64) as verify:
            record=adjudicate(verify_observations(bundle()))
        self.assertEqual(verify.call_count,3)
        self.assertEqual(record["status"],"CONSISTENT_SIGNED_SNAPSHOTS")
        self.assertFalse(record["independent_custody_ancestries_verified"])
        self.assertFalse(record["release_authorized"])

    def test_two_to_one_majority_does_not_erase_fork(self):
        with patch("multiwitness_rust026.verify_witness", return_value="f"*64):
            record=adjudicate(verify_observations(bundle([CHECKPOINT,CHECKPOINT,FORK])))
        self.assertEqual(record["status"],"HOLD_FORK_EVIDENCE")
        self.assertEqual(len(record["observed_candidate_sha256"]),2)
        self.assertEqual(len(record["observations"]),3)
        self.assertTrue(record["fork_detected"])

    def test_missing_or_duplicated_signers_rejected(self):
        with patch("multiwitness_rust026.verify_witness", return_value="f"*64):
            with self.assertRaises(ValueError):
                verify_observations(bundle()[:2])
            repeated=bundle()
            repeated[2]["external_pin"]=PINS[0]
            with self.assertRaises(ValueError):
                verify_observations(repeated)

    def test_bad_signature_and_false_claim_rejected(self):
        with patch("multiwitness_rust026.verify_witness", side_effect=ValueError("invalid signature")):
            with self.assertRaises(ValueError):
                verify_observations(bundle())
        with patch("multiwitness_rust026.verify_witness", return_value="f"*64):
            records=verify_observations(bundle())
        records[1]["signature_verified"]=False
        with self.assertRaises(ValueError):
            adjudicate(records)

    def test_role_swap_and_modified_checkpoint_rejected(self):
        items=bundle()
        items[0],items[1]=items[1],items[0]
        with self.assertRaises(ValueError):
            verify_observations(items)
        tampered=copy.deepcopy(bundle())
        tampered[0]["checkpoint"]["sequence"]=1
        with self.assertRaises(ValueError):
            verify_observations(tampered)

if __name__ == "__main__":
    unittest.main()
