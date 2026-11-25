import copy
import unittest

from genesis_rust020 import candidate, authenticated
from lineage_rust019 import digest
from successor_rust021 import first_successor, hold

GENESIS = "a" * 40
SUCCESSOR = "b" * 40
WASM = "c" * 64
REPLAY = "d" * 64

def adjudication(commit):
    d = {
        "phase": "RUST-018",
        "status": "CONSISTENT_OBSERVATIONS",
        "source_commit": commit,
        "wasm_sha256": WASM,
        "replay_sha256": REPLAY,
        "live_gameplay_authority": False,
        "source_independence_certified": False,
    }
    d["receipt_sha256"] = digest(d)
    return d

def simulated_verified(genesis):
    # Synthetic attestation is for PURE structural tests only.
    # Production CLI always calls authenticated(...) to verify Ed25519 first.
    d = {
        "phase": "RUST-020",
        "status": "CUSTODY_SIGNATURE_VERIFIED",
        "sequence": 0,
        "source_commit": genesis["source_commit"],
        "candidate_sha256": genesis["candidate_sha256"],
        "custody_authenticated": True,
        "source_independence_certified": False,
        "live_gameplay_authority": False,
        "external_key_pin_required": True,
    }
    d["attestation_sha256"] = digest(d)
    return d

class FirstSuccessor(unittest.TestCase):
    def test_unsigned_candidate_is_hold(self):
        status = hold(adjudication(SUCCESSOR), "no external signed genesis")
        self.assertEqual(status["status"], "HOLD_EXTERNAL_GENESIS")
        self.assertIsNone(status["sequence"])
        self.assertFalse(status["external_key_pin_verified"])

    def test_first_successor_structural_contract(self):
        origin = candidate(adjudication(GENESIS))
        signed = simulated_verified(origin)
        result = first_successor(
            adjudication(SUCCESSOR), origin, signed,
            lambda older, newer: older == GENESIS and newer == SUCCESSOR,
        )
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["genesis_candidate_sha256"], origin["candidate_sha256"])
        self.assertFalse(result["global_anti_rollback_certified"])
        self.assertFalse(result["external_custodian_identity_verified"])
        self.assertEqual(
            result["entry_sha256"],
            digest({k: v for k, v in result.items() if k != "entry_sha256"}),
        )

    def test_rejects_conflicting_ancestry_and_claims(self):
        original = candidate(adjudication(GENESIS))
        signed = simulated_verified(original)
        mutations = [
            (adjudication(SUCCESSOR), original, signed, lambda a, b: False),
            (adjudication(GENESIS), original, signed, lambda a, b: True),
        ]
        for current, genesis, att, ancestor in mutations:
            with self.assertRaises(ValueError):
                first_successor(current, genesis, att, ancestor)
        for field, new in [
            ("candidate_sha256", "f" * 64),
            ("source_commit", SUCCESSOR),
            ("custody_authenticated", False),
            ("status", "GENESIS_CANDIDATE"),
            ("live_gameplay_authority", True),
            ("source_independence_certified", True),
            ("attestation_sha256", "0" * 64),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(signed)
                changed[field] = new
                with self.assertRaises(ValueError):
                    first_successor(adjudication(SUCCESSOR), original, changed, lambda a, b: True)

if __name__ == "__main__":
    unittest.main()
