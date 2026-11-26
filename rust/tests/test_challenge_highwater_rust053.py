import copy
import hashlib
import unittest

from lineage_rust019 import digest
from fork_challenge_ledger_rust052 import audit as challenge_audit, genesis
from test_fork_challenge_ledger_rust052 import bundle, verifier as fake
from challenge_highwater_rust053 import audit, hold, highwater


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def histories():
    review, groups, pins, nonces = bundle()
    first = challenge_audit(review, genesis(), groups, pins, nonces, verifier=fake)
    second = copy.deepcopy(first)
    event = copy.deepcopy(first["entries"][-1])
    event["ordinal"] = 2
    event["previous_entry_sha256"] = first["head_sha256"]
    for c in event["witness_claims"]:
        c["nonce_sha256"] = h("new-nonce-" + c["role"])
        c["message_sha256"] = h("new-message-" + c["role"])
        c["signature_sha256"] = h("new-signature-" + c["role"])
    event["witness_claims_sha256"] = digest(event["witness_claims"])
    event["entry_sha256"] = digest({k: v for k, v in event.items()
                                     if k != "entry_sha256"})
    second["entries"].append(event)
    second["prefix_heads"].append(event["entry_sha256"])
    second["entry_count"] = 2
    second["head_sha256"] = event["entry_sha256"]
    second["receipt_sha256"] = digest({k: v for k, v in second.items()
                                       if k != "receipt_sha256"})
    return first, second


def floor(old):
    return {"phase": "RUST-053", "challenge_count": old["entry_count"],
            "head_sha256": old["head_sha256"]}


def session(tag="fresh", pin=None):
    return {
        "phase": "RUST-053",
        "session_nonce_sha256": h("session-nonce-" + tag),
        "acquisition_sha256": h("session-acquisition"),
        "operator_control_sha256": h("session-control"),
        "claimed_source_root_sha256": h("session-root"),
        "public_key": "session.pem", "signature": "session.sig",
    }


def verify(*args):
    return h("signature-hash")


class ChallengeHighwaterTests(unittest.TestCase):
    def run_audit(self, old=None, new=None, checkpoint=None, retained=None,
                  sessions=None, pins=None, witness=verify):
        a, b = histories()
        old = a if old is None else old
        new = b if new is None else new
        return audit(old, new, highwater(old) if checkpoint is None else checkpoint,
                     "checkpoint.pem", "checkpoint.sig", h("checkpoint-pin"),
                     floor(old) if retained is None else retained,
                     [session()] if sessions is None else sessions,
                     [h("session-pin")] if pins is None else pins,
                     verifier=witness)

    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"], "HOLD_MISSING_SIGNED_CHALLENGE_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_valid_signed_checkpoint_still_hold(self):
        out = self.run_audit()
        self.assertEqual(out["previous_count"], 1)
        self.assertEqual(out["current_count"], 2)
        self.assertTrue(out["challenge_history_prefix_preserved"])
        self.assertFalse(out["independent_external_custody_verified"])
        self.assertFalse(out["release_authorized"])

    def test_old_snapshot_rejected(self):
        a, _ = histories()
        with self.assertRaisesRegex(ValueError, "extend"):
            self.run_audit(a, a)

    def test_checkpoint_substitution_rejected(self):
        a, b = histories()
        checkpoint = highwater(a)
        checkpoint["head_sha256"] = h("fork")
        with self.assertRaisesRegex(ValueError, "checkpoint differs"):
            self.run_audit(a, b, checkpoint=checkpoint)

    def test_retained_floor_fork_rejected(self):
        a, b = histories()
        value = floor(a)
        value["head_sha256"] = h("other")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.run_audit(a, b, retained=value)

    def test_retained_floor_ahead_of_current_rejected(self):
        a, b = histories()
        value = {"phase": "RUST-053", "challenge_count": 3,
                 "head_sha256": h("newer")}
        with self.assertRaisesRegex(ValueError, "withheld"):
            self.run_audit(a, b, retained=value)

    def test_history_tampering_rejected(self):
        a, b = histories()
        b["entries"][0]["witness_claims"][0]["nonce_sha256"] = h("mutated")
        with self.assertRaises(ValueError):
            self.run_audit(a, b)

    def test_session_nonce_replay_of_ledger_rejected(self):
        a, b = histories()
        s = session()
        s["session_nonce_sha256"] = a["entries"][0]["witness_claims"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError, "nonce replay"):
            self.run_audit(a, b, sessions=[s])

    def test_session_nonce_replay_within_batch_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonce replay"):
            self.run_audit(sessions=[session(), session()],
                           pins=[h("signer-1"), h("signer-2")])

    def test_checkpoint_signer_cannot_self_witness(self):
        with self.assertRaisesRegex(ValueError, "self-witness"):
            self.run_audit(pins=[h("checkpoint-pin")])

    def test_bad_signature_rejected(self):
        def bad(*args):
            raise ValueError("invalid Ed25519 signature")
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            self.run_audit(witness=bad)

    def test_changed_claimed_ancestry_is_recorded(self):
        a, b = histories()
        prior_claim = a["entries"][0]["witness_claims"][0]
        s = session()
        out = self.run_audit(a, b, sessions=[s], pins=[prior_claim["pin"]])
        self.assertEqual(len(out["session_ancestry_conflicts"]), 1)
        self.assertFalse(out["fork_resolved"])

    def test_nonempty_prior_history_required(self):
        from fork_challenge_ledger_rust052 import genesis
        with self.assertRaisesRegex(ValueError, "nonempty"):
            highwater(genesis())

    def test_partial_origin_claim_rejected(self):
        s = session()
        del s["operator_control_sha256"]
        with self.assertRaises(ValueError):
            self.run_audit(sessions=[s])


if __name__ == "__main__":
    unittest.main()
