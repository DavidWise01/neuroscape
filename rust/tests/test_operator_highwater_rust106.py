import copy
import hashlib
import unittest

from test_operator_continuity_rust105 import sample
from operator_continuity_rust105 import append
from operator_highwater_rust106 import (
    assess, checkpoint, competing, missing, HOLD)

def h(v):
    return hashlib.sha256(v.encode()).hexdigest()

def fake_verify(key, signature, pin, payload):
    if signature != "signed:" + pin:
        raise ValueError("forged test signature")
    return h(signature)

def signed(history, i):
    pin, nonce = h("operator-highwater-signer-"+str(i)), h("epoch-nonce-"+str(i))
    return {"signer_pin": pin, "nonce_sha256": nonce,
            "public_key": "test-key", "signature": "signed:"+pin,
            "payload": checkpoint(history, pin, nonce)}

def fixture():
    temp, report, ancestry = sample()
    first = append([], report, ancestry)
    second = append(first, report, ancestry)
    return temp, [first, second, signed(first, 1), signed(second, 2)]

def run(parts):
    return assess(*parts, verifier=fake_verify)

class OperatorHighwaterRUST106(unittest.TestCase):
    def case(self):
        tmp, parts = fixture()
        self.addCleanup(tmp.cleanup)
        return parts
    def rejected(self, mutation):
        parts=self.case()
        mutation(parts)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            run(parts)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_SIGNED_OPERATOR_HIGHWATER")
    def test_monotone_signed_checkpoints_hold(self):
        r=run(self.case())
        self.assertEqual(r["status"],HOLD)
        self.assertTrue(r["historic_conflicts_retained"])
        for key in ("independent_operator_rotation_authenticated",
                    "globally_authenticated_latest",
                    "independent_external_custody_verified",
                    "fork_selected", "recovery_authorized",
                    "release_authorized", "live_gameplay_authorized"):
            self.assertFalse(r[key])
    def test_deterministic_replay(self):
        parts=self.case()
        self.assertEqual(run(parts),run(parts))
    def test_nonempty_previous_required(self):
        self.rejected(lambda p:p.__setitem__(0,[]))
    def test_stale_same_history_rejected(self):
        self.rejected(lambda p:p.__setitem__(1,p[0]))
    def test_rollback_rejected(self):
        self.rejected(lambda p:p.__setitem__(1,[]))
    def test_historical_ledger_rewrite_rejected(self):
        self.rejected(lambda p:p[1][0]["observation"]["operators"][0].update(
            archive_sha256="f"*64))
    def test_erased_historical_conflict_rejected(self):
        self.rejected(lambda p:p[1][-1].update(cross_epoch_conflicts=[]))
    def test_wrong_previous_head_rejected(self):
        self.rejected(lambda p:p[2]["payload"].update(head_sha256="f"*64))
    def test_wrong_current_head_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(head_sha256="f"*64))
    def test_changed_conflict_digest_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(
            retained_conflicts_sha256="f"*64))
    def test_replayed_highwater_nonce_rejected(self):
        self.rejected(lambda p:p[3].update(nonce_sha256=p[2]["nonce_sha256"]))
    def test_same_signer_rotation_rejected(self):
        self.rejected(lambda p:p[3].update(signer_pin=p[2]["signer_pin"]))
    def test_bad_previous_signature_rejected(self):
        self.rejected(lambda p:p[2].update(signature="forged"))
    def test_bad_current_signature_rejected(self):
        self.rejected(lambda p:p[3].update(signature="forged"))
    def test_release_promotion_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(release_authorized=True))
    def test_custody_promotion_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(
            independent_external_custody_verified=True))
    def test_global_latest_claim_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(
            globally_authenticated_latest=True))
    def test_wrong_signed_epoch_count_rejected(self):
        self.rejected(lambda p:p[3]["payload"].update(epoch_count=900))
    def test_competing_claims_preserve_both(self):
        parts=self.case()
        branches=competing(parts[1],signed(parts[1],3),signed(parts[1],4),
                           verifier=fake_verify)
        self.assertEqual(len(branches["both_claims_preserved"]),2)
        self.assertFalse(branches["fork_selected"])
        self.assertFalse(branches["independent_external_custody_verified"])
    def test_competing_replayed_identity_refused(self):
        parts=self.case()
        same=signed(parts[1],3)
        with self.assertRaises(ValueError):
            competing(parts[1],same,copy.deepcopy(same),verifier=fake_verify)
    def test_no_input_mutation(self):
        parts=self.case()
        old=copy.deepcopy(parts)
        run(parts)
        self.assertEqual(parts,old)

if __name__=="__main__":
    unittest.main()
