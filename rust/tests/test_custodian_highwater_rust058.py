import copy
import hashlib
import unittest

from lineage_rust019 import digest
from recovery_custody_rust057 import audit as custody_audit, genesis
from custodian_highwater_rust058 import (
    audit, hold, checkpoint_payload, compare_ancestry)
from test_recovery_custody_rust057 import materials, verify

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def fixture():
    src,recovery,revocations,groups,nonces=materials("epoch-a",shared=True)
    first=custody_audit(src,recovery,revocations,genesis(),
                        groups,nonces,verifier=verify)
    fresh_groups=copy.deepcopy(groups)
    for group in fresh_groups:
        for c in group:
            c["signer_pin"]=h("renamed-"+c["role"])
    next_nonces=[[h("epoch-b-"+str(i)+"-"+c["role"]) for c in g]
                 for i,g in enumerate(fresh_groups)]
    successor=custody_audit(src,recovery,revocations,first,
                            fresh_groups,next_nonces,verifier=verify)
    claims=[{
        "phase":"RUST-058",
        "challenge_entry_sha256":e["entry_sha256"],
        "epoch_nonce_sha256":h("claim-"+str(i)),
        "controller_sha256":e["witnesses"][0]["claimed_controller_sha256"],
        "acquisition_sha256":e["witnesses"][0]["acquisition_sha256"],
        "release_authorized":False,
    } for i,e in enumerate(successor["entries"][len(first["entries"]):])]
    floor={"phase":"RUST-058","challenge_count":first["event_count"],
           "head_sha256":first["head_sha256"]}
    return [first,successor,checkpoint_payload(first),floor,claims]

def run(b=None, pin=None, verifier=verify):
    first,new,checkpoint,floor,claims=b or fixture()
    return audit(first,new,checkpoint,"highwater.pem","highwater.sig",
                 pin or h("external-highwater-pin"),floor,claims,verifier=verifier)

class CustodianHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_CHALLENGE_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_signed_highwater_stays_hold(self):
        out=run()
        self.assertEqual(out["previous_challenge_count"],2)
        self.assertEqual(out["current_challenge_count"],4)
        self.assertTrue(out["custody_history_prefix_preserved"])
        self.assertFalse(out["independent_custody_verified"])

    def test_renamed_custodian_controller_collision(self):
        out=run()
        self.assertTrue(any(c["reason"]=="RENAMED_CUSTODIAN_SAME_CLAIMED_CONTROLLER"
                            for c in out["cross_epoch_ancestry_conflicts"]))
        self.assertFalse(out["fork_resolved"])

    def test_prior_conflicts_cannot_disappear(self):
        out=run()
        self.assertTrue(out["historical_custody_conflicts_preserved"])
        self.assertEqual(out["current_custody_conflicts_preserved"][:len(
            out["historical_custody_conflicts_preserved"])],
            out["historical_custody_conflicts_preserved"])

    def test_old_snapshot_not_current(self):
        a,*_=fixture()
        b=fixture()
        b[1]=a
        with self.assertRaisesRegex(ValueError,"strictly advance"):
            run(b)

    def test_tampered_history_rejected(self):
        b=fixture()
        b[1]["entries"][0]["witnesses"][0]["nonce_sha256"]=h("fake")
        with self.assertRaises(ValueError):
            run(b)

    def test_substituted_checkpoint_rejected(self):
        b=fixture()
        b[2]["head_sha256"]=h("fork")
        with self.assertRaisesRegex(ValueError,"checkpoint substituted"):
            run(b)

    def test_retained_floor_fork_rejected(self):
        b=fixture()
        b[3]["head_sha256"]=h("competing")
        with self.assertRaisesRegex(ValueError,"competing highwater"):
            run(b)

    def test_retained_floor_newer_than_history_rejected(self):
        b=fixture()
        b[3]["challenge_count"]=5
        with self.assertRaisesRegex(ValueError,"withheld below floor"):
            run(b)

    def test_self_signed_highwater_rejected(self):
        b=fixture()
        pin=b[0]["entries"][0]["witnesses"][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"self-issue"):
            run(b,pin=pin)

    def test_absent_epoch_claim_rejected(self):
        b=fixture()
        b[4].pop()
        with self.assertRaisesRegex(ValueError,"each new custody challenge"):
            run(b)

    def test_substituted_epoch_reference_rejected(self):
        b=fixture()
        b[4][0]["challenge_entry_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"not bound"):
            run(b)

    def test_nonce_replay_within_epoch_rejected(self):
        b=fixture()
        b[4][1]["epoch_nonce_sha256"]=b[4][0]["epoch_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(b)

    def test_epoch_nonce_may_not_equal_witness_challenge(self):
        b=fixture()
        b[4][0]["epoch_nonce_sha256"]=b[1]["entries"][-1]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(b)

    def test_authority_escalation_rejected(self):
        b=fixture()
        b[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"elevated authority"):
            run(b)

    def test_invalid_highwater_signature_rejected(self):
        def reject(*_): raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)

    def test_same_pin_altered_origin_detected(self):
        old={"witnesses":[{
            "signer_pin":h("p"),"claimed_controller_sha256":h("c"),
            "claimed_source_root_sha256":h("r"),"acquisition_sha256":h("a")}]}
        new={"witnesses":[{
            "signer_pin":h("p"),"claimed_controller_sha256":h("c2"),
            "claimed_source_root_sha256":h("r2"),"acquisition_sha256":h("a2")}]}
        rows=compare_ancestry([old],[new])
        self.assertEqual(rows[0]["reason"],"SIGNER_ANCESTRY_CHANGED_ACROSS_EPOCHS")

if __name__=="__main__":
    unittest.main()
