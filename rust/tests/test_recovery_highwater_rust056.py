import copy
import unittest
from lineage_rust019 import digest
from recovery_highwater_rust056 import audit, hold, checkpoint_payload
from witness_recovery_rust055 import audit as recover_audit, genesis
from test_witness_recovery_rust055 import registry, candidate, verify, h

def setup():
    rev=registry()
    first_candidate=candidate(nonce="one")
    first=recover_audit(rev,genesis(),[first_candidate],
                       [first_candidate["candidate_signer_pin"]],
                       [h("authority-pin")],verifier=verify)
    other=candidate(nonce="two",new=h("successor-two"))
    later=recover_audit(rev,first,[other],[other["candidate_signer_pin"]],
                       [h("authority-pin")],verifier=verify)
    observation={
        "recovery_entry_sha256":later["events"][-1]["entry_sha256"],
        "source_registry_receipt_sha256":rev["receipt_sha256"],
        "observation_nonce_sha256":h("observation-fresh-two"),
        "claimed_controller_sha256":later["events"][-1]["claimed_controller_sha256"],
        "acquisition_sha256":h("independent-acquisition-claim"),
        "operator_control_sha256":h("operator-claim"),
        "recovery_authorized":False,
    }
    floor={"phase":"RUST-056","recovery_event_count":1,
           "recovery_head_sha256":first["head_sha256"]}
    return first,later,rev,rev,checkpoint_payload(first,rev),floor,[observation]

def run(bundle=None,signer= None,verifier=verify):
    a,b,oldrev,newrev,cp,floor,observations = bundle or setup()
    return audit(a,b,oldrev,newrev,cp,"signer.pem","signature.sig",
                 signer or h("highwater-custodian"),floor,observations,
                 verifier=verifier)

class RecoveryHighwaterTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_RECOVERY_HIGHWATER_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_signed_successor_still_quarantined(self):
        report=run()
        self.assertEqual(report["current_recovery_count"],2)
        self.assertTrue(report["recovery_history_prefix_preserved"])
        self.assertFalse(report["independent_external_custody_verified"])
        self.assertFalse(report["release_authorized"])

    def test_history_preserved_exactly(self):
        a,b,*_=setup()
        report=run()
        self.assertEqual(report["historical_recovery_attempts_preserved"][:1],
                         a["events"])
        self.assertEqual(report["historical_recovery_attempts_preserved"],b["events"])

    def test_old_snapshot_cannot_become_current(self):
        values=list(setup())
        values[1]=values[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):
            run(values)

    def test_tampered_previous_event_rejected(self):
        values=list(setup())
        values[1]=copy.deepcopy(values[1])
        values[1]["events"][0]["candidate_nonce_sha256"]=h("tamper")
        with self.assertRaises(ValueError):
            run(values)

    def test_modified_previous_revocation_rejected(self):
        values=list(setup())
        values[3]=copy.deepcopy(values[3])
        values[3]["revoked_signer_pins"]=[]
        with self.assertRaises(ValueError):
            run(values)

    def test_retained_floor_conflict_rejected(self):
        values=list(setup())
        values[5]=dict(values[5])
        values[5]["recovery_head_sha256"]=h("fork-head")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):
            run(values)

    def test_retained_floor_ahead_rejected(self):
        values=list(setup())
        values[5]={"phase":"RUST-056","recovery_event_count":3,
                   "recovery_head_sha256":h("future-head")}
        with self.assertRaisesRegex(ValueError,"withheld"):
            run(values)

    def test_checkpoint_mismatch_rejected(self):
        values=list(setup())
        values[4]=dict(values[4])
        values[4]["recovery_head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"checkpoint substituted"):
            run(values)

    def test_revoked_signer_cannot_authenticate_highwater(self):
        with self.assertRaisesRegex(ValueError,"revoked witness"):
            run(signer=h("session-pin"))

    def test_missing_successor_observation_rejected(self):
        values=list(setup())
        values[6]=[]
        with self.assertRaisesRegex(ValueError,"each new recovery"):
            run(values)

    def test_observation_nonce_replay_rejected(self):
        values=list(setup())
        values[6]=copy.deepcopy(values[6])
        values[6][0]["observation_nonce_sha256"]=values[1]["events"][0]["candidate_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(values)

    def test_replacement_controller_substitution_rejected(self):
        values=list(setup())
        values[6]=copy.deepcopy(values[6])
        values[6][0]["claimed_controller_sha256"]=h("new-controller")
        with self.assertRaisesRegex(ValueError,"controller ancestry altered"):
            run(values)

    def test_false_successor_authority_rejected(self):
        values=list(setup())
        values[6]=copy.deepcopy(values[6])
        values[6][0]["recovery_authorized"]=True
        with self.assertRaisesRegex(ValueError,"asserted authorization"):
            run(values)

    def test_invalid_highwater_signature_rejected(self):
        def bad(*args): raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=bad)

    def test_matching_claimed_controller_still_unverified(self):
        out=run()
        self.assertTrue(out["successor_observations"][0]["revoked_controller_claimed"])
        self.assertFalse(out["successor_observations"][0]["independent_controller_verified"])

if __name__=="__main__":
    unittest.main()
