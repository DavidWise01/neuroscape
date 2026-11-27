import copy
import unittest
from recovery_highwater_rust068 import audit,checkpoint_payload,hold,compare_ancestry
from test_successor_recovery_rust067 import run as recovery_run,materials,h,verify

def fixture(renamed=False,shared=False):
    previous=recovery_run(materials(shared=shared))
    bundle=materials("next")
    if renamed:
        for item in bundle[2][0]:
            item["signer_pin"]=h("renamed-"+item["role"])
    current=recovery_run(bundle,history=previous)
    event=current["events"][-1]
    observation={"phase":"RUST-068",
                 "recovery_entry_sha256":event["entry_sha256"],
                 "epoch_nonce_sha256":h("068-observation"),
                 "candidate_pin":event["candidate_pin"],
                 "revocation_entry_sha256":event["revocation_entry_sha256"],
                 "claimed_controller_sha256":event["candidate_controller_sha256"],
                 "claimed_acquisition_sha256":event["candidate_acquisition_sha256"],
                 "quarantine_persists":True,
                 "recovery_authorized":False,"release_authorized":False}
    floor={"phase":"RUST-068","recovery_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,checkpoint_payload(previous),floor,[observation]]

def run(data=None,pin=None,verifier=verify):
    a,b,cp,floor,obs=data or fixture()
    return audit(a,b,cp,"checkpoint.pem","checkpoint.sig",
                 pin or h("external-highwater-068"),floor,obs,verifier=verifier)

class RecoveryHighwaterTests(unittest.TestCase):
    def test_default_missing_evidence_hold(self):
        x=hold()
        self.assertEqual(x["status"],"HOLD_MISSING_RECOVERY_HIGHWATER_EVIDENCE")
        self.assertFalse(x["recovery_authorized"])

    def test_signed_extension_remains_hold(self):
        x=run()
        self.assertEqual(x["previous_recovery_count"],1)
        self.assertEqual(x["current_recovery_count"],2)
        self.assertTrue(x["all_successors_quarantined"])
        self.assertFalse(x["release_authorized"])

    def test_prior_candidate_prefix_preserved(self):
        x=run()
        self.assertEqual(x["current_quarantined_candidates_preserved"][:1],
                         x["prior_quarantined_candidates_preserved"])

    def test_conflict_prefix_preserved(self):
        x=run(fixture(shared=True))
        self.assertEqual(x["current_conflicts_preserved"][:len(
            x["historical_conflicts_preserved"])],
            x["historical_conflicts_preserved"])

    def test_renamed_witness_same_controller_detected(self):
        x=run(fixture(renamed=True))
        self.assertIn("RENAMED_WITNESS_SHARED_CONTROLLER",
                      [c["reason"] for c in x["cross_epoch_ancestry_conflicts"]])

    def test_renamed_witness_same_acquisition_detected(self):
        x=run(fixture(renamed=True))
        self.assertIn("RENAMED_WITNESS_SHARED_ACQUISITION",
                      [c["reason"] for c in x["cross_epoch_ancestry_conflicts"]])

    def test_same_pin_changed_ancestry_detected(self):
        older={"witnesses":[{"pin":h("pin"),"controller_sha256":h("a"),
                             "source_root_sha256":h("b"),"acquisition_sha256":h("c")}]}
        newer=copy.deepcopy(older)
        newer["witnesses"][0]["source_root_sha256"]=h("changed")
        x=compare_ancestry([older],[newer])
        self.assertEqual(x[0]["reason"],"SAME_WITNESS_PIN_CHANGED_ANCESTRY")

    def test_stale_successor_rejected(self):
        args=fixture();args[1]=args[0]
        with self.assertRaisesRegex(ValueError,"strictly advance"):run(args)

    def test_tampered_historical_attempt_rejected(self):
        args=fixture()
        args[1]["events"][0]["quarantine_persists"]=False
        with self.assertRaises(ValueError):run(args)

    def test_checkpoint_substitution_rejected(self):
        args=fixture();args[2]["head_sha256"]=h("fake")
        with self.assertRaisesRegex(ValueError,"substituted"):run(args)

    def test_floor_branch_conflict_rejected(self):
        args=fixture();args[3]["head_sha256"]=h("fork")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(args)

    def test_floor_ahead_rejected(self):
        args=fixture();args[3]["recovery_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(args)

    def test_candidate_cannot_self_sign_highwater(self):
        args=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):run(
            args,pin=args[0]["events"][0]["candidate_pin"])

    def test_witness_cannot_self_sign_highwater(self):
        args=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):run(
            args,pin=args[0]["events"][0]["witnesses"][0]["pin"])

    def test_missing_epoch_observation_rejected(self):
        args=fixture();args[4]=[]
        with self.assertRaisesRegex(ValueError,"fresh observation"):run(args)

    def test_wrong_successor_reference_rejected(self):
        args=fixture();args[4][0]["candidate_pin"]=h("fake")
        with self.assertRaisesRegex(ValueError,"not bound"):run(args)

    def test_observation_ancestry_substitution_rejected(self):
        args=fixture()
        args[4][0]["claimed_acquisition_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"substituted ancestry"):run(args)

    def test_replayed_witness_nonce_rejected(self):
        args=fixture()
        args[4][0]["epoch_nonce_sha256"]=args[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(args)

    def test_forged_quarantine_clearance_rejected(self):
        args=fixture();args[4][0]["quarantine_persists"]=False
        with self.assertRaisesRegex(ValueError,"promoted authority"):run(args)

    def test_crypto_failure_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=invalid)

if __name__=="__main__":
    unittest.main()
