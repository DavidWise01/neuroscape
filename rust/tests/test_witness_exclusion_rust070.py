import copy,unittest
from witness_exclusion_rust070 import audit,checkpoint_payload,hold
from test_recovery_witness_revocation_rust069 import (
    run as revoked_run,materials,h,verify)

def fixture():
    prev=revoked_run()
    current=revoked_run(materials("b",bad_role="cf"),history=prev)
    event=current["events"][-1]
    prior_witness=prev["events"][0]["witnesses"][0]
    obs=[{"phase":"RUST-070","revocation_entry_sha256":event["entry_sha256"],
          "observation_nonce_sha256":h("epoch-070"),
          "signer_pin":h("new-observer-070"),
          "controller_sha256":prior_witness["controller_sha256"],
          "source_root_sha256":prior_witness["source_root_sha256"],
          "acquisition_sha256":prior_witness["acquisition_sha256"],
          "quarantine_persists":True,"recovery_authorized":False,
          "release_authorized":False}]
    floor={"phase":"RUST-070","event_count":prev["event_count"],
           "head_sha256":prev["head_sha256"]}
    return [prev,current,checkpoint_payload(prev),floor,obs]

def run(items=None,pin=None,verifier=verify):
    a,b,cp,floor,obs=items or fixture()
    return audit(a,b,cp,"highwater.pem","checkpoint.sig",
                 pin or h("outside-highwater-signer"),floor,obs,verifier=verifier)

class WitnessExclusionTests(unittest.TestCase):
    def test_missing_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_WITNESS_REVOCATION_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_exact_extension_remains_hold(self):
        x=run()
        self.assertEqual((x["previous_count"],x["current_count"]),(1,2))
        self.assertTrue(x["all_successors_quarantined"])
        self.assertFalse(x["independent_custody_verified"])
        self.assertFalse(x["release_authorized"])

    def test_old_revoked_pins_persist(self):
        x=run()
        self.assertEqual(x["current_revoked_pins_preserved"][:len(
            x["prior_revoked_pins_preserved"])],x["prior_revoked_pins_preserved"])

    def test_old_roots_persist(self):
        x=run()
        self.assertEqual(x["current_revoked_roots_preserved"][:len(
            x["prior_revoked_roots_preserved"])],x["prior_revoked_roots_preserved"])

    def test_historical_conflicts_persist(self):
        x=run()
        self.assertEqual(x["current_conflicts_preserved"][:len(
            x["historical_conflicts_preserved"])],x["historical_conflicts_preserved"])

    def test_renamed_controller_flagged(self):
        a=fixture()
        a[4][0]["controller_sha256"]=a[1]["revoked_controller_roots"][0]
        x=run(a)
        self.assertIn("RENAMED_KEY_REVOKED_CONTROLLER",
                      [c["reason"] for c in x["custodian_exclusion_conflicts"]])

    def test_reused_acquisition_flagged(self):
        self.assertIn("CROSS_EPOCH_REUSED_ACQUISITION",
                      [c["reason"] for c in run()["custodian_exclusion_conflicts"]])

    def test_reused_historical_controller_flagged(self):
        self.assertIn("CROSS_EPOCH_REUSED_CONTROLLER",
                      [c["reason"] for c in run()["custodian_exclusion_conflicts"]])

    def test_revoked_pin_reentry_recorded_no_authority(self):
        a=fixture()
        a[4][0]["signer_pin"]=a[0]["revoked_witness_pins"][0]
        x=run(a)
        self.assertIn("REVOKED_SIGNER_REENTRY",
                      [c["reason"] for c in x["custodian_exclusion_conflicts"]])
        self.assertFalse(x["recovery_authorized"])

    def test_older_successor_rejected(self):
        a=fixture();a[1]=a[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(a)

    def test_historical_entry_tamper_rejected(self):
        a=fixture()
        a[1]["events"][0]["quarantine_persists"]=False
        with self.assertRaises(ValueError):run(a)

    def test_highwater_substitution_rejected(self):
        a=fixture();a[2]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"substituted"):run(a)

    def test_floor_fork_rejected(self):
        a=fixture();a[3]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(a)

    def test_future_floor_rejected(self):
        a=fixture();a[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside known"):run(a)

    def test_revoked_key_cannot_sign_checkpoint(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(a,pin=a[0]["revoked_witness_pins"][0])

    def test_witness_cannot_sign_checkpoint(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(a,pin=a[0]["events"][0]["witnesses"][0]["pin"])

    def test_missing_observation_rejected(self):
        a=fixture();a[4]=[]
        with self.assertRaisesRegex(ValueError,"one cross-epoch"):run(a)

    def test_wrong_event_observation_rejected(self):
        a=fixture();a[4][0]["revocation_entry_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"not bound"):run(a)

    def test_nonce_reuse_rejected(self):
        a=fixture()
        a[4][0]["observation_nonce_sha256"]=a[0]["events"][0]["revocation_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(a)

    def test_observation_release_rejected(self):
        a=fixture();a[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"quarantine release"):run(a)

    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=reject)

if __name__=="__main__":unittest.main()
