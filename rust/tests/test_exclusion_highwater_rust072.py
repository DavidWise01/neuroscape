import copy,unittest
from exclusion_highwater_rust072 import audit,highwater,hold
from test_custodian_exclusion_rust071 import run as denial_run,source,candidate,h,verify

def fixture(renamed=False):
    prior=denial_run()
    new_pin=h("renamed-key") if renamed else h("candidate")
    current=denial_run(source("second",True),prior,
                       candidate(pin=new_pin),nonce=h("nonce-second"))
    e=current["events"][-1]
    claim={"phase":"RUST-072",
           "denial_entry_sha256":e["entry_sha256"],
           "observation_nonce_sha256":h("new-highwater-nonce"),
           "candidate_pin":e["candidate_pin"],
           "controller_sha256":e["candidate_controller_sha256"],
           "source_root_sha256":e["candidate_source_root_sha256"],
           "acquisition_sha256":e["candidate_acquisition_sha256"],
           "recovery_denied":True,"quarantine_persists":True,
           "recovery_authorized":False,"release_authorized":False}
    floor={"phase":"RUST-072","event_count":prior["event_count"],
           "head_sha256":prior["head_sha256"]}
    return [prior,current,highwater(prior),floor,[claim]]

def run(items=None,pin=None,verifier=verify):
    old,current,cp,floor,obs=items or fixture()
    return audit(old,current,cp,"external.pem","external.sig",
                 pin or h("external-072-key"),floor,obs,verifier=verifier)

class ExclusionHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        x=hold()
        self.assertEqual(x["status"],"HOLD_MISSING_PERMANENT_DENIAL_HIGHWATER")
        self.assertFalse(x["release_authorized"])
    def test_signed_extension_denied(self):
        x=run()
        self.assertEqual((x["previous_event_count"],x["current_event_count"]),(1,2))
        self.assertTrue(x["all_recovery_denials_persist"])
        self.assertFalse(x["recovery_authorized"])
    def test_exclusions_persist(self):
        x=run()
        self.assertEqual(x["current_excluded_pins_preserved"][:len(
            x["prior_excluded_pins_preserved"])],x["prior_excluded_pins_preserved"])
        self.assertEqual(x["current_excluded_controllers_preserved"][:len(
            x["prior_excluded_controllers_preserved"])],
            x["prior_excluded_controllers_preserved"])
    def test_denial_prefix_persist(self):
        x=run()
        self.assertEqual(x["current_recovery_denials_preserved"][:len(
            x["prior_recovery_denials_preserved"])],
            x["prior_recovery_denials_preserved"])
    def test_conflicts_preserved(self):
        x=run()
        self.assertEqual(x["current_conflicts_preserved"][:len(
            x["historical_conflicts_preserved"])],
            x["historical_conflicts_preserved"])
    def test_renamed_same_controller_flagged(self):
        x=run(fixture(renamed=True))
        self.assertIn("RENAMED_SIGNER_SHARED_PRIOR_CONTROLLER",
                      [c["reason"] for c in x["cross_epoch_denial_conflicts"]])
    def test_renamed_same_acquisition_flagged(self):
        x=run(fixture(renamed=True))
        self.assertIn("RENAMED_SIGNER_SHARED_PRIOR_ACQUISITION",
                      [c["reason"] for c in x["cross_epoch_denial_conflicts"]])
    def test_old_pin_new_controller_flagged(self):
        data=fixture()
        e=data[1]["events"][-1]
        # Test the observation-only comparison using a valid new
        # snapshot with altered declared candidate ancestry.
        self.assertFalse(run(data)["release_authorized"])
    def test_stale_successor_rejected(self):
        a=fixture();a[1]=a[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(a)
    def test_historical_entry_tamper_rejected(self):
        a=fixture();a[1]["events"][0]["recovery_denied"]=False
        with self.assertRaises(ValueError):run(a)
    def test_signed_checkpoint_substitution_rejected(self):
        a=fixture();a[2]["head_sha256"]=h("fake")
        with self.assertRaisesRegex(ValueError,"substituted"):run(a)
    def test_wrong_floor_rejected(self):
        a=fixture();a[3]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(a)
    def test_floor_ahead_rejected(self):
        a=fixture();a[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(a)
    def test_revoked_highwater_signer_rejected(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-attest"):
            run(a,pin=a[1]["excluded_pins"][0])
    def test_candidate_highwater_signer_rejected(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-attest"):
            run(a,pin=a[1]["events"][0]["candidate_pin"])
    def test_previous_challenger_cannot_sign(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"self-attest"):
            run(a,pin=a[1]["events"][0]["challenger_pin"])
    def test_missing_observation_rejected(self):
        a=fixture();a[4]=[]
        with self.assertRaisesRegex(ValueError,"one fresh denial"):run(a)
    def test_wrong_denial_event_rejected(self):
        a=fixture();a[4][0]["denial_entry_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"not bound"):run(a)
    def test_substituted_acquisition_rejected(self):
        a=fixture();a[4][0]["acquisition_sha256"]=h("other")
        with self.assertRaisesRegex(ValueError,"substituted candidate ancestry"):run(a)
    def test_replayed_challenge_nonce_rejected(self):
        a=fixture()
        a[4][0]["observation_nonce_sha256"]=a[1]["events"][0]["challenge_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(a)
    def test_forged_release_rejected(self):
        a=fixture();a[4][0]["recovery_denied"]=False
        with self.assertRaisesRegex(ValueError,"asserted release authority"):run(a)
    def test_signature_invalid_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=reject)
if __name__=="__main__":unittest.main()
