import copy,unittest
from denial_custody_highwater_rust074 import audit,highwater,hold
from test_denial_custody_rust073 import run as custody_run,materials,h,verify

def fixture(renamed=False):
    previous=custody_run()
    later_claims=materials("two")
    if renamed:
        later_claims[2][0]["signer_pin"]=h("renamed-external-custodian")
    current=custody_run(later_claims,history=previous)
    e=current["events"][-1]
    observation={"phase":"RUST-074",
                 "custody_entry_sha256":e["entry_sha256"],
                 "snapshot_nonce_sha256":h("074-fresh-nonce"),
                 "snapshot_denials_sha256":e["denials_sha256"],
                 "claimed_controller_sha256":h("claimed-external-controller"),
                 "claimed_acquisition_sha256":h("claimed-external-acquisition"),
                 "denials_retained":True,"recovery_authorized":False,
                 "release_authorized":False}
    floor={"phase":"RUST-074","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,highwater(previous),floor,[observation]]

def run(b=None,pin=None,verifier=verify):
    previous,current,checkpoint,floor,observations=b or fixture()
    return audit(previous,current,checkpoint,"custody.pem","custody.sig",
                 pin or h("external-074-signer"),floor,observations,
                 verifier=verifier)

class DenialCustodyHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_DENIAL_CUSTODY_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])
    def test_valid_extension_still_hold(self):
        result=run()
        self.assertEqual((result["previous_count"],result["current_count"]),(1,2))
        self.assertTrue(result["all_denials_retained"])
        self.assertFalse(result["independent_custody_verified"])
    def test_prior_denial_snapshot_preserved(self):
        result=run()
        self.assertEqual(result["current_denials_preserved"][:len(
            result["prior_denials_preserved"])],result["prior_denials_preserved"])
    def test_exclusion_and_conflicts_preserved(self):
        result=run()
        self.assertEqual(result["current_excluded_pins_preserved"][:len(
            result["prior_excluded_pins_preserved"])],result["prior_excluded_pins_preserved"])
        self.assertEqual(result["current_conflicts_preserved"][:len(
            result["historical_conflicts_preserved"])],result["historical_conflicts_preserved"])
    def test_identical_denial_snapshot_stale_flagged(self):
        reasons=[c["reason"] for c in run()["snapshot_conflicts"]]
        self.assertIn("STALE_DENIAL_SNAPSHOT_DIGEST",reasons)
    def test_renamed_custodian_controller_flagged(self):
        reasons=[c["reason"] for c in run(fixture(renamed=True))["snapshot_conflicts"]]
        self.assertIn("RENAMED_CUSTODIAN_REUSED_ANCESTRY",reasons)
    def test_history_rollback_rejected(self):
        b=fixture();b[1]=b[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(b)
    def test_tampered_historical_snapshot_rejected(self):
        b=fixture();b[1]["events"][0]["denials"][0]["recovery_denied"]=False
        with self.assertRaises(ValueError):run(b)
    def test_checkpoint_substitution_rejected(self):
        b=fixture();b[2]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"substituted"):run(b)
    def test_floor_wrong_head_rejected(self):
        b=fixture();b[3]["head_sha256"]=h("forked")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(b)
    def test_floor_ahead_rejected(self):
        b=fixture();b[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(b)
    def test_old_custodian_cannot_self_sign(self):
        b=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(b,pin=b[0]["events"][0]["witnesses"][0]["pin"])
    def test_excluded_signer_cannot_self_sign(self):
        b=fixture()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(b,pin=b[0]["events"][0]["excluded_pins"][0])
    def test_missing_observation_rejected(self):
        b=fixture();b[4]=[]
        with self.assertRaisesRegex(ValueError,"fresh external snapshot"):run(b)
    def test_wrong_entry_binding_rejected(self):
        b=fixture();b[4][0]["custody_entry_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"not bound"):run(b)
    def test_denial_snapshot_substitution_rejected(self):
        b=fixture();b[4][0]["snapshot_denials_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"not bound"):run(b)
    def test_witness_nonce_replay_rejected(self):
        b=fixture()
        b[4][0]["snapshot_nonce_sha256"]=b[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(b)
    def test_clearance_attempt_rejected(self):
        b=fixture();b[4][0]["denials_retained"]=False
        with self.assertRaisesRegex(ValueError,"denial clearance"):run(b)
    def test_release_attempt_rejected(self):
        b=fixture();b[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"denial clearance"):run(b)
    def test_signature_failure_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=invalid)
if __name__=="__main__":unittest.main()
