import unittest
from lineage_rust019 import digest
from custodian_quarantine_highwater_rust086 import (
    audit,checkpoint,hold,reentry_conflicts,RETAIN)
from test_cross_custodian_control_rust085 import (
    run as control_run,bundle,h,verify)

def fixture():
    previous=control_run()
    current=control_run(bundle("second"),history=previous,
                        nonce=h("085-second-nonce"))
    last=current["events"][-1]
    observation={"phase":"RUST-086",
        "entry_sha256":last["entry_sha256"],
        "nonce_sha256":h("086-new-observation"),
        "claims_sha256":last["claims_sha256"],
        "quarantine_sha256":digest(last["quarantined_claims"]),
        "exclusions_sha256":last["excluded_snapshot_sha256"],
        "denials_sha256":last["denial_snapshot_sha256"],
        "both_quarantined":True,"both_branches_retained":True,
        "winner_selected":False,"fork_resolved":False,
        "independent_custody_verified":False,
        "recovery_authorized":False,"release_authorized":False,
        "live_gameplay_authority":False}
    floor={"phase":"RUST-086","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,checkpoint(previous),floor,[observation]]

def run(parts=None,pin=None,verifier=verify):
    a,b,cp,floor,obs=parts or fixture()
    return audit(a,b,cp,"highwater.pem","highwater.sig",
                 pin or h("086-independent-highwater-signer"),floor,obs,
                 verifier=verifier)

class QuarantineHighwaterTests(unittest.TestCase):
    def test_missing_evidence_remains_hold(self):
        self.assertEqual(hold()["status"],
            "HOLD_MISSING_CROSS_CUSTODIAN_QUARANTINE_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])
    def test_valid_successor_remains_hold(self):
        result=run()
        self.assertEqual((result["previous_count"],result["current_count"]),(1,2))
        self.assertTrue(result["both_quarantined"])
        self.assertFalse(result["independent_custody_verified"])
    def test_all_prior_claims_and_denials_retained(self):
        result=run()
        for name in RETAIN:
            self.assertEqual(result["current_"+name][:len(
                result["historical_"+name])],result["historical_"+name])
    def test_each_new_witness_remains_quarantined(self):
        result=run()
        self.assertTrue(all(q["custody_independence_quarantined"] for q in
            result["current_quarantined_claims"][-2:]))
    def test_reentering_quarantined_pin_detected(self):
        result=run()
        self.assertIn("QUARANTINED_CUSTODIAN_REENTERED",
             [c["reason"] for c in result["cross_epoch_quarantine_conflicts"]])
    def test_renamed_key_reuses_control_detected(self):
        parts=fixture()
        prior=parts[0]["events"];new=parts[1]["events"][-1]
        row=dict(new["claims"][0]);row["pin"]=h("renamed-086")
        fake=dict(new,claims=[row,new["claims"][1]])
        conflicts=reentry_conflicts(prior,[fake])
        self.assertIn("RENAMED_CUSTODIAN_REUSES_CONTROL_ANCESTRY",
                      [f["reason"] for f in conflicts])
    def test_changing_claimed_controller_detected(self):
        parts=fixture()
        prior=parts[0]["events"];new=parts[1]["events"][-1]
        row=dict(new["claims"][0]);row["controller_sha256"]=h("changed-086")
        fake=dict(new,claims=[row,new["claims"][1]])
        self.assertIn("CUSTODIAN_PIN_CHANGED_DECLARED_CONTROL",
                      [f["reason"] for f in reentry_conflicts(prior,[fake])])
    def test_stale_ledger_rejected(self):
        x=fixture();x[1]=x[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(x)
    def test_old_registry_event_mutation_rejected(self):
        x=fixture();x[1]["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):run(x)
    def test_prior_quarantine_erasure_rejected(self):
        x=fixture();x[1]["quarantined_claims"]=[]
        with self.assertRaises(ValueError):run(x)
    def test_prior_denial_erasure_rejected(self):
        x=fixture();x[1]["denial_snapshots"]=[]
        with self.assertRaises(ValueError):run(x)
    def test_checkpoint_substitution_rejected(self):
        x=fixture();x[2]["head_sha256"]=h("bad-head")
        with self.assertRaisesRegex(ValueError,"substituted"):run(x)
    def test_bad_retention_floor_rejected(self):
        x=fixture();x[3]["head_sha256"]=h("bad-floor")
        with self.assertRaisesRegex(ValueError,"contradicts prefix"):run(x)
    def test_retention_floor_ahead_rejected(self):
        x=fixture();x[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(x)
    def test_old_witness_cannot_self_sign(self):
        x=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(x,pin=x[1]["custodian_claims"][0]["pin"])
    def test_old_registrar_cannot_self_sign(self):
        x=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(x,pin=x[1]["events"][0]["registrar_pin"])
    def test_missing_observation_rejected(self):
        x=fixture();x[4]=[]
        with self.assertRaisesRegex(ValueError,"observation required"):run(x)
    def test_claim_substitution_rejected(self):
        x=fixture();x[4][0]["claims_sha256"]=h("new-claims")
        with self.assertRaisesRegex(ValueError,"substituted source"):run(x)
    def test_quarantine_digest_substitution_rejected(self):
        x=fixture();x[4][0]["quarantine_sha256"]=h("new-quarantine")
        with self.assertRaisesRegex(ValueError,"substituted source"):run(x)
    def test_denial_digest_substitution_rejected(self):
        x=fixture();x[4][0]["denials_sha256"]=h("new-denial")
        with self.assertRaisesRegex(ValueError,"substituted source"):run(x)
    def test_nonce_replay_rejected(self):
        x=fixture()
        x[4][0]["nonce_sha256"]=x[1]["events"][0]["challenge_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(x)
    def test_false_quarantine_clearance_rejected(self):
        x=fixture();x[4][0]["both_quarantined"]=False
        with self.assertRaisesRegex(ValueError,"falsely cleared"):run(x)
    def test_false_recovery_authority_rejected(self):
        x=fixture();x[4][0]["recovery_authorized"]=True
        with self.assertRaisesRegex(ValueError,"falsely cleared"):run(x)
    def test_false_independence_rejected(self):
        x=fixture();x[4][0]["independent_custody_verified"]=True
        with self.assertRaisesRegex(ValueError,"falsely cleared"):run(x)
    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)
if __name__=="__main__":
    unittest.main()
