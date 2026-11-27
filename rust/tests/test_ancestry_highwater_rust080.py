import unittest
from ancestry_highwater_rust080 import audit,checkpoint_payload,hold,exclusion_findings
from test_custodian_ancestry_rust079 import run as ancestry_run,materials,h,verify

def fixture():
    prior=ancestry_run()
    current=ancestry_run(materials("two"),history=prior,nonce=h("079-nonce-two"))
    e=current["events"][-1]
    claims=e["claims"]
    observation={"phase":"RUST-080",
        "ancestry_entry_sha256":e["entry_sha256"],
        "observation_nonce_sha256":h("080-observation-nonce"),
        "claims_sha256":e["claims_sha256"],
        "branch_a_sha256":claims[0]["branch_sha256"],
        "branch_b_sha256":claims[1]["branch_sha256"],
        "both_branches_retained":True,"winner_selected":False,
        "fork_resolved":False,"independent_custody_verified":False,
        "recovery_authorized":False,"release_authorized":False}
    floor={"phase":"RUST-080","event_count":prior["event_count"],
           "head_sha256":prior["head_sha256"]}
    return [prior,current,checkpoint_payload(prior),floor,[observation]]

def run(items=None,pin=None,verifier=verify):
    prior,current,cp,floor,observations=items or fixture()
    return audit(prior,current,cp,"external.pem","external.sig",
                 pin or h("080-external-signer"),floor,observations,
                 verifier=verifier)

class AncestryHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_ANCESTRY_HIGHWATER")
        self.assertFalse(hold()["fork_resolved"])
    def test_signed_successor_remains_hold(self):
        x=run()
        self.assertEqual((x["previous_count"],x["current_count"]),(1,2))
        self.assertTrue(x["both_branches_retained"])
        self.assertFalse(x["release_authorized"])
        self.assertFalse(x["independent_custody_verified"])
    def test_prior_claims_retained(self):
        x=run()
        self.assertEqual(x["current_claims_preserved"][:len(
            x["historical_claims_preserved"])],x["historical_claims_preserved"])
    def test_prior_conflicts_retained(self):
        x=run()
        self.assertEqual(x["current_conflicts_preserved"][:len(
            x["historical_conflicts_preserved"])],x["historical_conflicts_preserved"])
    def test_repeated_control_claim_recorded(self):
        x=run()
        self.assertIn("PAST_CONTROL_ANCESTRY_PERSISTS",
                      [f["reason"] for f in x["cross_epoch_exclusion_conflicts"]])
    def test_renamed_key_shared_controller_recorded(self):
        x=fixture()
        old=x[0]["custodian_claims"]
        new=[dict(x[1]["events"][-1]["claims"][0]),
             dict(x[1]["events"][-1]["claims"][1])]
        new[0]["signer_pin"]=h("new-080-key")
        findings=exclusion_findings(old,new)
        self.assertIn("RENAMED_SIGNER_REUSES_EXCLUDED_ANCESTRY",
                      [f["reason"] for f in findings])
    def test_reused_key_changed_controller_recorded(self):
        x=fixture()
        old=x[0]["custodian_claims"]
        new=[dict(x[1]["events"][-1]["claims"][0]),
             dict(x[1]["events"][-1]["claims"][1])]
        new[0]["controller_sha256"]=h("changed-080-controller")
        findings=exclusion_findings(old,new)
        self.assertIn("EXCLUDED_SIGNER_CHANGED_CLAIMED_CONTROL",
                      [f["reason"] for f in findings])
    def test_stale_successor_rejected(self):
        x=fixture();x[1]=x[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(x)
    def test_old_event_mutation_rejected(self):
        x=fixture();x[1]["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):run(x)
    def test_erased_claims_rejected(self):
        x=fixture();x[1]["custodian_claims"]=[]
        with self.assertRaises(ValueError):run(x)
    def test_changed_highwater_rejected(self):
        x=fixture();x[2]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"substituted"):run(x)
    def test_wrong_floor_rejected(self):
        x=fixture();x[3]["head_sha256"]=h("false")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(x)
    def test_floor_ahead_rejected(self):
        x=fixture();x[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(x)
    def test_custody_pin_cannot_sign_highwater(self):
        x=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(x,pin=x[1]["custodian_claims"][0]["signer_pin"])
    def test_registrar_cannot_sign_highwater(self):
        x=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(x,pin=x[1]["events"][0]["signer_pin"])
    def test_missing_observation_rejected(self):
        x=fixture();x[4]=[]
        with self.assertRaisesRegex(ValueError,"one fresh ancestry"):run(x)
    def test_substituted_branch_rejected(self):
        x=fixture();x[4][0]["branch_a_sha256"]=h("other-branch")
        with self.assertRaisesRegex(ValueError,"substituted claims or branch"):run(x)
    def test_substituted_claim_hash_rejected(self):
        x=fixture();x[4][0]["claims_sha256"]=h("new-claims")
        with self.assertRaisesRegex(ValueError,"substituted claims or branch"):run(x)
    def test_observation_nonce_replay_rejected(self):
        x=fixture()
        x[4][0]["observation_nonce_sha256"]=x[1]["events"][0]["observation_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(x)
    def test_fabricated_independence_rejected(self):
        x=fixture();x[4][0]["independent_custody_verified"]=True
        with self.assertRaisesRegex(ValueError,"asserted authority"):run(x)
    def test_fabricated_release_rejected(self):
        x=fixture();x[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"asserted authority"):run(x)
    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=reject)
if __name__=="__main__":unittest.main()
