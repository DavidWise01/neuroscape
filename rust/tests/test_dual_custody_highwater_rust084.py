import unittest
from lineage_rust019 import digest
from dual_custody_highwater_rust084 import (
    audit,checkpoint,hold,witness_conflicts)
from test_exclusion_custody_rust083 import run as custody_run,bundle,h,verify

def fixture():
    previous=custody_run()
    current=custody_run(bundle("second"),history=previous)
    e=current["events"][-1]
    observation={"phase":"RUST-084",
        "custody_entry_sha256":e["entry_sha256"],
        "nonce_sha256":h("084-independent-observation"),
        "witnesses_sha256":digest(e["witnesses"]),
        "exclusions_sha256":e["exclusions_sha256"],
        "denials_sha256":e["denials_sha256"],
        "all_denials_retained":True,
        "both_branches_retained":True,
        "winner_selected":False,
        "fork_resolved":False,
        "independent_custody_verified":False,
        "recovery_authorized":False,
        "release_authorized":False,
        "live_gameplay_authority":False}
    floor={"phase":"RUST-084","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,checkpoint(previous),floor,[observation]]

def run(data=None,pin=None,verifier=verify):
    a,b,cp,floor,obs=data or fixture()
    return audit(a,b,cp,"highwater.pem","highwater.sig",
                 pin or h("084-separate-highwater-signer"),floor,obs,verifier=verifier)

class DualCustodyHighwaterTests(unittest.TestCase):
    def test_no_external_evidence_hold(self):
        result=hold()
        self.assertEqual(result["status"],"HOLD_MISSING_DUAL_CUSTODY_HIGHWATER")
        self.assertFalse(result["release_authorized"])
    def test_valid_extension_always_hold(self):
        result=run()
        self.assertEqual((result["previous_count"],result["current_count"]),(1,2))
        self.assertTrue(result["all_denials_retained"])
        self.assertFalse(result["independent_custody_verified"])
        self.assertFalse(result["fork_resolved"])
    def test_witness_pairs_preserved(self):
        result=run()
        self.assertEqual(result["current_witness_pairs"][:len(
            result["historical_witness_pairs"])],result["historical_witness_pairs"])
    def test_exclusion_snapshots_preserved(self):
        result=run()
        self.assertEqual(result["current_exclusions"][:len(
            result["historical_exclusions"])],result["historical_exclusions"])
    def test_denial_snapshots_preserved(self):
        result=run()
        self.assertEqual(result["current_denials"][:len(
            result["historical_denials"])],result["historical_denials"])
    def test_conflicts_preserved(self):
        result=run()
        self.assertEqual(result["current_conflicts"][:len(
            result["historical_conflicts"])],result["historical_conflicts"])
    def test_repeat_control_under_same_pin_is_recorded(self):
        result=run()
        findings=result["cross_epoch_conflicts"]
        self.assertTrue(all(x["independent_custody_verified"] is False for x in findings))
        self.assertFalse(result["release_authorized"])
    def test_renamed_controller_reuse_recorded(self):
        x=fixture();prior=x[0]["events"];new=x[1]["events"][-1]
        witness=dict(new["witnesses"][0])
        witness["pin"]=h("renamed-084-pin")
        synthetic=dict(new,witnesses=[witness,new["witnesses"][1]])
        findings=witness_conflicts(prior,[synthetic])
        self.assertIn("RENAMED_WITNESS_REUSED_PREVIOUS_CONTROL",
                      [f["reason"] for f in findings])
    def test_changed_controller_same_pin_recorded(self):
        x=fixture();prior=x[0]["events"];new=x[1]["events"][-1]
        witness=dict(new["witnesses"][0])
        witness["controller_sha256"]=h("changed-controller")
        synthetic=dict(new,witnesses=[witness,new["witnesses"][1]])
        findings=witness_conflicts(prior,[synthetic])
        self.assertIn("SAME_WITNESS_CHANGED_CONTROL_ANCESTRY",
                      [f["reason"] for f in findings])
    def test_shared_witness_ancestry_recorded(self):
        x=fixture();event=x[1]["events"][-1]
        a,b=event["witnesses"]
        fake=dict(event,witnesses=[a,{**b,"controller_sha256":a["controller_sha256"]}])
        self.assertIn("NEW_PAIR_SHARED_CONTROL_ANCESTRY",
                      [c["reason"] for c in witness_conflicts([], [fake])])
    def test_stale_successor_rejected(self):
        a=fixture();a[1]=a[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):run(a)
    def test_old_custody_event_mutation_rejected(self):
        a=fixture();a[1]["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):run(a)
    def test_removed_historical_denial_rejected(self):
        a=fixture();a[1]["denial_snapshots"]=[]
        with self.assertRaises(ValueError):run(a)
    def test_removed_exclusion_history_rejected(self):
        a=fixture();a[1]["excluded_snapshots"]=[]
        with self.assertRaises(ValueError):run(a)
    def test_checkpoint_head_substitution_rejected(self):
        a=fixture();a[2]["head_sha256"]=h("forged-head")
        with self.assertRaisesRegex(ValueError,"checkpoint substituted"):run(a)
    def test_retention_floor_substitution_rejected(self):
        a=fixture();a[3]["head_sha256"]=h("forked-prefix")
        with self.assertRaisesRegex(ValueError,"contradicts exact custody prefix"):run(a)
    def test_future_floor_rejected(self):
        a=fixture();a[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(a)
    def test_custody_witness_self_sign_rejected(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(a,pin=a[1]["events"][0]["witnesses"][0]["pin"])
    def test_excluded_identity_self_sign_rejected(self):
        a=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(a,pin=a[1]["events"][0]["exclusions"]["excluded_signer_pins"][0])
    def test_missing_epoch_observation_rejected(self):
        a=fixture();a[4]=[]
        with self.assertRaisesRegex(ValueError,"one custody snapshot"):run(a)
    def test_witness_claim_substitution_rejected(self):
        a=fixture();a[4][0]["witnesses_sha256"]=h("wrong-witness")
        with self.assertRaisesRegex(ValueError,"substituted witnesses or denials"):run(a)
    def test_denial_snapshot_substitution_rejected(self):
        a=fixture();a[4][0]["denials_sha256"]=h("wrong-denials")
        with self.assertRaisesRegex(ValueError,"substituted witnesses or denials"):run(a)
    def test_nonce_replay_rejected(self):
        a=fixture();a[4][0]["nonce_sha256"]=a[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(a)
    def test_false_independence_rejected(self):
        a=fixture();a[4][0]["independent_custody_verified"]=True
        with self.assertRaisesRegex(ValueError,"asserted independence"):run(a)
    def test_false_release_rejected(self):
        a=fixture();a[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"asserted independence"):run(a)
    def test_invalid_signature_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):run(verifier=invalid)
if __name__=="__main__":unittest.main()
