import copy
import unittest
from lineage_rust019 import digest
from cross_custodian_control_rust085 import (
    audit,genesis,hold,checked_history,claim_rows,compare)
from test_dual_custody_highwater_rust084 import fixture,run as highwater_run,h,verify

def bundle(tag="one"):
    items=fixture()
    source=highwater_run(items)
    custody=items[1]
    if tag!="one":
        source=copy.deepcopy(source)
        source["custodian_epoch_tag"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    return [source,custody]

def run(data=None,history=None,nonce=None,pin=None,floor=None,verifier=verify):
    source,custody=data or bundle()
    return audit(source,custody,history or genesis(),
                 pin or h("085-registrar-signing-pin"),
                 nonce or h("085-new-challenge-nonce"),
                 "control.pem","control.sig",floor,verifier=verifier)

class CrossCustodianControlTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        result=hold()
        self.assertEqual(result["status"],"HOLD_MISSING_CROSS_CUSTODIAN_CONTROL")
        self.assertFalse(result["release_authorized"])
    def test_new_registry_has_two_quarantined_claims(self):
        result=run()
        self.assertEqual(result["event_count"],1)
        self.assertEqual(len(result["quarantined_claims"]),2)
        self.assertTrue(all(q["custody_independence_quarantined"]
                            for q in result["quarantined_claims"]))
        self.assertFalse(result["independent_custody_verified"])
    def test_exact_witness_binding(self):
        source,custody=bundle()
        result=run([source,custody])
        self.assertEqual(result["custodian_claims"],
                         claim_rows(custody["events"][-1]))
    def test_dual_roles_still_present(self):
        result=run()
        self.assertEqual([c["role"] for c in result["custodian_claims"]],
                         ["left","right"])
    def test_original_exclusions_retained(self):
        source,custody=bundle()
        result=run([source,custody])
        self.assertEqual(result["excluded_snapshots"][0],
                         custody["events"][-1]["exclusions"])
    def test_original_denials_retained(self):
        source,custody=bundle()
        result=run([source,custody])
        self.assertEqual(result["denial_snapshots"][0],
                         custody["events"][-1]["denials"])
    def test_append_second_epoch_retains_old_data(self):
        previous=run()
        result=run(bundle("second"),history=previous,nonce=h("085-second-nonce"))
        self.assertEqual(result["event_count"],2)
        for name in ("events","custodian_claims","quarantined_claims",
                     "custody_conflicts","excluded_snapshots","denial_snapshots"):
            self.assertEqual(result[name][:len(previous[name])],previous[name])
        self.assertFalse(result["recovery_authorized"])
    def test_renamed_signer_shared_ancestry_detected(self):
        _,custody=bundle()
        old=[claim_rows(custody["events"][-1])[0]]
        current=copy.deepcopy(claim_rows(custody["events"][-1]))
        current[0]["pin"]=h("renamed-custodian")
        reasons=[c["reason"] for c in compare(old,current)]
        self.assertIn("RENAMED_CUSTODIAN_REUSES_CONTROL_ANCESTRY",reasons)
    def test_same_signer_changed_ancestry_detected(self):
        _,custody=bundle()
        old=[claim_rows(custody["events"][-1])[0]]
        current=copy.deepcopy(claim_rows(custody["events"][-1]))
        current[0]["controller_sha256"]=h("changed-controller")
        reasons=[c["reason"] for c in compare(old,current)]
        self.assertIn("CUSTODIAN_PIN_CHANGED_DECLARED_CONTROL",reasons)
    def test_cross_witness_shared_control_detected(self):
        _,custody=bundle()
        current=copy.deepcopy(claim_rows(custody["events"][-1]))
        current[1]["acquisition_sha256"]=current[0]["acquisition_sha256"]
        reasons=[c["reason"] for c in compare([],current)]
        self.assertIn("CURRENT_CUSTODIANS_SHARE_CLAIMED_CONTROL",reasons)
    def test_replayed_highwater_rejected(self):
        previous=run()
        with self.assertRaisesRegex(ValueError,"replayed RUST-084"):
            run(history=previous,nonce=h("unique-nonce"))
    def test_replayed_challenge_nonce_rejected(self):
        previous=run()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(bundle("second"),history=previous)
    def test_witness_nonce_replay_rejected(self):
        data=bundle()
        nonce=data[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(data,nonce=nonce)
    def test_source_receipt_tamper_rejected(self):
        data=bundle()
        data[0]["receipt_sha256"]=h("bad-receipt")
        with self.assertRaises(ValueError):run(data)
    def test_custody_denial_tamper_rejected(self):
        data=bundle()
        data[1]["denial_snapshots"]=[]
        with self.assertRaises(ValueError):run(data)
    def test_source_witness_self_sign_rejected(self):
        data=bundle()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(data,pin=data[1]["events"][0]["witnesses"][0]["pin"])
    def test_excluded_custodian_self_sign_rejected(self):
        data=bundle()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(data,pin=data[1]["events"][0]["exclusions"]["excluded_signer_pins"][0])
    def test_source_highwater_self_sign_rejected(self):
        data=bundle()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(data,pin=data[0]["checkpoint_signer_pin"])
    def test_wrong_retention_floor_rejected(self):
        previous=run()
        with self.assertRaisesRegex(ValueError,"contradicts exact retained prefix"):
            run(bundle("second"),history=previous,nonce=h("second"),
                floor={"phase":"RUST-085","event_count":1,"head_sha256":h("fake")})
    def test_genesis_floor_still_hold(self):
        result=run(floor={"phase":"RUST-085","event_count":0,
                          "head_sha256":genesis()["head_sha256"]})
        self.assertFalse(result["release_authorized"])
    def test_historical_quarantine_erasure_rejected(self):
        result=run();result["quarantined_claims"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):checked_history(result)
    def test_historical_control_record_mutation_rejected(self):
        result=run();result["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):checked_history(result)
    def test_historical_denial_snapshot_erasure_rejected(self):
        result=run();result["denial_snapshots"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):checked_history(result)
    def test_invalid_signature_rejected(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=bad)
if __name__=="__main__":
    unittest.main()
