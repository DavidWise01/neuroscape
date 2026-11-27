import copy,unittest
from lineage_rust019 import digest
from custodian_ancestry_rust079 import (
    audit,genesis,hold,checked_history,contradictions,claim_row)
from test_fork_branch_highwater_rust078 import (
    fixture,run as highwater_run,h,verify)

def materials(tag="one"):
    parts=fixture()
    source=highwater_run(parts)
    custody=parts[1]
    if tag!="one":
        source=copy.deepcopy(source)
        source["ancestry_epoch_tag"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    return [source,custody]

def run(bundle=None,history=None,nonce=None,pin=None,floor=None,verifier=verify):
    source,custody=bundle or materials()
    return audit(source,custody,history or genesis(),
                 nonce or h("079-nonce"),pin or h("079-external-signer"),
                 "registrar.pem","registrar.sig",floor,verifier=verifier)

class CustodianAncestryTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_ANCESTRY_EVIDENCE")
        self.assertFalse(hold()["fork_resolved"])
    def test_first_snapshot_always_hold(self):
        result=run()
        self.assertEqual(result["event_count"],1)
        self.assertTrue(result["both_branches_retained"])
        self.assertFalse(result["independent_custody_verified"])
        self.assertFalse(result["release_authorized"])
    def test_claims_bound_to_both_branches(self):
        source,custody=materials()
        result=run([source,custody])
        pair=result["events"][0]["claims"]
        self.assertEqual([c["role"] for c in pair],["a","b"])
        self.assertEqual([c["branch_sha256"] for c in pair],
                         [custody["events"][-1]["branch_a_sha256"],
                          custody["events"][-1]["branch_b_sha256"]])
    def test_claims_retain_controller_and_acquisition(self):
        source,custody=materials()
        result=run([source,custody])
        w=custody["events"][-1]["branches"][0]
        self.assertEqual(result["custodian_claims"][0]["controller_sha256"],
                         w["controller_sha256"])
        self.assertEqual(result["custodian_claims"][0]["acquisition_sha256"],
                         w["acquisition_sha256"])
    def test_history_appended_without_erasure(self):
        first=run()
        second=run(materials("two"),history=first,nonce=h("079-nonce-two"))
        self.assertEqual(second["event_count"],2)
        self.assertEqual(second["events"][:1],first["events"])
        self.assertEqual(second["prefix_heads"][:2],first["prefix_heads"])
        self.assertEqual(second["custodian_claims"][:2],first["custodian_claims"])
    def test_reused_highwater_rejected(self):
        first=run()
        with self.assertRaisesRegex(ValueError,"replayed RUST-078"):
            run(history=first,nonce=h("new-nonce"))
    def test_reused_nonce_rejected(self):
        first=run()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(materials("two"),history=first)
    def test_reused_branch_custody_nonce_rejected(self):
        source,custody=materials()
        bad=custody["events"][0]["branches"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run([source,custody],nonce=bad)
    def test_source_claims_tamper_rejected(self):
        source,custody=materials()
        source["current_claim_digests"]=[]
        with self.assertRaises(ValueError):run([source,custody])
    def test_source_highwater_authority_rejected(self):
        source,custody=materials()
        source["fork_resolved"]=True
        with self.assertRaises(ValueError):run([source,custody])
    def test_source_branch_history_rewrite_rejected(self):
        source,custody=materials()
        custody["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):run([source,custody])
    def test_source_custodian_cannot_self_sign(self):
        source,custody=materials()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run([source,custody],pin=custody["events"][0]["branches"][0]["pin"])
    def test_source_highwater_signer_cannot_self_sign(self):
        source,custody=materials()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run([source,custody],pin=source["checkpoint_signer_pin"])
    def test_floor_wrong_head_rejected(self):
        previous=run()
        with self.assertRaisesRegex(ValueError,"contradicts prefix"):
            run(materials("two"),history=previous,nonce=h("079-nonce-two"),
                floor={"phase":"RUST-079","event_count":1,
                       "head_sha256":h("false-floor")})
    def test_valid_genesis_floor_stays_hold(self):
        result=run(floor={"phase":"RUST-079","event_count":0,
                          "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(result["retained_floor_compared"])
        self.assertFalse(result["recovery_authorized"])
    def test_history_claim_removal_rejected(self):
        old=run();old["custodian_claims"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):checked_history(old)
    def test_history_conflict_erasure_rejected(self):
        old=run()
        old["events"][0]["conflicts"]=[{"reason":"synthetic"}]
        with self.assertRaises(ValueError):checked_history(old)
    def test_historical_resolution_rejected(self):
        old=run();old["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):checked_history(old)
    def test_renamed_controller_conflict(self):
        source,custody=materials()
        original=[claim_row(custody["events"][-1],"a")]
        clone=copy.deepcopy(original[0])
        clone["signer_pin"]=h("new-renamed-key")
        findings=contradictions(original,[clone,claim_row(custody["events"][-1],"b")])
        self.assertIn("RENAMED_SIGNER_SHARED_ANCESTRY",
                      [f["reason"] for f in findings])
    def test_same_signer_changed_controller_conflict(self):
        _,custody=materials()
        original=[claim_row(custody["events"][-1],"a")]
        changed=copy.deepcopy(original[0])
        changed["controller_sha256"]=h("different-controller")
        findings=contradictions(original,[changed,claim_row(custody["events"][-1],"b")])
        self.assertIn("SAME_SIGNER_CHANGED_ANCESTRY",
                      [f["reason"] for f in findings])
    def test_cross_branch_shared_control_conflict(self):
        _,custody=materials()
        a=claim_row(custody["events"][-1],"a")
        b=claim_row(custody["events"][-1],"b")
        b["controller_sha256"]=a["controller_sha256"]
        self.assertIn("COMPETING_BRANCHES_SHARE_ANCESTRY",
                      [x["reason"] for x in contradictions([],[a,b])])
    def test_invalid_signature_rejected(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=bad)
if __name__=="__main__":unittest.main()
