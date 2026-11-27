import copy
import unittest
from lineage_rust019 import digest
from control_reconciliation_rust060 import audit,hold,compare,checkpoint_payload
from external_control_rust059 import audit as control_audit,genesis
from test_external_control_rust059 import source,claim,h,verify

def branch(label,pin=None,controller=None,previous=None):
    return control_audit(source(label),previous or genesis(),
                         claim(label,pin=pin,controller=controller),
                         h("external-authority-pin"),verifier=verify)

def custody(tag,root=None,acquisition=None,operator=None):
    return {"phase":"RUST-060",
            "claimed_source_root_sha256":root or h("root-"+tag),
            "acquisition_sha256":acquisition or h("acq-"+tag),
            "claimed_operator_sha256":operator or h("operator-"+tag),
            "control_nonce_sha256":h("custody-nonce-"+tag),
            "independence_authenticated":False,
            "release_authorized":False}

def inputs():
    first=branch("left")
    right=branch("right",pin=h("different-pin"),controller=h("controller-two"))
    floor={"phase":"RUST-060","control_count":1,
           "head_sha256":first["head_sha256"]}
    return [first,right,checkpoint_payload(first),floor,custody("a"),custody("b")]

def run(args=None,signer=None,verifier=verify):
    a,b,cp,floor,ca,cb=args or inputs()
    return audit(a,b,cp,"checkpoint.pem","checkpoint.sig",
                 signer or h("external-checkpoint-key"),floor,ca,cb,
                 verifier=verifier)

class ControlReconciliationTests(unittest.TestCase):
    def test_missing_material_holds(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_INDEPENDENT_CONTROL_CUSTODY")
        self.assertFalse(hold()["release_authorized"])
    def test_two_branch_fork_preserved(self):
        out=run()
        self.assertTrue(out["incompatible_history_detected"])
        self.assertEqual(out["common_prefix_count"],0)
        self.assertEqual(len(out["left_branch_events_preserved"]),1)
        self.assertEqual(len(out["right_branch_events_preserved"]),1)
        self.assertFalse(out["winner_selected"])
    def test_matching_branches_not_independent(self):
        args=inputs()
        args[1]=copy.deepcopy(args[0])
        out=run(args)
        self.assertFalse(out["incompatible_history_detected"])
        self.assertFalse(out["independent_custodians_authenticated"])
    def test_extension_not_a_fork(self):
        first=branch("left")
        extension=branch("next",previous=first)
        common,diverged,_=compare(first,extension)
        self.assertEqual(common,1)
        self.assertFalse(diverged)
    def test_shared_custody_root_alert(self):
        args=inputs()
        args[5]["claimed_source_root_sha256"]=args[4]["claimed_source_root_sha256"]
        out=run(args)
        self.assertTrue(any(c["kind"]=="SHARED_CLAIMED_EXTERNAL_CUSTODY_ANCESTRY"
                            for c in out["reconciliation_disagreements"]))
    def test_same_signer_changes_controller_detected(self):
        args=inputs()
        args[1]=branch("right",controller=h("altered-controller"))
        out=run(args)
        self.assertTrue(any(c["kind"]=="CROSS_BRANCH_KEY_CONTROL_ANCESTRY_CONFLICT"
                            for c in out["reconciliation_disagreements"]))
    def test_renamed_key_shared_controller_detected(self):
        args=inputs()
        args[1]=branch("right",pin=h("renamed-custodian"))
        out=run(args)
        self.assertTrue(any(c["kind"]=="CROSS_BRANCH_SHARED_CLAIMED_CONTROLLER"
                            for c in out["reconciliation_disagreements"]))
    def test_modified_checkpoint_rejected(self):
        args=inputs()
        args[2]["head_sha256"]=h("fake")
        with self.assertRaisesRegex(ValueError,"checkpoint altered"):
            run(args)
    def test_bad_retained_floor_rejected(self):
        args=inputs()
        args[3]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"contradicts retained floor"):
            run(args)
    def test_duplicate_external_nonces_rejected(self):
        args=inputs()
        args[5]["control_nonce_sha256"]=args[4]["control_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"duplicate external custody nonce"):
            run(args)
    def test_checkpoint_self_signed_rejected(self):
        args=inputs()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run(args,signer=args[0]["events"][0]["custodian_pin"])
    def test_forged_right_history_rejected(self):
        args=inputs()
        args[1]["events"][0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            run(args)
    def test_erased_conflicts_rejected(self):
        args=inputs()
        left=branch("prior")
        args[1]=branch("right",pin=h("renamed"),previous=left)
        args[1]["control_conflicts"]=[]
        with self.assertRaises(ValueError):
            run(args)
    def test_authority_claim_rejected(self):
        args=inputs()
        args[4]["independence_authenticated"]=True
        with self.assertRaisesRegex(ValueError,"asserted operational authority"):
            run(args)
    def test_signature_failure_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)
    def test_floor_out_of_history_rejected(self):
        args=inputs()
        args[3]["control_count"]=2
        with self.assertRaisesRegex(ValueError,"beyond signed branch"):
            run(args)

if __name__=="__main__":
    unittest.main()
