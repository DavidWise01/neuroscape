import copy
import unittest
from lineage_rust019 import digest
from fork_highwater_rust064 import audit,highwater,hold,compare_witnesses
from test_fork_registry_rust063 import run as fork_run,source,witnesses,h,verify

def fixture(renamed=True):
    initial=fork_run()
    claims,nonces=witnesses("second",rename=renamed)
    successor=fork_run(source("second"),initial,claims,nonces)
    checkpoint=highwater(initial)
    floor={"phase":"RUST-064","event_count":initial["event_count"],
           "head_sha256":initial["head_sha256"]}
    last=successor["events"][-1]
    observations=[{"phase":"RUST-064",
                   "fork_event_sha256":last["entry_sha256"],
                   "epoch_nonce_sha256":h("epoch-new"),
                   "claimed_controller_sha256":h("controller-a"),
                   "acquisition_sha256":h("new-acquisition"),
                   "fork_resolved":False,"release_authorized":False}]
    return [initial,successor,checkpoint,floor,observations]

def run(items=None,pin=None,verifier=verify):
    old,new,checkpoint,floor,observations=items or fixture()
    return audit(old,new,checkpoint,"highwater.pem","highwater.sig",
                 pin or h("separate-checkpoint-pin"),floor,observations,
                 verifier=verifier)

class ForkHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_FORK_REGISTRY_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])
    def test_valid_checkpoint_still_hold(self):
        result=run()
        self.assertEqual(result["previous_count"],1)
        self.assertEqual(result["current_count"],2)
        self.assertFalse(result["independent_custody_verified"])
        self.assertFalse(result["release_authorized"])
    def test_original_forks_preserved(self):
        result=run()
        self.assertEqual(result["current_forks_preserved"][:len(
            result["previous_forks_preserved"])],result["previous_forks_preserved"])
    def test_previous_conflicts_preserved(self):
        a=run()
        self.assertEqual(a["current_conflicts_preserved"][:len(
            a["historical_conflicts_preserved"])],a["historical_conflicts_preserved"])
    def test_renamed_controller_alert(self):
        a=run()
        self.assertTrue(any(c["reason"]=="RENAMED_CUSTODIAN_REUSED_CONTROL_ROOT"
                            for c in a["cross_epoch_ancestry_conflicts"]))
    def test_same_key_changed_root_alert(self):
        a={"witnesses":[{"pin":h("same"),"source_root_sha256":h("a"),
                         "acquisition_sha256":h("b"),"operator_control_sha256":h("c")}]}
        b=copy.deepcopy(a)
        b["witnesses"][0]["source_root_sha256"]=h("other")
        self.assertEqual(compare_witnesses([a],[b])[0]["reason"],
                         "SIGNER_CLAIMED_ANCESTRY_CHANGED")
    def test_stale_successor_rejected(self):
        args=fixture();args[1]=args[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):
            run(args)
    def test_fork_history_tampering_rejected(self):
        args=fixture()
        args[1]["events"][0]["forks"][0]["left"]=h("forged")
        with self.assertRaises(ValueError):run(args)
    def test_highwater_checkpoint_substitution_rejected(self):
        args=fixture();args[2]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"substituted"):run(args)
    def test_retained_floor_fork_rejected(self):
        args=fixture();args[3]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"contradicts"):run(args)
    def test_retained_floor_ahead_rejected(self):
        args=fixture();args[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor"):run(args)
    def test_checkpoint_self_signing_rejected(self):
        args=fixture();pin=args[0]["events"][0]["witnesses"][0]["pin"]
        with self.assertRaisesRegex(ValueError,"self-sign"):run(args,pin=pin)
    def test_missing_observation_rejected(self):
        args=fixture();args[4]=[]
        with self.assertRaisesRegex(ValueError,"one separate epoch"):run(args)
    def test_wrong_event_observation_rejected(self):
        args=fixture();args[4][0]["fork_event_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"not bound"):run(args)
    def test_nonce_replay_against_custody_rejected(self):
        args=fixture()
        args[4][0]["epoch_nonce_sha256"]=args[1]["events"][-1]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(args)
    def test_fork_clearance_rejected(self):
        args=fixture();args[4][0]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"asserted fork resolution"):run(args)
    def test_invalid_signature_rejected(self):
        def reject(*args):raise ValueError("invalid Ed25519 signature")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=reject)
    def test_missing_retention_material_rejected(self):
        args=fixture();args[3]=None
        with self.assertRaisesRegex(ValueError,"floor missing"):run(args)

if __name__=="__main__":
    unittest.main()
