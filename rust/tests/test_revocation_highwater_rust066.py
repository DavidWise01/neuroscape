import copy
import unittest
from lineage_rust019 import digest
from revocation_highwater_rust066 import (
    audit, checkpoint_payload, hold, ancestry_conflicts)
from test_witness_rotation_rust065 import make, materials, h, verify

def fixture():
    first=make("one")
    _, registry=materials("two")
    second_witness=registry["events"][0]["witnesses"][1]
    def rotate(item,*_):
        item.update({
            "compromised_pin":second_witness["pin"],
            "compromised_controller_sha256":
                second_witness["operator_control_sha256"],
            "replacement_controller_sha256":
                first["events"][0]["replacement_controller_sha256"],
            "replacement_acquisition_sha256":
                first["events"][0]["replacement_acquisition_sha256"],
        })
    later=make("two",history=first,change=rotate)
    last=later["events"][-1]
    observations=[{
        "phase":"RUST-066",
        "revocation_entry_sha256":last["entry_sha256"],
        "observation_nonce_sha256":h("new-observation-nonce"),
        "claimed_controller_sha256":last["replacement_controller_sha256"],
        "claimed_acquisition_sha256":last["replacement_acquisition_sha256"],
        "recovery_authorized":False,
        "release_authorized":False,
    }]
    floor={"phase":"RUST-066","revocation_count":first["event_count"],
           "head_sha256":first["head_sha256"]}
    return [first,later,checkpoint_payload(first),floor,observations]

def run(data=None, signer=None, verifier=verify):
    first,later,checkpoint,floor,observations=data or fixture()
    return audit(first,later,checkpoint,"highwater.pem","highwater.sig",
                 signer or h("third-party-highwater-pin"),floor,observations,
                 verifier=verifier)

class RevocationHighwaterTests(unittest.TestCase):
    def test_missing_evidence_is_hold(self):
        self.assertEqual(hold()["status"],
                         "HOLD_MISSING_REVOCATION_SUCCESSOR_HIGHWATER")
        self.assertFalse(hold()["release_authorized"])

    def test_signed_extension_is_quarantined(self):
        result=run()
        self.assertEqual(result["previous_revocation_count"],1)
        self.assertEqual(result["current_revocation_count"],2)
        self.assertTrue(result["all_successors_quarantined"])
        self.assertFalse(result["independent_custody_verified"])
        self.assertFalse(result["release_authorized"])

    def test_original_revocations_preserved(self):
        result=run()
        first,later,*_=fixture()
        self.assertEqual(result["revoked_signer_pins_preserved"],
                         later["revoked_signer_pins"])
        self.assertEqual(result["historical_conflicts_preserved"],
                         first["rotation_conflicts"])

    def test_reused_controller_detected(self):
        rows=run()["successor_ancestry_conflicts"]
        self.assertIn("SUCCESSOR_REUSES_PRIOR_CONTROL_ROOT",
                      [x["reason"] for x in rows])

    def test_reused_acquisition_detected(self):
        rows=run()["successor_ancestry_conflicts"]
        self.assertIn("SUCCESSOR_REUSES_PRIOR_ACQUISITION",
                      [x["reason"] for x in rows])

    def test_new_root_still_no_authority(self):
        data=fixture()
        fresh=copy.deepcopy(data[1]["events"][-1])
        fresh["replacement_controller_sha256"]=h("new-control-root")
        fresh["replacement_acquisition_sha256"]=h("new-acquisition")
        fresh["replacement_source_root_sha256"]=h("new-source")
        self.assertFalse(run()["live_gameplay_authority"])

    def test_stale_successor_rejected(self):
        data=fixture()
        data[1]=data[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):
            run(data)

    def test_previous_entry_tamper_rejected(self):
        data=fixture()
        data[1]["events"][0]["quarantined"]=False
        with self.assertRaises(ValueError):
            run(data)

    def test_signed_checkpoint_substitution_rejected(self):
        data=fixture()
        data[2]["head_sha256"]=h("wrong-head")
        with self.assertRaisesRegex(ValueError,"substituted"):
            run(data)

    def test_floor_branch_conflict_rejected(self):
        data=fixture()
        data[3]["head_sha256"]=h("fork-head")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):
            run(data)

    def test_floor_outside_known_history_rejected(self):
        data=fixture()
        data[3]["revocation_count"]=3
        with self.assertRaisesRegex(ValueError,"outside successor history"):
            run(data)

    def test_revoked_key_cannot_sign_highwater(self):
        data=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(data,signer=data[0]["revoked_signer_pins"][0])

    def test_replacement_cannot_sign_highwater(self):
        data=fixture()
        with self.assertRaisesRegex(ValueError,"cannot self-sign"):
            run(data,signer=data[0]["events"][0]["replacement_pin"])

    def test_missing_observation_rejected(self):
        data=fixture()
        data[4]=[]
        with self.assertRaisesRegex(ValueError,"one successor custody"):
            run(data)

    def test_observation_wrong_event_rejected(self):
        data=fixture()
        data[4][0]["revocation_entry_sha256"]=h("wrong-event")
        with self.assertRaisesRegex(ValueError,"not bound"):
            run(data)

    def test_observation_ancestry_substitution_rejected(self):
        data=fixture()
        data[4][0]["claimed_acquisition_sha256"]=h("other-acquisition")
        with self.assertRaisesRegex(ValueError,"changed claimed ancestry"):
            run(data)

    def test_replayed_rotation_nonce_rejected(self):
        data=fixture()
        data[4][0]["observation_nonce_sha256"]=data[1]["events"][-1]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"observation replay"):
            run(data)

    def test_authority_escalation_rejected(self):
        data=fixture()
        data[4][0]["recovery_authorized"]=True
        with self.assertRaisesRegex(ValueError,"restoration of authority"):
            run(data)

    def test_signature_failure_rejected(self):
        def invalid(*_):
            raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=invalid)

    def test_same_replacement_pin_changed_ancestry_detected(self):
        first={"replacement_pin":h("pin"),
               "compromised_controller_sha256":h("old-controller"),
               "replacement_controller_sha256":h("control"),
               "replacement_source_root_sha256":h("root"),
               "replacement_acquisition_sha256":h("acquisition")}
        second=dict(first, replacement_controller_sha256=h("other-control"))
        reasons=[c["reason"] for c in ancestry_conflicts([first],[second])]
        self.assertIn("SUCCESSOR_KEY_CHANGED_CLAIMED_ANCESTRY",reasons)

if __name__=="__main__":
    unittest.main()
