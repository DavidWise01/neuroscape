import copy
import unittest
from lineage_rust019 import digest
from witness_rotation_rust065 import audit,genesis,hold,checked_history
from test_fork_highwater_rust064 import fixture,run as highwater_run,h,verify

def materials(tag="one"):
    args=fixture()
    registry=args[1]
    source=highwater_run(args)
    if tag!="one":
        source=copy.deepcopy(source)
        source["observation_epoch_tag"]=tag
        source["receipt_sha256"]=digest({k:v for k,v in source.items()
                                         if k!="receipt_sha256"})
    return source,registry

def rotation(source,registry,tag="one",bad=None,new=None,root=None,successor_root=None):
    witness=registry["events"][0]["witnesses"][0]
    return {
        "compromised_pin":bad or witness["pin"],
        "replacement_pin":new or h("replacement-"+tag),
        "compromised_controller_sha256":root or witness["operator_control_sha256"],
        "replacement_controller_sha256":successor_root or witness["operator_control_sha256"],
        "replacement_source_root_sha256":h("replacement-root-"+tag),
        "replacement_acquisition_sha256":h("replacement-acquisition-"+tag),
        "nonce_sha256":h("rotation-nonce-"+tag),
        "incident_sha256":h("incident-"+tag),
        "authority_public_key":"revoker.pem",
        "authority_signature":"revoker.sig",
    }

def make(tag="one",history=None,change=None,pin=None,floor=None,verifier=verify):
    source,registry=materials(tag)
    item=rotation(source,registry,tag)
    if change:change(item,source,registry)
    return audit(source,registry,history or genesis(),item,
                 pin or h("authority-pin"),floor,verifier=verifier)

class WitnessRotationTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_WITNESS_REVOCATION_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_first_revocation_quarantined(self):
        x=make()
        self.assertEqual(x["event_count"],1)
        self.assertTrue(x["events"][0]["quarantined"])
        self.assertFalse(x["independent_recovery_verified"])
        self.assertFalse(x["release_authorized"])

    def test_reused_revoked_controller_flagged(self):
        x=make()
        self.assertIn("REPLACEMENT_REUSES_REVOKED_CONTROLLER",
                      [c["reason"] for c in x["rotation_conflicts"]])

    def test_historical_forks_preserved(self):
        x=make()
        _,registry=materials()
        self.assertEqual(x["source_fork_keys_preserved"],registry["fork_keys"])

    def test_new_controller_still_hold(self):
        x=make(change=lambda item,*_:item.update(
            replacement_controller_sha256=h("apparently-new-controller")))
        self.assertFalse(x["release_authorized"])

    def test_unobserved_revoked_pin_rejected(self):
        with self.assertRaisesRegex(ValueError,"never observed"):
            make(change=lambda item,*_:item.update(
                compromised_pin=h("unknown-pin")))

    def test_controller_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError,"does not match"):
            make(change=lambda item,*_:item.update(
                compromised_controller_sha256=h("wrong-controller")))

    def test_replacement_equals_revoked_denied(self):
        with self.assertRaisesRegex(ValueError,"replacement signing key revoked"):
            make(change=lambda item,*_:item.update(
                replacement_pin=item["compromised_pin"]))

    def test_authority_cannot_be_revoked_signer(self):
        s,registry=materials()
        with self.assertRaisesRegex(ValueError,"self-issued"):
            make(pin=registry["events"][0]["witnesses"][0]["pin"])

    def test_authority_cannot_be_successor(self):
        with self.assertRaisesRegex(ValueError,"self-issued"):
            make(pin=h("replacement-one"))

    def test_duplicate_revocation_denied(self):
        first=make()
        with self.assertRaisesRegex(ValueError,"duplicate revocation"):
            make("two",history=first)

    def test_nonce_replay_rejected(self):
        first=make()
        second_pin=materials()[1]["events"][0]["witnesses"][1]["pin"]
        def alternate(item,*_):
            item.update(compromised_pin=second_pin,
                        compromised_controller_sha256=h("controller-b"),
                        nonce_sha256=h("rotation-nonce-one"))
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            make("two",history=first,change=alternate)

    def test_prior_history_tamper_rejected(self):
        prior=make()
        prior["events"][0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            checked_history(prior)

    def test_revocation_erasure_rejected(self):
        prior=make()
        prior["revoked_signer_pins"]=[]
        with self.assertRaises(ValueError):
            checked_history(prior)

    def test_retained_floor_fork_rejected(self):
        prior=make()
        _,registry=materials()
        second_pin=registry["events"][0]["witnesses"][1]["pin"]
        change=lambda item,*_:item.update(
            compromised_pin=second_pin,
            compromised_controller_sha256=registry["events"][0]["witnesses"][1][
                "operator_control_sha256"])
        with self.assertRaisesRegex(ValueError,"highwater forked"):
            make("two",history=prior,change=change,
                 floor={"phase":"RUST-065","event_count":1,
                        "head_sha256":h("false-head")})

    def test_genesis_floor_remains_hold(self):
        result=make(floor={"phase":"RUST-065","event_count":0,
                           "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(result["retained_floor_compared"])
        self.assertFalse(result["release_authorized"])

    def test_signature_failure_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):
            make(verifier=reject)

    def test_rotated_known_signer_logged(self):
        registry=materials()[1]
        pin=registry["events"][0]["witnesses"][1]["pin"]
        root=registry["events"][0]["witnesses"][1]["operator_control_sha256"]
        result=make(change=lambda item,*_:item.update(
            replacement_pin=pin,
            replacement_controller_sha256=root))
        self.assertIn("REPLACEMENT_KEY_ALREADY_OBSERVED",
                      [c["reason"] for c in result["rotation_conflicts"]])

if __name__=="__main__":
    unittest.main()
