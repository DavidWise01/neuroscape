import copy,unittest
from lineage_rust019 import digest
from external_control_rust059 import audit,genesis,hold,checked_history
from test_custodian_highwater_rust058 import fixture,run,h,verify

def source(tag):
    value=run()
    value["retained_floor_claim_sha256"]=h("external-run-"+tag)
    value["receipt_sha256"]=digest({k:v for k,v in value.items()
                                    if k!="receipt_sha256"})
    return value

def claim(tag="a",pin=None,controller=None,operator=None,acquisition=None):
    return {"custodian_pin":pin or h("custodian-pin"),
            "claimed_controller_sha256":controller or h("controller"),
            "claimed_operator_sha256":operator or h("operator"),
            "claimed_acquisition_sha256":acquisition or h("acquisition"),
            "nonce_sha256":h("nonce-"+tag),
            "external_evidence_sha256":h("external-evidence-"+tag),
            "custodian_public_key":"custodian.pem",
            "custodian_signature":"custodian.sig",
            "authority_public_key":"authority.pem",
            "authority_signature":"authority.sig"}

def first():
    return audit(source("a"),genesis(),claim(),h("authority-pin"),
                 verifier=verify)

class ExternalControlTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_CONTROL_CHALLENGE")
        self.assertFalse(hold()["release_authorized"])
    def test_first_signed_claim_still_hold(self):
        v=first()
        self.assertEqual(v["event_count"],1)
        self.assertFalse(v["independent_external_control_verified"])
        self.assertFalse(v["release_authorized"])
    def test_history_extension(self):
        prior=first()
        v=audit(source("b"),prior,claim("b"),h("authority-pin"),
                verifier=verify)
        self.assertEqual(v["events"][:1],prior["events"])
        self.assertEqual(v["prefix_heads"][:2],prior["prefix_heads"])
    def test_new_key_same_controller_flagged(self):
        prior=first()
        v=audit(source("b"),prior,claim("b",pin=h("new-pin")),
                h("authority-pin"),verifier=verify)
        self.assertTrue(any(c["reason"]=="NEW_PIN_SHARED_CLAIMED_CONTROLLER_SHA256"
                            for c in v["control_conflicts"]))
    def test_same_key_new_controller_flagged(self):
        prior=first()
        v=audit(source("b"),prior,claim("b",controller=h("new-controller")),
                h("authority-pin"),verifier=verify)
        self.assertTrue(any("SAME_PIN_CHANGED_CLAIMED_CONTROLLER" in c["reason"]
                            for c in v["control_conflicts"]))
    def test_same_key_changed_acquisition_flagged(self):
        prior=first()
        v=audit(source("b"),prior,claim("b",acquisition=h("changed")),
                h("authority-pin"),verifier=verify)
        self.assertTrue(any("ACQUISITION" in c["reason"]
                            for c in v["control_conflicts"]))
    def test_replayed_nonce_rejected(self):
        prior=first()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            audit(source("b"),prior,claim("a"),h("authority-pin"),
                  verifier=verify)
    def test_replayed_source_receipt_rejected(self):
        s=source("a")
        prior=audit(s,genesis(),claim(),h("authority-pin"),verifier=verify)
        with self.assertRaisesRegex(ValueError,"source receipt replay"):
            audit(s,prior,claim("b"),h("authority-pin"),verifier=verify)
    def test_self_attested_authority_rejected(self):
        with self.assertRaisesRegex(ValueError,"self-attestation"):
            audit(source("a"),genesis(),claim(),h("custodian-pin"),verifier=verify)
    def test_prior_custodian_as_authority_rejected(self):
        with self.assertRaisesRegex(ValueError,"self-attestation"):
            audit(source("b"),first(),claim("b",pin=h("new-pin")),
                  h("custodian-pin"),verifier=verify)
    def test_bad_signature_rejected(self):
        def bad(*_):raise ValueError("signature invalid")
        with self.assertRaisesRegex(ValueError,"signature invalid"):
            audit(source("a"),genesis(),claim(),h("authority-pin"),verifier=bad)
    def test_wrong_floor_rejected(self):
        with self.assertRaisesRegex(ValueError,"floor"):
            audit(source("b"),first(),claim("b"),h("authority-pin"),
                  floor={"phase":"RUST-059","event_count":1,
                         "head_sha256":h("false")},verifier=verify)
    def test_genesis_floor_preserves_hold(self):
        v=audit(source("a"),genesis(),claim(),h("authority-pin"),
                floor={"phase":"RUST-059","event_count":0,
                       "head_sha256":genesis()["head_sha256"]},verifier=verify)
        self.assertFalse(v["release_authorized"])
    def test_previous_conflict_erasure_rejected(self):
        prior=audit(source("b"),first(),claim("b",pin=h("new-pin")),
                    h("authority-pin"),verifier=verify)
        prior["control_conflicts"]=[]
        with self.assertRaises(ValueError):
            checked_history(prior)
    def test_previous_event_modification_rejected(self):
        prior=first()
        prior["events"][0]["claimed_operator_sha256"]=h("forged")
        with self.assertRaises(ValueError):
            checked_history(prior)
    def test_upstream_authority_rejected(self):
        s=source("a")
        s["release_authorized"]=True
        s["receipt_sha256"]=digest({k:v for k,v in s.items()
                                    if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"authority"):
            audit(s,genesis(),claim(),h("authority-pin"),verifier=verify)

if __name__=="__main__":unittest.main()
