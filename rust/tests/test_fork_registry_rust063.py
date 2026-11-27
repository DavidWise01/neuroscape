import copy
import unittest
from lineage_rust019 import digest
from fork_registry_rust063 import audit,genesis,hold,checked_history
from test_retention_highwater_rust062 import run as report, h, verify

def source(tag="first"):
    value=report()
    value["retained_floor_claim_sha256"]=h("source-"+tag)
    value["receipt_sha256"]=digest({k:v for k,v in value.items()
                                    if k!="receipt_sha256"})
    return value

def witnesses(tag="first",shared=False,rename=False):
    claims=[]
    for role in ("a","b"):
        claims.append({
            "signer_pin":h(("renamed-" if rename else "pin-")+role),
            "source_root_sha256":h("shared-root" if shared else "root-"+role),
            "acquisition_sha256":h("shared-acq" if shared else "acq-"+role),
            "operator_control_sha256":h("shared-controller" if shared
                                        else "controller-"+role),
            "public_key":role+".pem","signature":role+".sig",
            "fork_resolved":False,"release_authorized":False})
    return claims,[h("nonce-"+tag+"-"+role) for role in ("a","b")]

def run(s=None,history=None,claims=None,nonces=None,floor=None,verifier=verify):
    cs,ns=witnesses()
    return audit(s or source(),history or genesis(),
                 claims if claims is not None else cs,
                 nonces if nonces is not None else ns,
                 floor=floor,verifier=verifier)

class ForkRegistryTests(unittest.TestCase):
    def test_missing_external_witness_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_FORK_RETENTION_CHALLENGES")
        self.assertFalse(hold()["release_authorized"])
    def test_first_registry_entry_no_winner(self):
        out=run()
        self.assertEqual(out["event_count"],1)
        self.assertEqual(len(out["events"][0]["witnesses"]),2)
        self.assertFalse(out["winner_selected"])
        self.assertFalse(out["independent_custody_verified"])
    def test_every_fork_key_retained(self):
        out=run()
        self.assertEqual(len(out["fork_keys"]),len(source()["current_forks_preserved"]))
        self.assertEqual(out["events"][0]["fork_keys"],out["fork_keys"])
    def test_append_only_second_epoch(self):
        first=run()
        claims,nonces=witnesses("second")
        later=run(source("second"),first,claims,nonces)
        self.assertEqual(later["events"][:1],first["events"])
        self.assertEqual(later["prefix_heads"][:2],first["prefix_heads"])
        self.assertEqual(later["fork_keys"],first["fork_keys"])
    def test_shared_ancestry_recorded(self):
        claims,nonces=witnesses(shared=True)
        out=run(claims=claims,nonces=nonces)
        self.assertEqual(len(out["custody_conflicts"]),3)
    def test_renamed_controller_flag(self):
        prior=run()
        claims,nonces=witnesses("second",rename=True)
        later=run(source("second"),prior,claims,nonces)
        self.assertTrue(any(c["reason"]=="RENAMED_CUSTODIAN_REUSED_CONTROLLER"
                            for c in later["custody_conflicts"]))
    def test_replayed_nonce_rejected(self):
        prior=run()
        claims,nonces=witnesses("first")
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(source("second"),prior,claims,nonces)
    def test_repeat_source_receipt_rejected(self):
        prior=run()
        claims,nonces=witnesses("second")
        with self.assertRaisesRegex(ValueError,"source receipt replay"):
            run(source(),prior,claims,nonces)
    def test_witness_self_attestation_rejected(self):
        claims,nonces=witnesses()
        claims[0]["signer_pin"]=source()["checkpoint_pin"]
        with self.assertRaisesRegex(ValueError,"self-attesting"):
            run(claims=claims,nonces=nonces)
    def test_duplicate_pins_rejected(self):
        claims,nonces=witnesses()
        claims[1]["signer_pin"]=claims[0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"repeated"):
            run(claims=claims,nonces=nonces)
    def test_missing_witness_rejected(self):
        cs,ns=witnesses()
        with self.assertRaisesRegex(ValueError,"two fresh"):
            run(claims=cs[:1],nonces=ns[:1])
    def test_tampered_prior_event_rejected(self):
        prior=run()
        prior["events"][0]["forks"][0]["left"]=h("forgery")
        with self.assertRaises(ValueError):
            checked_history(prior)
    def test_erased_historical_conflicts_rejected(self):
        claims,nonces=witnesses(shared=True)
        prior=run(claims=claims,nonces=nonces)
        prior["custody_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):
            checked_history(prior)
    def test_removed_historical_fork_rejected(self):
        prior=run()
        next_source=source("second")
        next_source["current_forks_preserved"].pop()
        next_source["current_count"]-=1
        next_source["receipt_sha256"]=digest({
            k:v for k,v in next_source.items() if k!="receipt_sha256"})
        cs,ns=witnesses("second")
        with self.assertRaisesRegex(ValueError,"removed"):
            run(next_source,prior,cs,ns)
    def test_retained_floor_conflict_rejected(self):
        prior=run()
        cs,ns=witnesses("second")
        with self.assertRaisesRegex(ValueError,"rollback"):
            run(source("second"),prior,cs,ns,
                floor={"phase":"RUST-063","event_count":1,
                       "head_sha256":h("wrong")})
    def test_genesis_floor_without_authority(self):
        x=run(floor={"phase":"RUST-063","event_count":0,
                     "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(x["retained_floor_compared"])
        self.assertFalse(x["release_authorized"])
    def test_bad_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)
    def test_witness_cannot_claim_fork_resolved(self):
        cs,ns=witnesses()
        cs[0]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"clear fork"):
            run(claims=cs,nonces=ns)
if __name__=="__main__":
    unittest.main()
