import copy,unittest
from lineage_rust019 import digest
from custodian_exclusion_rust071 import audit,genesis,hold,checked_history
from test_witness_exclusion_rust070 import run as highwater_run,h,verify

def source(tag="first",new_exclusion=False):
    s=highwater_run()
    if tag!="first":
        s=copy.deepcopy(s)
        s["epoch_label"]=tag
        if new_exclusion:
            s["current_revoked_pins_preserved"].append(h("revoked-extra-"+tag))
            s["current_revoked_roots_preserved"].append(h("revoked-root-extra-"+tag))
        s["receipt_sha256"]=digest({k:v for k,v in s.items()
                                    if k!="receipt_sha256"})
    return s

def candidate(pin=None,controller=None,acquisition=None):
    return {"signer_pin":pin or h("candidate"),
            "controller_sha256":controller or h("candidate-controller"),
            "source_root_sha256":h("candidate-root"),
            "acquisition_sha256":acquisition or h("candidate-acq")}

def run(s=None,history=None,claim=None,nonce=None,challenger=None,floor=None,
        verifier=verify):
    return audit(s or source(),history or genesis(),claim or candidate(),
                 nonce or h("nonce-first"),challenger or h("outside-challenger"),
                 "outside.pem","outside.sig",floor,verifier=verifier)

class CustodianExclusionTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODIAN_EXCLUSION_EVIDENCE")
        self.assertFalse(hold()["recovery_authorized"])
    def test_first_recovery_denial(self):
        x=run()
        self.assertEqual(x["event_count"],1)
        self.assertTrue(x["events"][0]["recovery_denied"])
        self.assertFalse(x["release_authorized"])
    def test_preserves_all_source_exclusions(self):
        s=source()
        x=run(s)
        self.assertEqual(x["excluded_pins"],s["current_revoked_pins_preserved"])
        self.assertEqual(x["excluded_controller_roots"],s["current_revoked_roots_preserved"])
    def test_revoked_pin_reentry_recorded(self):
        s=source()
        x=run(s,claim=candidate(pin=s["current_revoked_pins_preserved"][0]))
        self.assertIn("EXCLUDED_SIGNER_REENTRY",[c["reason"] for c in x["custody_conflicts"]])
    def test_renamed_pin_excluded_controller_recorded(self):
        s=source()
        x=run(s,claim=candidate(controller=s["current_revoked_roots_preserved"][0]))
        self.assertIn("RENAMED_SIGNER_REUSES_EXCLUDED_CONTROLLER",
                      [c["reason"] for c in x["custody_conflicts"]])
    def test_new_ancestry_still_denied(self):
        self.assertFalse(run()["recovery_authorized"])
        self.assertFalse(run()["live_gameplay_authority"])
    def test_append_new_epoch(self):
        old=run()
        x=run(source("second",True),old,candidate(pin=h("new-key")),
              nonce=h("nonce-second"))
        self.assertEqual(x["events"][:1],old["events"])
        self.assertEqual(x["event_count"],2)
        self.assertEqual(x["excluded_pins"][:len(old["excluded_pins"])],
                         old["excluded_pins"])
    def test_reused_source_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"source exclusion highwater replay"):
            run(source(),old,candidate(pin=h("new-key")),nonce=h("nonce-second"))
    def test_reused_nonce_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(source("second"),old,candidate(pin=h("new-key")))
    def test_renamed_acquisition_flagged(self):
        old=run()
        x=run(source("second"),old,
              candidate(pin=h("other"),acquisition=h("candidate-acq")),
              nonce=h("nonce-second"))
        self.assertIn("RENAMED_SIGNER_SHARED_ACQUISITION",
                      [c["reason"] for c in x["custody_conflicts"]])
    def test_changed_signer_controller_flagged(self):
        old=run()
        x=run(source("second"),old,
              candidate(controller=h("changed-controller")),
              nonce=h("nonce-second"))
        self.assertIn("SAME_SIGNER_CHANGED_CLAIMED_CONTROLLER",
                      [c["reason"] for c in x["custody_conflicts"]])
    def test_history_denial_erasure_rejected(self):
        x=run();x["recovery_denials"]=[]
        with self.assertRaisesRegex(ValueError,"denial records erased"):
            checked_history(x)
    def test_history_exclusion_erasure_rejected(self):
        x=run();x["excluded_pins"]=[]
        with self.assertRaises(ValueError):checked_history(x)
    def test_historical_entry_mutation_rejected(self):
        x=run();x["events"][0]["recovery_denied"]=False
        with self.assertRaises(ValueError):checked_history(x)
    def test_retained_floor_fork_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"contradicts prefix"):
            run(source("second"),old,candidate(pin=h("other")),
                nonce=h("nonce-second"),
                floor={"phase":"RUST-071","event_count":1,"head_sha256":h("wrong")})
    def test_genesis_floor_no_release(self):
        x=run(floor={"phase":"RUST-071","event_count":0,
                     "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(x["retained_floor_compared"])
        self.assertFalse(x["recovery_authorized"])
    def test_old_exclusion_missing_rejected(self):
        old=run()
        s=source("second")
        s["current_revoked_pins_preserved"].pop(0)
        s["receipt_sha256"]=digest({k:v for k,v in s.items() if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            run(s,old,candidate(pin=h("other")),nonce=h("nonce-second"))
    def test_revoked_challenger_rejected(self):
        s=source()
        with self.assertRaisesRegex(ValueError,"cannot self-attest"):
            run(s,challenger=s["current_revoked_pins_preserved"][0])
    def test_candidate_challenger_self_attest_rejected(self):
        with self.assertRaisesRegex(ValueError,"cannot self-attest"):
            run(challenger=h("candidate"))
    def test_tampered_source_rejected(self):
        s=source();s["release_authorized"]=True
        with self.assertRaises(ValueError):run(s)
    def test_invalid_signature_rejected(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=bad)
if __name__=="__main__":unittest.main()
