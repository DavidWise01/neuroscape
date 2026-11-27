import copy,unittest
from lineage_rust019 import digest
from controller_exclusion_rust081 import (
    audit,genesis,hold,checked_history,denial_rows,excluded_fingerprints)
from test_ancestry_highwater_rust080 import fixture,run as source_run,h,verify
from test_custodian_ancestry_rust079 import run as ancestry_run,materials

def sample(tag="one"):
    parts=fixture()
    source=source_run(parts)
    ancestry=parts[1]
    if tag!="one":
        source=copy.deepcopy(source)
        source["custody_epoch_tag"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    return [source,ancestry]

def run(bundle=None,history=None,nonce=None,pin=None,floor=None,verifier=verify):
    source,ancestry=bundle or sample()
    return audit(source,ancestry,history or genesis(),
                 pin or h("081-registry-signer"),nonce or h("081-nonce"),
                 "registrar.pem","registrar.sig",floor,verifier=verifier)

class ControllerExclusionTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CONTROLLER_EXCLUSION_EVIDENCE")
        self.assertFalse(hold()["recovery_authorized"])
    def test_dual_branch_reentry_denied(self):
        result=run()
        self.assertEqual(result["event_count"],1)
        self.assertEqual(len(result["denied_reentries"]),2)
        self.assertTrue(all(r["reentry_denied"] for r in result["denied_reentries"]))
        self.assertFalse(result["release_authorized"])
    def test_exclusions_include_all_source_ancestry(self):
        source,ancestry=sample()
        result=run([source,ancestry])
        self.assertEqual(result["excluded_signer_pins"],
                         list(dict.fromkeys(c["signer_pin"] for c in ancestry["custodian_claims"])))
        self.assertEqual(result["excluded_controllers"],
                         list(dict.fromkeys(c["controller_sha256"] for c in ancestry["custodian_claims"])))
    def test_claims_remain_two_competing_branches(self):
        r=run()["events"][0]["denied_reentries"]
        self.assertEqual([x["role"] for x in r],["a","b"])
        self.assertNotEqual(r[0]["branch_sha256"],r[1]["branch_sha256"])
    def test_reused_controller_flagged(self):
        self.assertIn("REENTRY_USES_EXCLUDED_CONTROLLER_SHA256",
                      [c["reason"] for c in run()["custody_conflicts"]])
    def test_renamed_pin_same_controller_denied(self):
        source,ancestry=sample()
        a=dict(ancestry["events"][-1]["claims"][0])
        a["signer_pin"]=h("renamed")
        b=dict(ancestry["events"][-1]["claims"][1])
        excluded={
            "excluded_signer_pins":[h("another")],
            "excluded_controllers":[a["controller_sha256"]],
            "excluded_source_roots":[],
            "excluded_acquisitions":[]}
        rows,conflicts=denial_rows([a,b],excluded)
        self.assertTrue(rows[0]["reentry_denied"])
        self.assertIn("controller_sha256",rows[0]["matched_exclusions"])
    def test_unmatched_candidate_still_denied(self):
        _,ancestry=sample()
        a,b=ancestry["events"][-1]["claims"]
        excluded={k:[] for k in ("excluded_signer_pins","excluded_controllers",
                                 "excluded_source_roots","excluded_acquisitions")}
        rows,conflicts=denial_rows([a,b],excluded)
        self.assertTrue(all(r["reentry_denied"] for r in rows))
        self.assertIn("NO_INDEPENDENT_CUSTODY_QUALIFICATION",
                      [x["reason"] for x in conflicts])
    def test_append_epoch_no_erasure(self):
        old=run()
        later=run(sample("two"),history=old,nonce=h("081-nonce-two"))
        self.assertEqual(later["event_count"],2)
        self.assertEqual(later["events"][:1],old["events"])
        self.assertEqual(later["excluded_controllers"][:len(old["excluded_controllers"])],
                         old["excluded_controllers"])
        self.assertEqual(later["denied_reentries"][:2],old["denied_reentries"])
    def test_source_replay_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"replayed ancestry"):
            run(history=old,nonce=h("other-nonce"))
    def test_nonce_replay_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(sample("two"),history=old)
    def test_old_ancestry_nonce_rejected(self):
        source,ancestry=sample()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run([source,ancestry],nonce=ancestry["events"][0]["observation_nonce_sha256"])
    def test_source_receipt_tamper_rejected(self):
        source,ancestry=sample()
        source["receipt_sha256"]=h("tampered")
        with self.assertRaises(ValueError):run([source,ancestry])
    def test_ancestry_claim_tamper_rejected(self):
        source,ancestry=sample()
        ancestry["custodian_claims"]=[]
        with self.assertRaises(ValueError):run([source,ancestry])
    def test_registrar_cannot_self_attest(self):
        source,ancestry=sample()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run([source,ancestry],pin=ancestry["events"][0]["signer_pin"])
    def test_custodian_cannot_self_attest(self):
        source,ancestry=sample()
        with self.assertRaisesRegex(ValueError,"self-sign"):
            run([source,ancestry],pin=ancestry["custodian_claims"][0]["signer_pin"])
    def test_retained_floor_mismatch_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"contradicts prefix"):
            run(sample("two"),history=old,nonce=h("081-nonce-two"),
                floor={"phase":"RUST-081","event_count":1,"head_sha256":h("wrong")})
    def test_genesis_floor_still_denied(self):
        result=run(floor={"phase":"RUST-081","event_count":0,
                          "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(result["retained_floor_compared"])
        self.assertFalse(result["recovery_authorized"])
    def test_historical_denial_erasure_rejected(self):
        history=run()
        history["denied_reentries"]=[]
        with self.assertRaisesRegex(ValueError,"records erased"):
            checked_history(history)
    def test_historical_exclusion_erasure_rejected(self):
        history=run()
        history["excluded_controllers"]=[]
        with self.assertRaises(ValueError):checked_history(history)
    def test_historical_event_mutation_rejected(self):
        history=run()
        history["events"][0]["recovery_authorized"]=True
        with self.assertRaises(ValueError):checked_history(history)
    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)
if __name__=="__main__":unittest.main()
