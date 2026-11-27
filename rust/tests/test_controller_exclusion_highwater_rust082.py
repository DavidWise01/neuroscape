import unittest
from controller_exclusion_highwater_rust082 import (
    audit,highwater,hold,conflicts_from_prior,EXCLUSIONS,DENIAL_FIELDS)
from test_controller_exclusion_rust081 import run as exclusion_run,sample,h,verify

def fixture():
    previous=exclusion_run()
    current=exclusion_run(sample("two"),history=previous,nonce=h("081-nonce-two"))
    event=current["events"][-1]
    observation={
        "phase":"RUST-082",
        "exclusion_entry_sha256":event["entry_sha256"],
        "observation_nonce_sha256":h("082-fresh-observation"),
        "denied_reentries_sha256":__import__("lineage_rust019").digest(event["denied_reentries"]),
        "excluded_controllers_sha256":__import__("lineage_rust019").digest(event["excluded_controllers"]),
        "excluded_acquisitions_sha256":__import__("lineage_rust019").digest(event["excluded_acquisitions"]),
        "all_reentries_denied":True,"both_branches_retained":True,
        "independent_custody_verified":False,"winner_selected":False,
        "fork_resolved":False,"recovery_authorized":False,"release_authorized":False}
    floor={"phase":"RUST-082","event_count":previous["event_count"],
           "head_sha256":previous["head_sha256"]}
    return [previous,current,highwater(previous),floor,[observation]]

def run(bundle=None,pin=None,verifier=verify):
    before,after,cp,floor,obs=bundle or fixture()
    return audit(before,after,cp,"highwater.pem","highwater.sig",
                 pin or h("082-independent-highwater-key"),floor,obs,
                 verifier=verifier)

class ExclusionHighwaterTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        x=hold()
        self.assertEqual(x["status"],"HOLD_MISSING_CONTROLLER_EXCLUSION_HIGHWATER")
        self.assertFalse(x["release_authorized"])
    def test_strict_extension_still_hold(self):
        x=run()
        self.assertEqual((x["previous_count"],x["current_count"]),(1,2))
        self.assertTrue(x["all_reentries_denied"])
        self.assertFalse(x["independent_custody_verified"])
    def test_all_four_exclusion_lists_retained(self):
        x=run()
        for name in EXCLUSIONS:
            self.assertEqual(x["current_"+name][:len(x["historical_"+name])],
                             x["historical_"+name])
    def test_denial_and_conflict_history_retained(self):
        x=run()
        for name in DENIAL_FIELDS:
            self.assertEqual(x["current_"+name][:len(x["historical_"+name])],
                             x["historical_"+name])
    def test_both_branches_still_denied(self):
        x=run()
        self.assertEqual([c["role"] for c in x["current_denied_reentries"][-2:]],
                         ["a","b"])
        self.assertFalse(x["fork_resolved"])
    def test_reentry_overlap_flagged(self):
        reasons=[c["reason"] for c in run()["cross_epoch_reentry_conflicts"]]
        self.assertIn("REENTRY_MATCHES_SIGNED_PRIOR_EXCLUSION",reasons)
    def test_renamed_key_control_overlap_flagged(self):
        before=exclusion_run()
        row=dict(before["denied_reentries"][0])
        row["signer_pin"]=h("renamed-but-same-control")
        evidence=conflicts_from_prior(before,[row])
        self.assertIn("controller_sha256",evidence[0]["matched_fields"])
    def test_no_prior_match_does_not_grant_release(self):
        before=exclusion_run()
        row=dict(before["denied_reentries"][0])
        for field in ("signer_pin","controller_sha256","source_root_sha256",
                      "acquisition_sha256"):
            row[field]=h("completely-new-"+field)
        findings=conflicts_from_prior(before,[row])
        self.assertEqual(findings[0]["reason"],
                         "UNQUALIFIED_REENTRY_DENIED_WITHOUT_PRIOR_MATCH")
    def test_rollback_rejected(self):
        b=fixture();b[1]=b[0]
        with self.assertRaisesRegex(ValueError,"strict successor"):run(b)
    def test_prior_history_edit_rejected(self):
        b=fixture();b[1]["events"][0]["recovery_authorized"]=True
        with self.assertRaises(ValueError):run(b)
    def test_denial_erasure_rejected(self):
        b=fixture();b[1]["denied_reentries"]=[]
        with self.assertRaises(ValueError):run(b)
    def test_excluded_controller_erasure_rejected(self):
        b=fixture();b[1]["excluded_controllers"]=[]
        with self.assertRaises(ValueError):run(b)
    def test_checkpoint_substitution_rejected(self):
        b=fixture();b[2]["head_sha256"]=h("fake-highwater")
        with self.assertRaisesRegex(ValueError,"substituted"):run(b)
    def test_false_retention_floor_rejected(self):
        b=fixture();b[3]["head_sha256"]=h("forked-floor")
        with self.assertRaisesRegex(ValueError,"contradicts exact prefix"):run(b)
    def test_ahead_floor_rejected(self):
        b=fixture();b[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside known"):run(b)
    def test_excluded_signer_cannot_sign_checkpoint(self):
        b=fixture()
        with self.assertRaisesRegex(ValueError,"cannot sign"):
            run(b,pin=b[1]["excluded_signer_pins"][0])
    def test_denial_registrar_cannot_sign_checkpoint(self):
        b=fixture()
        with self.assertRaisesRegex(ValueError,"cannot sign"):
            run(b,pin=b[1]["events"][0]["registrar_pin"])
    def test_missing_observation_rejected(self):
        b=fixture();b[4]=[]
        with self.assertRaisesRegex(ValueError,"one new controller-denial"):run(b)
    def test_denial_snapshot_substitution_rejected(self):
        b=fixture();b[4][0]["denied_reentries_sha256"]=h("different")
        with self.assertRaisesRegex(ValueError,"snapshot or ancestry substituted"):run(b)
    def test_acquisition_snapshot_substitution_rejected(self):
        b=fixture();b[4][0]["excluded_acquisitions_sha256"]=h("different")
        with self.assertRaisesRegex(ValueError,"snapshot or ancestry substituted"):run(b)
    def test_nonce_replay_rejected(self):
        b=fixture()
        b[4][0]["observation_nonce_sha256"]=b[1]["events"][0]["challenge_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(b)
    def test_false_denial_clearance_rejected(self):
        b=fixture();b[4][0]["all_reentries_denied"]=False
        with self.assertRaisesRegex(ValueError,"fabricated recovery"):run(b)
    def test_false_independent_custody_rejected(self):
        b=fixture();b[4][0]["independent_custody_verified"]=True
        with self.assertRaisesRegex(ValueError,"fabricated recovery"):run(b)
    def test_fabricated_release_rejected(self):
        b=fixture();b[4][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"fabricated recovery"):run(b)
    def test_invalid_signature_rejected(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=bad)

if __name__=="__main__":unittest.main()
