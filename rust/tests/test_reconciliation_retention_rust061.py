import copy
import unittest
from lineage_rust019 import digest
from reconciliation_retention_rust061 import audit,genesis,hold,checked_history
from test_control_reconciliation_rust060 import inputs,run,h,verify

def source(tag="a",fork=True):
    out=run()
    if not fork:
        out["incompatible_history_detected"]=False
    out["retained_floor_claim_sha256"]=h("source-epoch-"+tag)
    out["receipt_sha256"]=digest({k:v for k,v in out.items()
                                  if k!="receipt_sha256"})
    return out

def witness(tag="a",root=None,operator=None):
    return {
        "retention_nonce_sha256":h("nonce-"+tag),
        "claimed_custodian_root_sha256":root or h("third-root"),
        "claimed_acquisition_sha256":h("third-acquisition-"+tag),
        "claimed_operator_sha256":operator or h("third-operator"),
        "public_key":"retention.pem","signature":"retention.sig",
    }

def run_audit(s=None,hist=None,w=None,pin=None,floor=None,verifier=verify):
    return audit(s if s is not None else source(),
                 hist if hist is not None else genesis(),
                 w if w is not None else witness(),
                 pin or h("third-party-pin"),floor,verifier=verifier)

class ReconciliationRetentionTests(unittest.TestCase):
    def test_missing_material_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_RECONCILIATION_RETENTION")
        self.assertFalse(hold()["release_authorized"])
    def test_first_retention_preserves_two_branches(self):
        out=run_audit()
        e=out["events"][0]
        self.assertEqual(out["event_count"],1)
        self.assertTrue(e["left_events"])
        self.assertTrue(e["right_events"])
        self.assertFalse(e["winner_selected"])
        self.assertFalse(out["independent_retention_verified"])
    def test_unresolved_fork_persists(self):
        out=run_audit()
        self.assertIn("HISTORICAL_CONTROL_FORK_REMAINS_UNRESOLVED",
                      [d["kind"] for d in out["unresolved_disputes"]])
    def test_ledger_appends_and_preserves_history(self):
        first=run_audit()
        nxt=run_audit(source("b"),first,witness("b"))
        self.assertEqual(nxt["events"][:1],first["events"])
        self.assertEqual(nxt["prefix_heads"][:2],first["prefix_heads"])
        self.assertFalse(nxt["release_authorized"])
    def test_original_source_replay_rejected(self):
        s=source("same")
        prior=run_audit(s)
        with self.assertRaisesRegex(ValueError,"receipt replay"):
            run_audit(s,prior,witness("b"))
    def test_duplicate_nonce_rejected(self):
        prior=run_audit()
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run_audit(source("b"),prior,witness("a"))
    def test_retainers_same_claimed_root_flagged(self):
        prior=run_audit()
        nxt=run_audit(source("b"),prior,witness("b"),pin=h("renamed-retainer"))
        self.assertIn("RENAMED_RETENTION_PIN_SHARED_CUSTODIAN_ROOT",
                      [d["kind"] for d in nxt["unresolved_disputes"]])
    def test_multiple_keys_same_operator_flagged(self):
        prior=run_audit()
        nxt=run_audit(source("b"),prior,witness("b"),pin=h("second-retainer"))
        self.assertIn("MULTIPLE_RETENTION_KEYS_SHARED_OPERATOR",
                      [d["kind"] for d in nxt["unresolved_disputes"]])
    def test_self_retention_rejected(self):
        s=source()
        with self.assertRaisesRegex(ValueError,"self-retain"):
            run_audit(s,pin=s["highwater_signer_pin"])
    def test_same_retainer_claims_different_root_rejected(self):
        prior=run_audit()
        with self.assertRaisesRegex(ValueError,"changed claimed origin"):
            run_audit(source("b"),prior,
                      witness("b",root=h("new-third-root")))
    def test_retention_floor_fork_rejected(self):
        prior=run_audit()
        with self.assertRaisesRegex(ValueError,"rollback or fork"):
            run_audit(source("b"),prior,witness("b"),
                      floor={"phase":"RUST-061","event_count":1,
                             "head_sha256":h("wrong-head")})
    def test_genesis_floor_does_not_release(self):
        x=run_audit(floor={"phase":"RUST-061","event_count":0,
                           "head_sha256":genesis()["head_sha256"]})
        self.assertFalse(x["release_authorized"])
    def test_tampered_old_branch_rejected(self):
        prior=run_audit()
        prior["events"][0]["right_events"][0]["entry_sha256"]=h("corrupt")
        with self.assertRaises(ValueError):
            checked_history(prior)
    def test_prior_conflicts_erasure_rejected(self):
        prior=run_audit()
        prior["unresolved_disputes"]=[]
        with self.assertRaisesRegex(ValueError,"disputes erased"):
            checked_history(prior)
    def test_upstream_authority_rejected(self):
        s=source()
        s["winner_selected"]=True
        s["receipt_sha256"]=digest({k:v for k,v in s.items()
                                    if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"authority promotion"):
            run_audit(s)
    def test_invalid_external_signature_rejected(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run_audit(verifier=bad)
    def test_floor_ahead_of_history_rejected(self):
        with self.assertRaisesRegex(ValueError,"beyond local history"):
            run_audit(floor={"phase":"RUST-061","event_count":2,
                             "head_sha256":h("future")})
if __name__=="__main__":unittest.main()
