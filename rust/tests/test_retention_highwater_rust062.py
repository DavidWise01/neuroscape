import copy,unittest
from lineage_rust019 import digest
from retention_highwater_rust062 import audit,hold,highwater
from reconciliation_retention_rust061 import audit as retention_audit,genesis
from test_reconciliation_retention_rust061 import source,witness,verify,h

def fixture():
    first=retention_audit(source("one"),genesis(),witness("one"),
                          h("retainer-one"),verifier=verify)
    second=retention_audit(source("two"),first,witness("two",root=h("other-root"),
                             operator=h("other-operator")),
                           h("retainer-two"),verifier=verify)
    floor={"phase":"RUST-062","event_count":1,
           "head_sha256":first["head_sha256"]}
    claims=[{"signer_pin":h("external-witness-"+role),
             "source_root_sha256":h("source-root-"+role),
             "acquisition_sha256":h("acquisition-"+role),
             "operator_control_sha256":h("controller-"+role),
             "nonce_sha256":h("nonce-"+role),
             "public_key":role+".pem","signature":role+".sig",
             "fork_resolved":False,"release_authorized":False}
             for role in ("left","right")]
    return [first,second,highwater(first),floor,claims]

def run(items=None,checkpoint_pin=None,verifier=verify):
    a,b,c,floor,claims=items if items is not None else fixture()
    return audit(a,b,c,"highwater.pem","signed.sig",
                 checkpoint_pin or h("highwater-external"),
                 floor,claims,verifier=verifier)

class RetentionHighwaterTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CROSS_CUSTODY_RETENTION")
        self.assertFalse(hold()["release_authorized"])

    def test_two_signed_claims_preserve_hold(self):
        result=run()
        self.assertEqual(result["previous_count"],1)
        self.assertEqual(result["current_count"],2)
        self.assertEqual(len(result["custody_challenges"]),2)
        self.assertFalse(result["independent_custodians_authenticated"])
        self.assertFalse(result["winner_selected"])

    def test_old_forks_preserved(self):
        result=run()
        self.assertEqual(result["current_forks_preserved"][:1],
                         result["historical_forks_preserved"])
        self.assertEqual(result["current_disputes_preserved"][:len(
            result["historical_disputes_preserved"])],
            result["historical_disputes_preserved"])

    def test_shared_claimed_root_flagged(self):
        items=fixture()
        items[4][1]["source_root_sha256"]=items[4][0]["source_root_sha256"]
        result=run(items)
        self.assertTrue(any(x["shared_field"]=="source_root_sha256"
                            for x in result["custody_ancestry_conflicts"]))

    def test_same_operator_flagged(self):
        items=fixture()
        items[4][1]["operator_control_sha256"]=items[4][0]["operator_control_sha256"]
        self.assertTrue(run(items)["custody_ancestry_conflicts"])

    def test_stale_snapshot_rejected(self):
        items=fixture()
        items[1]=items[0]
        with self.assertRaisesRegex(ValueError,"strictly extend"):
            run(items)

    def test_modified_old_branch_rejected(self):
        items=fixture()
        items[1]["events"][0]["left_events"][0]["entry_sha256"]=h("tampered")
        with self.assertRaises(ValueError):
            run(items)

    def test_highwater_substitution_rejected(self):
        items=fixture()
        items[2]["head_sha256"]=h("wrong")
        with self.assertRaisesRegex(ValueError,"checkpoint substituted"):
            run(items)

    def test_retained_floor_conflict_rejected(self):
        items=fixture()
        items[3]["head_sha256"]=h("fork")
        with self.assertRaisesRegex(ValueError,"contradicts"):
            run(items)

    def test_retained_floor_ahead_of_history_rejected(self):
        items=fixture()
        items[3]["event_count"]=3
        with self.assertRaisesRegex(ValueError,"outside available"):
            run(items)

    def test_duplicate_custody_signer_rejected(self):
        items=fixture()
        items[4][1]["signer_pin"]=items[4][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"duplicate or self-attesting"):
            run(items)

    def test_highwater_signer_cannot_self_attest(self):
        items=fixture()
        with self.assertRaisesRegex(ValueError,"duplicate or self-attesting"):
            run(items,checkpoint_pin=items[4][0]["signer_pin"])

    def test_replayed_nonce_rejected(self):
        items=fixture()
        items[4][1]["nonce_sha256"]=items[4][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(items)

    def test_original_retention_nonce_rejected(self):
        items=fixture()
        items[4][0]["nonce_sha256"]=items[0]["events"][0]["retention_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(items)

    def test_one_custodian_is_insufficient(self):
        items=fixture()
        items[4]=items[4][:1]
        with self.assertRaisesRegex(ValueError,"two independently"):
            run(items)

    def test_claim_cannot_resolve_fork(self):
        items=fixture()
        items[4][1]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"attempted fork clearance"):
            run(items)

    def test_invalid_signature_rejected(self):
        def reject(*_): raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):
            run(verifier=reject)

    def test_earlier_dispute_erasure_rejected(self):
        items=fixture()
        items[1]["unresolved_disputes"]=[]
        with self.assertRaises(ValueError):
            run(items)

if __name__=="__main__":unittest.main()
