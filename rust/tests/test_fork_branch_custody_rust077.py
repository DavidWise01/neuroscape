import copy,unittest
from lineage_rust019 import digest
from fork_branch_custody_rust077 import audit,genesis,hold,checked_history
from test_custody_fork_highwater_rust076 import fixture,run as highwater_run,h,verify

def materials(tag="one",shared=False):
    parts=fixture()
    highwater=highwater_run(parts)
    forks=parts[1]
    if tag!="one":
        highwater=copy.deepcopy(highwater)
        highwater["custody_epoch_tag"]=tag
        highwater["receipt_sha256"]=digest({
            k:v for k,v in highwater.items() if k!="receipt_sha256"})
    claims=[]
    for role in ("a","b"):
        claims.append({
            "role":role,"signer_pin":h("077-custody-"+role),
            "nonce_sha256":h("077-nonce-"+tag+"-"+role),
            "controller_sha256":h("same-controller" if shared else "controller-"+role),
            "source_root_sha256":h("same-source" if shared else "source-"+role),
            "acquisition_sha256":h("same-acquisition" if shared else "acquisition-"+role),
            "public_key":role+".pem","signature":role+".sig",
            "winner_selected":False,"fork_resolved":False,"release_authorized":False})
    return [highwater,forks,claims]

def run(bundle=None,history=None,floor=None,verifier=verify):
    source,forks,claims=bundle or materials()
    return audit(source,forks,history or genesis(),claims,floor,verifier=verifier)

class ForkBranchCustodyTests(unittest.TestCase):
    def test_missing_custody_hold(self):
        x=hold()
        self.assertEqual(x["status"],"HOLD_MISSING_FORK_BRANCH_CUSTODY_CHALLENGES")
        self.assertFalse(x["fork_resolved"])
    def test_separate_signed_branches_remain_hold(self):
        x=run()
        self.assertEqual(x["event_count"],1)
        self.assertTrue(x["both_branches_retained"])
        self.assertFalse(x["independent_custody_verified"])
        self.assertFalse(x["release_authorized"])
    def test_branch_heads_match_original_fork(self):
        source,forks,claims=materials()
        x=run([source,forks,claims])
        event=x["events"][0]
        self.assertEqual([event["branch_a_sha256"],event["branch_b_sha256"]],
                         forks["fork_pairs"][-1])
        self.assertEqual([c["role"] for c in event["branches"]],["a","b"])
    def test_both_challenges_bind_distinct_heads(self):
        x=run()
        a,b=x["events"][0]["branches"]
        self.assertNotEqual(a["branch_sha256"],b["branch_sha256"])
        self.assertNotEqual(a["message_sha256"],b["message_sha256"])
    def test_shared_ancestry_recorded_not_authorized(self):
        x=run(materials(shared=True))
        self.assertEqual(len(x["custody_conflicts"]),3)
        self.assertFalse(x["recovery_authorized"])
    def test_bad_highwater_receipt_rejected(self):
        bundle=materials()
        bundle[0]["receipt_sha256"]=h("fake")
        with self.assertRaises(ValueError):run(bundle)
    def test_changed_fork_history_rejected(self):
        bundle=materials()
        bundle[1]["events"][0]["winner_selected"]=True
        with self.assertRaises(ValueError):run(bundle)
    def test_missing_highwater_branch_evidence_rejected(self):
        bundle=materials()
        bundle[0]["new_fork_observations"]=[]
        bundle[0]["receipt_sha256"]=digest({
            k:v for k,v in bundle[0].items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"new RUST-076 fork evidence absent"):
            run(bundle)
    def test_duplicate_signers_rejected(self):
        bundle=materials()
        bundle[2][1]["signer_pin"]=bundle[2][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"reused or duplicated"):run(bundle)
    def test_prior_fork_witness_rejected(self):
        bundle=materials()
        bundle[2][0]["signer_pin"]=bundle[1]["events"][0]["witness_a_pin"]
        with self.assertRaisesRegex(ValueError,"reused or duplicated"):run(bundle)
    def test_highwater_signer_rejected(self):
        bundle=materials()
        bundle[2][0]["signer_pin"]=bundle[0]["checkpoint_signer_pin"]
        with self.assertRaisesRegex(ValueError,"reused or duplicated"):run(bundle)
    def test_nonce_replay_from_fork_rejected(self):
        bundle=materials()
        bundle[2][0]["nonce_sha256"]=bundle[1]["events"][0]["nonce_a_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(bundle)
    def test_duplicate_nonce_rejected(self):
        bundle=materials()
        bundle[2][1]["nonce_sha256"]=bundle[2][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(bundle)
    def test_missing_branch_claim_rejected(self):
        bundle=materials();bundle[2].pop()
        with self.assertRaisesRegex(ValueError,"two separately pinned"):run(bundle)
    def test_swapped_roles_rejected(self):
        bundle=materials()
        bundle[2][0]["role"]="b"
        with self.assertRaisesRegex(ValueError,"two separately pinned"):run(bundle)
    def test_false_resolution_rejected(self):
        bundle=materials()
        bundle[2][0]["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"false resolution"):run(bundle)
    def test_release_claim_rejected(self):
        bundle=materials()
        bundle[2][1]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"false resolution"):run(bundle)
    def test_append_epoch_preserves_prior_claims(self):
        old=run()
        more=run(materials("two"),history=old)
        self.assertEqual(more["event_count"],2)
        self.assertEqual(more["events"][:1],old["events"])
        self.assertFalse(more["fork_resolved"])
    def test_replayed_highwater_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"highwater replay"):
            run(history=old)
    def test_replayed_old_nonce_rejected(self):
        old=run()
        bundle=materials("two")
        bundle[2][0]["nonce_sha256"]=old["events"][0]["branches"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(bundle,history=old)
    def test_retained_floor_fork_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"contradicts history"):
            run(materials("two"),history=old,
                floor={"phase":"RUST-077","event_count":1,"head_sha256":h("wrong")})
    def test_original_conflicts_cannot_be_erased(self):
        x=run(materials(shared=True))
        x["custody_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"conflicts or events erased"):
            checked_history(x)
    def test_historic_entry_mutation_rejected(self):
        x=run()
        x["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):checked_history(x)
    def test_invalid_signature_rejected(self):
        def invalid(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=invalid)
if __name__=="__main__":unittest.main()
