import copy,unittest
from lineage_rust019 import digest
from custody_fork_rust075 import audit,genesis,hold,checked_history,checked_source
from test_denial_custody_highwater_rust074 import fixture,run as highwater_run,h,verify
from test_denial_custody_rust073 import run as custody_run,materials

def sample(tag="one"):
    parts=fixture()
    base,branch_a=parts[:2]
    branch_b=custody_run(materials("other-"+tag),history=base)
    source=highwater_run(parts)
    if tag!="one":
        source=copy.deepcopy(source)
        source["fork_epoch_tag"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    claims=[
        {"role":role,"pin":h(role+"-fork-signer"),
         "nonce_sha256":h(tag+"-fork-nonce-"+role),
         "controller_sha256":h("controller-"+role),
         "acquisition_sha256":h("acq-"+role),
         "public_key":role+".pem","signature":role+".sig"}
        for role in ("a","b")]
    return [source,base,branch_a,branch_b,claims]

def run(items=None,history=None,floor=None,verifier=verify):
    source,base,a,b,claims=items or sample()
    return audit(source,base,a,b,history or genesis(),claims,floor,verifier=verifier)

class CustodyForkTests(unittest.TestCase):
    def test_default_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CUSTODY_FORK_EVIDENCE")
        self.assertFalse(hold()["fork_resolved"])
    def test_divergent_branches_preserved(self):
        x=run()
        self.assertEqual(x["event_count"],1)
        self.assertEqual(len(x["fork_pairs"]),1)
        self.assertNotEqual(*x["fork_pairs"][0])
        self.assertFalse(x["winner_selected"])
        self.assertFalse(x["release_authorized"])
    def test_first_divergence_identified(self):
        x=run()
        self.assertEqual(x["custody_conflicts"][0]["first_divergent_ordinal"],2)
    def test_branch_full_history_hashed(self):
        x=run()
        self.assertEqual(x["events"][0]["branch_a_full_history_sha256"],
                         digest(sample()[2]["events"]))
    def test_shared_prefix_required(self):
        data=sample()
        data[3]=copy.deepcopy(data[3])
        data[3]["events"][0]["denials"][0]["recovery_denied"]=False
        with self.assertRaises(ValueError):run(data)
    def test_identical_branch_rejected(self):
        data=sample();data[3]=data[2]
        with self.assertRaisesRegex(ValueError,"no conflicting custody fork"):run(data)
    def test_prior_denial_erasure_rejected(self):
        data=sample();data[3]=copy.deepcopy(data[3])
        data[3]["events"][-1]["denials"]=[]
        with self.assertRaises(ValueError):run(data)
    def test_source_receipt_tamper_rejected(self):
        data=sample();data[0]["release_authorized"]=True
        with self.assertRaises(ValueError):run(data)
    def test_source_unbound_branch_rejected(self):
        data=sample();data[2],data[3]=data[3],data[2]
        with self.assertRaisesRegex(ValueError,"unbound"):run(data)
    def test_repeat_source_rejected(self):
        first=run()
        with self.assertRaisesRegex(ValueError,"assessment replay"):
            run(history=first)
    def test_multiple_epochs_append_only(self):
        first=run()
        second=run(sample("second"),history=first)
        self.assertEqual(second["events"][:1],first["events"])
        self.assertEqual(second["prefix_heads"][:2],first["prefix_heads"])
        self.assertFalse(second["fork_resolved"])
    def test_nonce_replay_rejected(self):
        first=run();data=sample("second")
        data[4][0]["nonce_sha256"]=first["events"][0]["nonce_a_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(data,history=first)
    def test_duplicate_witness_pin_rejected(self):
        data=sample()
        data[4][1]["pin"]=data[4][0]["pin"]
        with self.assertRaisesRegex(ValueError,"shares branch custody"):
            run(data)
    def test_branch_witness_cannot_attest(self):
        data=sample()
        data[4][0]["pin"]=data[2]["events"][0]["witnesses"][0]["pin"]
        with self.assertRaisesRegex(ValueError,"shares branch custody"):
            run(data)
    def test_retained_floor_fork_rejected(self):
        first=run()
        with self.assertRaisesRegex(ValueError,"floor contradictory"):
            run(sample("second"),history=first,
                floor={"phase":"RUST-075","event_count":1,
                       "head_sha256":h("wrong")})
    def test_genesis_floor_still_hold(self):
        x=run(floor={"phase":"RUST-075","event_count":0,
                     "head_sha256":genesis()["head_sha256"]})
        self.assertFalse(x["recovery_authorized"])
    def test_old_fork_erasure_rejected(self):
        first=run()
        first["fork_pairs"]=[]
        with self.assertRaisesRegex(ValueError,"fork keys/conflicts lost"):
            checked_history(first)
    def test_old_event_modification_rejected(self):
        first=run()
        first["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):checked_history(first)
    def test_shared_claimed_control_flagged(self):
        data=sample()
        data[4][1]["controller_sha256"]=data[4][0]["controller_sha256"]
        x=run(data)
        self.assertIn("FORK_WITNESSES_SHARE_CLAIMED_CONTROL",
                      [c["reason"] for c in x["custody_conflicts"]])
    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):
            run(verifier=reject)
if __name__=="__main__":unittest.main()
