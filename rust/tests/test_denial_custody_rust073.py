import copy,unittest
from lineage_rust019 import digest
from denial_custody_rust073 import audit,genesis,hold,checked_history
from test_exclusion_highwater_rust072 import fixture,run as highwater_run,h,verify

def materials(tag="one",shared=False):
    original=fixture()
    source=highwater_run(original)
    denial=original[1]
    if tag!="one":
        source=copy.deepcopy(source)
        source["custody_epoch_tag"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    witnesses=[]
    for role in ("left","right"):
        witnesses.append({
            "role":role,"signer_pin":h("custody-pin-"+role),
            "nonce_sha256":h("custody-nonce-"+tag+"-"+role),
            "controller_sha256":h("same-controller" if shared else "control-"+role),
            "source_root_sha256":h("same-root" if shared else "root-"+role),
            "acquisition_sha256":h("same-acquisition" if shared else "acq-"+role),
            "public_key":role+".pem","signature":role+".sig",
            "recovery_authorized":False,"release_authorized":False})
    return [source,denial,witnesses]

def run(bundle=None,history=None,floor=None,verifier=verify):
    s,d,w=bundle or materials()
    return audit(s,d,history or genesis(),w,floor=floor,verifier=verifier)

class DenialCustodyTests(unittest.TestCase):
    def test_missing_custody_remains_hold(self):
        x=hold()
        self.assertEqual(x["status"],"HOLD_MISSING_INDEPENDENT_DENIAL_CUSTODY")
        self.assertFalse(x["recovery_authorized"])
    def test_two_signed_custodians_still_hold(self):
        x=run()
        self.assertEqual(x["event_count"],1)
        self.assertEqual([w["role"] for w in x["events"][0]["witnesses"]],
                         ["left","right"])
        self.assertFalse(x["independent_custody_verified"])
        self.assertFalse(x["release_authorized"])
    def test_complete_denial_snapshot_retained(self):
        s,d,w=materials()
        x=run([s,d,w])
        self.assertEqual(x["events"][0]["denials"],d["recovery_denials"])
        self.assertEqual(x["events"][0]["excluded_pins"],d["excluded_pins"])
    def test_shared_claimed_ancestry_conflict(self):
        x=run(materials(shared=True))
        self.assertEqual(len(x["custody_conflicts"]),3)
    def test_strict_source_binding(self):
        b=materials()
        b[1]=copy.deepcopy(b[1]);b[1]["recovery_denials"].pop()
        with self.assertRaises(ValueError):run(b)
    def test_missing_denial_fails(self):
        b=materials()
        b[1]=copy.deepcopy(b[1]);b[1]["events"]=[]
        with self.assertRaises(ValueError):run(b)
    def test_duplicate_custodian_signers_rejected(self):
        b=materials();b[2][1]["signer_pin"]=b[2][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"duplicate signer"):run(b)
    def test_candidate_cannot_attest(self):
        b=materials();b[2][0]["signer_pin"]=b[1]["events"][0]["candidate_pin"]
        with self.assertRaisesRegex(ValueError,"source or duplicate"):run(b)
    def test_highwater_signer_cannot_attest(self):
        b=materials();b[2][0]["signer_pin"]=b[0]["checkpoint_signer_pin"]
        with self.assertRaisesRegex(ValueError,"source or duplicate"):run(b)
    def test_recovery_release_claim_rejected(self):
        b=materials();b[2][0]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"unauthorized release"):run(b)
    def test_wrong_role_order_rejected(self):
        b=materials();b[2][0]["role"]="right"
        with self.assertRaisesRegex(ValueError,"left/right"):run(b)
    def test_missing_second_witness_rejected(self):
        b=materials();b[2].pop()
        with self.assertRaisesRegex(ValueError,"left/right"):run(b)
    def test_invalid_custody_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):run(verifier=reject)
    def test_history_event_mutation_rejected(self):
        prev=run();prev["events"][0]["denials"][0]["recovery_denied"]=False
        with self.assertRaises(ValueError):checked_history(prev)
    def test_historic_conflict_erasure_rejected(self):
        prev=run(materials(shared=True));prev["custody_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"conflicts erased"):checked_history(prev)
    def test_append_second_snapshot_still_hold(self):
        old=run()
        more=run(materials("two"),old)
        self.assertEqual(more["events"][:1],old["events"])
        self.assertEqual(more["event_count"],2)
        self.assertFalse(more["recovery_authorized"])
    def test_replay_source_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"duplicate source"):
            run(materials(),old)
    def test_replay_prior_nonce_rejected(self):
        old=run();b=materials("two")
        b[2][0]["nonce_sha256"]=old["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(b,old)
    def test_retention_floor_mismatch_rejected(self):
        old=run()
        with self.assertRaisesRegex(ValueError,"contradicts history"):
            run(materials("two"),old,
                floor={"phase":"RUST-073","event_count":1,"head_sha256":h("wrong")})
    def test_genesis_floor_still_hold(self):
        x=run(floor={"phase":"RUST-073","event_count":0,
                     "head_sha256":genesis()["head_sha256"]})
        self.assertTrue(x["retained_floor_compared"])
        self.assertFalse(x["independent_custody_verified"])
    def test_renamed_prior_controller_flagged(self):
        old=run();b=materials("two")
        b[2][0]["signer_pin"]=h("renamed-custodian")
        b[2][0]["controller_sha256"]=old["events"][0]["witnesses"][0]["controller_sha256"]
        x=run(b,old)
        self.assertIn("RENAMED_CUSTODIAN_REUSED_PRIOR_ANCESTRY",
                      [c["reason"] for c in x["custody_conflicts"]])
if __name__=="__main__":unittest.main()
