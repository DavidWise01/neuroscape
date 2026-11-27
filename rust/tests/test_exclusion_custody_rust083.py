import copy,unittest
from lineage_rust019 import digest
from exclusion_custody_rust083 import audit,genesis,hold,checked_history,EXCLUSIONS,DENIAL_FIELDS
from test_controller_exclusion_highwater_rust082 import fixture,run as source_run,h,verify

def bundle(tag="one",shared=False):
    parts=fixture()
    source=source_run(parts)
    exclusion=parts[1]
    if tag!="one":
        source=copy.deepcopy(source)
        source["custody_observation_epoch"]=tag
        source["receipt_sha256"]=digest({
            k:v for k,v in source.items() if k!="receipt_sha256"})
    claims=[]
    for role in ("left","right"):
        claims.append({"role":role,"pin":h("083-"+role+"-pin"),
            "nonce_sha256":h("083-"+tag+"-"+role+"-nonce"),
            "controller_sha256":h("shared-controller" if shared else role+"-controller"),
            "source_root_sha256":h("shared-root" if shared else role+"-source"),
            "acquisition_sha256":h("shared-acquisition" if shared else role+"-acquisition"),
            "public_key":role+".pem","signature":role+".sig",
            "independent_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False})
    return [source,exclusion,claims]

def run(data=None,history=None,floor=None,verifier=verify):
    source,exclusion,claims=data or bundle()
    return audit(source,exclusion,history or genesis(),claims,floor,verifier=verifier)

class DualExclusionCustodyTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        out=hold()
        self.assertEqual(out["status"],"HOLD_MISSING_DUAL_EXCLUSION_CUSTODY")
        self.assertFalse(out["release_authorized"])
    def test_signed_witness_claims_remain_hold(self):
        out=run()
        self.assertEqual(out["event_count"],1)
        self.assertEqual(len(out["events"][0]["witnesses"]),2)
        self.assertFalse(out["independent_custody_verified"])
        self.assertFalse(out["fork_resolved"])
    def test_complete_exclusion_and_denial_snapshots(self):
        source,exclusion,claims=bundle()
        out=run([source,exclusion,claims])
        e=out["events"][0]
        for k in EXCLUSIONS:
            self.assertEqual(e["exclusions"][k],exclusion[k])
        for k in DENIAL_FIELDS:
            self.assertEqual(e["denials"][k],exclusion[k])
    def test_left_right_distinct_signatures(self):
        a,b=run()["events"][0]["witnesses"]
        self.assertNotEqual(a["message_sha256"],b["message_sha256"])
        self.assertNotEqual(a["pin"],b["pin"])
    def test_shared_ancestry_not_independent(self):
        out=run(bundle(shared=True))
        self.assertEqual(len(out["custody_conflicts"]),3)
        self.assertFalse(out["independent_custody_verified"])
    def test_tampered_source_receipt_rejected(self):
        data=bundle()
        data[0]["receipt_sha256"]=h("forged")
        with self.assertRaises(ValueError):run(data)
    def test_tampered_exclusion_source_rejected(self):
        data=bundle()
        data[1]["excluded_controllers"]=[]
        with self.assertRaises(ValueError):run(data)
    def test_duplicate_custodians_rejected(self):
        data=bundle();data[2][1]["pin"]=data[2][0]["pin"]
        with self.assertRaisesRegex(ValueError,"duplicate custodian"):run(data)
    def test_source_signer_cannot_claim_external_custody(self):
        data=bundle();data[2][0]["pin"]=data[0]["checkpoint_signer_pin"]
        with self.assertRaisesRegex(ValueError,"excluded/duplicate"):run(data)
    def test_excluded_custodian_cannot_reenter(self):
        data=bundle();data[2][0]["pin"]=data[1]["excluded_signer_pins"][0]
        with self.assertRaisesRegex(ValueError,"excluded/duplicate"):run(data)
    def test_replayed_exclusion_nonce_rejected(self):
        data=bundle()
        data[2][0]["nonce_sha256"]=data[1]["events"][0]["challenge_nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(data)
    def test_duplicate_fresh_nonce_rejected(self):
        data=bundle();data[2][1]["nonce_sha256"]=data[2][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):run(data)
    def test_missing_witness_rejected(self):
        data=bundle();data[2].pop()
        with self.assertRaisesRegex(ValueError,"two branch-exclusion"):run(data)
    def test_reordered_roles_rejected(self):
        data=bundle();data[2][0]["role"]="right"
        with self.assertRaisesRegex(ValueError,"two branch-exclusion"):run(data)
    def test_claimed_release_rejected(self):
        data=bundle();data[2][1]["release_authorized"]=True
        with self.assertRaisesRegex(ValueError,"attempted release"):run(data)
    def test_claimed_independence_rejected(self):
        data=bundle();data[2][1]["independent_custody_verified"]=True
        with self.assertRaisesRegex(ValueError,"attempted release"):run(data)
    def test_append_second_epoch_preserves_first(self):
        prior=run()
        after=run(bundle("second"),history=prior)
        self.assertEqual(after["event_count"],2)
        self.assertEqual(after["events"][:1],prior["events"])
        self.assertEqual(after["excluded_snapshots"][0],prior["excluded_snapshots"][0])
        self.assertEqual(after["denial_snapshots"][0],prior["denial_snapshots"][0])
        self.assertFalse(after["release_authorized"])
    def test_replayed_highwater_rejected(self):
        prior=run()
        with self.assertRaisesRegex(ValueError,"replayed exclusion highwater"):
            run(history=prior)
    def test_replayed_prior_epoch_nonce_rejected(self):
        prior=run();data=bundle("second")
        data[2][0]["nonce_sha256"]=prior["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(data,history=prior)
    def test_retention_floor_mismatch_rejected(self):
        prior=run()
        with self.assertRaisesRegex(ValueError,"contradicts prefix"):
            run(bundle("second"),history=prior,
                floor={"phase":"RUST-083","event_count":1,"head_sha256":h("wrong")})
    def test_valid_genesis_floor_remains_hold(self):
        out=run(floor={"phase":"RUST-083","event_count":0,
                       "head_sha256":genesis()["head_sha256"]})
        self.assertFalse(out["independent_custody_verified"])
    def test_prior_denial_erasure_rejected(self):
        prior=run()
        prior["denial_snapshots"]=[]
        with self.assertRaisesRegex(ValueError,"history erased"):
            checked_history(prior)
    def test_historical_custody_mutation_rejected(self):
        prior=run()
        prior["events"][0]["fork_resolved"]=True
        with self.assertRaises(ValueError):checked_history(prior)
    def test_invalid_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):
            run(verifier=reject)
if __name__=="__main__":unittest.main()
