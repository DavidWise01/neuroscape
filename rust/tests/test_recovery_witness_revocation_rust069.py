import copy,unittest
from lineage_rust019 import digest
from recovery_witness_revocation_rust069 import audit,genesis,hold,checked_history
from test_recovery_highwater_rust068 import fixture,run as highwater_run,h,verify

def materials(tag="a",shared=False,bad_role="ff"):
    sample=fixture()
    highwater=highwater_run(sample)
    recovery=sample[1]
    if tag!="a":
        highwater=copy.deepcopy(highwater)
        highwater["external_epoch_tag"]=tag
        highwater["receipt_sha256"]=digest({
            k:v for k,v in highwater.items() if k!="receipt_sha256"})
    compromised=next(w for w in recovery["events"][0]["witnesses"]
                     if w["role"]==bad_role)
    witnesses=[]
    nonces=[]
    for role in ("ff","cf","rr"):
        witnesses.append({
            "role":role,"signer_pin":h("revocation-attestor-"+role),
            "controller_sha256":h("shared-controller" if shared else "controller-"+role),
            "source_root_sha256":h("shared-root" if shared else "root-"+role),
            "acquisition_sha256":h("shared-acquisition" if shared else "acq-"+role),
            "public_key":role+".pem","signature":role+".sig"})
        nonces.append(h("witness-nonce-"+tag+"-"+role))
    return [highwater,recovery,compromised["pin"],h("revocation-"+tag),witnesses,nonces]

def run(bundle=None,history=None,floor=None,verifier=verify):
    source,recovery,pin,nonce,witnesses,nonces=bundle or materials()
    return audit(source,recovery,history or genesis(),pin,nonce,
                 witnesses,nonces,floor,verifier=verifier)

class RecoveryWitnessRevocationTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_RECOVERY_CUSTODY_REVOCATION")
        self.assertFalse(hold()["recovery_authorized"])

    def test_three_witness_quarantine_stays_hold(self):
        x=run()
        self.assertEqual(x["event_count"],1)
        self.assertEqual([w["role"] for w in x["events"][0]["witnesses"]],
                         ["ff","cf","rr"])
        self.assertTrue(x["quarantine_persists"])
        self.assertFalse(x["independent_custody_verified"])
        self.assertFalse(x["release_authorized"])

    def test_source_revoked_pin_and_candidates_preserved(self):
        bundle=materials()
        x=run(bundle)
        self.assertEqual(x["revoked_witness_pins"],[bundle[2]])
        self.assertEqual(x["source_recovery_candidates_preserved"],
                         bundle[0]["current_quarantined_candidates_preserved"])

    def test_same_witness_ancestry_detected(self):
        x=run(materials(shared=True))
        self.assertIn("NEW_ATTESTORS_SHARE_CLAIMED_ANCESTRY",
                      [c["reason"] for c in x["custody_conflicts"]])

    def test_compromised_controller_reuse_detected(self):
        data=materials()
        compromised=data[1]["events"][0]["witnesses"][0]
        data[4][0]["controller_sha256"]=compromised["controller_sha256"]
        x=run(data)
        self.assertIn("ATTESTOR_REUSES_REVOKED_CONTROLLER",
                      [c["reason"] for c in x["custody_conflicts"]])

    def test_historical_acquisition_reuse_detected(self):
        data=materials()
        data[4][0]["acquisition_sha256"]=data[1]["events"][0]["witnesses"][1]["acquisition_sha256"]
        x=run(data)
        self.assertIn("ATTESTOR_REUSES_HISTORICAL_ACQUISITION",
                      [c["reason"] for c in x["custody_conflicts"]])

    def test_unknown_compromised_key_rejected(self):
        data=materials()
        data[2]=h("unobserved-pin")
        with self.assertRaisesRegex(ValueError,"not present"):
            run(data)

    def test_replacement_candidate_signer_rejected(self):
        data=materials()
        data[4][0]["signer_pin"]=data[1]["events"][0]["candidate_pin"]
        with self.assertRaisesRegex(ValueError,"non-independent"):
            run(data)

    def test_historical_witness_cannot_attest(self):
        data=materials()
        data[4][0]["signer_pin"]=data[1]["events"][0]["witnesses"][0]["pin"]
        with self.assertRaisesRegex(ValueError,"non-independent"):
            run(data)

    def test_duplicate_signer_pins_rejected(self):
        data=materials()
        data[4][1]["signer_pin"]=data[4][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"non-independent"):
            run(data)

    def test_missing_custodian_role_rejected(self):
        data=materials()
        data[4].pop()
        with self.assertRaisesRegex(ValueError,"exactly ff/cf/rr"):
            run(data)

    def test_wrong_order_roles_rejected(self):
        data=materials()
        data[4][0]["role"]="rr"
        with self.assertRaisesRegex(ValueError,"exactly ff/cf/rr"):
            run(data)

    def test_replayed_recovery_nonce_rejected(self):
        data=materials()
        data[5][0]=data[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(data)

    def test_replayed_revocation_nonce_rejected(self):
        data=materials()
        data[3]=data[1]["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"revocation nonce replay"):
            run(data)

    def test_source_receipt_tamper_rejected(self):
        data=materials()
        data[0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            run(data)

    def test_source_history_tamper_rejected(self):
        data=materials()
        data[1]["events"][0]["quarantine_persists"]=False
        with self.assertRaises(ValueError):
            run(data)

    def test_old_ledger_conflict_erasure_rejected(self):
        prior=run(materials(shared=True))
        prior["custody_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):
            checked_history(prior)

    def test_prior_event_tamper_rejected(self):
        prior=run()
        prior["events"][0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            checked_history(prior)

    def test_cross_epoch_append_preserves_revoked_pins(self):
        prior=run()
        future=materials("b",bad_role="cf")
        later=run(future,history=prior)
        self.assertEqual(later["events"][:1],prior["events"])
        self.assertEqual(later["revoked_witness_pins"][:1],
                         prior["revoked_witness_pins"])
        self.assertFalse(later["recovery_authorized"])

    def test_cross_epoch_nonce_replay_rejected(self):
        prior=run()
        future=materials("b",bad_role="cf")
        future[5][0]=prior["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(future,history=prior)

    def test_duplicate_revocation_rejected(self):
        prior=run()
        with self.assertRaisesRegex(ValueError,"already revoked"):
            run(materials("b"),history=prior)

    def test_retained_floor_fork_rejected(self):
        prior=run()
        with self.assertRaisesRegex(ValueError,"floor forked"):
            run(materials("b",bad_role="cf"),history=prior,
                floor={"phase":"RUST-069","event_count":1,
                       "head_sha256":h("wrong")})

    def test_crypto_signature_rejection(self):
        def bad(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"invalid Ed25519"):
            run(verifier=bad)

if __name__=="__main__":unittest.main()
