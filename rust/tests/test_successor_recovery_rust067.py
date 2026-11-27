import copy
import unittest
from lineage_rust019 import digest
from successor_recovery_rust067 import audit,genesis,hold,checked_history
from test_revocation_highwater_rust066 import fixture,run as highwater_run,h,verify

def materials(tag="a",shared=False,revoked=False):
    args=fixture()
    highwater=highwater_run(args)
    revocations=args[1]
    if tag!="a":
        highwater=copy.deepcopy(highwater)
        highwater["challenge_epoch_tag"]=tag
        highwater["receipt_sha256"]=digest({
            k:v for k,v in highwater.items() if k!="receipt_sha256"})
    groups=[];nonces=[]
    for i,_ in enumerate(highwater["successor_observations"]):
        group=[];nn=[]
        for role in ("ff","cf","rr"):
            group.append({
                "role":role,
                "signer_pin":revocations["revoked_signer_pins"][0] if revoked and role=="ff" else h("custodian-pin-"+role),
                "controller_sha256":h("same-controller" if shared else "controller-"+role),
                "source_root_sha256":h("same-root" if shared else "root-"+role),
                "acquisition_sha256":h("same-acq" if shared else "acq-"+role),
                "public_key":"witness-"+role+".pem",
                "signature":"witness-"+role+".sig"})
            nn.append(h(tag+"-custody-nonce-"+str(i)+"-"+role))
        groups.append(group);nonces.append(nn)
    return highwater,revocations,groups,nonces

def run(bundle=None,history=None,floor=None,verifier=verify):
    source,revocations,claims,nonces=bundle or materials()
    return audit(source,revocations,history or genesis(),claims,nonces,
                 floor=floor,verifier=verifier)

class QuarantinedRecoveryTests(unittest.TestCase):
    def test_missing_evidence_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_INDEPENDENT_SUCCESSOR_CUSTODY")
        self.assertFalse(hold()["recovery_authorized"])

    def test_all_attempts_quarantined(self):
        out=run()
        self.assertEqual(out["event_count"],1)
        self.assertTrue(out["events"][0]["quarantine_persists"])
        self.assertFalse(out["independent_custody_verified"])
        self.assertFalse(out["release_authorized"])

    def test_three_witnesses_and_revocation_bound(self):
        b=materials()
        out=run(b)
        self.assertEqual([w["role"] for w in out["events"][0]["witnesses"]],
                         ["ff","cf","rr"])
        self.assertEqual(out["revoked_pins_preserved"],b[1]["revoked_signer_pins"])
        self.assertEqual(out["source_revocation_events_preserved"],b[1]["events"])

    def test_shared_ancestry_detected(self):
        out=run(materials(shared=True))
        self.assertTrue(any(c["reason"]=="WITNESSES_SHARE_CLAIMED_ANCESTRY"
                            for c in out["custody_conflicts"]))

    def test_revoked_witness_rejected(self):
        with self.assertRaisesRegex(ValueError,"revoked"):
            run(materials(revoked=True))

    def test_custodian_same_as_successor_rejected(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0][0]["signer_pin"]=b[1]["events"][-1]["replacement_pin"]
        with self.assertRaisesRegex(ValueError,"replacement"):
            run(b)

    def test_candidate_controller_overlap_alert(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0][0]["controller_sha256"]=b[1]["events"][-1]["replacement_controller_sha256"]
        out=run(b)
        self.assertIn("WITNESS_REUSES_REVOKED_OR_SUCCESSOR_CONTROLLER",
                      [c["reason"] for c in out["custody_conflicts"]])

    def test_candidate_acquisition_overlap_alert(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0][0]["acquisition_sha256"]=b[1]["events"][-1]["replacement_acquisition_sha256"]
        out=run(b)
        self.assertIn("WITNESS_REUSES_SUCCESSOR_ACQUISITION",
                      [c["reason"] for c in out["custody_conflicts"]])

    def test_duplicate_witness_pin_rejected(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0][1]["signer_pin"]=b[2][0][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"not distinct"):
            run(b)

    def test_wrong_role_rejected(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0][0]["role"]="unknown"
        with self.assertRaisesRegex(ValueError,"ordered ff/cf/rr"):
            run(b)

    def test_missing_one_witness_rejected(self):
        b=list(materials())
        b[2]=copy.deepcopy(b[2])
        b[2][0].pop()
        with self.assertRaisesRegex(ValueError,"three ordered"):
            run(b)

    def test_revocation_source_tamper_rejected(self):
        b=list(materials())
        b[1]=copy.deepcopy(b[1])
        b[1]["events"][0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            run(b)

    def test_highwater_receipt_tamper_rejected(self):
        b=list(materials())
        b[0]=copy.deepcopy(b[0])
        b[0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            run(b)

    def test_replayed_revocation_nonce_rejected(self):
        b=list(materials())
        b[3]=copy.deepcopy(b[3])
        b[3][0][0]=b[1]["events"][-1]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(b)

    def test_prior_registry_event_tamper_rejected(self):
        prior=run()
        prior["events"][0]["quarantine_persists"]=False
        with self.assertRaises(ValueError):
            checked_history(prior)

    def test_prior_conflict_erasure_rejected(self):
        prior=run(materials(shared=True))
        prior["custody_conflicts"]=[]
        with self.assertRaisesRegex(ValueError,"erased"):
            checked_history(prior)

    def test_append_only_epoch_and_nonce_freshness(self):
        prior=run()
        bundle=materials("b")
        later=run(bundle,history=prior)
        self.assertEqual(later["events"][:1],prior["events"])
        self.assertEqual(later["prefix_heads"][:2],prior["prefix_heads"])
        self.assertEqual(later["event_count"],2)
        self.assertFalse(later["recovery_authorized"])

    def test_old_nonce_replay_across_epoch_rejected(self):
        prior=run()
        bundle=list(materials("b"))
        bundle[3]=copy.deepcopy(bundle[3])
        bundle[3][0][0]=prior["events"][0]["witnesses"][0]["nonce_sha256"]
        with self.assertRaisesRegex(ValueError,"nonce replay"):
            run(bundle,history=prior)

    def test_retained_floor_fork_rejected(self):
        prior=run()
        with self.assertRaisesRegex(ValueError,"floor forked"):
            run(materials("b"),history=prior,
                floor={"phase":"RUST-067","event_count":1,"head_sha256":h("false")})

    def test_invalid_custody_signature_rejected(self):
        def reject(*_):raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=reject)

if __name__=="__main__":
    unittest.main()
