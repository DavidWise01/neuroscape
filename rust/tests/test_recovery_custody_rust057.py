import copy
import unittest
from lineage_rust019 import digest
from recovery_custody_rust057 import audit, genesis, hold, checked_history, GENESIS
from recovery_highwater_rust056 import audit as highwater_audit
from test_recovery_highwater_rust056 import setup, verify, h

ROLES=("ff","cf","rr")

def materials(tag="first",shared=False,compromised=False):
    a,b,oldrev,newrev,checkpoint,floor,observations=setup()
    source=highwater_audit(a,b,oldrev,newrev,checkpoint,"highwater.pem",
                           "highwater.sig",h("highwater-custodian"),
                           floor,observations,verifier=verify)
    groups=[]
    nonces=[]
    for i,_ in enumerate(b["events"]):
        group=[]
        nonce_group=[]
        for role in ROLES:
            control=(h("session-control") if compromised and role=="ff" else
                     h("same-control") if shared else
                     h("custodian-control-"+role))
            group.append({
                "role":role,"signer_pin":h("custodian-pin-"+role),
                "claimed_controller_sha256":control,
                "claimed_source_root_sha256":h("custodian-root-"+role),
                "acquisition_sha256":h("acquisition-"+role),
                "public_key":"custodian-"+role+".pem",
                "signature":"custodian-"+role+".sig",
            })
            nonce_group.append(h(tag+"-nonce-"+str(i)+"-"+role))
        groups.append(group)
        nonces.append(nonce_group)
    return source,b,newrev,groups,nonces

def run(data=None,history=None,floor=None,verifier=verify):
    s,recovery,revocations,groups,nonces=data or materials()
    return audit(s,recovery,revocations,history or genesis(),groups,nonces,
                 floor=floor,verifier=verifier)

class CustodyChallengeTests(unittest.TestCase):
    def test_no_inputs_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_RECOVERY_CUSTODIAN_CHALLENGES")
        self.assertFalse(hold()["release_authorized"])

    def test_three_witnesses_per_candidate_still_hold(self):
        out=run()
        self.assertEqual(out["event_count"],2)
        self.assertEqual(out["prefix_heads"][0],GENESIS)
        self.assertEqual(len(out["entries"][0]["witnesses"]),3)
        self.assertFalse(out["independent_external_custody_verified"])
        self.assertFalse(out["release_authorized"])

    def test_recovery_preserved(self):
        data=materials()
        out=run(data)
        self.assertEqual(out["recovery_candidates_preserved"],data[1]["events"])
        self.assertEqual(out["revoked_witnesses_preserved"],
                         data[2]["revoked_signer_pins"])

    def test_shared_controller_alerted(self):
        out=run(materials(shared=True))
        self.assertTrue(any(c["reason"]=="SHARED_CLAIMED_WITNESS_ANCESTRY"
                            for c in out["custody_conflicts"]))
        self.assertFalse(out["fork_resolved"])

    def test_compromised_controller_alerted(self):
        out=run(materials(compromised=True))
        self.assertTrue(any(c["reason"]=="WITNESS_SHARES_COMPROMISED_OR_CANDIDATE_CONTROLLER"
                            for c in out["custody_conflicts"]))

    def test_replayed_nonce_rejected(self):
        data=list(materials())
        data[4]=copy.deepcopy(data[4])
        data[4][1][0]=data[4][0][0]
        with self.assertRaisesRegex(ValueError,"replayed"):
            run(data)

    def test_same_signer_as_candidate_rejected(self):
        data=list(materials())
        data[3]=copy.deepcopy(data[3])
        data[3][0][0]["signer_pin"]=data[1]["events"][0]["candidate_signer_pin"]
        with self.assertRaisesRegex(ValueError,"candidate signer"):
            run(data)

    def test_revoked_signer_rejected(self):
        data=list(materials())
        data[3]=copy.deepcopy(data[3])
        data[3][0][0]["signer_pin"]=h("session-pin")
        with self.assertRaisesRegex(ValueError,"revoked"):
            run(data)

    def test_duplicate_signer_pins_rejected(self):
        data=list(materials())
        data[3]=copy.deepcopy(data[3])
        data[3][0][1]["signer_pin"]=data[3][0][0]["signer_pin"]
        with self.assertRaisesRegex(ValueError,"not distinct"):
            run(data)

    def test_missing_witness_group_rejected(self):
        data=list(materials())
        data[3]=data[3][:1]
        with self.assertRaisesRegex(ValueError,"one complete challenge set"):
            run(data)

    def test_invalid_signature_rejected(self):
        def bad(*args): raise ValueError("invalid Ed25519")
        with self.assertRaisesRegex(ValueError,"Ed25519"):
            run(verifier=bad)

    def test_changed_highwater_receipt_rejected(self):
        data=list(materials())
        data[0]=copy.deepcopy(data[0])
        data[0]["current_rust055_receipt_sha256"]=h("false")
        data[0]["receipt_sha256"]=digest({k:v for k,v in data[0].items()
                                          if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"entire recovery ancestry"):
            run(data)

    def test_changed_revocation_custody_rejected(self):
        data=list(materials())
        data[2]=copy.deepcopy(data[2])
        data[2]["revoked_signer_pins"]=[]
        with self.assertRaises(ValueError):
            run(data)

    def test_tampered_prior_entry_rejected(self):
        first=run()
        first["entries"][0]["release_authorized"]=True
        with self.assertRaises(ValueError):
            checked_history(first)

    def test_rollback_floor_rejected(self):
        first=run()
        changed=list(materials("next"))
        changed[0]=copy.deepcopy(changed[0])
        changed[0]["retained_floor_claim_sha256"]=h("second-session")
        changed[0]["receipt_sha256"]=digest({k:v for k,v in changed[0].items()
                                             if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"withheld or forked"):
            run(changed,history=first,
                floor={"phase":"RUST-057","event_count":1,
                       "head_sha256":h("fake-head")})

    def test_historical_conflict_erasures_rejected(self):
        prior=run(materials(shared=True))
        prior["custody_conflicts"]=[]
        prior["receipt_sha256"]=digest({k:v for k,v in prior.items()
                                        if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"conflicts erased"):
            checked_history(prior)

if __name__=="__main__":
    unittest.main()
