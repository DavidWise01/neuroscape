import copy
import hashlib
import unittest
from test_external_floor_quarantine_rust108 import report_fixture
from external_floor_quarantine_rust108 import append
from signed_quarantine_highwater_rust109 import (
    checkpoint, audit, competing, missing, HOLD)

def h(v):
    return hashlib.sha256(v.encode()).hexdigest()

def verify_mock(key, signature, pin, payload):
    if signature != "signed:"+pin: raise ValueError("bad signature")
    return h(signature)

def sign(history, index):
    pin,nonce=h("quarantine-signer-"+str(index)),h("quarantine-nonce-"+str(index))
    return {"signer_pin":pin,"nonce_sha256":nonce,
            "public_key":"mock-key","signature":"signed:"+pin,
            "payload":checkpoint(history,pin,nonce)}

def fixture():
    temp,report=report_fixture()
    prior=append([],report)
    current=append(prior,report)
    return temp,[prior,current,sign(prior,1),sign(current,2)]

def run(parts):
    return audit(*parts,verifier=verify_mock)

class SignedQuarantineHighwaterRUST109(unittest.TestCase):
    def case(self):
        temp,parts=fixture();self.addCleanup(temp.cleanup)
        return parts
    def reject(self,change):
        parts=self.case();change(parts)
        with self.assertRaises((ValueError,KeyError,TypeError)):
            run(parts)
    def test_missing_evidence_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_SIGNED_QUARANTINE_HIGHWATER")
    def test_valid_signed_extension_still_hold(self):
        o=run(self.case())
        self.assertEqual(o["status"],HOLD)
        self.assertTrue(o["exclusion_history_preserved"])
        self.assertFalse(o["independent_external_custody_verified"])
        self.assertFalse(o["release_authorized"])
    def test_deterministic_replay(self):
        p=self.case();self.assertEqual(run(p),run(p))
    def test_nonempty_predecessor_required(self):
        self.reject(lambda p:p.__setitem__(0,[]))
    def test_same_history_rejected(self):
        self.reject(lambda p:p.__setitem__(1,p[0]))
    def test_rollback_rejected(self):
        self.reject(lambda p:p.__setitem__(1,[]))
    def test_erased_quarantine_reason_rejected(self):
        self.reject(lambda p:p[1][-1].update(quarantine_reasons=[]))
    def test_erased_stale_conflict_rejected(self):
        self.reject(lambda p:p[1][0]["observation"].update(derived_conflicts=[]))
    def test_changed_old_entry_rejected(self):
        self.reject(lambda p:p[1][0]["observation"]["copies"][0].update(
            payload_sha256="f"*64))
    def test_wrong_prior_head_rejected(self):
        self.reject(lambda p:p[2]["payload"].update(head_sha256="f"*64))
    def test_wrong_new_head_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(head_sha256="f"*64))
    def test_history_digest_tamper_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(history_sha256="f"*64))
    def test_exclusion_digest_tamper_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(excluded_history_sha256="f"*64))
    def test_replayed_nonce_rejected(self):
        self.reject(lambda p:p[3].update(nonce_sha256=p[2]["nonce_sha256"]))
    def test_reused_signer_rejected(self):
        self.reject(lambda p:p[3].update(signer_pin=p[2]["signer_pin"]))
    def test_bad_previous_signature_rejected(self):
        self.reject(lambda p:p[2].update(signature="bad"))
    def test_bad_current_signature_rejected(self):
        self.reject(lambda p:p[3].update(signature="bad"))
    def test_false_release_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(release_authorized=True))
    def test_false_external_custody_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(
            independent_external_custody_verified=True))
    def test_false_global_latest_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(globally_authenticated_latest=True))
    def test_false_fork_winner_rejected(self):
        self.reject(lambda p:p[3]["payload"].update(fork_selected=True))
    def test_competing_claims_are_preserved(self):
        parts=self.case()
        result=competing(parts[1],sign(parts[1],3),sign(parts[1],4),
                         verifier=verify_mock)
        self.assertEqual(len(result["preserved_claims"]),2)
        self.assertFalse(result["fork_selected"])
    def test_competing_reused_signer_rejected(self):
        parts=self.case();s=sign(parts[1],3)
        with self.assertRaises(ValueError):
            competing(parts[1],s,copy.deepcopy(s),verifier=verify_mock)
    def test_no_input_mutation(self):
        parts=self.case();saved=copy.deepcopy(parts)
        run(parts);self.assertEqual(parts,saved)

if __name__=="__main__":unittest.main()
