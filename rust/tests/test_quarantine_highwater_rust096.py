import copy
import hashlib
import unittest
from test_anti_mirror_custody_rust094 import setup
from persistent_anti_mirror_rust095 import append
from quarantine_highwater_rust096 import (
    audit, checkpoint, missing, HOLD, verify_signed)

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def fake_verify(key, signature, pin, message):
    if signature != "signed:" + pin:
        raise ValueError("signature rejected")
    return h(signature)

def signed(history, i):
    pin = h("highwater-signer-"+str(i))
    nonce = h("unique-highwater-nonce-"+str(i))
    return {"signer_pin":pin, "nonce_sha256":nonce, "public_key":"mock",
            "signature":"signed:"+pin,
            "payload":checkpoint(history,pin,nonce)}

def fixture():
    prior, witnesses=setup()
    first=append([],prior,witnesses)
    second=append(first,prior,witnesses)
    return first,second,signed(first,1),signed(second,2)

def run(parts=None):
    a,b,c,d=fixture() if parts is None else parts
    return audit(a,b,c,d,verifier=fake_verify)

class QuarantineHighwaterRUST096(unittest.TestCase):
    def reject(self, mutate):
        parts=list(fixture())
        mutate(parts)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            run(parts)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"],
            "HOLD_MISSING_SIGNED_QUARANTINE_HIGHWATER")
    def test_two_signed_highwaters_still_hold(self):
        result=run()
        self.assertEqual(result["status"],HOLD)
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["global_latest_floor_authenticated"])
    def test_replay_deterministic(self):
        self.assertEqual(run(),run())
    def test_successor_is_monotone(self):
        self.assertEqual(run()["historic_quarantine_retained"],True)
    def test_stale_same_history(self):
        self.reject(lambda p:p.__setitem__(1,p[0]))
    def test_rollback_history(self):
        self.reject(lambda p:p.__setitem__(1,[]))
    def test_prefix_rewrite(self):
        self.reject(lambda p:p[1][0]["fingerprints"][0].update(raw_sha256=h("rewrite")))
    def test_signed_old_head_substituted(self):
        self.reject(lambda p:p[2]["payload"].update(head_sha256=h("false-head")))
    def test_signed_new_head_substituted(self):
        self.reject(lambda p:p[3]["payload"].update(head_sha256=h("false-head")))
    def test_replayed_nonce(self):
        self.reject(lambda p:p[3].update(nonce_sha256=p[2]["nonce_sha256"]))
    def test_same_signer(self):
        self.reject(lambda p:p[3].update(signer_pin=p[2]["signer_pin"]))
    def test_bad_first_signature(self):
        self.reject(lambda p:p[2].update(signature="bad"))
    def test_bad_second_signature(self):
        self.reject(lambda p:p[3].update(signature="bad"))
    def test_release_forgery(self):
        self.reject(lambda p:p[3]["payload"].update(release_authorized=True))
    def test_quarantine_clear_forgery(self):
        self.reject(lambda p:p[2]["payload"].update(quarantine_cleared=True))
    def test_missing_signed_payload(self):
        self.reject(lambda p:p[3].pop("payload"))
    def test_unbounded_signer_claim(self):
        self.reject(lambda p:p[3].update(signer_pin="wrong"))
    def test_wrong_signed_epoch_count(self):
        self.reject(lambda p:p[3]["payload"].update(event_count=100))
    def test_current_signer_signature_receipt(self):
        result=run()
        self.assertEqual(len(result["current_signature_receipt_sha256"]),64)
    def test_no_history_mutation(self):
        parts=fixture()
        snapshot=copy.deepcopy(parts)
        run(parts)
        self.assertEqual(parts,snapshot)
    def test_empty_predecessor_refused(self):
        self.reject(lambda p:p.__setitem__(0,[]))

if __name__=="__main__":
    unittest.main()
