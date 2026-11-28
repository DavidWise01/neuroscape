import base64
import copy
import hashlib
import unittest
from rotation_rust022 import canonical
from cross_run_acquisition_ledger_rust091 import digest
from external_highwater_witness_rust097 import (
    verify, signed_payload, missing, HOLD)

def h(v):
    return hashlib.sha256(v.encode()).hexdigest()

def fixture():
    prior={"phase":"RUST-096",
           "status":"HOLD_QUARANTINE_HIGHWATER_INDEPENDENCE_UNVERIFIED",
           "current_head_sha256":h("head"),
           "global_latest_floor_authenticated":False,
           "independent_external_custody_verified":False,
           "release_authorized":False}
    raw=canonical(prior)
    rows=[]
    for i in (1,2):
        pin=h("pin"+str(i));nonce=h("nonce"+str(i))
        ancestry={k:h(k+str(i)) for k in ("controller","root","source","acquisition")}
        fingerprint=hashlib.sha256(raw).hexdigest()
        rows.append({"signer_pin":pin,"nonce_sha256":nonce,
            "control_ancestry":ancestry,
            "highwater_base64":base64.b64encode(raw).decode(),
            "evidence_sha256":fingerprint,
            "payload":signed_payload(digest(prior),pin,nonce,ancestry,fingerprint),
            "public_key":"test-key","signature":"signed:"+pin})
    return prior,rows

def mocked(key,signature,pin,content):
    if signature != "signed:"+pin:
        raise ValueError("invalid signature")
    return h(signature)

def run(parts=None):
    p,w=fixture() if parts is None else parts
    return verify(p,w,verifier=mocked)

class ExternalHighwaterRUST097(unittest.TestCase):
    def rejected(self,change):
        p,w=fixture()
        change(p,w)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            run((p,w))
    def test_missing_remains_hold(self):
        self.assertEqual(missing()["status"],"HOLD_MISSING_EXTERNAL_HIGHWATER_WITNESSES")
    def test_valid_submissions_remain_hold(self):
        o=run()
        self.assertEqual(o["status"],HOLD)
        self.assertTrue(o["matching_submitted_highwater_bytes"])
        self.assertFalse(o["independent_external_custody_verified"])
        self.assertFalse(o["global_anti_rollback_verified"])
        self.assertFalse(o["release_authorized"])
    def test_deterministic_replay(self):
        self.assertEqual(run(),run())
    def test_missing_witness(self):
        self.rejected(lambda p,w:w.pop())
    def test_extra_witness(self):
        self.rejected(lambda p,w:w.append(copy.deepcopy(w[0])))
    def test_duplicate_signer(self):
        self.rejected(lambda p,w:w[1].update(signer_pin=w[0]["signer_pin"]))
    def test_duplicate_nonce(self):
        self.rejected(lambda p,w:w[1].update(nonce_sha256=w[0]["nonce_sha256"]))
    def test_shared_controller(self):
        self.shared("controller")
    def test_shared_root(self):
        self.shared("root")
    def test_shared_source(self):
        self.shared("source")
    def test_shared_acquisition(self):
        self.shared("acquisition")
    def shared(self,key):
        self.rejected(lambda p,w:w[1]["control_ancestry"].update(
            {key:w[0]["control_ancestry"][key]}))
    def test_altered_archive_bytes(self):
        self.rejected(lambda p,w:w[1].update(
            highwater_base64=base64.b64encode(b"other").decode()))
    def test_bad_base64(self):
        self.rejected(lambda p,w:w[1].update(highwater_base64="!bad!"))
    def test_repackaged_json(self):
        self.rejected(lambda p,w:w[1].update(
            highwater_base64=base64.b64encode(
                b'{ "phase": "RUST-096" }').decode()))
    def test_forged_release(self):
        self.rejected(lambda p,w:w[1]["payload"].update(release_authorized=True))
    def test_forged_custody(self):
        self.rejected(lambda p,w:w[0]["payload"].update(independent_custody_verified=True))
    def test_replaced_head(self):
        self.rejected(lambda p,w:p.update(current_head_sha256=h("rollback")))
    def test_replaced_signature(self):
        self.rejected(lambda p,w:w[1].update(signature="bad"))
    def test_missing_signed_payload(self):
        self.rejected(lambda p,w:w[1].pop("payload"))
    def test_highwater_authority_promoted(self):
        self.rejected(lambda p,w:p.update(global_latest_floor_authenticated=True))
    def test_no_mutation(self):
        p,w=fixture()
        before=copy.deepcopy((p,w))
        run((p,w))
        self.assertEqual((p,w),before)
if __name__=="__main__":
    unittest.main()
