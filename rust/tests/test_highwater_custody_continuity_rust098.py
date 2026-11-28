import copy
import hashlib
import unittest
from cross_run_acquisition_ledger_rust091 import digest
from highwater_custody_continuity_rust098 import (
    append, audit, conflicts, missing, observe, validate, HOLD, ZERO)

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def bundle(i=1, head=None, receipt_id=None, reuse=False):
    pin_offset = 1 if reuse else i
    claims = []
    witness_receipts = []
    for n in (1,2):
        pin = h("signer-%s-%s" % (pin_offset, n))
        nonce = h("nonce-%s-%s" % (pin_offset, n))
        roots = {k: h("%s-%s-%s" % (k,pin_offset,n)) for k in
                 ("controller","root","source","acquisition")}
        claims.append({"signer_pin": pin, "control_ancestry": roots})
        witness_receipts.append({
            "signer_pin": pin, "nonce_sha256": nonce,
            "evidence_sha256": h("bytes-%s-%s" % (pin_offset,n)),
            "signature_receipt_sha256": h("signature-%s-%s" % (pin_offset,n)),
            "control_ancestry_sha256": digest(roots)})
    receipt = {
        "phase": "RUST-097",
        "status": "HOLD_EXTERNAL_HIGHWATER_CUSTODY_UNVERIFIED",
        "highwater_head_sha256": head or h("head-"+str(i)),
        "rust096_receipt_sha256": receipt_id or h("receipt-"+str(i)),
        "witness_receipts": witness_receipts,
        "independent_external_custody_verified": False,
        "global_anti_rollback_verified": False,
        "release_authorized": False}
    return receipt, claims

def fixture():
    a,ca = bundle(1)
    past = append([], a, ca)
    b,cb = bundle(2)
    later = append(past, b, cb)
    return past, later

class HighwaterContinuityRUST098(unittest.TestCase):
    def test_missing_remains_hold(self):
        self.assertEqual(missing()["status"],
            "HOLD_MISSING_CUSTODY_CONTINUITY_LEDGER")
    def test_empty_head(self):
        self.assertEqual(validate([]),ZERO)
    def test_append_monotone(self):
        a,b = fixture()
        self.assertEqual(b[:len(a)], a)
        self.assertNotEqual(validate(a),validate(b))
    def test_distinct_claims_still_hold(self):
        a,b = fixture()
        r = audit(a,b)
        self.assertEqual(r["status"], HOLD)
        for field in ("fork_selected","independent_external_custody_verified",
                      "global_latest_floor_authenticated","recovery_authorized",
                      "release_authorized","live_gameplay_authorized"):
            self.assertFalse(r[field])
    def test_deterministic_replay(self):
        self.assertEqual(fixture(),fixture())
    def test_duplicate_highwater_head_recorded(self):
        old,_ = fixture()
        r,c = bundle(3,head=old[0]["observation"]["highwater_head_sha256"])
        new = append(old,r,c)
        self.assertIn("REPEATED_HIGHWATER_HEAD",new[-1]["conflicts"])
    def test_fork_with_same_receipt_recorded(self):
        old,_ = fixture()
        r,c = bundle(3,receipt_id=old[0]["observation"]["rust096_receipt_sha256"])
        new = append(old,r,c)
        self.assertIn("CONFLICTING_HEAD_FOR_HIGHWATER_RECEIPT",
                      new[-1]["conflicts"])
        self.assertFalse(audit(old,new)["fork_selected"])
    def test_same_receipt_and_head_recorded(self):
        old,_ = fixture()
        ob=old[0]["observation"]
        r,c=bundle(3,head=ob["highwater_head_sha256"],
                   receipt_id=ob["rust096_receipt_sha256"])
        new=append(old,r,c)
        self.assertIn("REPEATED_HIGHWATER_RECEIPT",new[-1]["conflicts"])
    def test_reappearing_signer_recorded(self):
        old,_ = fixture()
        r,c=bundle(3,reuse=True)
        new=append(old,r,c)
        self.assertIn("REAPPEARING_SIGNER",new[-1]["conflicts"])
    def test_reused_ancestry_recorded(self):
        old,_=fixture()
        r,c=bundle(3,reuse=True)
        new=append(old,r,c)
        self.assertIn("REUSED_SOURCE_ANCESTRY",new[-1]["conflicts"])
    def test_reused_byte_digest_recorded(self):
        old,_=fixture()
        r,c=bundle(3,reuse=True)
        new=append(old,r,c)
        self.assertIn("REUSED_HIGHWATER_BYTES",new[-1]["conflicts"])
    def test_nonce_replay_recorded(self):
        old,_=fixture()
        r,c=bundle(3,reuse=True)
        new=append(old,r,c)
        self.assertIn("REPLAYED_WITNESS_NONCE",new[-1]["conflicts"])
    def test_no_extension_rejected(self):
        old,_=fixture()
        with self.assertRaises(ValueError): audit(old,old)
    def test_rollback_rejected(self):
        old,new=fixture()
        with self.assertRaises(ValueError): audit(new,old)
    def test_history_rewrite_rejected(self):
        old,new=fixture()
        tampered=copy.deepcopy(new)
        tampered[0]["observation"]["highwater_head_sha256"]=h("rewritten")
        with self.assertRaises(ValueError): audit(old,tampered)
    def test_deleted_fork_contradiction_rejected(self):
        old,_=fixture()
        r,c=bundle(3,receipt_id=old[0]["observation"]["rust096_receipt_sha256"])
        new=append(old,r,c)
        new[-1]["conflicts"]=[]
        with self.assertRaises(ValueError):validate(new)
    def test_false_release_rejected(self):
        r,c=bundle(1);r["release_authorized"]=True
        with self.assertRaises(ValueError):append([],r,c)
    def test_false_external_custody_rejected(self):
        r,c=bundle(1);r["independent_external_custody_verified"]=True
        with self.assertRaises(ValueError):append([],r,c)
    def test_wrong_ancestry_binding_rejected(self):
        r,c=bundle(1);c[0]["control_ancestry"]["source"]=h("other-source")
        with self.assertRaises(ValueError):append([],r,c)
    def test_same_epoch_duplicate_signer_rejected(self):
        r,c=bundle(1);r["witness_receipts"][1]["signer_pin"]=r["witness_receipts"][0]["signer_pin"]
        c[1]["signer_pin"]=c[0]["signer_pin"]
        with self.assertRaises(ValueError):append([],r,c)
    def test_historical_conflicts_survive_later_append(self):
        old,_=fixture()
        r,c=bundle(3,reuse=True)
        second=append(old,r,c)
        later,claims=bundle(4)
        third=append(second,later,claims)
        self.assertEqual(third[1], second[1])
        self.assertTrue(audit(second,third)["retained_conflicts"])

if __name__=="__main__":
    unittest.main()
