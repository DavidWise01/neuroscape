import base64
import copy
import hashlib
import unittest

from rotation_rust022 import canonical
from test_operator_highwater_rust106 import fixture, fake_verify, signed
from external_highwater_floor_rust107 import compare, missing, HOLD, DOMAIN

def h(x):
    return hashlib.sha256(x.encode()).hexdigest()

def sample():
    tmp, parts = fixture()
    previous,current,prior_signed,current_signed = parts
    copies = []
    for i, s in enumerate((prior_signed,current_signed)):
        raw = canonical(s["payload"])
        copies.append({
            "domain": DOMAIN, "ledger_epoch": i, "signed_highwater": s,
            "payload_base64": base64.b64encode(raw).decode("ascii"),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "acquisition_nonce_sha256": h("acquisition-"+str(i)),
            "custody": {k:h(k+"-"+str(i)) for k in
                        ("controller","operator","root","network","acquisition")},
            "independent_custody_verified": False, "release_authorized": False})
    return tmp, previous, current, copies

def check(previous,current,copies):
    return compare(previous,current,copies,verifier=fake_verify)

class ExternalHighwaterFloorRUST107(unittest.TestCase):
    def case(self):
        tmp,old,now,copies=sample()
        self.addCleanup(tmp.cleanup)
        return old,now,copies
    def rejected(self,modify):
        old,now,copies=self.case()
        modify(old,now,copies)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            check(old,now,copies)
    def test_missing_evidence_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_EXTERNAL_HIGHWATER_COPY_BYTES")
    def test_two_copies_are_structural_only(self):
        out=check(*self.case())
        self.assertEqual(out["status"],HOLD)
        self.assertFalse(out["external_acquisition_authenticated"])
        self.assertFalse(out["independent_external_custody_verified"])
        self.assertFalse(out["release_authorized"])
    def test_old_copy_flagged_stale(self):
        self.assertIn("STALE_HIGHWATER_COPY",
                      check(*self.case())["provenance_conflicts"])
    def test_mixed_heads_remain_conflicting(self):
        self.assertIn("CONFLICTING_OBSERVED_FLOORS",
                      check(*self.case())["provenance_conflicts"])
    def test_deterministic_replay(self):
        old,now,copies=self.case()
        self.assertEqual(check(old,now,copies),check(old,now,copies))
    def test_same_copy_recorded(self):
        old,now,copies=self.case()
        copies[0]=copy.deepcopy(copies[1])
        out=check(old,now,copies)
        self.assertIn("IDENTICAL_HIGHWATER_COPY",out["provenance_conflicts"])
    def test_same_nonce_recorded(self):
        old,now,copies=self.case()
        copies[1]["acquisition_nonce_sha256"]=copies[0]["acquisition_nonce_sha256"]
        self.assertIn("REPLAYED_ACQUISITION_NONCE",
                      check(old,now,copies)["provenance_conflicts"])
    def test_shared_network_recorded(self):
        self.shared("network")
    def test_shared_root_recorded(self):
        self.shared("root")
    def test_shared_controller_recorded(self):
        self.shared("controller")
    def test_shared_operator_recorded(self):
        self.shared("operator")
    def test_shared_acquisition_recorded(self):
        self.shared("acquisition")
    def shared(self,k):
        old,now,copies=self.case()
        copies[1]["custody"][k]=copies[0]["custody"][k]
        self.assertIn("SHARED_"+k.upper()+"_ANCESTRY",
                      check(old,now,copies)["provenance_conflicts"])
    def test_altered_highwater_bytes_rejected(self):
        self.rejected(lambda old,now,c: c[1].update(
            payload_base64=base64.b64encode(b"forgery").decode()))
    def test_altered_digest_rejected(self):
        self.rejected(lambda old,now,c: c[0].update(payload_sha256="f"*64))
    def test_bad_base64_rejected(self):
        self.rejected(lambda old,now,c: c[0].update(payload_base64="!?"))
    def test_wrong_signed_head_rejected(self):
        self.rejected(lambda old,now,c: c[1]["signed_highwater"]["payload"].update(
            head_sha256="f"*64))
    def test_forged_signature_rejected(self):
        self.rejected(lambda old,now,c: c[1]["signed_highwater"].update(
            signature="not-valid"))
    def test_claimed_release_rejected(self):
        self.rejected(lambda old,now,c: c[0].update(release_authorized=True))
    def test_claimed_custody_rejected(self):
        self.rejected(lambda old,now,c: c[0].update(
            independent_custody_verified=True))
    def test_ledger_rollback_rejected(self):
        self.rejected(lambda old,now,c: now.pop())
    def test_history_rewrite_rejected(self):
        self.rejected(lambda old,now,c: now[0]["observation"]["operators"][0].update(
            report_sha256="f"*64))
    def test_missing_custody_fingerprint_rejected(self):
        self.rejected(lambda old,now,c: c[0]["custody"].pop("network"))
    def test_no_mutation(self):
        old,now,copies=self.case()
        frozen=copy.deepcopy((old,now,copies))
        check(old,now,copies)
        self.assertEqual((old,now,copies),frozen)

if __name__ == "__main__":
    unittest.main()
