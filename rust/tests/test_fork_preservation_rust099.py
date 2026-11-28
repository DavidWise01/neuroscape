import copy
import hashlib
import unittest
from highwater_custody_continuity_rust098 import append
from test_highwater_custody_continuity_rust098 import bundle
from fork_preservation_rust099 import adjudicate, fork_pairs, missing, HOLD

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def fixture():
    first, roots1 = bundle(1)
    history = append([], first, roots1)
    second, roots2 = bundle(2, receipt_id=first["rust096_receipt_sha256"])
    history = append(history, second, roots2)
    claims = []
    for index in (0, 1):
        claims.append({
            "branch_index": index,
            "highwater_head_sha256": history[index]["observation"]["highwater_head_sha256"],
            "independent_external_custody_verified": False,
            "release_authorized": False, "fork_selected": False,
            "witness": {
                "signer_pin": h("external-signer-"+str(index)),
                "nonce_sha256": h("external-nonce-"+str(index)),
                "control_ancestry": {
                    k: h("external-"+k+"-"+str(index))
                    for k in ("controller","root","source","acquisition")}}})
    return history, claims

class ForkPreservationRUST099(unittest.TestCase):
    def rejected(self, mutate):
        history, claims = fixture()
        mutate(history, claims)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            adjudicate(history, claims)
    def test_missing_evidence_hold(self):
        self.assertEqual(missing()["status"],
                         "HOLD_MISSING_INDEPENDENT_FORK_ADJUDICATION")
    def test_both_forks_retained(self):
        history, claims = fixture()
        result = adjudicate(history, claims)
        self.assertTrue(result["both_branches_retained"])
        self.assertEqual(len(result["preserved_fork_pairs"]), 1)
    def test_no_winner_selected(self):
        history, claims = fixture()
        result = adjudicate(history, claims)
        self.assertEqual(result["status"], HOLD)
        for k in ("fork_selected","independent_external_custody_verified",
                  "recovery_authorized","release_authorized",
                  "live_gameplay_authorized"):
            self.assertFalse(result[k])
    def test_deterministic_replay(self):
        self.assertEqual(adjudicate(*fixture()), adjudicate(*fixture()))
    def test_wrong_branch_head(self):
        self.rejected(lambda h,c: c[1].update(highwater_head_sha256="f"*64))
    def test_missing_branch(self):
        self.rejected(lambda h,c: c.pop())
    def test_extra_claim(self):
        self.rejected(lambda h,c: c.append(copy.deepcopy(c[0])))
    def test_same_branch_twice(self):
        self.rejected(lambda h,c: c[1].update(branch_index=0,
            highwater_head_sha256=c[0]["highwater_head_sha256"]))
    def test_forged_release(self):
        self.rejected(lambda h,c: c[1].update(release_authorized=True))
    def test_forged_fork_selection(self):
        self.rejected(lambda h,c: c[1].update(fork_selected=True))
    def test_forged_custody(self):
        self.rejected(lambda h,c: c[0].update(independent_external_custody_verified=True))
    def test_history_rewrite(self):
        self.rejected(lambda h,c: h[0]["observation"].update(highwater_head_sha256="f"*64))
    def test_history_removed(self):
        self.rejected(lambda h,c: h.pop())
    def test_shared_signer_not_independent(self):
        history, claims = fixture()
        claims[1]["witness"]["signer_pin"] = claims[0]["witness"]["signer_pin"]
        result = adjudicate(history, claims)
        self.assertIn("SHARED_SIGNER", result["ancestry_conflicts"])
        self.assertFalse(result["fork_selected"])
    def test_shared_nonce_recorded(self):
        history, claims = fixture()
        claims[1]["witness"]["nonce_sha256"] = claims[0]["witness"]["nonce_sha256"]
        self.assertIn("REPLAYED_NONCE", adjudicate(history, claims)["ancestry_conflicts"])
    def test_shared_controller_recorded(self):
        self.shared("controller")
    def test_shared_root_recorded(self):
        self.shared("root")
    def test_shared_source_recorded(self):
        self.shared("source")
    def test_shared_acquisition_recorded(self):
        self.shared("acquisition")
    def shared(self, field):
        history, claims = fixture()
        claims[1]["witness"]["control_ancestry"][field] = (
            claims[0]["witness"]["control_ancestry"][field])
        result = adjudicate(history, claims)
        self.assertIn("SHARED_"+field.upper()+"_ANCESTRY",
                      result["ancestry_conflicts"])
        self.assertFalse(result["independent_external_custody_verified"])
    def test_no_fork_cannot_adjudicate(self):
        history, claims = fixture()
        first = history[:1]
        with self.assertRaises(ValueError): adjudicate(first, claims)
    def test_mutation_free(self):
        history, claims = fixture()
        original = copy.deepcopy((history,claims))
        adjudicate(history,claims)
        self.assertEqual((history,claims),original)

if __name__=="__main__":
    unittest.main()
