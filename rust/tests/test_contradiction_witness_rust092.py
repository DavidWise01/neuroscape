import copy
import hashlib
import unittest
from cross_run_acquisition_ledger_rust091 import append
from contradiction_witness_rust092 import reconcile, payload, hold, HOLD
from cross_run_acquisition_ledger_rust091 import digest, verify_ledger

def h(v):
    return hashlib.sha256(v.encode()).hexdigest()

def observation(i):
    return {"phase":"RUST-090",
        "status":"HOLD_EXTERNAL_INDEPENDENT_CUSTODY_UNVERIFIED",
        "repository":"DavidWise01/neuroscape",
        "run_id":i + 100, "artifact_id":i + 200,
        "run_commit_sha":h("commit"+str(i))[:40],
        "archive_length":100,
        "archive_sha256":h("archive"+str(i)),
        "run_metadata_sha256":h("run"+str(i)),
        "artifact_metadata_sha256":h("meta"+str(i)),
        "bytes_acquired_via_github_api":True,
        "independent_external_custody_verified":False,
        "global_anti_rollback_verified":False,
        "recovery_authorized":False,
        "release_authorized":False,
        "live_gameplay_authorized":False}

def ledger():
    a = append([], observation(1))
    b = observation(2)
    b["artifact_id"] = observation(1)["artifact_id"]
    return append(a,b)

def witness(i, history):
    pin, nonce = h("signer"+str(i)), h("nonce"+str(i))
    ancestry = {k:h(k+str(i)) for k in ("controller","root","source","acquisition")}
    conflicts = [{"index":e["index"],"reasons":e["contradictions"]}
                 for e in history if e["contradictions"]]
    return {"signer_pin":pin, "nonce_sha256":nonce,
            "control_ancestry":ancestry,
            "public_key":"mock", "signature":"sig:"+pin,
            "payload":payload(verify_ledger(history), digest(conflicts),
                              pin,nonce,ancestry)}

def mock_verify(key, signature, pin, data):
    if signature != "sig:"+pin:
        raise ValueError("invalid signature")
    return h(signature)

def run(history=None, ws=None):
    history = ledger() if history is None else history
    return reconcile(history, [witness(1,history),witness(2,history)]
                     if ws is None else ws, verifier=mock_verify)

class ContradictionWitnessTests(unittest.TestCase):
    def reject(self, changes):
        hist=ledger()
        ws=[witness(1,hist), witness(2,hist)]
        changes(hist,ws)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            run(hist,ws)
    def test_missing_hold(self):
        self.assertEqual(hold()["status"],
                         "HOLD_MISSING_INDEPENDENT_CONTRADICTION_WITNESSES")
    def test_two_signatures_still_hold(self):
        r=run()
        self.assertEqual(r["status"],HOLD)
        self.assertFalse(r["historical_contradictions_cleared"])
        self.assertFalse(r["independent_external_custody_verified"])
        self.assertFalse(r["release_authorized"])
    def test_deterministic_replay(self):
        self.assertEqual(run(),run())
    def test_contradictions_retained(self):
        self.assertIn("REUSED_ARTIFACT",run()["retained_contradictions"][0]["reasons"])
    def test_missing_witness(self):
        self.reject(lambda h,w: w.pop())
    def test_extra_witness(self):
        self.reject(lambda h,w: w.append(copy.deepcopy(w[1])))
    def test_same_signer(self):
        self.reject(lambda h,w: w.__setitem__(1,copy.deepcopy(w[0])))
    def test_duplicate_nonce(self):
        self.reject(lambda h,w: w[1].update(nonce_sha256=w[0]["nonce_sha256"]))
    def test_shared_controller(self):
        self.shared("controller")
    def test_shared_root(self):
        self.shared("root")
    def test_shared_source(self):
        self.shared("source")
    def test_shared_acquisition(self):
        self.shared("acquisition")
    def shared(self,k):
        self.reject(lambda h,w: w[1]["control_ancestry"].update(
            {k:w[0]["control_ancestry"][k]}))
    def test_malformed_ancestry(self):
        self.reject(lambda h,w: w[1]["control_ancestry"].pop("root"))
    def test_payload_substitution(self):
        self.reject(lambda h,w: w[1]["payload"].update(
            ledger_head_sha256="f"*64))
    def test_forged_release(self):
        self.reject(lambda h,w: w[1]["payload"].update(release_authorized=True))
    def test_false_custody(self):
        self.reject(lambda h,w: w[1]["payload"].update(
            independent_custody_verified=True))
    def test_bad_signature(self):
        self.reject(lambda h,w: w[0].update(signature="forged"))
    def test_historical_rewrite(self):
        self.reject(lambda h,w: h[0]["observation"].update(archive_length=999))
    def test_no_contradiction(self):
        good = append([],observation(1))
        good = append(good,observation(2))
        with self.assertRaises(ValueError):
            run(good,[witness(1,good),witness(2,good)])
    def test_immutable_signature_digest(self):
        self.assertEqual(len(run()["witness_receipts"]),2)
        self.assertTrue(all(len(x["signed_payload_sha256"]) == 64
                            for x in run()["witness_receipts"]))
if __name__=="__main__":
    unittest.main()
