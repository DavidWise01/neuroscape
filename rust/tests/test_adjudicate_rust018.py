import copy
import unittest
from adjudicate_rust018 import adjudicate

A="a"*40
B="b"*64
C="c"*64
def receipts():
    build={"source_commit":A,"github_run_id":"123","wasm_sha256":B,
      "replay_sha256":C,"replay_steps":3,"reproducible_build":True,
      "cross_runner_reproducible":True,"reproduction_wasm_sha256":B,
      "cross_runner_wasm_sha256":B,"native_rust_gate":"passed_in_deployment_job",
      "chromium_phase_and_combat_gate":"passed_in_deployment_job",
      "live_gameplay_authority":False}
    replay={"source_commit":A,"replay_sha256":C,"replay_steps":3}
    public={"source_commit":A,"github_run_id":"123","wasm_sha256":B,
      "replay_sha256":C,"public_manifest":"MATCH","public_browser_combat":"PASS",
      "cross_runner_sha256":B,"reproduced_wasm_sha256":B,
      "live_gameplay_authority":False}
    return build,replay,public

class ThreeObservations(unittest.TestCase):
    def test_agreement_is_not_independent_ancestry(self):
        a,b,c=receipts()
        x=adjudicate(a,b,c)
        self.assertEqual(x["status"],"CONSISTENT_OBSERVATIONS")
        self.assertEqual(x["independent_source_ancestries"],1)
        self.assertFalse(x["source_independence_certified"])
        self.assertEqual(x,adjudicate(a,b,c))
    def test_contradictions_rejected(self):
        mutations=[
          (0,"cross_runner_wasm_sha256",C),(0,"replay_steps",2),
          (0,"native_rust_gate","failed"),(0,"live_gameplay_authority",True),
          (1,"source_commit","d"*40),(1,"replay_sha256",B),
          (2,"github_run_id","124"),(2,"public_browser_combat","HOLD"),
          (2,"replay_sha256",B),(2,"live_gameplay_authority",True),
        ]
        for index,key,value in mutations:
            with self.subTest(index=index,key=key):
                values=list(copy.deepcopy(receipts()))
                values[index][key]=value
                with self.assertRaises(ValueError):
                    adjudicate(*values)

if __name__=="__main__":
    unittest.main()
