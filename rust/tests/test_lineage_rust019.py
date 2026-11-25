import copy
import unittest
from lineage_rust019 import build, digest, validate_predecessor

OLD="a"*40
NEW="b"*40
WASM="c"*64
REPLAY="d"*64

def evidence(source=NEW):
    raw={
        "phase":"RUST-018","status":"CONSISTENT_OBSERVATIONS",
        "source_commit":source,"wasm_sha256":WASM,"replay_sha256":REPLAY,
        "source_independence_certified":False,"live_gameplay_authority":False,
    }
    raw["receipt_sha256"]=digest(raw)
    return raw

def predecessor():
    base={
        "phase":"RUST-019","status":"ANCHORED",
        "sequence":1,"source_commit":OLD,
        "receipt_sha256":"e"*64,"predecessor_sha256":"f"*64,
        "predecessor_source_commit":"0"*40,
        "source_independence_certified":False,"live_gameplay_authority":False,
    }
    base["entry_sha256"]=digest(base)
    return base

class LineageTests(unittest.TestCase):
    def test_no_predecessor_is_hold(self):
        value=build(evidence())
        self.assertEqual(value["status"],"HOLD_UNANCHORED")
        self.assertIsNone(value["sequence"])
        self.assertNotIn("entry_sha256",value)
    def test_append_link_and_sequence(self):
        p=predecessor()
        value=build(evidence(),p,lambda a,b:a==OLD and b==NEW)
        self.assertEqual(value["sequence"],2)
        self.assertEqual(value["predecessor_sha256"],p["entry_sha256"])
        self.assertEqual(digest({k:v for k,v in value.items() if k!="entry_sha256"}),value["entry_sha256"])
    def test_rejected_rollbacks_and_forgery(self):
        p=predecessor()
        cases=[
            (evidence(),p,lambda a,b:False),
            (evidence(OLD),p,lambda a,b:True),
            (evidence(),{**p,"sequence":0},lambda a,b:True),
            (evidence(),{**p,"entry_sha256":"0"*64},lambda a,b:True),
            ({**evidence(),"receipt_sha256":"0"*64},p,lambda a,b:True),
            (evidence(),None,lambda a,b:True),
        ]
        for current,previous,test in cases:
            with self.subTest(case=str(current)[:40]):
                if previous is None:
                    self.assertEqual(build(current,previous,test)["status"],"HOLD_UNANCHORED")
                else:
                    with self.assertRaises(ValueError):
                        build(current,previous,test)

if __name__=="__main__":
    unittest.main()
