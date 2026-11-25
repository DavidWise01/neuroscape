import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from genesis_rust020 import candidate, check_candidate, authenticated, save_exclusive
from lineage_rust019 import digest

def adjudication():
    data={
        "phase":"RUST-018","status":"CONSISTENT_OBSERVATIONS",
        "source_commit":"a"*40,"wasm_sha256":"b"*64,
        "replay_sha256":"c"*64,"live_gameplay_authority":False,
        "source_independence_certified":False,
    }
    data["receipt_sha256"]=digest(data)
    return data

class GenesisTests(unittest.TestCase):
    def test_genesis_is_candidate_not_authority(self):
        x=candidate(adjudication())
        self.assertEqual(x["status"],"GENESIS_CANDIDATE")
        self.assertEqual(x["sequence"],0)
        self.assertFalse(x["custody_authenticated"])
        self.assertEqual(check_candidate(x),x)
        self.assertEqual(x,candidate(adjudication()))
    def test_tampering_and_self_issued_authority_fail(self):
        x=candidate(adjudication())
        for k,v in [
            ("source_commit","e"*40),("sequence",1),
            ("custody_authenticated",True),
            ("live_gameplay_authority",True),
            ("independent_source_ancestries",3),
            ("candidate_sha256","0"*64),
        ]:
            with self.subTest(field=k):
                y=copy.deepcopy(x);y[k]=v
                with self.assertRaises(ValueError):
                    check_candidate(y)
    def test_missing_external_pin_fails_closed(self):
        with self.assertRaises(ValueError):
            authenticated(candidate(adjudication()),"absent.pem","absent.sig",None)
    def test_exclusive_write_does_not_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"genesis.json"
            save_exclusive(p,candidate(adjudication()))
            before=p.read_bytes()
            with self.assertRaises(FileExistsError):
                save_exclusive(p,{"tampered":True})
            self.assertEqual(p.read_bytes(),before)

if __name__=="__main__":
    unittest.main()
