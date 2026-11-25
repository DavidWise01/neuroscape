import copy
import unittest
from unittest.mock import patch
from highwater_rust025 import make_candidate, check_checkpoint, validate_successor, observe, hold

A="a"*40
B="b"*40
C="c"*40

def old():
    return make_candidate(2,17,A,"d"*64,"e"*64)

def successor():
    return make_candidate(2,18,B,"f"*64,old()["candidate_sha256"])

class ExternalHighwaterTests(unittest.TestCase):
    def test_missing_witness_is_hold(self):
        self.assertEqual(hold("no external witness")["status"],"HOLD_EXTERNAL_HIGHWATER")
        self.assertFalse(hold("no external witness")["release_authorized"])
    def test_exact_successor(self):
        self.assertTrue(validate_successor(old(), successor()))
    def test_fork_rollback_replay_and_skip(self):
        a=old()
        mutations=[
            ("previous_highwater_sha256","0"*64),
            ("sequence",17),("sequence",19),
            ("epoch",1),("source_commit",A),
            ("entry_sha256",a["entry_sha256"]),
        ]
        for name,value in mutations:
            with self.subTest(field=name):
                base={k:v for k,v in successor().items() if k!="candidate_sha256"}
                base[name]=value
                from lineage_rust019 import digest
                base["candidate_sha256"]=digest(base)
                with self.assertRaises(ValueError):
                    validate_successor(a,base)
    def test_candidate_tampering_fails(self):
        item=copy.deepcopy(old())
        item["epoch"]=3
        with self.assertRaises(ValueError):
            check_checkpoint(item)
    def test_signature_is_not_global_latest_or_release_authority(self):
        with patch("highwater_rust025.verify_witness",return_value="1"*64) as verify:
            result=observe(old(),"witness.pem","witness.sig","2"*64,successor())
        self.assertEqual(verify.call_count,1)
        self.assertEqual(result["status"],"SIGNED_HIGHWATER_OBSERVED")
        self.assertFalse(result["external_latest_checkpoint_confirmed"])
        self.assertFalse(result["release_authorized"])
    def test_signature_must_be_real_not_self_reported(self):
        with self.assertRaises(ValueError):
            observe(old(),"absent.pem","absent.sig",None)
    def test_no_duplicate_candidate(self):
        with self.assertRaises(ValueError):
            validate_successor(old(),old())

if __name__=="__main__":
    unittest.main()
