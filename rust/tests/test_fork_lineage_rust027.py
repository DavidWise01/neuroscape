import copy
import unittest

from highwater_rust025 import make_candidate
from lineage_rust019 import digest
from fork_lineage_rust027 import reconstruct, hold

GEN=make_candidate(0,10,"a"*40,"1"*64,"9"*64)
LEFT=make_candidate(0,11,"b"*40,"2"*64,GEN["candidate_sha256"])
RIGHT=make_candidate(0,11,"c"*40,"3"*64,GEN["candidate_sha256"])
NEXT=make_candidate(0,12,"d"*40,"4"*64,LEFT["candidate_sha256"])
PINS=["5"*64,"6"*64,"7"*64]
ROLES=["ff","cf","rr"]

def witness(points):
    observations=[]
    for role,pin,cp in zip(ROLES,PINS,points):
        observations.append({
            "role":role,"candidate_sha256":cp["candidate_sha256"],
            "source_commit":cp["source_commit"],"epoch":cp["epoch"],
            "sequence":cp["sequence"],
            "previous_highwater_sha256":cp["previous_highwater_sha256"],
            "entry_sha256":cp["entry_sha256"],
            "key_spki_sha256":pin,"signature_sha256":"8"*64,
            "signature_verified":True,
        })
    record={"phase":"RUST-026","status":"HOLD_FORK_EVIDENCE" if len({x["candidate_sha256"] for x in observations})>1 else "CONSISTENT_SIGNED_SNAPSHOTS",
            "observations":observations,"release_authorized":False,
            "independent_custody_ancestries_verified":False}
    record["receipt_sha256"]=digest(record)
    return record

class ForkLineageTests(unittest.TestCase):
    def test_missing_graph_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_FORK_GRAPH")
    def test_fork_retains_all_claims_and_common_ancestor(self):
        output=reconstruct(witness([NEXT,LEFT,RIGHT]),[GEN,LEFT,RIGHT,NEXT])
        self.assertTrue(output["fork_detected"])
        self.assertEqual(output["observed_common_ancestor_sha256"],GEN["candidate_sha256"])
        self.assertEqual(len(output["branches"]),3)
        self.assertEqual(len(output["fork_heads_sha256"]),3)
        self.assertFalse(output["release_authorized"])
    def test_missing_predecessor_does_not_invent_genesis(self):
        output=reconstruct(witness([LEFT,LEFT,RIGHT]),[LEFT,RIGHT])
        self.assertEqual(output["status"],"HOLD_NO_PROVEN_COMMON_ANCESTOR")
        self.assertIsNone(output["observed_common_ancestor_sha256"])
    def test_repeated_observations_not_independent_ancestry(self):
        output=reconstruct(witness([LEFT,LEFT,LEFT]),[GEN,LEFT])
        self.assertFalse(output["independent_custody_ancestries_verified"])
        self.assertEqual(output["status"],"HOLD_INCOMPLETE_ANCESTRY")
    def test_tampered_graph_refused(self):
        records=[GEN,LEFT,RIGHT,NEXT]
        for field,value in [("source_commit","f"*40),("sequence",99)]:
            items=copy.deepcopy(records)
            items[1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                reconstruct(witness([LEFT,LEFT,RIGHT]),items)
    def test_graph_head_and_witness_mismatch_refused(self):
        record=witness([LEFT,LEFT,RIGHT])
        record["observations"][0]["entry_sha256"]="0"*64
        record["receipt_sha256"]=digest({k:v for k,v in record.items() if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            reconstruct(record,[GEN,LEFT,RIGHT])
    def test_missing_head_and_duplicate_node_refused(self):
        with self.assertRaises(ValueError):
            reconstruct(witness([LEFT,LEFT,RIGHT]),[GEN,LEFT])
        with self.assertRaises(ValueError):
            reconstruct(witness([LEFT,LEFT,RIGHT]),[GEN,LEFT,LEFT,RIGHT])
    def test_broken_sequence_link_refused(self):
        bad=make_candidate(0,15,"f"*40,"a"*64,GEN["candidate_sha256"])
        with self.assertRaises(ValueError):
            reconstruct(witness([bad,bad,bad]),[GEN,bad])
    def test_witness_digest_tampering_refused(self):
        record=witness([LEFT,LEFT,RIGHT])
        record["observations"][0]["signature_verified"]=False
        with self.assertRaises(ValueError):
            reconstruct(record,[GEN,LEFT,RIGHT])

if __name__=="__main__":
    unittest.main()
