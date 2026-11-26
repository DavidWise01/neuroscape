import copy
import unittest

from lineage_rust019 import digest
from cross_custody_highwater_rust049 import audit as cross_audit
from fork_registry_rust050 import audit, genesis, hold, checked_history, GENESIS
from test_cross_custody_highwater_rust049 import (
    histories, branch, PINS, verifier, sha)


def observation(fork=False, shared=False, newer=False):
    _, second, other, third=histories()
    left=branch(third if newer else second)
    right=branch(other if fork else (third if newer else second), 1)
    if shared:
        right["custody_root_sha256"]=left["custody_root_sha256"]
    return cross_audit(left,right,PINS,verifier=verifier)


def floor(registry):
    return {"phase":"RUST-050","entry_count":registry["entry_count"],
            "head_sha256":registry["head_sha256"]}


class ForkRegistryTests(unittest.TestCase):
    def test_missing_external_history_hold(self):
        out=hold()
        self.assertEqual(out["status"],"HOLD_MISSING_EXTERNAL_FORK_CUSTODY")
        self.assertFalse(out["release_authorized"])

    def test_genesis_first_fork_keeps_both_branches(self):
        out=audit(observation(fork=True),genesis())
        self.assertEqual(out["entry_count"],1)
        self.assertEqual(out["prefix_heads"][0],GENESIS)
        self.assertEqual(len(out["fork_events"]),1)
        self.assertEqual(len(out["entries"][0]["source_branch_snapshots"]),2)
        self.assertFalse(out["fork_events"][0]["winner_selected"])
        self.assertFalse(out["fork_resolved"])

    def test_later_convergence_cannot_erase_first_fork(self):
        first=audit(observation(fork=True),genesis())
        second=audit(observation(newer=True),first,floor(first))
        self.assertEqual(second["fork_events"],first["fork_events"])
        self.assertEqual(second["entries"][:1],first["entries"])
        self.assertEqual(second["prefix_heads"][:2],first["prefix_heads"])
        self.assertFalse(second["release_authorized"])

    def test_shared_claimed_root_retained(self):
        out=audit(observation(shared=True),genesis())
        self.assertEqual(len(out["custody_ancestry_alerts"]),1)
        self.assertTrue(out["custody_ancestry_alerts"][0]["shared_claimed_source"])
        self.assertFalse(out["independent_evidence_custody_authenticated"])

    def test_replay_same_cross_custody_receipt_rejected(self):
        sample=observation(fork=True)
        first=audit(sample,genesis())
        with self.assertRaisesRegex(ValueError,"receipt replay"):
            audit(sample,first)

    def test_wrong_retained_floor_fails(self):
        first=audit(observation(fork=True),genesis())
        bad=floor(first)
        bad["head_sha256"]=sha("alternate")
        with self.assertRaisesRegex(ValueError,"rewritten or withheld"):
            audit(observation(newer=True),first,bad)

    def test_tampered_previous_fork_ledger_fails(self):
        first=audit(observation(fork=True),genesis())
        first["entries"][0]["source_branch_snapshots"][0]["head_sha256"]=sha("bad")
        with self.assertRaises(ValueError):
            audit(observation(newer=True),first)

    def test_removed_prior_fork_event_fails(self):
        first=audit(observation(fork=True),genesis())
        first["fork_events"]=[]
        first["receipt_sha256"]=digest({k:v for k,v in first.items()
                                        if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"alerts discarded"):
            audit(observation(newer=True),first)

    def test_upstream_fork_rebranded_as_clean_rejected(self):
        upstream=observation(fork=True)
        upstream["same_count_fork_evidence"]=None
        upstream["status"]="HOLD_EXTERNAL_CUSTODY_UNVERIFIED"
        upstream["receipt_sha256"]=digest({k:v for k,v in upstream.items()
                                            if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"conflicting branches"):
            audit(upstream,genesis())

    def test_substituted_branch_head_fails(self):
        upstream=observation(fork=True)
        upstream["right_branch"]["head_sha256"]=sha("new-root")
        upstream["receipt_sha256"]=digest({k:v for k,v in upstream.items()
                                            if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"terminal head"):
            audit(upstream,genesis())

    def test_forged_authority_flag_rejected(self):
        upstream=observation()
        upstream["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"authority promotion"):
            audit(upstream,genesis())

    def test_forged_prior_authority_rejected(self):
        first=audit(observation(fork=True),genesis())
        first["fork_resolved"]=True
        with self.assertRaisesRegex(ValueError,"promoted authority"):
            audit(observation(newer=True),first)

    def test_external_floor_at_genesis(self):
        out=audit(observation(),genesis(),
                  {"phase":"RUST-050","entry_count":0,"head_sha256":GENESIS})
        self.assertTrue(out["retained_floor_compared"])

    def test_invalid_signature_digest_rejected(self):
        upstream=observation()
        upstream["left_branch"]["signature_sha256"]="invalid"
        upstream["receipt_sha256"]=digest({k:v for k,v in upstream.items()
                                            if k!="receipt_sha256"})
        with self.assertRaises(ValueError):
            audit(upstream,genesis())

if __name__=="__main__":
    unittest.main()
