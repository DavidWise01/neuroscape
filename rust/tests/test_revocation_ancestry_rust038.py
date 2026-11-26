import copy
import unittest

from lineage_rust019 import digest
from registry_highwater_rust037 import anchor_payload
from revocation_ancestry_rust038 import GENESIS, audit, build_chain, check_floor, hold

PIN="a"*64

def rev(pin,role="ff",epoch=2):
    return {
        "phase":"RUST-036","kind":"KEY_REVOCATION",
        "role":role,"revoked_pin":pin,
        "effective_epoch":epoch,"evidence_sha256":"b"*64,
        "authority_pin":"c"*64,"authority_signature_sha256":"d"*64,
        "release_authorized":False,
    }

def registry(revocations=None, fork=False):
    records=[]
    for role,pin in zip(("ff","cf","rr"),("1"*64,"2"*64,"3"*64)):
        records.append({
            "role":role,"epoch":1,"ledger_sha256":("e"*64 if fork and role=="rr" else "f"*64),
            "checkpoint_sha256":"4"*64,"signing_key_spki_sha256":pin,
            "signature_sha256":"5"*64,"signed_checkpoint_verified":True,
        })
    value={
        "phase":"RUST-036",
        "status":"HOLD_EQUIVOCATION_OR_SHARED_KEYS" if fork else "HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN",
        "epoch_key_claims":records,"verified_rotations":[],
        "revocation_evidence":revocations if revocations is not None else [rev("1"*64),rev("2"*64,"cf")],
        "equivocation_evidence":[{"epoch":1,"conflict":True}] if fork else [],
        "shared_witness_key_evidence":[],
        "external_key_registry_ancestry_verified":False,
        "release_authorized":False,"fork_resolved":False,
    }
    value["receipt_sha256"]=digest(value)
    return value

def anchor(source):
    value={
        "phase":"RUST-037",
        "status":"HOLD_REGISTRY_EQUIVOCATION" if source["status"]=="HOLD_EQUIVOCATION_OR_SHARED_KEYS"
                else "HOLD_EXTERNAL_LATEST_REGISTRY_UNVERIFIED",
        "signed_anchor":anchor_payload(source),
        "anchor_witness_key_spki_sha256":PIN,
        "anchor_signature_sha256":"9"*64,
        "preserved_equivocation_evidence":source["equivocation_evidence"],
        "release_authorized":False,"fork_resolved":False,
    }
    value["receipt_sha256"]=digest(value)
    return value

def fake(*args):
    return "9"*64

def floor(count,head):
    return {"phase":"RUST-038","entry_count":count,"head_sha256":head}

class RevocationAncestryTests(unittest.TestCase):
    def test_default_missing_external_inputs_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EXTERNAL_REVOCATION_ANCESTRY")
        self.assertFalse(hold()["release_authorized"])
    def test_exact_prefix_match_with_new_events(self):
        src=registry()
        entries,heads=build_chain(src["revocation_evidence"])
        result=audit(src,anchor(src),"key.pem","sig.bin",PIN,floor(1,heads[1]),verifier=fake)
        self.assertEqual(result["status"],"HOLD_EXTERNAL_PREFIX_CUSTODY_UNVERIFIED")
        self.assertEqual(len(result["revocation_chain"]),2)
        self.assertEqual(result["revocation_chain_head_sha256"],heads[-1])
        self.assertTrue(result["retained_floor_compared"])
        self.assertFalse(result["release_authorized"])
    def test_genesis_floor_is_explicit(self):
        src=registry([])
        result=audit(src,anchor(src),"key.pem","sig.bin",PIN,floor(0,GENESIS),verifier=fake)
        self.assertEqual(result["revocation_chain_head_sha256"],GENESIS)
    def test_inserted_event_before_retained_floor_rejected(self):
        old=registry()
        _,heads=build_chain(old["revocation_evidence"])
        changed=registry([rev("3"*64,"rr"),*old["revocation_evidence"]])
        with self.assertRaisesRegex(ValueError,"prefix rewritten"):
            audit(changed,anchor(changed),"key.pem","sig.bin",PIN,floor(1,heads[1]),verifier=fake)
    def test_removed_retained_event_rejected(self):
        src=registry()
        _,heads=build_chain(src["revocation_evidence"])
        shortened=registry([src["revocation_evidence"][0]])
        with self.assertRaisesRegex(ValueError,"truncated"):
            audit(shortened,anchor(shortened),"key.pem","sig.bin",PIN,floor(2,heads[2]),verifier=fake)
    def test_modified_retained_event_with_same_count_rejected(self):
        src=registry()
        _,heads=build_chain(src["revocation_evidence"])
        changed=copy.deepcopy(src["revocation_evidence"])
        changed[0]["effective_epoch"]=9
        latest=registry(changed)
        with self.assertRaisesRegex(ValueError,"prefix rewritten"):
            audit(latest,anchor(latest),"key.pem","sig.bin",PIN,floor(2,heads[2]),verifier=fake)
    def test_duplicate_revocation_rejected(self):
        with self.assertRaisesRegex(ValueError,"repeated"):
            build_chain([rev("1"*64),rev("1"*64)])
    def test_untrusted_anchor_signature_rejected(self):
        src=registry()
        def reject(*args):
            raise ValueError("invalid Ed25519")
        with self.assertRaises(ValueError):
            audit(src,anchor(src),"pub.pem","sig.bin",PIN,None,verifier=reject)
    def test_anchor_receipt_signature_and_pin_mismatch_rejected(self):
        src=registry()
        receipt=anchor(src)
        receipt["anchor_signature_sha256"]="0"*64
        receipt["receipt_sha256"]=digest({k:v for k,v in receipt.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"anchor signature differs"):
            audit(src,receipt,"pub.pem","sig.bin",PIN,None,verifier=fake)
        with self.assertRaises(ValueError):
            audit(src,anchor(src),"pub.pem","sig.bin","f"*64,None,verifier=fake)
    def test_tampered_registry_history_rejected(self):
        src=registry()
        src["revocation_evidence"].pop()
        with self.assertRaisesRegex(ValueError,"altered"):
            audit(src,anchor(registry()),"pub.pem","sig.bin",PIN,None,verifier=fake)
    def test_upstream_equivocation_preserved(self):
        src=registry(fork=True)
        result=audit(src,anchor(src),"pub.pem","sig.bin",PIN,None,verifier=fake)
        self.assertEqual(result["status"],"HOLD_PRESERVED_EQUIVOCATION")
        self.assertTrue(result["preserved_equivocation_evidence"])
        self.assertFalse(result["fork_resolved"])

if __name__=="__main__":
    unittest.main()
