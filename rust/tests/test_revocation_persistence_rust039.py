import copy
import unittest

from lineage_rust019 import digest
from revocation_ancestry_rust038 import build_chain
from revocation_persistence_rust039 import audit, hold

ROLES=("ff","cf","rr")
PINS={"ff":"1"*64,"cf":"2"*64,"rr":"3"*64}

def revocation(role="ff",pin=None,epoch=2):
    return {
        "phase":"RUST-036","kind":"KEY_REVOCATION",
        "role":role,"revoked_pin":pin or PINS[role],
        "effective_epoch":epoch,"evidence_sha256":"a"*64,
        "authority_pin":"b"*64,"authority_signature_sha256":"c"*64,
        "release_authorized":False,
    }

def fixture(keys_extra=None,revocations=None):
    keys_extra=keys_extra or []
    claims=[]
    for role in ROLES:
        claims.append({
            "role":role,"epoch":1,
            "signing_key_spki_sha256":PINS[role],
            "checkpoint_sha256":"d"*64,
            "signature_sha256":"e"*64,
            "signed_checkpoint_verified":True,
        })
        if role in keys_extra:
            claims.append({
                "role":role,"epoch":2,
                "signing_key_spki_sha256":"4"*64,
                "checkpoint_sha256":"f"*64,
                "signature_sha256":"6"*64,
                "signed_checkpoint_verified":True,
            })
    revocations=[revocation()] if revocations is None else revocations
    reg={
        "phase":"RUST-036","status":"HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN",
        "epoch_key_claims":claims,
        "verified_rotations":[],
        "revocation_evidence":revocations,
        "external_key_registry_ancestry_verified":False,
        "release_authorized":False,"fork_resolved":False,
    }
    reg["receipt_sha256"]=digest(reg)
    entries,heads=build_chain(revocations)
    chain={
        "phase":"RUST-038","status":"HOLD_EXTERNAL_PREFIX_CUSTODY_UNVERIFIED",
        "upstream_rust036_receipt_sha256":reg["receipt_sha256"],
        "revocation_chain":entries,
        "prefix_head_sha256_by_count":heads,
        "revocation_entry_count":len(entries),
        "revocation_chain_head_sha256":heads[-1],
        "release_authorized":False,"fork_resolved":False,
        "preserved_equivocation_evidence":[],
    }
    chain["receipt_sha256"]=digest(chain)
    return reg,chain

def controller(role,pin,owner):
    return {"role":role,"key_spki_sha256":pin,"custody_controller":owner}

class RevocationPersistenceTests(unittest.TestCase):
    def test_missing_external_evidence_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_CROSS_EPOCH_CUSTODY")
        self.assertFalse(hold()["release_authorized"])

    def test_exact_inherited_revocations_remain_hold(self):
        old,oc=fixture()
        new,nc=fixture(keys_extra=["ff"])
        result=audit(old,new,oc,nc,[])
        self.assertEqual(result["status"],"HOLD_EXTERNAL_CUSTODY_UNPROVEN")
        self.assertEqual(result["inherited_revocation_count"],1)
        self.assertEqual(result["preserved_revocation_prefix_sha256"],
                         result["current_revocation_head_sha256"])
        self.assertFalse(result["external_custodian_identity_verified"])
        self.assertFalse(result["release_authorized"])

    def test_appended_revocation_preserves_prefix(self):
        old,oc=fixture()
        new,nc=fixture(keys_extra=["ff"],revocations=[
            revocation(),revocation("cf",epoch=3)])
        result=audit(old,new,oc,nc,[])
        self.assertEqual(result["current_revocation_count"],2)
        self.assertEqual(result["inherited_revocation_count"],1)

    def test_removed_or_rewritten_revocation_rejected(self):
        old,oc=fixture()
        current,cc=fixture(keys_extra=["ff"],revocations=[])
        with self.assertRaisesRegex(ValueError,"revocations omitted"):
            audit(old,current,oc,cc,[])
        mutated=revocation(epoch=4)
        current,cc=fixture(keys_extra=["ff"],revocations=[mutated])
        with self.assertRaisesRegex(ValueError,"prefix rewritten"):
            audit(old,current,oc,cc,[])

    def test_key_renewal_under_same_controller_is_suspect_not_independent(self):
        old,oc=fixture()
        current,cc=fixture(keys_extra=["ff"])
        lineage=[
            controller("ff",PINS["ff"],"custodian-A"),
            controller("ff","4"*64,"custodian-A"),
        ]
        result=audit(old,current,oc,cc,lineage)
        self.assertEqual(result["status"],"HOLD_SHARED_CUSTODY_LINEAGE")
        self.assertEqual(len(result["suspected_same_custodian_replacements"]),1)
        self.assertFalse(result["suspected_same_custodian_replacements"][0]
                         ["control_independently_verified"])

    def test_distinct_declared_controller_does_not_certify_independence(self):
        old,oc=fixture()
        current,cc=fixture(keys_extra=["ff"])
        lineage=[controller("ff",PINS["ff"],"custodian-A"),
                 controller("ff","4"*64,"custodian-B")]
        result=audit(old,current,oc,cc,lineage)
        self.assertEqual(result["status"],"HOLD_EXTERNAL_CUSTODY_UNPROVEN")
        self.assertFalse(result["external_custodian_identity_verified"])

    def test_revoked_key_after_effective_epoch_rejected(self):
        old,oc=fixture()
        current,cc=fixture()
        # Re-signs with the historically revoked FF key at epoch 2.
        current["epoch_key_claims"].insert(1,{
            "role":"ff","epoch":2,"signing_key_spki_sha256":PINS["ff"],
            "checkpoint_sha256":"f"*64,"signature_sha256":"6"*64,
            "signed_checkpoint_verified":True,
        })
        current["receipt_sha256"]=digest({k:v for k,v in current.items() if k!="receipt_sha256"})
        cc["upstream_rust036_receipt_sha256"]=current["receipt_sha256"]
        cc["receipt_sha256"]=digest({k:v for k,v in cc.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"revoked key used"):
            audit(old,current,oc,cc,[])

    def test_prior_key_history_substitution_rejected(self):
        old,oc=fixture()
        current,cc=fixture(keys_extra=["ff"])
        current["epoch_key_claims"][0]["checkpoint_sha256"]="0"*64
        current["receipt_sha256"]=digest({k:v for k,v in current.items() if k!="receipt_sha256"})
        cc["upstream_rust036_receipt_sha256"]=current["receipt_sha256"]
        cc["receipt_sha256"]=digest({k:v for k,v in cc.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"prior epoch key history"):
            audit(old,current,oc,cc,[])

    def test_chain_receipt_tampering_rejected(self):
        old,oc=fixture()
        current,cc=fixture()
        cc["revocation_chain_head_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"receipt modified"):
            audit(old,current,oc,cc,[])

    def test_unknown_or_duplicate_controller_claim_rejected(self):
        old,oc=fixture()
        current,cc=fixture()
        with self.assertRaisesRegex(ValueError,"unknown epoch key"):
            audit(old,current,oc,cc,[controller("ff","8"*64,"fake")])
        claim=controller("ff",PINS["ff"],"same")
        with self.assertRaisesRegex(ValueError,"duplicate controller"):
            audit(old,current,oc,cc,[claim,claim])

    def test_partial_missing_witness_epoch_rejected(self):
        old,oc=fixture()
        current,cc=fixture()
        current["epoch_key_claims"]=[x for x in current["epoch_key_claims"] if x["role"]!="rr"]
        current["receipt_sha256"]=digest({k:v for k,v in current.items() if k!="receipt_sha256"})
        cc["upstream_rust036_receipt_sha256"]=current["receipt_sha256"]
        cc["receipt_sha256"]=digest({k:v for k,v in cc.items() if k!="receipt_sha256"})
        with self.assertRaisesRegex(ValueError,"witness roles incomplete"):
            audit(old,current,oc,cc,[])

if __name__=="__main__":
    unittest.main()
