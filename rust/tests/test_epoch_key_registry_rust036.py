import copy
import unittest

from epoch_key_registry_rust036 import audit, hold, rotation_message
from lineage_rust019 import digest

ROLES=("ff","cf","rr")
PINS=["1"*64,"2"*64,"3"*64]
NEW_PIN="4"*64
AUTHORITY="a"*64

def cp(epoch, value):
    return {
        "phase":"RUST-033","kind":"SIGNED_SESSION_HIGHWATER",
        "epoch":epoch,"entry_count":epoch*3,
        "ledger_sha256":value,"entries_sha256":"b"*64,
        "last_entry_sha256":"c"*64,
        "release_authorized":False,"global_anti_rollback_certified":False,
    }

def fixture(rotated=False,revoked=False,conflict=False):
    histories=[]
    registries=[]
    for idx,role in enumerate(ROLES):
        pin=PINS[idx]
        second=NEW_PIN if rotated and role=="ff" else pin
        snapshots=[
            {"checkpoint":cp(1,"d"*64),"public_key":role+"-1.pem","signature":role+"-1.sig"},
            {"checkpoint":cp(2,"e"*64 if conflict and role=="rr" else "f"*64),
             "public_key":role+"-2.pem","signature":role+"-2.sig"},
        ]
        histories.append({"role":role,"snapshots":snapshots,"rotations":[],"revocations":[]})
        registries.append({"role":role,
                           "epochs":[{"epoch":1,"pin":pin},{"epoch":2,"pin":second}],
                           "revocation_authority_pin":AUTHORITY})
        if role=="ff" and rotated:
            histories[-1]["rotations"]=[{
                "from_epoch":1,"to_epoch":2,"old_pin":pin,"new_pin":NEW_PIN,
                "old_public_key":"old.pem","old_signature":"old.sig",
                "new_public_key":"new.pem","new_signature":"new.sig",
            }]
            if revoked:
                histories[-1]["revocations"]=[{
                    "revoked_pin":pin,"effective_epoch":2,
                    "evidence_sha256":"9"*64,
                    "authority_public_key":"authority.pem",
                    "authority_signature":"authority.sig",
                }]
    return histories,registries

def verified(*args):
    return "8"*64

class EpochKeyRegistryTests(unittest.TestCase):
    def test_missing_registry_is_hold(self):
        self.assertEqual(hold()["status"],"HOLD_MISSING_EPOCH_KEY_REGISTRY")
        self.assertFalse(hold()["release_authorized"])

    def test_per_epoch_same_key_history_is_still_hold(self):
        histories, registries=fixture()
        result=audit(histories,registries,verifier=verified)
        self.assertEqual(result["per_epoch_signature_checks_completed"],6)
        self.assertEqual(len(result["verified_rotations"]),0)
        self.assertEqual(result["status"],"HOLD_EXTERNAL_KEY_CUSTODY_UNPROVEN")
        self.assertFalse(result["release_authorized"])

    def test_dual_signed_rotation_and_revocation(self):
        histories,registries=fixture(rotated=True,revoked=True)
        calls=[]
        def verify(*args):
            calls.append(args)
            return "8"*64
        result=audit(histories,registries,verifier=verify)
        self.assertEqual(len(result["verified_rotations"]),1)
        self.assertEqual(result["rotation_signature_checks_completed"],2)
        self.assertEqual(len(result["revocation_evidence"]),1)
        self.assertEqual(len(calls),9)
        self.assertFalse(result["independent_custodian_control_verified"])

    def test_missing_rotation_rejected(self):
        histories,registries=fixture(rotated=True)
        histories[0]["rotations"]=[]
        with self.assertRaisesRegex(ValueError,"missing or excess"):
            audit(histories,registries,verifier=verified)

    def test_wrong_old_pin_on_transition_rejected(self):
        histories,registries=fixture(rotated=True)
        histories[0]["rotations"][0]["old_pin"]="0"*64
        with self.assertRaisesRegex(ValueError,"rotation mismatch"):
            audit(histories,registries,verifier=verified)

    def test_reactivated_superseded_key_rejected(self):
        histories,registries=fixture(rotated=True)
        histories[0]["snapshots"].append({
            "checkpoint":cp(3,"7"*64),"public_key":"old.pem","signature":"old.sig",
        })
        registries[0]["epochs"].append({"epoch":3,"pin":PINS[0]})
        with self.assertRaisesRegex(ValueError,"superseded"):
            audit(histories,registries,verifier=verified)

    def test_revocation_cannot_be_self_issued(self):
        histories,registries=fixture(rotated=True,revoked=True)
        registries[0]["revocation_authority_pin"]=PINS[0]
        with self.assertRaisesRegex(ValueError,"self-issued"):
            audit(histories,registries,verifier=verified)

    def test_revoked_key_cannot_sign_after_effective_epoch(self):
        histories,registries=fixture(rotated=False)
        histories[0]["revocations"]=[{
            "revoked_pin":PINS[0],"effective_epoch":2,
            "evidence_sha256":"9"*64,"authority_public_key":"a.pem",
            "authority_signature":"a.sig",
        }]
        with self.assertRaisesRegex(ValueError,"revoked key used"):
            audit(histories,registries,verifier=verified)

    def test_fork_is_preserved_no_majority_override(self):
        histories,registries=fixture(conflict=True)
        result=audit(histories,registries,verifier=verified)
        self.assertTrue(result["equivocation_evidence"])
        self.assertEqual(result["status"],"HOLD_EQUIVOCATION_OR_SHARED_KEYS")
        self.assertEqual(len(result["equivocation_evidence"][0]["claims"]),3)
        self.assertFalse(result["fork_resolved"])

    def test_one_key_shared_across_witness_roles_is_collision(self):
        histories,registries=fixture()
        registries[1]["epochs"][0]["pin"]=PINS[0]
        registries[1]["epochs"][1]["pin"]=PINS[0]
        result=audit(histories,registries,verifier=verified)
        self.assertTrue(result["shared_witness_key_evidence"])
        self.assertFalse(result["release_authorized"])

    def test_missing_epoch_or_bad_signature_rejected(self):
        histories,registries=fixture()
        registries[0]["epochs"][1]["epoch"]=3
        with self.assertRaisesRegex(ValueError,"wrong epoch"):
            audit(histories,registries,verifier=verified)
        histories,registries=fixture()
        def reject(*args):
            raise ValueError("bad signature")
        with self.assertRaises(ValueError):
            audit(histories,registries,verifier=reject)

if __name__=="__main__":
    unittest.main()
