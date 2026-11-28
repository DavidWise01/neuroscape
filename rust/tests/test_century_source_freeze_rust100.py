import copy
import tempfile
import unittest
from pathlib import Path

from century_source_freeze_rust100 import (
    ALL_PATHS, BASELINE, DOMAIN, HOLD, MODULES, PHASE_PATHS,
    PROTECTED, canonical, freeze, missing, sha)

def fixture():
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    originals = {}
    for path in ALL_PATHS:
        data = ("immutable fixture bytes:" + path).encode("utf-8")
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        originals[path] = data
    def read_baseline(repo, path):
        return originals[path]
    return temporary, root, originals, read_baseline

class CenturyFreezeRUST100(unittest.TestCase):
    def test_missing_source_hold(self):
        self.assertEqual(missing()["status"],
            "HOLD_MISSING_CENTURY_SOURCE_CHECKPOINT")
    def test_all_fourteen_phases_included(self):
        self.assertEqual(set(MODULES), set(range(86,100)))
    def test_phase_path_count(self):
        self.assertEqual(len(PHASE_PATHS), 14)
    def test_protected_gameplay_sources_count(self):
        self.assertEqual(len(PROTECTED), 3)
    def test_no_duplicate_inventory_paths(self):
        self.assertEqual(len(set(ALL_PATHS)), len(ALL_PATHS))
    def test_freeze_records_exact_baseline(self):
        t, root, original, loader = fixture()
        with t:
            record=freeze(root,loader)
            self.assertEqual(record["baseline_commit"],BASELINE)
            self.assertEqual(record["source_entry_count"],len(ALL_PATHS))
            self.assertEqual(record["domain"],DOMAIN)
    def test_source_hashes_match_exact_bytes(self):
        t, root, original, loader = fixture()
        with t:
            rows=freeze(root,loader)["source_entries"]
            self.assertTrue(all(r["sha256"]==sha(original[r["path"]])
                                and r["length"]==len(original[r["path"]])
                                for r in rows))
    def test_deterministic_manifest(self):
        t, root, _, loader = fixture()
        with t:
            self.assertEqual(freeze(root,loader),freeze(root,loader))
    def test_reject_historical_rewrite(self):
        t, root, _, loader = fixture()
        with t:
            (root/PHASE_PATHS[0]).write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError,"historical source changed"):
                freeze(root,loader)
    def test_reject_gameplay_html_change(self):
        t, root, _, loader = fixture()
        with t:
            (root/"index.html").write_bytes(b"replaced arcade")
            with self.assertRaises(ValueError):
                freeze(root,loader)
    def test_reject_wasm_change(self):
        t, root, _, loader = fixture()
        with t:
            (root/PROTECTED[-1]).write_bytes(b"modified wasm adapter")
            with self.assertRaises(ValueError):
                freeze(root,loader)
    def test_missing_source_rejected(self):
        t, root, _, loader = fixture()
        with t:
            (root/PHASE_PATHS[-1]).unlink()
            with self.assertRaises(FileNotFoundError):
                freeze(root,loader)
    def test_custody_and_release_remain_hold(self):
        t, root, _, loader = fixture()
        with t:
            r=freeze(root,loader)
            self.assertEqual(r["status"],HOLD)
            for k in ("historical_execution_verified","hosted_ci_verified",
                      "independent_external_custody_verified",
                      "global_anti_rollback_verified","fork_selected",
                      "recovery_authorized","release_authorized",
                      "live_gameplay_authorized"):
                self.assertFalse(r[k], k)
    def test_checkpoint_binds_manifest(self):
        t, root, _, loader = fixture()
        with t:
            result=freeze(root,loader)
            body={k:v for k,v in result.items()
                  if k not in ("checkpoint_sha256","status")}
            self.assertEqual(result["checkpoint_sha256"],sha(canonical(body)))
    def test_baseline_loader_cannot_return_text(self):
        t, root, _, loader = fixture()
        with t:
            with self.assertRaises(ValueError):
                freeze(root,lambda _,p:"text rather than bytes")
    def test_freeze_does_not_mutate_sources(self):
        t, root, originals, loader = fixture()
        with t:
            freeze(root,loader)
            for path, data in originals.items():
                self.assertEqual((root/path).read_bytes(),data)

if __name__=="__main__":
    unittest.main()
