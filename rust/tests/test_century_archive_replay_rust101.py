import copy
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from century_source_freeze_rust100 import ALL_PATHS, freeze
from century_archive_replay_rust101 import (
    verify, missing, archive_fingerprints, validate_manifest, HOLD)

def h(s):
    return hashlib.sha256(s.encode()).hexdigest()

def bundle():
    temp=tempfile.TemporaryDirectory()
    root=Path(temp.name)
    originals={}
    for path in ALL_PATHS:
        raw=("frozen-source:"+path).encode()
        file=root/path
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(raw)
        originals[path]=raw
    manifest=freeze(root, lambda _,p:originals[p])
    def archive(prefix="neuroscape-80313da", mutate=None):
        f=io.BytesIO()
        with zipfile.ZipFile(f,"w",compression=zipfile.ZIP_STORED) as z:
            for path,data in originals.items():
                z.writestr(prefix+"/"+path,
                           mutate(path,data) if mutate else data)
        return f.getvalue()
    a=archive("neuroscape-a")
    b=archive("neuroscape-b")
    claims=[]
    for i,data in enumerate((a,b)):
        claims.append({"archive_sha256":hbytes(data),
                       "ancestry":{k:h(k+str(i)) for k in
                                   ("controller","root","source","acquisition")}})
    return temp,manifest,[a,b],claims,archive

def hbytes(data):
    return hashlib.sha256(data).hexdigest()

class CenturyArchiveReplayRUST101(unittest.TestCase):
    def case(self):
        tmp,manifest,archives,claims,make=bundle()
        self.addCleanup(tmp.cleanup)
        return manifest,archives,claims,make
    def reject(self,modify):
        m,a,c,make=self.case()
        modify(m,a,c,make)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            verify(m,a,c)
    def test_missing_hold(self):
        self.assertEqual(missing()["status"],"HOLD_MISSING_INDEPENDENT_ARCHIVE_BYTES")
    def test_valid_two_archives_still_hold(self):
        m,a,c,_=self.case()
        r=verify(m,a,c)
        self.assertEqual(r["status"],HOLD)
        self.assertTrue(r["snapshot_byte_parity"])
        self.assertFalse(r["independent_external_custody_verified"])
        self.assertFalse(r["release_authorized"])
    def test_deterministic_replay(self):
        m,a,c,_=self.case()
        self.assertEqual(verify(m,a,c),verify(m,a,c))
    def test_repacked_archive_is_not_independent_proof(self):
        m,a,c,_=self.case()
        r=verify(m,a,c)
        self.assertFalse(r["claimed_independence_is_authenticated"])
    def test_identical_archives_flagged(self):
        m,a,c,_=self.case()
        a[1]=a[0];c[1]["archive_sha256"]=c[0]["archive_sha256"]
        self.assertIn("IDENTICAL_ARCHIVE_BYTES",verify(m,a,c)["provenance_conflicts"])
    def test_shared_controller_flagged(self):
        m,a,c,_=self.case()
        c[1]["ancestry"]["controller"]=c[0]["ancestry"]["controller"]
        self.assertIn("SHARED_CONTROLLER_ANCESTRY",verify(m,a,c)["provenance_conflicts"])
    def test_shared_source_flagged(self):
        m,a,c,_=self.case()
        c[1]["ancestry"]["source"]=c[0]["ancestry"]["source"]
        self.assertIn("SHARED_SOURCE_ANCESTRY",verify(m,a,c)["provenance_conflicts"])
    def test_bad_claim_digest_rejected(self):
        self.reject(lambda m,a,c,make:c[0].update(archive_sha256=h("wrong")))
    def test_altered_source_rejected(self):
        def mutate(m,a,c,make):
            a[1]=make("other",lambda p,b: b+b"x" if p==ALL_PATHS[0] else b)
            c[1]["archive_sha256"]=hbytes(a[1])
        self.reject(mutate)
    def test_missing_source_rejected(self):
        def mutate(m,a,c,make):
            f=io.BytesIO()
            with zipfile.ZipFile(f,"w") as z:
                for p in ALL_PATHS[1:]:z.writestr("new/"+p,b"missing")
            a[1]=f.getvalue()
            c[1]["archive_sha256"]=hbytes(a[1])
        self.reject(mutate)
    def test_mutated_manifest_rejected(self):
        self.reject(lambda m,a,c,make:m["source_entries"][0].update(sha256=h("forged")))
    def test_release_promotion_rejected(self):
        self.reject(lambda m,a,c,make:m.update(release_authorized=True))
    def test_traversal_zip_rejected(self):
        def mutate(m,a,c,make):
            b=io.BytesIO()
            with zipfile.ZipFile(b,"w") as z:
                z.writestr("../escape",b"unsafe")
            a[1]=b.getvalue();c[1]["archive_sha256"]=hbytes(a[1])
        self.reject(mutate)
    def test_duplicate_zip_paths_rejected(self):
        def mutate(m,a,c,make):
            b=io.BytesIO()
            with zipfile.ZipFile(b,"w") as z:
                z.writestr("x/dup",b"one")
                z.writestr("x/dup",b"two")
            a[1]=b.getvalue();c[1]["archive_sha256"]=hbytes(a[1])
        self.reject(mutate)
    def test_missing_second_archive_rejected(self):
        self.reject(lambda m,a,c,make:a.pop())
    def test_missing_ancestry_rejected(self):
        self.reject(lambda m,a,c,make:c[1]["ancestry"].pop("root"))
    def test_checkpoint_digest_bound(self):
        m,a,c,_=self.case()
        self.assertEqual(verify(m,a,c)["source_checkpoint_sha256"],
                         m["checkpoint_sha256"])
    def test_no_mutation(self):
        m,a,c,_=self.case()
        snapshot=copy.deepcopy((m,a,c))
        verify(m,a,c)
        self.assertEqual((m,a,c),snapshot)

if __name__=="__main__":
    unittest.main()
