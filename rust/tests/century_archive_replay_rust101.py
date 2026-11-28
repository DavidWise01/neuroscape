#!/usr/bin/env python3
"""RUST-101: bounded ZIP byte replay against a frozen RUST-100 source manifest.

Archive acquisition and custody claims are caller-supplied and unauthenticated.
Matching source bytes prove snapshot parity, NOT independent ancestry or release.
"""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path
from century_source_freeze_rust100 import BASELINE, canonical, sha, require

DOMAIN = "NEUROSCAPE_RUST101_ARCHIVE_PARITY_V1"
HOLD = "HOLD_ARCHIVE_ACQUISITION_INDEPENDENCE_UNVERIFIED"
MAX_ARCHIVE = 25 * 1024 * 1024
MAX_MEMBER = 5 * 1024 * 1024
MAX_MEMBERS = 4096
ANCESTRY = ("controller", "root", "source", "acquisition")

def hexsha(value):
    require(isinstance(value,str) and len(value)==64
            and all(ch in "0123456789abcdef" for ch in value),
            "invalid SHA-256")
    return value

def validate_manifest(manifest):
    require(isinstance(manifest,dict)
            and manifest.get("domain")=="NEUROSCAPE_RUST100_CENTURY_SOURCE_FREEZE_V1"
            and manifest.get("phase")=="RUST-100"
            and manifest.get("baseline_commit")==BASELINE
            and manifest.get("status")=="HOLD_CENTURY_EXTERNAL_CUSTODY_UNVERIFIED",
            "frozen RUST-100 source manifest required")
    entries=manifest.get("source_entries")
    require(isinstance(entries,list) and len(entries)==17,
            "17 frozen files required")
    from century_source_freeze_rust100 import ALL_PATHS
    require([e.get("path") for e in entries]==list(ALL_PATHS),
            "ordered RUST-100 file inventory changed")
    for e in entries:
        hexsha(e.get("sha256"))
        require(type(e.get("length")) is int and 0<=e["length"]<=MAX_MEMBER,
                "invalid manifest file size")
    require(manifest.get("source_manifest_sha256")==sha(canonical(entries)),
            "manifest entry hash mismatch")
    body={k:v for k,v in manifest.items()
          if k not in ("checkpoint_sha256","status")}
    require(manifest.get("checkpoint_sha256")==sha(canonical(body)),
            "century checkpoint checksum mismatch")
    for k in ("historical_execution_verified","independent_external_custody_verified",
              "global_anti_rollback_verified","release_authorized",
              "recovery_authorized","live_gameplay_authorized"):
        require(manifest.get(k) is False, "upstream authority promoted")
    return entries

def archive_fingerprints(data, entries):
    require(isinstance(data,bytes) and 0<len(data)<=MAX_ARCHIVE,
            "missing or oversized archive")
    try:
        zipdata=zipfile.ZipFile(io.BytesIO(data))
        with zipdata:
            members=zipdata.infolist()
            require(len(members)<=MAX_MEMBERS, "excessive archive members")
            files={}
            for member in members:
                name=member.filename
                require(not name.startswith("/") and "\\" not in name
                        and all(part not in ("", ".", "..") for part in name.rstrip("/").split("/")),
                        "unsafe archive path")
                if member.is_dir():
                    continue
                require(member.file_size<=MAX_MEMBER,
                        "oversized archive member")
                require(name not in files, "duplicate ZIP archive path")
                files[name]=member
            matched={}
            for e in entries:
                path=e["path"]
                # GitHub repository ZIPs place files under one top-level directory.
                candidates=[name for name in files
                            if name==path or (name.endswith("/"+path)
                                and name.count("/")==path.count("/")+1)]
                require(len(candidates)==1,
                        "missing or ambiguous archive path: "+path)
                member=files[candidates[0]]
                require(member.file_size==e["length"],
                        "archive file size mismatch: "+path)
                with zipdata.open(member) as stream:
                    blob=stream.read(MAX_MEMBER+1)
                require(len(blob)==e["length"]
                        and sha(blob)==e["sha256"],
                        "frozen source bytes mismatch: "+path)
                matched[path]={"sha256":sha(blob),"length":len(blob)}
            return {"archive_sha256":sha(data),
                    "archive_length":len(data),
                    "source_sha256":sha(canonical(matched))}
    except (zipfile.BadZipFile,RuntimeError,EOFError) as ex:
        raise ValueError("invalid or unreadable archive") from ex

def verify(manifest, archives, claims):
    entries=validate_manifest(manifest)
    require(isinstance(archives,list) and len(archives)==2,
            "exactly two archives required")
    require(isinstance(claims,list) and len(claims)==2,
            "two provenance declarations required")
    records=[]
    for data,claim in zip(archives,claims):
        require(isinstance(claim,dict), "source claim required")
        ancestry=claim.get("ancestry")
        require(isinstance(ancestry,dict) and set(ancestry)==set(ANCESTRY),
                "complete ancestry declaration required")
        for field in ANCESTRY:hexsha(ancestry[field])
        fingerprint=archive_fingerprints(data,entries)
        require(fingerprint["archive_sha256"]==hexsha(claim.get("archive_sha256")),
                "archive digest not bound to claim")
        records.append({"fingerprints":fingerprint,
                        "ancestry":{k:ancestry[k] for k in ANCESTRY}})
    reasons=[]
    if records[0]["fingerprints"]["archive_sha256"]==records[1]["fingerprints"]["archive_sha256"]:
        reasons.append("IDENTICAL_ARCHIVE_BYTES")
    for field in ANCESTRY:
        if records[0]["ancestry"][field]==records[1]["ancestry"][field]:
            reasons.append("SHARED_"+field.upper()+"_ANCESTRY")
    return {"phase":"RUST-101","domain":DOMAIN,"status":HOLD,
            "source_checkpoint_sha256":manifest["checkpoint_sha256"],
            "snapshot_byte_parity":True,
            "archives":[{"archive_sha256":r["fingerprints"]["archive_sha256"],
                         "archive_length":r["fingerprints"]["archive_length"],
                         "source_sha256":r["fingerprints"]["source_sha256"]}
                        for r in records],
            "provenance_conflicts":sorted(reasons),
            "claimed_independence_is_authenticated":False,
            "independent_external_custody_verified":False,
            "global_anti_rollback_verified":False,
            "fork_selected":False,"release_authorized":False,
            "recovery_authorized":False,"live_gameplay_authorized":False}

def missing():
    return {"phase":"RUST-101","status":"HOLD_MISSING_INDEPENDENT_ARCHIVE_BYTES",
            "snapshot_byte_parity":False,
            "independent_external_custody_verified":False,
            "recovery_authorized":False,"release_authorized":False,
            "live_gameplay_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest")
    p.add_argument("--archive-a")
    p.add_argument("--archive-b")
    p.add_argument("--claims")
    p.add_argument("--output",required=True)
    p.add_argument("--allow-hold-record",action="store_true")
    args=p.parse_args()
    values=(args.manifest,args.archive_a,args.archive_b,args.claims)
    require(all(values) or not any(values),"partial acquisition bundle refused")
    if all(values):
        data=json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        claims=json.loads(Path(args.claims).read_text(encoding="utf-8"))
        outcome=verify(data,[Path(args.archive_a).read_bytes(),
                             Path(args.archive_b).read_bytes()],claims)
    else:
        outcome=missing()
    target=Path(args.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("x",encoding="utf-8") as f:
        json.dump(outcome,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps(outcome,sort_keys=True))
    if not args.allow_hold_record:
        raise SystemExit("RUST-101 HOLD: independent archive custody unverified")
if __name__=="__main__":
    main()
