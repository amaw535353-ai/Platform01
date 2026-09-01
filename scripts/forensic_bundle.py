#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

files = [p for p in Path("evidence").glob("*.json") if p.name != "forensic-manifest.json"]
manifest = [
    {"file": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(files)
]
Path("evidence/forensic-manifest.json").write_text(
    json.dumps({"version": 1, "sanitized_files": manifest}, indent=2) + "\n"
)
