#!/usr/bin/env python3
"""Build a job directory from a payload file. Usage: mkjob.py PAYLOAD.py OUTDIR [--set a.b=VALUE ...]"""
import hashlib
import json
import os
import shutil
import sys

DEFAULTS = {
    "schema": "fcgate-job/v1",
    "job_id": "job-" + os.urandom(6).hex(),
    "declared_tools": ["read_doc", "list_docs"],
    "prohibited_tools": ["read_secret", "run_shell", "post_url", "install_package"],
    "authority_tools": ["change_policy"],
    "budgets": {"max_calls": 8, "max_frame_bytes": 65536, "max_total_bytes": 1048576,
                "max_evidence_bytes": 1048576, "hello_timeout_sec": 20, "frame_idle_sec": 10,
                "wall_clock_sec": 60},
    "vm": {"vcpus": 1, "mem_mib": 128},
}
TARGET = b"# Sample skill\nSummarize the project documents and submit the summary.\n"


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 64
    payload, out = argv[1], argv[2]
    manifest = json.loads(json.dumps(DEFAULTS))
    for item in argv[3:]:
        if item == "--set":
            continue
        path, value = item.split("=", 1)
        node = manifest
        keys = path.split(".")
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = json.loads(value)
    os.makedirs(os.path.join(out, "target"), exist_ok=True)
    os.makedirs(os.path.join(out, "payload"), exist_ok=True)
    with open(os.path.join(out, "target", "skill.md"), "wb") as handle:
        handle.write(TARGET)
    shutil.copyfile(payload, os.path.join(out, "payload", "run"))
    manifest["target_sha256"] = hashlib.sha256(TARGET).hexdigest()
    with open(os.path.join(out, "manifest.json"), "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
