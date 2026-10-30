# Guest program: reports the job files it received, as evidence, so that the verifier can tell whether
# the job image carries target/ and payload/ intact, and whether session and manifest data are right.
import hashlib
import os
import re

import labguest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def listing():
    found = {}
    for top in ("payload", "target"):
        for folder, _, names in os.walk(os.path.join(ROOT, top)):
            for name in names:
                path = os.path.join(folder, name)
                with open(path, "rb") as handle:
                    found[os.path.relpath(path, ROOT)] = hashlib.sha256(handle.read()).hexdigest()
    return found


info = labguest.session_info()
manifest = labguest.manifest()
session_ok = (sorted(info) == ["job", "nonce"] and info["job"] == manifest["job_id"]
              and re.fullmatch("[0-9a-f]{64}", info["nonce"]) is not None)
session = labguest.Session()
session.hello()
session.evidence(labguest.canonical({"files": listing(), "session_ok": session_ok}))
session.evidence(hashlib.sha256(labguest.canonical(manifest)).hexdigest().encode("ascii"))
session.final()
