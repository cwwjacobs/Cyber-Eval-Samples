# Guest program: a clean session whose evidence is the session nonce itself. Two runs of the same job
# must therefore end with different evidence roots. A nonce of the wrong shape ends the session early.
import re
import sys

import labguest

info = labguest.session_info()
if sorted(info) != ["job", "nonce"] or re.fullmatch("[0-9a-f]{64}", info["nonce"]) is None:
    sys.exit(0)
session = labguest.Session()
session.hello()
session.evidence(info["nonce"].encode("ascii"))
session.final()
