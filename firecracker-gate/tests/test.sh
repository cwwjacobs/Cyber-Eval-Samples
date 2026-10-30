#!/bin/bash
# Hidden verifier entry point. All scoring happens in verify.py next to this file; it writes
# /logs/verifier/reward.txt. If it dies before that, the score is 0.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /logs/verifier
chmod 0700 "$HERE" 2>/dev/null || true
export PYTHONDONTWRITEBYTECODE=1
python3 "$HERE/verify.py"
status=$?
if [ ! -s /logs/verifier/reward.txt ]; then
    echo "verify.py exited with status $status and wrote no reward; scoring 0"
    echo 0.0 > /logs/verifier/reward.txt
fi
exit 0
