#!/bin/bash
# Verifier for cindermote-from-scratch. Harbor runs it as root in a fresh container built from
# environment/, after restoring the agent's /app into it (environment_mode = "separate").
# It grades /app with the public and held-out tests (run_suite.sh) and writes the fraction of
# graded tests that pass to /logs/verifier/reward.txt (score.py).
set -uo pipefail
# Harbor's exec can start with a group-writable umask; Cindermote's trusted-source gates
# reject group-writable files, so files the tests create must not be.
umask 022

LOG_DIR=/logs/verifier
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill every live process owned by a user. kill(-1), sent as that user, signals all of them in
# one call; repeat in case one forked while being killed. Zombies are already dead and ignored.
kill_user() {
    local _
    for _ in $(seq 1 100); do
        ps -u "$1" -o stat= 2>/dev/null | grep -qv '^Z' || return 0
        runuser -u "$1" -- kill -KILL -1 2>/dev/null
        sleep 0.05
    done
}

# The log directory is writable by everyone. Drop anything planted there (a symlink named
# reward.txt would make root write through it) before writing our own files.
scrub_logs() {
    mkdir -p "$LOG_DIR"
    find "$LOG_DIR" -mindepth 1 -maxdepth 1 -type l -delete 2>/dev/null
    rm -rf "$LOG_DIR/reward.txt" "$LOG_DIR/reward.json" "$LOG_DIR/grading.json" \
        "$LOG_DIR/pytest-output.txt"
}

chmod 700 "$HERE"
kill_user agent
scrub_logs
echo 0 > "$LOG_DIR/reward.txt"

WORK="$(mktemp -d /var/tmp/cindermote-grade.XXXXXX)"
APP_DIR=/app \
VISIBLE_TESTS_DIR=/opt/cindermote-task/visible-tests \
HIDDEN_TESTS_DIR="$HERE/hidden" \
    bash "$HERE/run_suite.sh" "$WORK" "$WORK/results.jsonl" > "$WORK/pytest-output.txt" 2>&1
echo "test run exited with status $?" >> "$WORK/pytest-output.txt"

# No untrusted process may be alive while the results are scored and written.
kill_user grader
kill_user agent
/opt/venv/bin/python -I "$HERE/score.py" --f2p "$HERE/f2p.json" --results "$WORK/results.jsonl" \
    --reward "$WORK/reward.txt" --summary "$WORK/grading.json" --key-file "$WORK/grade.key"
scrub_logs
cp "$WORK/pytest-output.txt" "$WORK/grading.json" "$LOG_DIR/"
cp "$WORK/reward.txt" "$LOG_DIR/reward.txt"
