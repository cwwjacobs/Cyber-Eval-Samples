#!/bin/bash
# Run the full Cindermote suite (pristine public tests plus held-out tests) against a snapshot
# of an implementation tree, as an unprivileged user, recording per-test outcomes.
#
#   run_suite.sh WORK_DIR RESULTS_JSONL   (the signing key is left in WORK_DIR/grade.key)
#
# Environment: APP_DIR (implementation tree), VISIBLE_TESTS_DIR (pristine public tests),
# HIDDEN_TESTS_DIR (held-out tests), PYTHON (default /opt/venv/bin/python),
# GRADER_USER (default grader). Must run as root.
set -uo pipefail
# Harbor's exec can start with a group-writable umask; Cindermote's trusted-source gates
# reject group-writable files, so files the tests create must not be.
umask 022

WORK="$1"
RESULTS="$2"
PYTHON="${PYTHON:-/opt/venv/bin/python}"
GRADER_USER="${GRADER_USER:-grader}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf "$WORK/app" "$WORK/home" "$WORK/lib"
mkdir -p "$WORK/app/tests" "$WORK/home" "$WORK/lib"

# Snapshot only the tree's original top-level entries (toplevel.txt), so nothing the agent added
# at the top level (pytest.py, sitecustomize.py, *.dist-info, conftest.py) reaches the grader.
# The tests come from pristine copies, never from the agent's tests/.
while IFS= read -r entry; do
    [ -n "$entry" ] && [ -e "$APP_DIR/$entry" ] || continue
    tar -C "$APP_DIR" --exclude='__pycache__' -cf - "./$entry" | tar -C "$WORK/app" -xf -
done < "$HERE/toplevel.txt"
cp -a "$VISIBLE_TESTS_DIR/." "$WORK/app/tests/"
cp -a "$HIDDEN_TESTS_DIR/." "$WORK/app/tests/"
cp "$HERE/grade_plugin.py" "$WORK/lib/"
# pytest puts the implementation on sys.path only after pytest itself has been imported.
printf '[pytest]\npythonpath = %s\n' "$WORK/app" > "$WORK/lib/pytest.ini"

# Reset modes, whatever the copy into this container preserved: Cindermote's trusted-source
# gates reject group- or world-writable files, and the grader must be able to read every file.
chmod -R u+rwX,go-w "$WORK/app"
chown -R "$GRADER_USER:$GRADER_USER" "$WORK/app" "$WORK/home"
chmod 755 "$WORK" "$WORK/lib"
chmod 644 "$WORK/lib/grade_plugin.py" "$WORK/lib/pytest.ini"
# Outcomes travel through a FIFO into a file only root can write. Graded code shares the
# writer's process, so it can add lines but never remove or rewrite one already recorded.
: > "$RESULTS"
# Every record is HMAC-signed with a per-run key that only root can read from disk. The plugin
# receives it on fd 4 and closes that before any graded module loads, so forged lines fail.
KEY_FILE="$WORK/grade.key"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEY_FILE"
chmod 600 "$KEY_FILE"
FIFO="$WORK/results.fifo"
rm -f "$FIFO"
mkfifo -m 0620 "$FIFO"
chown "root:$GRADER_USER" "$FIFO"
cat "$FIFO" >> "$RESULTS" &
reader=$!
exec 3>"$FIFO"

# -P keeps the working directory off sys.path at startup, and plugin autoloading is off, so
# the implementation cannot shadow or extend pytest before it starts.
cd "$WORK/app"
runuser -u "$GRADER_USER" -- env -i 3>&- 4<"$KEY_FILE" \
    PATH="$(dirname "$PYTHON"):/usr/local/bin:/usr/bin:/bin" \
    HOME="$WORK/home" LANG=C.UTF-8 PYTHONPATH="$WORK/lib" PYTHONDONTWRITEBYTECODE=1 \
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
    timeout --kill-after=30 1500 "$PYTHON" -P -m pytest tests -q -p grade_plugin -p no:cacheprovider \
        --noconftest --continue-on-collection-errors -c "$WORK/lib/pytest.ini" --rootdir "$WORK/app" \
        --grade-out "$FIFO" --grade-timeout 120
status=$?

# Nothing the graded code started may outlive the run. kill(-1), sent as the grader, signals all
# of its processes in one call; repeat in case one forked while being killed. Zombies are ignored.
for _ in $(seq 1 100); do
    ps -u "$GRADER_USER" -o stat= 2>/dev/null | grep -qv '^Z' || break
    runuser -u "$GRADER_USER" -- kill -KILL -1 2>/dev/null
    sleep 0.05
done

# With every grader process gone, closing our end gives the reader end of file.
exec 3>&-
( sleep 15; kill "$reader" 2>/dev/null ) &
wait "$reader" 2>/dev/null
exit "$status"
