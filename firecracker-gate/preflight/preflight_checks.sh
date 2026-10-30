# preflight: firecracker-gate
#
# Structural checks mirroring the FrontierSWE preflight expectations. Runs in the agent environment;
# records a pass/fail verdict.
set -u
_DIR=/logs/agent; mkdir -p "$_DIR" 2>/dev/null || true
_JSONL="$_DIR/preflight.jsonl"; : > "$_JSONL" 2>/dev/null || true

_record() { echo "{\"bucket\":\"$1\",\"check\":\"$2\",\"status\":\"$3\"}" >> "$_JSONL" 2>/dev/null || true; }
ok()      { if eval "$3" >/dev/null 2>&1; then _record "$1" "$2" ok; else _record "$1" "$2" FAIL; fi; }
blocked() { if eval "$3" >/dev/null 2>&1; then _record "$1" "$2" FAIL; else _record "$1" "$2" ok; fi; }

ok baseline cc        'cc --version'
ok baseline python3   'python3 --version'
ok baseline mke2fs    'command -v mke2fs'
ok baseline git       'git --version'

ok kvm device         'test -r /dev/kvm && test -w /dev/kvm'
ok kvm firecracker    'firecracker --version'
ok kvm kernel         'test -r /opt/lab/vmlinux'
ok kvm rootfs         'test -r /opt/lab/rootfs.ext4'
ok kvm lock           'test -r /opt/lab/assets.lock.json'

ok      perms app-read    'ls /app >/dev/null'
ok      perms app-write   'touch /app/.px && rm -f /app/.px'
blocked perms tests-read  'ls /tests'

ok workspace spec     'test -f /app/docs/SPEC.md'
ok workspace examples 'test -f /app/examples/benign/manifest.json'
ok workspace runner   'test -x /app/tools/run_examples.py'

ok timer cli 'command -v sandbox-timer'

if grep -q '"status":"FAIL"' "$_JSONL" 2>/dev/null; then echo "preflight FAIL"; else echo "preflight ok"; fi
