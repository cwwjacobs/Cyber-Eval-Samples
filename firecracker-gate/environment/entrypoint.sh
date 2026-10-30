#!/bin/sh
# Container init, run once per sandbox.
set -e
sandbox-timer start || true
# The passed-through device node belongs to this container's own /dev, so this changes nothing on the host.
if [ -e /dev/kvm ]; then chmod 0666 /dev/kvm || true; fi
# The oracle uploads its files into /solution, so it must exist and be agent-owned for that stage only.
if [ -n "${HARBOR_ORACLE_FLAG:-}" ]; then
    mkdir -p /solution && chown agent:agent /solution
fi
[ "$#" -gt 0 ] || set -- tail -f /dev/null
exec "$@"
