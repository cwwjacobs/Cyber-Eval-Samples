#!/bin/bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$here/fcgate.py" /app/fcgate
chmod 0755 /app/fcgate
