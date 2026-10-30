#!/bin/bash
# Reference solution: apply the patch that creates every Cindermote module in /app.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /app
patch -p1 --forward --batch --no-backup-if-mismatch -i "$HERE/reference.patch"
while IFS= read -r path; do
    [ -n "$path" ] && chmod +x "$path"
done < "$HERE/executables.txt"
