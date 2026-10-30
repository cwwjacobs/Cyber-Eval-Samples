#!/bin/sh
# Reports the work directory and waits until the verifier has planted root-owned residue in it.
echo "start $$" >> "@AUX@/vmm.log"
prev=""
for arg in "$@"; do
    if [ "$prev" = "--api-sock" ]; then
        echo "workdir $(dirname "$arg")" >> "@AUX@/vmm.log"
    fi
    prev="$arg"
done
tries=0
while [ ! -e "@AUX@/planted" ] && [ "$tries" -lt 300 ]; do
    sleep 0.05
    tries=$((tries + 1))
done
exec "@REAL@" "$@"
