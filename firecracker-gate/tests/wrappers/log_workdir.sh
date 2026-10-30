#!/bin/sh
# Reports the work directory, then becomes the real VMM.
echo "start $$" >> "@AUX@/vmm.log"
prev=""
for arg in "$@"; do
    if [ "$prev" = "--api-sock" ]; then
        echo "workdir $(dirname "$arg")" >> "@AUX@/vmm.log"
    fi
    prev="$arg"
done
exec "@REAL@" "$@"
