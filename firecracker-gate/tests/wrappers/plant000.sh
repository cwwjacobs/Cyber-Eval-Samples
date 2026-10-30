#!/bin/sh
# Plants a mode-000 directory with a file in it under the work directory, then becomes the real VMM.
echo "start $$" >> "@AUX@/vmm.log"
prev=""
for arg in "$@"; do
    if [ "$prev" = "--api-sock" ]; then
        work=$(dirname "$arg")
        echo "workdir $work" >> "@AUX@/vmm.log"
        mkdir "$work/stuck" && : > "$work/stuck/file" && chmod 000 "$work/stuck"
    fi
    prev="$arg"
done
exec "@REAL@" "$@"
