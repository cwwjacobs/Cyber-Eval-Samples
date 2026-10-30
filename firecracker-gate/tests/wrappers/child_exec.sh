#!/bin/sh
# Starts a same-group child, then becomes the real VMM. The child outlives the VMM's own exit.
echo "start $$" >> "@AUX@/vmm.log"
sleep 100000 &
echo "child $!" >> "@AUX@/vmm.log"
exec "@REAL@" "$@"
