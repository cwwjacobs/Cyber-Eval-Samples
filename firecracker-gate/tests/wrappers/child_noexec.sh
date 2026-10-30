#!/bin/sh
# Runs the real VMM as a child, next to another same-group child, and waits for the VMM.
echo "start $$" >> "@AUX@/vmm.log"
sleep 100000 &
echo "child $!" >> "@AUX@/vmm.log"
"@REAL@" "$@" &
vmm=$!
echo "child $vmm" >> "@AUX@/vmm.log"
wait "$vmm"
