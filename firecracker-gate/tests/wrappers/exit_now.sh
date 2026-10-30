#!/bin/sh
# A VMM that exits at once, before any API call can be accepted.
echo "start $$" >> "@AUX@/vmm.log"
exit 1
