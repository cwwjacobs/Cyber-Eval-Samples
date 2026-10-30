#!/bin/sh
# Records every VMM start, then becomes the real VMM.
case " $* " in *" --api-sock "*) echo "start $$" >> "@AUX@/vmm.log" ;; esac
exec "@REAL@" "$@"
