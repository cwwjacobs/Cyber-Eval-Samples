#!/usr/bin/env python3
"""Run a command under the namespace rules of Docker's default seccomp profile (x86_64).

    python3 tools/docker_like_seccomp.py COMMAND [ARGS...]

tools/compute_f2p.py must see the same kernel features the task container will have, or a test
that passes only because the build host allows something Docker forbids would be graded and the
reference would score below 1. Docker's default profile refuses unshare and setns, refuses clone
with any namespace flag (EPERM, without CAP_SYS_ADMIN) and answers clone3 with ENOSYS. This
installs a filter with exactly those rules and execs COMMAND. Pair it with a network namespace
that only has loopback to mirror the task's lack of egress.
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
EPERM, ENOSYS = 1, 38
AUDIT_ARCH_X86_64 = 0xC000003E
NR_CLONE, NR_UNSHARE, NR_SETNS, NR_CLONE3 = 56, 272, 308, 435
CLONE_NAMESPACE_FLAGS = 0x7E020000  # NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET

LD_ABS_W, JEQ_K, AND_K, RET_K = 0x20, 0x15, 0x54, 0x06


def insn(code: int, k: int, jt: int = 0, jf: int = 0) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


PROGRAM = [
    insn(LD_ABS_W, 4),                                  # 0  A = arch
    insn(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),               # 1  x86_64 -> 3
    insn(RET_K, SECCOMP_RET_ALLOW),                     # 2
    insn(LD_ABS_W, 0),                                  # 3  A = syscall number
    insn(JEQ_K, NR_UNSHARE, 8, 0),                      # 4  -> 13
    insn(JEQ_K, NR_SETNS, 7, 0),                        # 5  -> 13
    insn(JEQ_K, NR_CLONE3, 7, 0),                       # 6  -> 14
    insn(JEQ_K, NR_CLONE, 1, 0),                        # 7  -> 9
    insn(RET_K, SECCOMP_RET_ALLOW),                     # 8
    insn(LD_ABS_W, 16),                                 # 9  A = low word of clone flags
    insn(AND_K, CLONE_NAMESPACE_FLAGS),                 # 10
    insn(JEQ_K, 0, 0, 1),                               # 11 no namespace flags -> 12, else 13
    insn(RET_K, SECCOMP_RET_ALLOW),                     # 12
    insn(RET_K, SECCOMP_RET_ERRNO | EPERM),             # 13
    insn(RET_K, SECCOMP_RET_ERRNO | ENOSYS),            # 14
]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    if os.uname().machine != "x86_64":
        raise SystemExit("this filter is written for x86_64")
    raw = b"".join(PROGRAM)
    buffer = ctypes.create_string_buffer(raw, len(raw))
    program = SockFprog(len(PROGRAM), ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "installing the seccomp filter failed")
    os.execvp(sys.argv[1], sys.argv[1:])
    return 127


if __name__ == "__main__":
    sys.exit(main())
