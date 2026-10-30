#!/usr/bin/env python3
"""Run /app/fcgate over the sample jobs on real VMs and compare decisions with the expected ones."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "..", "examples")
GATE = os.path.join(HERE, "..", "fcgate")
EXPECTED = {
    "benign": ("ALLOW", "complete", 0),
    "prohibited": ("DENY", "prohibited_tool", 2),
    "truncated": ("EVALUATION_INCOMPLETE", "no_final", 4),
    "stall": ("EVALUATION_INCOMPLETE", "timeout_hello", 4),
}


def main():
    if not os.access(GATE, os.X_OK):
        print("/app/fcgate is not there yet, or is not executable")
        return 1
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        key = os.path.join(tmp, "key")
        fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32))
        os.close(fd)
        for name, (decision, reason, code) in EXPECTED.items():
            out = os.path.join(tmp, name)
            run = subprocess.run([GATE, "run", "--job", os.path.join(EXAMPLES, name), "--out", out,
                                  "--key-file", key], capture_output=True, text=True, timeout=120)
            line = run.stdout.strip()
            good = line == f"{decision} {reason}" and run.returncode == code
            check = subprocess.run([GATE, "verify", "--receipt", os.path.join(out, "receipt.json"),
                                    "--key-file", key], capture_output=True, text=True)
            good = good and check.returncode == 0 and check.stdout.strip() == "VALID"
            print(f"{'ok  ' if good else 'FAIL'} {name}: got {line!r} exit {run.returncode}, verify {check.stdout.strip()!r}")
            failures += 0 if good else 1
    print(f"{len(EXPECTED) - failures}/{len(EXPECTED)} sample jobs as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
