#!/usr/bin/env python3
"""Hidden verifier for fcgate. Runs /app/fcgate over every case in cases.py on real VMs and scores the runs.

Score = passed / total, multiplied by 0 if any case whose expected decision is not ALLOW was answered ALLOW
by stdout, exit code or receipt. The score comes only from runs of the program.

The optional --only NAME[,NAME...] and --list arguments are for working on the verifier itself. test.sh
passes no arguments.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True

import cases  # noqa: E402
import harness  # noqa: E402

LOG_DIR = "/logs/verifier"
TOTAL_BUDGET_SEC = 14 * 60    # no new case starts after this
HARD_STOP_SEC = 14.75 * 60    # and any case still running is cut off here


def emit(reward, valid, reason, extra=None, cases_detail=None):
    """Writes reward.txt, which Harbor reports as the Mean, and details.json for reading."""
    os.makedirs(LOG_DIR, exist_ok=True)
    value = round(float(reward), 6) if valid else 0.0
    details = {"reward": value, "valid": bool(valid), "reason": reason}
    details.update(extra or {})
    if cases_detail is not None:
        details["cases"] = cases_detail
    for name, text in (("reward.txt", "%s\n" % value), ("details.json", json.dumps(details, indent=2))):
        path = os.path.join(LOG_DIR, name)
        if os.path.lexists(path):
            os.unlink(path)
        with open(path, "w") as handle:
            handle.write(text)
    print("reward=%s valid=%d - %s" % (value, 1 if valid else 0, reason), flush=True)


def lock_down():
    """The tests become root-only before anything runs, and only root may write the logs. A read-only mount is fine."""
    try:
        os.chmod(harness.HERE, 0o700)
    except OSError as error:
        print("tests directory left as it is: %s" % error.strerror, flush=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    try:
        os.chown(LOG_DIR, 0, 0)
        os.chmod(LOG_DIR, 0o755)
    except OSError:
        pass
    for name in ("reward.txt", "reward.json", "details.json"):
        path = os.path.join(LOG_DIR, name)
        if os.path.lexists(path):
            os.unlink(path)


def prepare_app():
    """Puts back what an artifact copy can lose. Returns the reason the gate cannot run, or None."""
    gate = harness.GATE
    if not os.path.lexists(gate) or not os.path.exists(gate):
        return "/app/fcgate is missing"
    if os.path.isdir(gate):
        return "/app/fcgate is a directory"
    for folder, subdirs, files in os.walk("/app"):
        for name in subdirs + files + ["."]:
            path = os.path.normpath(os.path.join(folder, name))
            try:
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    continue
                os.lchown(path, harness.UID, harness.GID)
                mode = stat.S_IMODE(info.st_mode) | 0o444
                if stat.S_ISDIR(info.st_mode):
                    mode |= 0o111
                elif mode & 0o111 or is_program(path):
                    mode |= 0o111
                os.chmod(path, mode)
            except OSError:
                pass
    try:
        info = os.stat(gate)
        os.chmod(gate, stat.S_IMODE(info.st_mode) | 0o555)
    except OSError:
        pass
    probe = subprocess.run(["test", "-x", gate], user=harness.UID, group=harness.GID, extra_groups=[],
                           env=harness.ENV, cwd="/", stdin=subprocess.DEVNULL, capture_output=True)
    if probe.returncode != 0:
        return "/app/fcgate is not executable by the agent user"
    return None


def is_program(path):
    try:
        with open(path, "rb") as handle:
            start = handle.read(4)
    except OSError:
        return False
    return start.startswith(b"#!") or start == b"\x7fELF"


def run_case(definition, index):
    """Runs one case to a result. A case that raises is a failed case; the machine is restored either way."""
    started = time.monotonic()
    context = None
    harness_error = None
    try:
        context = harness.Ctx(index)
        definition.function(context)
    except harness.Stop:
        pass
    except Exception:  # noqa: BLE001 - one broken case must not stop the others
        harness_error = traceback.format_exc(limit=4)
    problems = list(context.problems) if context else []
    false_allows = list(context.false_allows) if context else []
    if harness_error:
        problems.append("verifier error: " + harness_error.strip().splitlines()[-1])
        print(harness_error, flush=True)
    harness.clean_case_state(context)
    return {"name": definition.name, "group": definition.group, "doc": definition.doc, "passed": not problems,
            "reason": "; ".join(problems)[:800], "false_allow": false_allows, "elapsed": round(time.monotonic() - started, 2)}


def print_table(results):
    width = max(len(result["name"]) for result in results)
    print("\n%-5s %-*s %7s  %s" % ("", width, "case", "seconds", "reason"))
    for result in results:
        flag = "pass" if result["passed"] else "FAIL"
        reason = ("[false ALLOW] " if result["false_allow"] else "") + result["reason"]
        print("%-5s %-*s %7.1f  %s" % (flag, width, result["name"], result["elapsed"], reason))
    print(flush=True)


def main(argv):
    only = None
    for index, item in enumerate(argv):
        if item == "--only":
            only = set(argv[index + 1].split(","))
        if item == "--list":
            for definition in cases.CASES:
                print("%-46s %-9s %s" % (definition.name, definition.group, definition.doc))
            print("%d cases" % len(cases.CASES))
            return 0
    started = time.monotonic()
    lock_down()
    reason = prepare_app()
    if reason:
        print(reason, flush=True)
        emit(0.0, True, reason, {"passed": 0, "total": len(cases.CASES), "false_allow_count": 0})
        return 0
    harness.prepare_machine()
    harness.State.hard_stop = started + HARD_STOP_SEC
    selected = [definition for definition in cases.CASES if only is None or definition.name in only]
    results = []
    for index, definition in enumerate(selected):
        if time.monotonic() - started > TOTAL_BUDGET_SEC:
            results.append({"name": definition.name, "group": definition.group, "doc": definition.doc, "passed": False,
                            "reason": "not run: verifier time budget used up", "false_allow": [], "elapsed": 0.0})
            continue
        result = run_case(definition, index)
        results.append(result)
        print("[%3d/%3d] %-5s %-46s %6.1fs %s" % (index + 1, len(selected), "pass" if result["passed"] else "FAIL",
                                                  definition.name, result["elapsed"], result["reason"][:300]), flush=True)
    print_table(results)
    passed = sum(1 for result in results if result["passed"])
    total = len(results)
    false_allow = [{"case": result["name"], "why": result["false_allow"]} for result in results if result["false_allow"]]
    elapsed = round(time.monotonic() - started, 1)
    fraction = passed / total if total else 0.0
    reward = 0.0 if false_allow else fraction
    summary = "%d/%d cases passed; %d answered ALLOW when they should not have; %.1fs" % (passed, total, len(false_allow), elapsed)
    if false_allow:
        print("FALSE ALLOW:", json.dumps(false_allow, indent=1), flush=True)
    harness.kill_everything()
    emit(reward, True, summary, {"passed": passed, "total": total, "false_allow_count": len(false_allow),
                                 "false_allow": false_allow, "elapsed_sec": elapsed}, results)
    for path in (harness.DISK, harness.SHM, harness.CAPTURE):
        shutil.rmtree(path, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
