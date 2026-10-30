#!/usr/bin/env python3
"""Compute tests/f2p.json, the list of graded tests.

    sudo python3 tools/compute_f2p.py --stub-app DIR [--python /opt/venv/bin/python] [--runs 3]

Runs the full suite (tests/run_suite.sh) against the agent's starting tree (environment/app, no
Python source), against the stubbed tree from tools/build_task.py --stub-tree (every module
present, every body raising NotImplementedError), against that tree with every stub returning
None, and --runs times against the reference tree (environment/app plus solution/reference.patch).
A test is graded when it passes in every reference run and in none of the baseline trees. Doing
nothing, a body-less skeleton, or returning nothing everywhere therefore scores exactly 0, and the
reference scores exactly 1. Tests that skip, fail or flake against the reference are left out. A
tree that returns False everywhere is also run and its score reported, because fail-closed checks
are exactly what such a tree would pass.

Run it as root in an environment that matches the task image: Python 3.11, libsodium, the pinned
test requirements, a non-root grader user, and no KVM.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parent.parent
TESTS = TASK_DIR / "tests"
APP = TASK_DIR / "environment" / "app"


def _load_outcomes():
    spec = importlib.util.spec_from_file_location("score", TESTS / "score.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_outcomes


def stub_variant(stub: Path, dest: Path, statement: bytes) -> None:
    """Copy the stubbed tree with every stub body replaced by STATEMENT."""
    shutil.copytree(stub, dest, symlinks=True)
    for path in dest.rglob("*"):
        if not path.is_file() or "tests" in path.relative_to(dest).parts:
            continue
        data = path.read_bytes()
        if b"raise NotImplementedError" not in data:
            continue
        changed = data.replace(b"raise NotImplementedError", statement)
        ast.parse(changed)
        path.write_bytes(changed)


def run_suite(app: Path, work: Path, python: str, grader: str) -> dict[str, str]:
    work.mkdir(parents=True)
    results = work / "results.jsonl"
    env = dict(os.environ, APP_DIR=str(app), VISIBLE_TESTS_DIR=str(APP / "tests"),
               HIDDEN_TESTS_DIR=str(TESTS / "hidden"), PYTHON=python, GRADER_USER=grader)
    subprocess.run(["bash", str(TESTS / "run_suite.sh"), str(work), str(results)], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key_file = work / "grade.key"
    key = bytes.fromhex(key_file.read_text().strip()) if key_file.exists() else b""
    return _load_outcomes()(str(results), key)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python", default="/opt/venv/bin/python")
    parser.add_argument("--grader-user", default="grader")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--stub-app", default=None,
                        help="the stubbed tree from tools/build_task.py --stub-tree")
    args = parser.parse_args()

    scratch = Path(tempfile.mkdtemp(prefix="cindermote-f2p-"))
    os.chmod(scratch, 0o755)
    stub = scratch / "stub"
    reference = scratch / "reference"
    if not args.stub_app:
        parser.error("--stub-app is required: generate it with tools/build_task.py --stub-tree DIR")
    shutil.copytree(args.stub_app, stub, symlinks=True)
    shutil.copytree(APP, reference, symlinks=True)
    subprocess.run(["patch", "-p1", "--batch", "--silent", "-i",
                    str(TASK_DIR / "solution" / "reference.patch")], cwd=reference, check=True)

    stub_variant(stub, scratch / "returns-none", b"return None")
    stub_variant(stub, scratch / "returns-false", b"return False")

    empty_outcomes = run_suite(APP, scratch / "run-empty", args.python, args.grader_user)
    stub_outcomes = run_suite(stub, scratch / "run-stub", args.python, args.grader_user)
    none_outcomes = run_suite(scratch / "returns-none", scratch / "run-none", args.python, args.grader_user)
    false_outcomes = run_suite(scratch / "returns-false", scratch / "run-false", args.python, args.grader_user)
    reference_runs = [run_suite(reference, scratch / f"run-ref-{i}", args.python, args.grader_user)
                      for i in range(args.runs)]

    seen = set().union(*reference_runs)
    always_pass = {n for n in seen if all(run.get(n) == "passed" for run in reference_runs)}
    ever_pass = {n for n in seen if any(run.get(n) == "passed" for run in reference_runs)}
    not_on_empty = {n for n in always_pass if empty_outcomes.get(n) != "passed"}
    not_on_stub = {n for n in not_on_empty if stub_outcomes.get(n) != "passed"}
    graded = sorted(n for n in not_on_stub if none_outcomes.get(n) != "passed")
    false_score = sum(false_outcomes.get(n) == "passed" for n in graded) / max(len(graded), 1)

    version = subprocess.run([args.python, "-c", "import sys; print(sys.version.split()[0])"],
                             capture_output=True, text=True).stdout.strip()
    commit_file = TASK_DIR / "tools" / "SOURCE_COMMIT"
    report = {
        "description": "Graded tests: pass in every reference run and in none of the baseline trees (empty, stubbed, returns None).",
        "source_commit": commit_file.read_text().strip() if commit_file.exists() else None,
        "python": version,
        "reference_runs": args.runs,
        "counts": {
            "collected_in_reference": len(seen),
            "graded": len(graded),
            "pass_on_empty_tree_excluded": len(always_pass) - len(not_on_empty),
            "pass_on_stub_excluded": len(not_on_empty) - len(not_on_stub),
            "pass_on_return_none_excluded": len(not_on_stub) - len(graded),
            "flaky_excluded": len(ever_pass - always_pass),
            "never_pass_on_reference_excluded": len(seen - ever_pass),
        },
        "return_false_tree_score": round(false_score, 6),
        "tests": graded,
    }
    (TESTS / "f2p.json").write_text(json.dumps(report, indent=2) + "\n")
    shutil.rmtree(scratch, ignore_errors=True)
    print(json.dumps(report["counts"]))
    return 0 if graded else 1


if __name__ == "__main__":
    sys.exit(main())
