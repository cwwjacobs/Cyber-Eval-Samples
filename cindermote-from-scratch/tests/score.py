"""Score a cindermote-rebuild grading run.

The reward is the fraction of graded tests that passed. Graded tests (f2p.json) are the tests
that fail against the stubbed starting tree and pass against the reference implementation, so
doing nothing scores 0 and the reference scores 1. A graded test with no result counts as failed.
Only records carrying a valid HMAC from the per-run key count. The integrity test is collected first and must always fail. If it is reported as passed, or not
reported at all (the run was cut short before any test ran), the reward is 0.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from collections import defaultdict

_RANK = {"passed": 0, "skipped": 1, "failed": 2}
INTEGRITY_TEST = "tests/aaa_grader_integrity/test_integrity.py::test_integrity_check"


def load_outcomes(path: str, key: bytes) -> dict[str, str]:
    """Per-test outcomes from correctly signed records only; the worst outcome wins."""
    outcomes: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    wrapper = json.loads(line)
                    body, signature = wrapper["record"], wrapper["sig"]
                    expected = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
                    if not key or not hmac.compare_digest(expected, signature):
                        continue
                    record = json.loads(body)
                    nodeid, outcome = record["nodeid"], record["outcome"]
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                if outcome not in _RANK:
                    continue
                prior = outcomes.get(nodeid)
                if prior is None or _RANK[outcome] > _RANK[prior]:
                    outcomes[nodeid] = outcome
    except OSError:
        pass
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--f2p", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--reward", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args()
    try:
        with open(args.key_file, encoding="ascii") as handle:
            key = bytes.fromhex(handle.read().strip())
    except (OSError, ValueError):
        key = b""

    with open(args.f2p, encoding="utf-8") as handle:
        graded = json.load(handle)["tests"]
    outcomes = load_outcomes(args.results, key)

    per_file: dict[str, dict[str, int]] = defaultdict(lambda: {"graded": 0, "passed": 0})
    passed = 0
    for nodeid in graded:
        bucket = per_file[nodeid.split("::", 1)[0]]
        bucket["graded"] += 1
        if outcomes.get(nodeid) == "passed":
            bucket["passed"] += 1
            passed += 1
    reward = passed / len(graded) if graded else 0.0
    tampered = outcomes.get(INTEGRITY_TEST) != "failed"
    if tampered:
        reward = 0.0

    with open(args.reward, "w", encoding="utf-8") as handle:
        handle.write(f"{reward:.6f}\n")
    with open(args.summary, "w", encoding="utf-8") as handle:
        json.dump(
            {"reward": round(reward, 6), "graded": len(graded), "passed": passed,
             "outcomes_rewritten": tampered, "results_recorded": len(outcomes),
             "per_file": dict(sorted(per_file.items()))},
            handle, indent=2,
        )
    print(f"graded {len(graded)} tests, {passed} passed, reward {reward:.6f}"
          + (" (integrity test not reported as failed: run rejected)" if tampered else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
