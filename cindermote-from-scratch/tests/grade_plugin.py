"""Pytest plugin for the cindermote-from-scratch verifier.

Records one outcome per test node id and writes each decision to the verifier's results channel as
soon as it is known, so a crash or a timeout later in the run cannot erase earlier results. A test is
failed if any of its reports failed (setup, call, teardown or a subtest). Any single test that
runs longer than --grade-timeout seconds is interrupted and fails.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal

import pytest


def _read_key() -> bytes:
    """Read the per-run signing key from fd 4 and close it; empty when run without one."""
    try:
        data = b""
        while chunk := os.read(4, 4096):
            data += chunk
        os.close(4)
        return bytes.fromhex(data.decode("ascii").strip())
    except (OSError, ValueError):
        return b""


def _make_emitter(key: bytes):
    # Everything the emitter needs is bound now, before any graded module is imported.
    write, new, sha256, dumps = os.write, hmac.new, hashlib.sha256, json.dumps

    def emit(fd: int, nodeid: str, outcome: str) -> None:
        body = dumps({"nodeid": nodeid, "outcome": outcome}, sort_keys=True)
        signature = new(key, body.encode("utf-8"), sha256).hexdigest()
        write(fd, (dumps({"record": body, "sig": signature}) + "\n").encode("utf-8"))

    return emit


_emit = _make_emitter(_read_key())

_RANK = {"passed": 0, "skipped": 1, "failed": 2}
_state: dict = {"out": None, "timeout": 0, "outcomes": {}}


class GradeTimeout(Exception):
    """Raised inside a test that exceeded the per-test time limit."""


def pytest_addoption(parser):
    parser.addoption("--grade-out", default=None, help="JSON-lines file for per-test outcomes")
    parser.addoption("--grade-timeout", type=int, default=0, help="per-test limit in seconds")


def pytest_configure(config):
    out = config.getoption("--grade-out")
    _state["out"] = os.open(out, os.O_WRONLY | os.O_APPEND) if out else None
    _state["timeout"] = config.getoption("--grade-timeout")


def _on_alarm(signum, frame):
    raise GradeTimeout(f"test exceeded {_state['timeout']}s")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    seconds = _state["timeout"]
    previous = None
    if seconds:
        previous = signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(seconds)
    try:
        return (yield)
    finally:
        if seconds:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)


def pytest_runtest_logreport(report):
    if report.when != "call" and report.outcome == "passed":
        return
    prior = _state["outcomes"].get(report.nodeid)
    if prior is not None and _RANK[report.outcome] <= _RANK[prior]:
        return
    _state["outcomes"][report.nodeid] = report.outcome
    if _state["out"] is not None:
        _emit(_state["out"], report.nodeid, report.outcome)
