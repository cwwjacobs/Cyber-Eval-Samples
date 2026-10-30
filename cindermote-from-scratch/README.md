# cindermote-from-scratch

A long-horizon software-engineering task in a security domain, packaged as a Harbor task folder in the FrontierSWE format.

## The task

The agent receives a checkout of [Cindermote](environment/app/README.md), a fail-closed containment runtime for untrusted AI-agent material, with all of its Python source removed. What remains is the documentation (about 25,000 words), the JSON schemas and policy files, the image definitions and shell scripts, a 10-line launcher, a 5-line package bridge and the public test suite. The agent must design and write the implementation: 53 modules, which in the original come to 20,246 lines and 619 functions. The budget is 20 hours (`timeout_sec = 72000`), as in FrontierSWE.

**The proof it can be built:** the finished Cindermote, at commit `67d993e`, is the reference solution. `solve.sh` creates its modules and scores 1.000.

## Why it is one system, not many small tasks

The agent decides module boundaries, private helpers and data structures, and the pieces have to agree with each other:

- the guest/host protocol;
- the evidence bundle, which one module seals with HPKE and secretstream and an offline viewer opens;
- the contracts, roads and receipts signed in one place and verified in another;
- the proxy events consumed by the worker and the browser-receipt validator;
- the runtime evidence the gate reduces to a verdict.

Cross-module tests (the vertical spine, the browser receipts, the supported-host fixtures) expose any disagreement. The scope spans:

- Firecracker microVM and jailer orchestration;
- a pinned-DNS CONNECT egress proxy with a privilege-separated worker;
- RFC 9180 HPKE and libsodium secretstream evidence sealing;
- HMAC-signed contracts and receipts and a policy gate;
- an agent-probe broker that trips on prohibited tool use;
- CDP browser-probe evidence;
- a legacy namespace sandbox with seccomp, ptrace observation and canary probes.

## Layout

| Path | Purpose |
|---|---|
| `instruction.md` | What the agent is told, including the allowed top-level layout and the exact evidence-cryptography API the held-out tests call |
| `task.toml` | Budgets, users and resources. The agent runs as `agent` and the verifier as `root`; egress is limited to an installed agent's model endpoint |
| `environment/Dockerfile`, `environment/app/` | The starting tree (no Python source) and the public tests. The base is the official `python:3.11.15-slim-bookworm`, pinned by digest |
| `tests/test.sh` | Verifier entry point. Writes `/logs/verifier/reward.txt` and a per-file breakdown in `grading.json` |
| `tests/run_suite.sh`, `grade_plugin.py`, `score.py`, `toplevel.txt` | Grading harness |
| `tests/f2p.json` | The graded tests |
| `tests/hidden/` | The held-out tests and the integrity test |
| `solution/solve.sh`, `solution/reference.patch`, `solution/executables.txt` | The reference solution |
| `tools/` | How the task was generated, so reviewers can reproduce it |

## Grading

`test.sh` performs these steps:

1. Makes `/tests` root-only, kills every process the agent left running and removes anything planted in `/logs/verifier`.
2. Snapshots only the top-level entries the reference tree has (`toplevel.txt`, also listed in the instruction), then adds pristine copies of the public tests (baked into the image, root-owned) and the held-out tests.
3. Runs pytest as the unprivileged `grader` user. Python starts with `-P` and plugin autoloading off, so nothing in the snapshot can shadow or extend pytest. It also uses `--noconftest`, an explicit config, a scrubbed environment and a 120-second limit per test.
   - Each outcome is recorded as it happens, signed with HMAC under a per-run key. The key reaches the plugin on a private file descriptor that it reads and closes before any graded module loads.
   - Records go through a FIFO into a file only root can write. Graded code can add lines but never remove one, and unsigned or wrongly signed lines are ignored.
4. Kills every `grader` and `agent` process, using `kill(-1)` as each user until none remain, then writes the reward.

The reward is the fraction of graded tests that pass.

A test is graded when it passes in each of three runs against the reference and fails against all three baselines:

- the empty starting tree;
- a tree with every module present but every function body replaced by `raise NotImplementedError`;
- that tree with every body returning `None`.

Doing nothing, a body-less skeleton, or returning nothing everywhere therefore scores exactly 0, and the reference scores exactly 1. The cheapest way to pass fail-closed checks is a tree that returns `False` everywhere; it scores 0.023.

- **485 tests are graded.** The 26 held out are the RFC 9180 known-answer, PyCA interop and libsodium misuse tests. They call an API the instruction states exactly, so they test the standards and not guesses about names.
- **Why so little is held out:** a per-test audit of an earlier split found that tests pinning details from the original code (the guest's request layout, error texts, internal call order behind mocks, private attributes used by test doubles) were not derivable from what the agent sees. They are public, so a full score is attainable from what the agent is given, as FrontierSWE v2 requires.
- **Not graded:**
  - 9 tests that pass on the empty tree;
  - 24 that pass on the body-less skeleton;
  - 12 that pass when every body returns `None`;
  - 25 that skip or fail without KVM, root, a writable cgroup v2 mount, Linux namespaces or live credentials;
  - the integrity test, which is collected first and must fail. If it is reported as passed, or not reported at all, the run is rejected and the reward is 0.
- **Conditions:** the list was computed under Python 3.11.15 with Docker's default seccomp namespace rules emulated (`tools/docker_like_seccomp.py`) and no network, so a test that passes only on a more permissive build host is not graded. No test was flaky.

## Scores measured before submission

These runs used a mock of the container layout on Linux with the same Python, Docker-like seccomp and no network. That is not Docker itself; `harbor run -a oracle` and `-a nop` in Docker are the authoritative checks.

| Scenario | Reward |
|---|---|
| nop (empty starting tree) | 0.000000 |
| oracle (`solve.sh`) | 1.000000 |
| partial: only the evidence-cryptography modules built | 0.053608 |
| root `conftest.py` forcing passes, a `pytest.ini` plugin, public tests replaced | 0.000000 |
| top-level `pytest.py`, `_pytest/`, `sitecustomize.py` and a `pytest11` entry point planted | 0.000000 |
| a module rewrites every test report to "passed" in-process | 0.000000 (caught by the integrity test) |
| an exit hook truncates the results and writes "passed" for every graded test (full knowledge of the graded list) | 0.000000 (only signed records count; a FIFO alone let this score 0.996) |
| forged "passed" records written at import, then the process exits before any test runs | 0.000000 (integrity test never reported) |
| `reward.txt` planted as a symlink to a root-owned file, plus a forked daemon that keeps writing `1.0` | 0.000000; three seconds later the reward is unchanged, the target is untouched and no live process remains |

A full grading run takes about 25 seconds.

## Calibration (estimates, not measurements)

Two independent reviews of this variant, one bottom-up by subsystem and one by comparison with FrontierSWE v2 tasks, produced these estimates:

| Who | Target | Estimate |
|---|---|---|
| Senior engineer, no AI help | 50% of graded tests | about 95 focused hours (range 65–135) |
| Senior engineer, no AI help | Finishing | about 300 focused hours (range 215–415), or 2–3 calendar months; top-down, 350–500 hours to pass at least 95% |
| Strongest current agents | 20 hours | about 0.65–0.80 |
| Mid-tier agents | 20 hours | about 0.25–0.70 |

- **Held-out set:** all 26 held-out tests are fully determined by the instruction, RFC 9180 and libsodium's documented semantics.
- **Not yet measured:** there are no real agent rollouts yet.

## Residual risk

- **Targeted in-process tampering.** Graded code necessarily runs inside the test process. Rewriting or forging the results file fails without the per-run key, and blanket rewriting is caught by the integrity test. An agent that reads the grader plugin and digs its key out of the process's memory, or rewrites the reports of specific known tests in-process, could still forge results. That is deliberate exploitation of the grader; it is the same exposure as SWE-bench-style tasks, and transcripts should be reviewed for it.
- **Shared-mode upload window.** The verifier runs in Harbor's default shared mode, and Harbor uploads `tests/` into the running container just before `test.sh` starts. A daemon that outlived the agent session could read the held-out tests in that window. FrontierSWE's `[verifier] environment_mode = "separate"` closes the window. It is not enabled here because it has not been exercised with this task.

## Reference solution

`solve.sh` applies `reference.patch`, which creates every module of Cindermote commit `67d993e`, then marks the files listed in `executables.txt` executable.

It is a patch rather than copied source files because the original code names the sandbox user's home directory (user `mote` under `/home`). The submission checker reads that path in a `.py` file under `solution/` as a path from the author's machine. `tools/build_task.py` checks that the patch creates every module byte for byte.

## Reproducing

```bash
python3 tools/build_task.py /path/to/cindermote 67d993e --stub-tree /tmp/cindermote-stubs
sudo python3 tools/docker_like_seccomp.py python3 tools/compute_f2p.py --stub-app /tmp/cindermote-stubs --runs 3
```

Run the second command in an environment that matches the image, with a `grader` user and no network. Then run the submission checks:

```bash
python3 frontierswe-check.py cindermote-from-scratch
harbor run -p cindermote-from-scratch -a oracle
harbor run -p cindermote-from-scratch -a nop
```

## Limitations

- The grader is Cindermote's own unit suite. Module paths and the names the tests touch are fixed by the tests, and behaviour that no test covers, about a third of the original's lines, is not graded.
- With 95% of graded tests public, an agent could special-case tests instead of implementing behaviour. The held-out standards tests and transcript review are the checks against that.
- The implementation language and names match the original. Once this folder is public, `reference.patch` is the answer verbatim, so the task is contamination-sensitive in the way FrontierSWE's language-changing tasks are not.
- The KVM and Firecracker paths are graded only through the suite's fakes. A real microVM boot is out of reach in an unprivileged container.
- Requires Docker 20.10 or later, whose seccomp profile allows `pidfd_open`.
