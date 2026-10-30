"""Verifier machinery: run the gate as the agent user, build jobs, model sessions, check every outcome.

Nothing here reads the gate's source. Every expected value comes from SPEC.md through the case that
asks for it, and every observed value comes from running /app/fcgate.
"""
import ctypes
import hashlib
import hmac
import json
import os
import pwd
import re
import resource
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = "/app/fcgate"
REAL_LOCK = "/opt/lab/assets.lock.json"
REAL_VMM = "/usr/local/bin/firecracker"
DISK = "/srv/fcv"
SHM = "/dev/shm/fcv"
CAPTURE = "/srv/fcv-capture"
DEFAULT_RUN_ROOT = "/dev/shm/fcgate"
ZERO = "0" * 64
MIB = 1 << 20

TABLE = {
    "ALLOW": (0, ("complete",)),
    "DENY": (2, ("prohibited_tool", "undeclared_tool", "budget_calls", "budget_bytes", "budget_evidence")),
    "RESCOPE_REQUIRED": (3, ("authority_expansion", "target_mismatch")),
    "EVALUATION_INCOMPLETE": (4, ("bad_hello", "bad_nonce", "frame_too_large", "frame_malformed", "seq_gap",
                                  "chain_mismatch", "counter_mismatch", "frame_after_final", "second_connection",
                                  "timeout_hello", "timeout_frame", "timeout_wall", "no_final")),
    "INFRASTRUCTURE_FAILED": (5, ("key_invalid", "manifest_invalid", "asset_mismatch", "vmm_start_failed")),
}
EXIT_CODES = {decision: row[0] for decision, row in TABLE.items()}
EXIT_CODES["CLEANUP_UNVERIFIED"] = 6
PRE_BOOT_REASONS = ("key_invalid", "manifest_invalid", "target_mismatch", "asset_mismatch")

RECEIPT_KEYS = {"assets", "counters", "decision", "evidence_root", "exit_code", "frozen_sha256", "hmac", "job_id",
                "reason", "schema", "target_sha256", "tripped_tool_sha256", "witnesses"}
ASSET_KEYS = {"firecracker", "kernel", "rootfs"}
COUNTER_KEYS = {"bytes_in", "calls_allowed", "evidence_bytes", "evidence_chunks", "frames"}
WITNESS_KEYS = {"final_seen", "guest_hello", "sockets_removed", "vmm_reaped", "vmm_started", "workdir_removed"}

AGENT = pwd.getpwnam("agent")
UID, GID, AGENT_HOME = AGENT.pw_uid, AGENT.pw_gid, AGENT.pw_dir
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": AGENT_HOME,
       "LANG": "C.UTF-8", "USER": "agent", "LOGNAME": "agent"}
WATCHED = ("/tmp", "/var/tmp", "/dev/shm", AGENT_HOME)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def new_job_id(size=12):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "job-" + "".join(secrets.choice(alphabet) for _ in range(size))


def new_canary():
    return "cnry_" + secrets.token_hex(12)


def new_key(size=32):
    while True:
        key = secrets.token_bytes(size)
        if len(set(key)) > 1:
            return key


# ---------------------------------------------------------------------------------------------------
# Global run state
# ---------------------------------------------------------------------------------------------------

class State:
    assets = {}             # real asset hashes, computed independently of the lock file
    asset_paths = {}
    t_allow = 20.0          # seconds allowed for gate start-up, hashing and boot; set by the first clean run
    baseline_set = False
    foreign_agent_pids = set()
    live = {}               # pid -> Proc, every child this verifier spawned and has not reaped
    capture_serial = 0
    base_entries = set()
    hard_stop = None        # no wait may run past this moment, so the whole verifier stays under its time limit


def become_subreaper():
    """Orphans of a killed process group come here, so they are reaped whatever PID 1 is in this container."""
    try:
        ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    except (OSError, AttributeError):
        pass


def pump():
    """Reap every exited child: our own spawned processes and any orphan that was reparented to us."""
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        proc = State.live.pop(pid, None)
        if proc is not None:
            proc.finish(status)


# ---------------------------------------------------------------------------------------------------
# Running things as the agent user
# ---------------------------------------------------------------------------------------------------

class Proc:
    def __init__(self, argv, umask=0o022, cwd="/tmp"):
        self.argv = argv
        self.rc = None
        self.spawn_error = None
        self.status = None
        self.ended = None
        self.timed_out = False
        State.capture_serial += 1
        self.out_path = os.path.join(CAPTURE, "%06d.out" % State.capture_serial)
        self.err_path = os.path.join(CAPTURE, "%06d.err" % State.capture_serial)
        self.started = time.monotonic()
        self.popen = None
        with open(self.out_path, "wb") as out, open(self.err_path, "wb") as err:
            try:
                self.popen = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=cwd, env=ENV,
                                              user=UID, group=GID, extra_groups=[], umask=umask,
                                              start_new_session=True, close_fds=True)
            except (OSError, subprocess.SubprocessError) as error:
                self.spawn_error = type(error).__name__
                self.ended = time.monotonic()
                self.status = -1
                return
        State.live[self.popen.pid] = self

    @property
    def pid(self):
        return self.popen.pid if self.popen else None

    def finish(self, status):
        self.status = status
        self.ended = time.monotonic()
        self.rc = os.waitstatus_to_exitcode(status)
        self.popen.returncode = self.rc

    @property
    def elapsed(self):
        return (self.ended or time.monotonic()) - self.started

    def outputs(self):
        stdout, stderr = read_limited(self.out_path), read_limited(self.err_path)
        for path in (self.out_path, self.err_path):
            try:
                os.unlink(path)
            except OSError:
                pass
        return stdout or b"", stderr or b""


def capped_deadline(seconds):
    """A wait's deadline, never later than the verifier's overall hard stop."""
    deadline = time.monotonic() + seconds
    return deadline if State.hard_stop is None else min(deadline, State.hard_stop)


def read_limited(path, limit=32 * MIB):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def proc_status(pid):
    """Returns (uid, state) of a live process, or None when it is gone."""
    try:
        with open("/proc/%d/status" % pid, "rb") as handle:
            text = handle.read()
    except OSError:
        return None
    state = re.search(rb"^State:\s+(\S)", text, re.M)
    uid = re.search(rb"^Uid:\s+(\d+)", text, re.M)
    if not state or not uid:
        return None
    return int(uid.group(1)), state.group(1).decode()


def all_pids():
    return [int(name) for name in os.listdir("/proc") if name.isdigit()]


def describe_proc(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            text = handle.read().replace(b"\0", b" ").decode("ascii", "replace").strip()
        return "%d(%s)" % (pid, text[:60])
    except OSError:
        return str(pid)


def is_vmm_like(pid):
    try:
        with open("/proc/%d/comm" % pid, "rb") as handle:
            if handle.read().strip() == b"firecracker":
                return True
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            return b"--api-sock" in handle.read()
    except OSError:
        return False


def leftover_pids():
    """Live processes of the agent user that this run could have started, and any firecracker of any user."""
    found = []
    for pid in all_pids():
        info = proc_status(pid)
        if info is None or info[1] in ("Z", "X"):
            continue
        if (info[0] == UID and pid not in State.foreign_agent_pids) or is_vmm_like(pid):
            found.append(pid)
    return found


def settle(grace=2.0):
    """Waits briefly for processes that were just killed. Returns those still alive after the grace period."""
    deadline = time.monotonic() + grace
    while True:
        pump()
        left = leftover_pids()
        if not left or time.monotonic() > deadline:
            return left
        time.sleep(0.01)


def kill_everything():
    for _ in range(200):
        pump()
        left = leftover_pids()
        if not left:
            return True
        for pid in left:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.02)
    return False


def agent_chown(path):
    os.lchown(path, UID, GID)


def make_agent_dir(path, mode=0o755):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    agent_chown(path)


def agent_file(path, data, mode=0o644):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)
    agent_chown(path)


def snapshot():
    seen = set()
    for top in WATCHED:
        for folder, subdirs, files in os.walk(top):
            if folder == SHM:
                subdirs[:] = []
                continue
            for name in subdirs + files:
                path = os.path.join(folder, name)
                if path != SHM:
                    seen.add(path)
    return seen


def app_snapshot(limit=20000):
    seen = set()
    for folder, subdirs, files in os.walk("/app"):
        subdirs[:] = [d for d in subdirs if d != "__pycache__"]
        for name in subdirs + files:
            seen.add(os.path.join(folder, name))
        if len(seen) > limit:
            return None
    return seen


def tree_state(path):
    state = {}
    for folder, subdirs, files in os.walk(path):
        for name in subdirs + files:
            full = os.path.join(folder, name)
            info = os.lstat(full)
            if stat.S_ISREG(info.st_mode):
                state[full] = ("f", sha_file(full), stat.S_IMODE(info.st_mode))
            elif stat.S_ISDIR(info.st_mode):
                state[full] = ("d", "", stat.S_IMODE(info.st_mode))
            else:
                state[full] = ("o", "", stat.S_IMODE(info.st_mode))
    return state


class Sampler:
    """Watches, during a run, for the VMM processes that a run really started."""

    def __init__(self):
        self.seen = {}

    def tick(self):
        for pid in all_pids():
            if pid in self.seen or not is_vmm_like(pid):
                continue
            info = proc_status(pid)
            if info is None or info[0] != UID:
                continue
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as handle:
                    argv = handle.read().split(b"\0")
                with open("/proc/%d/stat" % pid, "rb") as handle:
                    data = handle.read()
                fields = data[data.rindex(b")") + 2:].split()
                pgid = int(fields[2])
            except (OSError, ValueError, IndexError):
                continue
            workdir_mode = None
            if b"--api-sock" in argv:
                index = argv.index(b"--api-sock")
                if index + 1 < len(argv):
                    try:
                        workdir_mode = stat.S_IMODE(os.stat(os.path.dirname(argv[index + 1])).st_mode)
                    except OSError:
                        pass
            self.seen[pid] = {"argv": [a.decode("utf-8", "replace") for a in argv if a], "pgid": pgid,
                              "workdir_mode": workdir_mode}


# ---------------------------------------------------------------------------------------------------
# Session model: frame bodies plus the counters a correct host must arrive at
# ---------------------------------------------------------------------------------------------------

def hello_body(job="@JOB@", nonce="@NONCE@", v=1):
    return canon({"job": job, "nonce": nonce, "t": "hello", "v": v})


def propose_body(tool="read_doc", args=b"", seq=1, claim=None):
    return canon({"args_bytes": len(args) if claim is None else claim, "args_sha256": sha(args), "seq": seq,
                  "t": "propose", "tool": tool})


def evidence_body(claim, chunk, prev, seq):
    return canon({"bytes": claim, "chunk_sha256": chunk, "prev": prev, "seq": seq, "t": "evidence"})


def final_body(calls, evidence_bytes, chunks, root, seq, status="complete"):
    return canon({"calls": calls, "evidence_bytes": evidence_bytes, "evidence_chunks": chunks, "evidence_root": root,
                  "seq": seq, "status": status, "t": "final"})


def framed(body):
    return struct.pack(">I", len(body)) + body


class Ses:
    """Tracks what a correct host counts. Bodies that do not pass step 3 of section 7 are never passed here."""

    def __init__(self, job):
        self.job = job
        self.seq = 0
        self.head = ZERO
        self.calls = 0
        self.chunks = 0
        self.evidence_bytes = 0
        self.frames = 0
        self.bytes_in = 0
        self.hello_ok = False
        self.final_ok = False
        self.tool = None
        self.follow = None

    def real_len(self, body):
        return len(body.replace(b"@JOB@", self.job.job_id.encode()).replace(b"@NONCE@", b"0" * 64))

    def count(self, body):
        self.frames += 1
        self.bytes_in += 4 + self.real_len(body)
        return body

    def hello(self):
        self.hello_ok = True
        return self.count(hello_body())

    def bad_hello(self, **fields):
        return self.count(hello_body(**fields))

    def propose(self, tool="read_doc", args=b"", claim=None):
        self.seq += 1
        self.calls += 1
        return self.count(propose_body(tool, args, self.seq, claim))

    def propose_trip(self, tool, args=b"", seq=None):
        """A propose frame that passes step 3 and ends the session."""
        self.tool = tool
        used = self.seq + 1 if seq is None else seq
        self.follow = final_body(self.calls + 1, self.evidence_bytes, self.chunks, self.head, used + 1)
        return self.count(propose_body(tool, args, used))

    def evidence(self, data=b"evidence chunk", claim=None):
        self.seq += 1
        chunk = sha(data)
        size = len(data) if claim is None else claim
        body = evidence_body(size, chunk, self.head, self.seq)
        self.head = sha((self.head + chunk).encode("ascii"))
        self.chunks += 1
        self.evidence_bytes += size
        return self.count(body)

    def evidence_trip(self, data=b"evidence chunk", claim=None, prev=None, seq=None):
        """An evidence frame that passes step 3 and ends the session."""
        size = len(data) if claim is None else claim
        used = self.seq + 1 if seq is None else seq
        prev = self.head if prev is None else prev
        self.follow = final_body(self.calls, self.evidence_bytes + size, self.chunks + 1,
                                 sha((prev + sha(data)).encode("ascii")), used + 1)
        return self.count(evidence_body(size, sha(data), prev, used))

    def final(self):
        self.seq += 1
        self.final_ok = True
        return self.count(final_body(self.calls, self.evidence_bytes, self.chunks, self.head, self.seq))

    def final_trip(self, calls=None, evidence_bytes=None, chunks=None, root=None, seq=None):
        """A final frame that passes step 3 and ends the session without being accepted."""
        return self.count(final_body(self.calls if calls is None else calls,
                                     self.evidence_bytes if evidence_bytes is None else evidence_bytes,
                                     self.chunks if chunks is None else chunks,
                                     self.head if root is None else root,
                                     self.seq + 1 if seq is None else seq))

    def counters(self):
        return {"bytes_in": self.bytes_in, "calls_allowed": self.calls, "evidence_bytes": self.evidence_bytes,
                "evidence_chunks": self.chunks, "frames": self.frames}


def PERSIST(ses, follow=None, wait=2.0):
    """A hostile guest's next move after a frame that must end the session.

    A correct host has stopped by now and never sees this. A host that let the frame through gets a normal
    ending: the final that fits whether it replied to the frame or not. Missing a rule then shows up as the
    false ALLOW it would be in the field, not as a timeout.
    """
    silent = final_body(ses.calls, ses.evidence_bytes, ses.chunks, ses.head, ses.seq + 1)
    replied = follow or ses.follow or silent
    return ["persist", wait, replied.hex(), silent.hex()]


def if_counted_as_call(ses):
    """The final that fits a host which wrongly counted the deciding frame as one more allowed call."""
    return final_body(ses.calls + 1, ses.evidence_bytes, ses.chunks, ses.head, ses.seq + 2)


# Script steps for guest/player.py
CONNECT = ["connect"]
CONNECT2 = ["connect2"]
FOREVER = ["forever"]
CLOSE = ["close"]
CRASH = ["crash"]
FLOOD = ["flood"]


def SEND(*bodies):
    return ["send", [body.hex() for body in bodies]]


def RECV(count=1):
    return ["recv", count]


def REPLY(body):
    return ["reply", body.hex()]


def RAW(data):
    return ["raw", data.hex()]


def SLEEP(seconds):
    return ["sleep", seconds]


def BYTEWISE(*bodies, delay=0):
    return ["bytewise", [body.hex() for body in bodies], delay]


def CONSOLE(chunk, total):
    return ["console", chunk.hex(), total]


def CONSOLE_FOREVER(chunk):
    return ["console_forever", chunk.hex()]


def CONSOLE_FORK(chunk):
    return ["console_fork", chunk.hex()]


def SHOW(*names):
    return ["show", list(names)]


def guest_source(name):
    with open(os.path.join(HERE, "guest", name), "rb") as handle:
        return handle.read()


class Job:
    """One job directory, built only when the case runs it."""

    def __init__(self, ctx, job_id=None, name="job"):
        self.ctx = ctx
        self.path = os.path.join(ctx.dir, name)
        self.job_id = job_id or new_job_id()
        self.target = b"# Sample skill\nSummarize the documents.\nnote " + ctx.canary.encode() + b"\n"
        self.program = self.stamped(guest_source("player.py") + b"\nrun([])\n")
        self.files = {}
        self.nodes = []
        self.raw_manifest = None
        self.skip = set()
        self.manifest = {
            "schema": "fcgate-job/v1", "job_id": self.job_id, "target_sha256": sha(self.target),
            "declared_tools": ["read_doc", "list_docs"],
            "prohibited_tools": ["read_secret", "run_shell", "post_url", "install_package"],
            "authority_tools": ["change_policy"],
            "budgets": {"max_calls": 8, "max_frame_bytes": 65536, "max_total_bytes": MIB,
                        "max_evidence_bytes": MIB, "hello_timeout_sec": 40, "frame_idle_sec": 20,
                        "wall_clock_sec": 300},
            "vm": {"vcpus": 1, "mem_mib": 128},
        }
        self.written_state = None

    def budgets(self, **values):
        self.manifest["budgets"].update(values)
        return self

    def set_target(self, data):
        self.target = data
        self.manifest["target_sha256"] = sha(data)

    def stamped(self, source):
        """Every payload carries the case's canary, so that any copy of it reaching an output is caught."""
        return b"# note " + self.ctx.canary.encode() + b"\n" + source

    def play(self, *steps):
        self.program = self.stamped(guest_source("player.py") + b"\nrun(" + repr(list(steps)).encode("ascii") + b")\n")
        return self

    def use_program(self, source):
        self.program = self.stamped(source)
        return self

    @property
    def target_hash(self):
        return sha(self.target)

    @property
    def frozen(self):
        return sha(canon(self.manifest))

    def manifest_bytes(self):
        if self.raw_manifest is not None:
            return self.raw_manifest
        return json.dumps(self.manifest, indent=2, sort_keys=True).encode("ascii")

    def content_size(self):
        size = len(self.manifest_bytes()) + len(self.target) + len(self.program)
        return size + sum(len(data) for data in self.files.values())

    def write(self):
        make_agent_dir(self.path)
        make_agent_dir(os.path.join(self.path, "target"))
        make_agent_dir(os.path.join(self.path, "payload"))
        if "manifest.json" not in self.skip:
            agent_file(os.path.join(self.path, "manifest.json"), self.manifest_bytes())
        if "target/skill.md" not in self.skip:
            agent_file(os.path.join(self.path, "target", "skill.md"), self.target)
        if "payload/run" not in self.skip:
            agent_file(os.path.join(self.path, "payload", "run"), self.program)
        for relative, data in self.files.items():
            full = os.path.join(self.path.encode(), relative if isinstance(relative, bytes) else relative.encode())
            parent = os.path.dirname(full)
            os.makedirs(parent, exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(data)
        for build in self.nodes:
            build(self.path)
        for folder, subdirs, files in os.walk(self.path.encode()):
            os.lchown(folder, UID, GID)
            for name in subdirs + files:
                os.lchown(os.path.join(folder, name), UID, GID)
        self.written_state = tree_state(self.path)


# ---------------------------------------------------------------------------------------------------
# Expectations
# ---------------------------------------------------------------------------------------------------

class OneOf:
    """The spec leaves this value open among the listed choices; anything else is wrong."""

    def __init__(self, *values):
        self.values = values

    def __repr__(self):
        return "one of %r" % (self.values,)

    def __eq__(self, other):
        return other in self.values


class Check:
    """A value judged by a predicate, used where a timer decides how far a session got."""

    def __init__(self, function, label):
        self.function = function
        self.label = label

    def __repr__(self):
        return self.label

    def __eq__(self, other):
        return bool(self.function(other))


EMPTY_ASSETS = {"firecracker": "", "kernel": "", "rootfs": ""}


class Expect:
    def __init__(self, decision, reason, ses=None, *, vm=True, receipt=True, job_id=None, frozen=None, target=None,
                 tripped=None, counters=None, root=None, assets=None, witnesses=None, min_elapsed=None,
                 max_elapsed=None, vmm=None, residue=False):
        self.decision = decision
        self.reason = reason
        self.ses = ses
        self.vm = vm
        self.receipt = receipt
        self.job_id = job_id
        self.frozen = frozen
        self.target = target
        self.tripped = tripped
        self.counters = counters
        self.root = root
        self.assets = assets
        self.witnesses = witnesses
        self.min_elapsed = min_elapsed
        self.max_elapsed = max_elapsed
        self.vmm = vmm if vmm is not None else ("yes" if vm else "no")
        self.residue = residue

    @property
    def exit_code(self):
        return EXIT_CODES[self.decision]


# ---------------------------------------------------------------------------------------------------
# One case's context
# ---------------------------------------------------------------------------------------------------

class GateRun:
    def __init__(self, proc, job, out, run_root, key, keyfile):
        self.proc = proc
        self.job = job
        self.out = out
        self.run_root = run_root
        self.key = key
        self.keyfile = keyfile
        self.stdout = b""
        self.stderr = b""
        self.receipt = None

    @property
    def rc(self):
        return self.proc.rc

    @property
    def elapsed(self):
        return self.proc.elapsed


class Stop(Exception):
    """Ends a case early once it has already failed."""


class Ctx:
    def __init__(self, index, parent=None, label=""):
        self.index = index
        self.parent = parent
        self.label = label
        self.tag = "c%03d" % index
        self.dir = os.path.join(DISK, self.tag)
        self.shm = os.path.join(SHM, self.tag)
        make_agent_dir(self.dir)
        make_agent_dir(self.shm)
        self.aux = os.path.join(self.dir, "aux")
        make_agent_dir(self.aux)
        self.run_root = os.path.join(self.shm, "r")
        self.out = os.path.join(self.dir, "out")
        self.keyfile = os.path.join(self.dir, "key")
        self.key = new_key()
        agent_file(self.keyfile, self.key, 0o600)
        self.canary = new_canary()
        self.forbidden = [self.canary.encode()]
        self.problems = [] if parent is None else parent.problems
        self.false_allows = [] if parent is None else parent.false_allows
        self.sampler = Sampler()
        self.sub_count = 0 if parent is None else None

    # ----- small helpers
    def fail(self, message):
        self.problems.append(("%s: " % self.label if self.label else "") + message)

    def job(self, **kwargs):
        return Job(self, **kwargs)

    def sub(self, label):
        """A fresh set of paths inside the same case, for cases that make several runs."""
        root = self.parent or self
        root.sub_count += 1
        return Ctx(root.index * 1000 + root.sub_count, parent=root, label=label)

    def forbid(self, *values):
        for value in values:
            self.forbidden.append(value if isinstance(value, bytes) else value.encode())

    def fast(self, extra=0.0):
        """§7: the gate exits within 5 s of the session ending; 10 s allowed, plus start-up, hashing and boot."""
        return State.t_allow + extra + 10.0

    def booted_by(self):
        """Whole seconds after InstanceStart by which a guest can be taken to have booted, scaled to this machine."""
        return max(5, int(State.t_allow / 3.0 + 0.999))

    def timer(self, seconds, extra=0.0):
        """Bounds from process start for a timer that fires `seconds` after InstanceStart."""
        return {"min_elapsed": max(0.0, seconds - 1.0), "max_elapsed": seconds + extra + State.t_allow + 10.0}

    # ----- locks and wrappers
    def wrapper(self, name):
        with open(os.path.join(HERE, "wrappers", name), "rb") as handle:
            text = handle.read()
        text = text.replace(b"@AUX@", self.aux.encode()).replace(b"@REAL@", REAL_VMM.encode())
        path = os.path.join(self.aux, "firecracker")
        agent_file(path, text, 0o755)
        return path

    def write_lock(self, firecracker=None, kernel=None, rootfs=None, name="lock.json"):
        """Writes a lock listing the given paths (real assets by default). Returns (path, asset hashes)."""
        entries = {}
        assets = {}
        for field, override in (("firecracker", firecracker), ("kernel", kernel), ("rootfs", rootfs)):
            path = override or State.asset_paths[field]
            digest = State.assets[field] if override is None else sha_file(path)
            entries[field] = {"path": path, "sha256": digest}
            assets[field] = digest
        lock_path = os.path.join(self.aux, name)
        agent_file(lock_path, json.dumps(entries).encode("ascii"))
        return lock_path, assets

    def logging_lock(self):
        """A lock with correct hashes whose VMM logs every start, which proves that no VMM ran."""
        return self.write_lock(firecracker=self.wrapper("logging.sh"))

    def vmm_log(self):
        data = read_limited(os.path.join(self.aux, "vmm.log"))
        return (data or b"").decode("ascii", "replace").splitlines()

    # ----- running
    def gate_argv(self, job_path, out, keyfile, lock, run_root):
        argv = [GATE, "run", "--job", job_path, "--out", out, "--key-file", keyfile]
        if lock:
            argv += ["--lock", lock]
        if run_root:
            argv += ["--run-root", run_root]
        return argv

    def start(self, job, lock=None, run_root="", out=None, keyfile=None, key=None, umask=0o022):
        """Writes the job and starts the gate. run_root="" means this case's own; None leaves the spec's default."""
        if job is not None and job.written_state is None:
            job.write()
        if run_root == "":
            run_root = self.run_root
        out = out or self.out
        keyfile = keyfile or self.keyfile
        job_path = job.path if job is not None else os.path.join(self.dir, "nojob")
        proc = Proc(self.gate_argv(job_path, out, keyfile, lock, run_root), umask=umask)
        return GateRun(proc, job, out, run_root or DEFAULT_RUN_ROOT, self.key if key is None else key, keyfile)

    def wait(self, runs, hard, tick=None):
        """Waits for gate runs under a hard limit. A run that hits the limit is killed and recorded as failed."""
        deadline = capped_deadline(hard)
        next_sample = 0.0
        while True:
            pump()
            now = time.monotonic()
            if now >= next_sample:
                self.sampler.tick()
                next_sample = now + 0.05
            if tick is not None:
                tick()
            if all(run.proc.status is not None for run in runs):
                break
            if now > deadline:
                for run in runs:
                    if run.proc.status is None:
                        run.proc.timed_out = True
                        try:
                            os.killpg(run.proc.pid, signal.SIGKILL)
                        except OSError:
                            pass
                kill_everything()
                for _ in range(200):
                    pump()
                    if all(run.proc.status is not None for run in runs):
                        break
                    time.sleep(0.01)
                break
            time.sleep(0.01)
        for run in runs:
            run.stdout, run.stderr = run.proc.outputs()

    def gate(self, job, expect, *, lock=None, run_root="", out=None, keyfile=None, key=None, umask=0o022, hard=None,
             tick=None, leaves=()):
        """One complete graded run: start, wait, then check the outcome and everything left behind."""
        before = snapshot()
        app_before = app_snapshot()
        run = self.start(job, lock=lock, run_root=run_root, out=out, keyfile=keyfile, key=key, umask=umask)
        known = None if callable(expect) else expect
        if hard is None:
            if known is not None and known.vm:
                if known.max_elapsed is None:
                    known.max_elapsed = self.fast()
                hard = known.max_elapsed + 5.0
            else:
                hard = 60.0
        self.wait([run], hard, tick)
        self.check(run, expect)
        self.after([run], before, app_before)
        return run

    # ----- checking
    def check(self, run, expect):
        chosen = expect(run) if callable(expect) else expect
        run.expect = chosen
        run.receipt = read_limited(os.path.join(run.out, "receipt.json"))
        self.check_false_allow(run, chosen)
        if run.proc.spawn_error:
            self.fail("gate could not be started (%s)" % run.proc.spawn_error)
            return
        if run.proc.timed_out:
            self.fail("hard time limit exceeded after %.1fs" % run.elapsed)
            return
        self.check_outputs(run, chosen)
        self.check_receipt(run, chosen)
        self.check_timing(run, chosen)
        self.check_vmm(chosen)

    def check_false_allow(self, run, expect):
        if expect.decision == "ALLOW":
            return
        channels = []
        words = run.stdout.split()
        if words and words[0] == b"ALLOW":
            channels.append("stdout")
        if run.rc == 0:
            channels.append("exit code")
        if run.receipt is not None and re.search(rb'"decision"\s*:\s*"ALLOW"', run.receipt):
            channels.append("receipt")
        if channels:
            self.false_allows.append("expected %s %s, answered ALLOW by %s" % (expect.decision, expect.reason,
                                                                              ", ".join(channels)))

    def check_outputs(self, run, expect):
        line = ("%s %s" % (expect.decision, expect.reason)).encode()
        if run.stdout not in (line + b"\n", line):
            self.fail("stdout: expected %r got %r" % (line, run.stdout[:120]))
        if run.rc != expect.exit_code:
            self.fail("exit code: expected %d got %s" % (expect.exit_code, run.rc))
        if b"Traceback (most recent call last)" in run.stderr or b"Traceback (most recent call last)" in run.stdout:
            self.fail("traceback in output")
        self.check_leaks(run, expect)

    def check_leaks(self, run, expect):
        """§1: guest, target and payload bytes reach no output, tool names cross only as hashes, the key never does."""
        streams = [("stdout", run.stdout), ("stderr", run.stderr)]
        if os.path.isdir(run.out):
            for name in os.listdir(run.out):
                data = read_limited(os.path.join(run.out, name)) or b""
                streams.append(("output file " + name, data))
        needles = list(self.forbidden)
        if expect.ses is not None and expect.ses.tool:
            needles.append(expect.ses.tool.encode())
        if run.key:
            needles += [run.key, run.key.hex().encode()]
        for label, data in streams:
            for needle in needles:
                if needle and needle in data:
                    self.fail("forbidden bytes reached %s" % label)
                    return

    def check_receipt(self, run, expect):
        path = os.path.join(run.out, "receipt.json")
        entries = sorted(os.listdir(run.out)) if os.path.isdir(run.out) else []
        if not expect.receipt:
            if entries:
                self.fail("output directory should hold no receipt, found %r" % entries[:5])
            return
        if entries != ["receipt.json"]:
            self.fail("output directory listing: %r" % entries[:8])
        if run.receipt is None:
            self.fail("receipt missing")
            return
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            self.fail("receipt mode %o" % stat.S_IMODE(info.st_mode))
        problems_before = len(self.problems)
        obj = self.parse_receipt(run.receipt)
        if obj is None:
            return
        self.compare_receipt(obj, run, expect)
        if len(self.problems) == problems_before:
            self.check_verify_accepts(run, path)

    def parse_receipt(self, data):
        def pairs(items):
            seen = {}
            for key, value in items:
                if key in seen:
                    raise ValueError("duplicate key")
                seen[key] = value
            return seen
        try:
            obj = json.loads(data.decode("ascii"), object_pairs_hook=pairs)
        except ValueError:
            self.fail("receipt is not ASCII JSON without duplicate keys")
            return None
        if not isinstance(obj, dict) or canon(obj) != data:
            self.fail("receipt bytes are not canonical")
            return None
        if any(byte < 0x20 or byte > 0x7e for byte in data):
            self.fail("receipt has non-printable bytes")
            return None
        if set(obj) != RECEIPT_KEYS:
            self.fail("receipt keys differ: %r" % sorted(set(obj) ^ RECEIPT_KEYS))
            return None
        for field, keys in (("assets", ASSET_KEYS), ("counters", COUNTER_KEYS), ("witnesses", WITNESS_KEYS)):
            if not isinstance(obj[field], dict) or set(obj[field]) != keys:
                self.fail("receipt %s keys differ" % field)
                return None
        return obj

    def compare_receipt(self, obj, run, expect):
        job = run.job
        ses = expect.ses
        unsigned = {key: value for key, value in obj.items() if key != "hmac"}
        digest = hmac.new(run.key, canon(unsigned), hashlib.sha256).hexdigest()
        if obj["hmac"] != digest:
            self.fail("receipt hmac does not verify under the key")
        wanted = {
            "schema": "fcgate-receipt/v1",
            "decision": expect.decision,
            "reason": expect.reason,
            "exit_code": expect.exit_code,
        }
        wanted["job_id"] = expect.job_id if expect.job_id is not None else (job.job_id if job else "")
        wanted["frozen_sha256"] = expect.frozen if expect.frozen is not None else (job.frozen if job else "")
        wanted["target_sha256"] = expect.target if expect.target is not None else (job.target_hash if job else "")
        if expect.tripped is not None:
            wanted["tripped_tool_sha256"] = expect.tripped
        else:
            wanted["tripped_tool_sha256"] = sha(ses.tool.encode()) if ses is not None and ses.tool else ""
        if expect.root is not None:
            wanted["evidence_root"] = expect.root
        else:
            wanted["evidence_root"] = ses.head if ses is not None else ZERO
        for field, value in wanted.items():
            if not value == obj[field]:
                self.fail("receipt %s: expected %r got %r" % (field, value, obj[field]))
        if type(obj["exit_code"]) is not int:
            self.fail("receipt exit_code is not an integer")

        if expect.assets is not None:
            assets = expect.assets
        else:
            assets = dict(State.assets) if expect.vm else EMPTY_ASSETS
        if obj["assets"] != assets:
            self.fail("receipt assets: expected %r got %r" % (assets, obj["assets"]))

        if expect.counters is not None:
            counters = expect.counters
        else:
            counters = ses.counters() if ses is not None else {key: 0 for key in COUNTER_KEYS}
        if not counters == obj["counters"]:
            self.fail("receipt counters: expected %r got %r" % (counters, obj["counters"]))
        for field in COUNTER_KEYS:
            if type(obj["counters"][field]) is not int:
                self.fail("receipt counter %s is not an integer" % field)

        witnesses = {"vmm_started": expect.vm, "guest_hello": bool(ses and ses.hello_ok),
                     "final_seen": bool(ses and ses.final_ok), "vmm_reaped": True, "sockets_removed": True,
                     "workdir_removed": True}
        if expect.witnesses:
            witnesses.update(expect.witnesses)
        for field, value in witnesses.items():
            actual = obj["witnesses"][field]
            if not isinstance(actual, bool) or not value == actual:
                self.fail("witness %s: expected %r got %r" % (field, value, actual))

    def check_verify_accepts(self, run, path):
        """§12: the gate's own verify accepts every real receipt it wrote."""
        code, stdout, stderr = self.verify_call(path, run.keyfile)
        if stdout.strip() != b"VALID" or code != 0:
            self.fail("fcgate verify rejected a correct real receipt: exit %s output %r" % (code, stdout[:60]))
        if b"Traceback (most recent call last)" in stderr:
            self.fail("fcgate verify wrote a traceback")

    def verify_call(self, receipt_path, keyfile, hard=20.0):
        return self.call(["verify", "--receipt", receipt_path, "--key-file", keyfile], hard)

    def call(self, arguments, hard=20.0):
        """Runs the gate with these arguments under a hard limit. Returns (exit code, stdout, stderr)."""
        proc = Proc([GATE] + arguments)
        if proc.spawn_error:
            return None, b"", b""
        deadline = capped_deadline(hard)
        while proc.status is None:
            pump()
            if time.monotonic() > deadline:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.timed_out = True
                for _ in range(200):
                    pump()
                    if proc.status is not None:
                        break
                    time.sleep(0.01)
                break
            time.sleep(0.003)
        stdout, stderr = proc.outputs()
        return ("timeout" if proc.timed_out else proc.rc), stdout, stderr

    def check_timing(self, run, expect):
        if expect.max_elapsed is not None and run.elapsed > expect.max_elapsed:
            self.fail("took %.1fs, limit %.1fs" % (run.elapsed, expect.max_elapsed))
        if expect.min_elapsed is not None and run.elapsed < expect.min_elapsed:
            self.fail("returned after %.1fs, a timer cannot have fired before %.1fs" % (run.elapsed, expect.min_elapsed))

    def check_vmm(self, expect):
        started = [line for line in self.vmm_log() if line.startswith("start")]
        if expect.vmm == "no" and (self.sampler.seen or started):
            self.fail("a VMM was started before the checks of section 4 finished")
        if expect.vmm == "yes" and not (self.sampler.seen or started):
            self.fail("no VMM process was ever seen")

    def after(self, runs, before, app_before):
        """§9: no process and no file from the run remains, other than the receipt."""
        left = settle()
        if left:
            self.fail("process left running after exit: %s" % ", ".join(describe_proc(pid) for pid in left[:4]))
            kill_everything()
        for run in runs:
            allowed = run.expect.residue
            if not allowed and os.path.isdir(run.run_root):
                entries = os.listdir(run.run_root)
                if entries:
                    self.fail("run root not empty: %r" % sorted(entries)[:4])
            if run.job is not None and run.job.written_state is not None:
                if tree_state(run.job.path) != run.job.written_state:
                    self.fail("job directory changed during the run")
        new = {path for path in snapshot() - before
               if not (path == DEFAULT_RUN_ROOT and any(run.run_root == DEFAULT_RUN_ROOT for run in runs))}
        if new:
            self.fail("new files outside the output directory: %r" % sorted(new)[:4])
            for path in new:
                remove_path(path)
        if app_before is not None:
            app_after = app_snapshot()
            if app_after is not None and app_after - app_before:
                self.fail("new files under /app: %r" % sorted(app_after - app_before)[:4])

    def check_dir_mode(self, path, label, wanted=0o700):
        if os.path.isdir(path):
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            if mode != wanted:
                self.fail("%s has mode %o, expected %o" % (label, mode, wanted))
        else:
            self.fail("%s was not created" % label)


def remove_path(path):
    try:
        info = os.lstat(path)
    except OSError:
        return
    try:
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)
    except OSError:
        pass


def clean_case_state(ctx):
    """Forcibly restores the machine so that one failure cannot poison the next case."""
    kill_everything()
    pump()
    for root in (DISK, SHM):
        if os.path.isdir(root):
            for name in os.listdir(root):
                shutil.rmtree(os.path.join(root, name), ignore_errors=True)
    shutil.rmtree(DEFAULT_RUN_ROOT, ignore_errors=True)
    for path in snapshot() - State.base_entries:
        remove_path(path)
    for name in os.listdir(CAPTURE):
        try:
            os.unlink(os.path.join(CAPTURE, name))
        except OSError:
            pass


def prepare_machine():
    """Lays out the scratch directories and records the real asset hashes, independently of the lock."""
    become_subreaper()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for path in (DISK, CAPTURE):
        shutil.rmtree(path, ignore_errors=True)
    os.makedirs(DISK, mode=0o755, exist_ok=True)
    os.chmod(DISK, 0o755)
    os.makedirs(CAPTURE, mode=0o700, exist_ok=True)
    os.chmod(CAPTURE, 0o700)
    os.makedirs(SHM, mode=0o755, exist_ok=True)
    os.chmod(SHM, 0o755)
    with open(REAL_LOCK, "rb") as handle:
        lock = json.load(handle)
    for name, entry in lock.items():
        State.asset_paths[name] = entry["path"]
        State.assets[name] = sha_file(entry["path"])
    try:
        os.chmod("/dev/kvm", 0o666)
    except OSError:
        pass
    State.base_entries = snapshot()
    for pid in all_pids():
        info = proc_status(pid)
        if info is not None and info[0] == UID:
            State.foreign_agent_pids.add(pid)
