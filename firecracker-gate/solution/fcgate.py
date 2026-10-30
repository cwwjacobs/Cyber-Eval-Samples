#!/usr/bin/python3 -I
"""fcgate: run one untrusted program in one disposable Firecracker microVM and sign what it did.

The contract is /app/docs/SPEC.md; section numbers below refer to it.
"""
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

try:
    import ctypes

    LIBC = ctypes.CDLL(None)
except (ImportError, OSError):
    LIBC = None

EXIT_USAGE = 64
USAGE = (
    "usage: fcgate run --job DIR --out DIR --key-file FILE [--lock FILE] [--run-root DIR]\n"
    "       fcgate verify --receipt FILE --key-file FILE\n"
)
DEFAULT_LOCK = "/opt/lab/assets.lock.json"
DEFAULT_RUN_ROOT = "/dev/shm/fcgate"

MAX_INT = 2**53 - 1
ZERO_HEAD = "0" * 64
JOB_BYTES_LIMIT = 16 * 1024 * 1024
MANIFEST_BYTES_LIMIT = 64 * 1024
LOCK_BYTES_LIMIT = 1024 * 1024
RECEIPT_BYTES_LIMIT = 1024 * 1024
KEY_MIN_BYTES, KEY_MAX_BYTES = 32, 4096

READ_SIZE = 64 * 1024
TICK_SEC = 0.1
AFTER_FINAL_SEC = 5.0
API_STEP_SEC = 10.0
MKE2FS_SEC = 600  # mke2fs -d is quadratic in the entries of a directory; a slow job is not a broken one
REAP_SEC = 4.0  # section 7 allows 5 seconds from the end of the session to the exit of fcgate

REASONS = {
    "ALLOW": {"complete"},
    "DENY": {"prohibited_tool", "undeclared_tool", "budget_calls", "budget_bytes", "budget_evidence"},
    "RESCOPE_REQUIRED": {"authority_expansion", "target_mismatch"},
    "EVALUATION_INCOMPLETE": {
        "bad_hello", "bad_nonce", "frame_too_large", "frame_malformed", "seq_gap", "chain_mismatch",
        "counter_mismatch", "frame_after_final", "second_connection", "timeout_hello", "timeout_frame",
        "timeout_wall", "no_final",
    },
    "INFRASTRUCTURE_FAILED": {"key_invalid", "manifest_invalid", "asset_mismatch", "vmm_start_failed"},
}
PRE_BOOT_REASONS = {"key_invalid", "manifest_invalid", "target_mismatch", "asset_mismatch"}
DECISION_OF = {reason: decision for decision, reasons in REASONS.items() for reason in reasons}
REASONS["CLEANUP_UNVERIFIED"] = set(DECISION_OF) - PRE_BOOT_REASONS
EXIT_CODES = {
    "ALLOW": 0, "DENY": 2, "RESCOPE_REQUIRED": 3, "EVALUATION_INCOMPLETE": 4,
    "INFRASTRUCTURE_FAILED": 5, "CLEANUP_UNVERIFIED": 6,
}

NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
JOB_ID_RE = re.compile(r"job-[a-z0-9]{6,32}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PRINTABLE_RE = re.compile(r"[ !#-\[\]-~]*")  # printable ASCII less '"' and '\', which would need escapes

TOOL_LISTS = ("declared_tools", "prohibited_tools", "authority_tools")
MANIFEST_KEYS = {"schema", "job_id", "target_sha256", "budgets", "vm", *TOOL_LISTS}
BUDGET_RANGES = {
    "max_calls": (0, 1000),
    "max_frame_bytes": (64, 1048576),
    "max_total_bytes": (64, 67108864),
    "max_evidence_bytes": (0, 1073741824),
    "hello_timeout_sec": (1, 600),
    "frame_idle_sec": (1, 600),
    "wall_clock_sec": (1, 3600),
}
VM_RANGES = {"vcpus": (1, 4), "mem_mib": (64, 2048)}
ASSET_NAMES = ("firecracker", "kernel", "rootfs")

RECEIPT_SCHEMA = "fcgate-receipt/v1"
RECEIPT_SHAPE = {
    "assets": dict.fromkeys(ASSET_NAMES, str),
    "counters": dict.fromkeys(("bytes_in", "calls_allowed", "evidence_bytes", "evidence_chunks", "frames"), int),
    "decision": str,
    "evidence_root": str,
    "exit_code": int,
    "frozen_sha256": str,
    "hmac": str,
    "job_id": str,
    "reason": str,
    "schema": str,
    "target_sha256": str,
    "tripped_tool_sha256": str,
    "witnesses": dict.fromkeys(
        ("final_seen", "guest_hello", "sockets_removed", "vmm_reaped", "vmm_started", "workdir_removed"), bool
    ),
}

_COUNT = rb"(0|[1-9][0-9]{0,15})"
_HEX64 = rb"([0-9a-f]{64})"
# Guest bytes meet nothing but these. Each pattern admits exactly the canonical form of one message, so
# there is no parser to exhaust and no nesting to recurse into; fullmatch keeps a trailing newline out.
FRAME_FORMS = (
    ("hello", ("job", "nonce", "v"),
     re.compile(rb'\{"job":"([ !#-\[\]-~]{0,128})","nonce":"' + _HEX64 + rb'","t":"hello","v":' + _COUNT + rb"\}")),
    ("propose", ("args_bytes", "args_sha256", "seq", "tool"),
     re.compile(rb'\{"args_bytes":' + _COUNT + rb',"args_sha256":"' + _HEX64 + rb'","seq":' + _COUNT
                + rb',"t":"propose","tool":"([a-z][a-z0-9_]{0,63})"\}')),
    ("evidence", ("bytes", "chunk_sha256", "prev", "seq"),
     re.compile(rb'\{"bytes":' + _COUNT + rb',"chunk_sha256":"' + _HEX64 + rb'","prev":"' + _HEX64 + rb'","seq":'
                + _COUNT + rb',"t":"evidence"\}')),
    ("final", ("calls", "evidence_bytes", "evidence_chunks", "evidence_root", "seq"),
     re.compile(rb'\{"calls":' + _COUNT + rb',"evidence_bytes":' + _COUNT + rb',"evidence_chunks":' + _COUNT
                + rb',"evidence_root":"' + _HEX64 + rb'","seq":' + _COUNT + rb',"status":"complete","t":"final"\}')),
)
COUNT_FIELDS = {"v", "args_bytes", "seq", "bytes", "calls", "evidence_bytes", "evidence_chunks"}

_stop_requested = False


class UsageError(Exception):
    pass


class StartFailed(Exception):
    pass


def write_fd(fd, text):
    try:
        os.write(fd, text.encode())
    except OSError:
        pass


def canonical(value):
    """Section 5, for values the host built or has already parsed. Raises ValueError on anything else."""
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if type(value) is int:
        if not 0 <= value <= MAX_INT:
            raise ValueError("integer out of range")
        return b"%d" % value
    if type(value) is str:
        if not PRINTABLE_RE.fullmatch(value):
            raise ValueError("string out of form")
        return b'"' + value.encode("ascii") + b'"'
    if type(value) is list:
        return b"[" + b",".join(canonical(item) for item in value) + b"]"
    if type(value) is dict:
        return b"{" + b",".join(canonical(key) + b":" + canonical(value[key]) for key in sorted(value)) + b"}"
    raise ValueError("no canonical form")


def strict_json(raw):
    """Parses UTF-8 JSON, refusing duplicate keys, floats and the NaN family. Raises on anything else."""

    def unique_keys(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate key")
        return result

    def refuse(_token):
        raise ValueError("not an integer")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys, parse_float=refuse, parse_constant=refuse)


def read_bounded(path, limit, follow=False):
    """The bytes of a regular file of at most limit bytes, or None. Never blocks on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW))
    except (OSError, ValueError):
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks) if remaining > 0 else None
    except OSError:
        return None
    finally:
        os.close(fd)


def hash_regular(path, follow=False):
    """SHA-256 of a regular file. Raises OSError for anything else, without blocking on a FIFO."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                return digest.hexdigest()
            digest.update(block)
    finally:
        os.close(fd)


def load_key(path):
    """Section 10. The key bytes, or None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError):
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or not KEY_MIN_BYTES <= info.st_size <= KEY_MAX_BYTES):
            return None
        key = os.read(fd, KEY_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if not KEY_MIN_BYTES <= len(key) <= KEY_MAX_BYTES or key.count(key[0]) == len(key):
        return None
    return key


def scan_job(job):
    """Section 3, the tree. Returns (content bytes, entry count). Raises OSError or ValueError if unusable."""
    if not stat.S_ISDIR(os.lstat(job).st_mode):
        raise ValueError("not a directory")
    total = entries = 0
    pending = [job]
    while pending:
        with os.scandir(pending.pop()) as listing:
            for entry in listing:
                entries += 1
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(entry.path)
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    os.close(os.open(entry.path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW))
                else:
                    raise ValueError("neither a file nor a directory")
    if total > JOB_BYTES_LIMIT:
        raise ValueError("job too large")
    for required in (("manifest.json",), ("target", "skill.md"), ("payload", "run")):
        if not stat.S_ISREG(os.lstat(os.path.join(job, *required)).st_mode):
            raise ValueError("required file missing")
    return total, entries


def valid_manifest(manifest):
    """Section 3, the fields."""
    if type(manifest) is not dict or set(manifest) != MANIFEST_KEYS:
        return False
    if manifest["schema"] != "fcgate-job/v1":
        return False
    for field, pattern in (("job_id", JOB_ID_RE), ("target_sha256", HEX64_RE)):
        if type(manifest[field]) is not str or not pattern.fullmatch(manifest[field]):
            return False
    seen = set()
    for field in TOOL_LISTS:
        if type(manifest[field]) is not list:
            return False
        for tool in manifest[field]:
            if type(tool) is not str or not NAME_RE.fullmatch(tool) or tool in seen:
                return False
            seen.add(tool)
    for field, ranges in (("budgets", BUDGET_RANGES), ("vm", VM_RANGES)):
        section = manifest[field]
        if type(section) is not dict or set(section) != set(ranges):
            return False
        for name, (low, high) in ranges.items():
            if type(section[name]) is not int or not low <= section[name] <= high:
                return False
    return True


def target_digest(job):
    """Hash of target/skill.md when it is a real file reached through real directories, else ''."""
    try:
        for path in (job, os.path.join(job, "target")):
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                return ""
        return hash_regular(os.path.join(job, "target", "skill.md"))
    except (OSError, ValueError):
        return ""


def check_lock(path):
    """Section 4 step 4. Returns (paths, hashes) if every listed file hashes to its listed value, else None."""
    raw = read_bounded(path, LOCK_BYTES_LIMIT, follow=True)
    if raw is None:
        return None
    lock = strict_json(raw)
    if type(lock) is not dict or set(lock) != set(ASSET_NAMES):
        return None
    paths, hashes = {}, {}
    for name in ASSET_NAMES:
        entry = lock[name]
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            return None
        if type(entry["path"]) is not str or not entry["path"]:
            return None
        if type(entry["sha256"]) is not str or not HEX64_RE.fullmatch(entry["sha256"]):
            return None
        if hash_regular(entry["path"], follow=True) != entry["sha256"]:
            return None
        paths[name], hashes[name] = entry["path"], entry["sha256"]
    return paths, hashes


def copy_file(source, dest, limit):
    """Copies one regular file, at most limit bytes of it. Returns the bytes copied."""
    src = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(src)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        dst = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        copied = 0
        try:
            while True:
                block = os.read(src, 1 << 20)
                if not block:
                    break
                copied += len(block)
                if copied > limit:
                    raise OSError("job grew while being copied")
                while block:
                    block = block[os.write(dst, block):]
            os.fchmod(dst, stat.S_IMODE(info.st_mode) & 0o777)
        finally:
            os.close(dst)
        return copied
    finally:
        os.close(src)


def copy_job_tree(source, dest, limit):
    """Copies a validated tree. Returns the budget left."""
    pending = [(source, dest)]
    while pending:
        src_dir, dst_dir = pending.pop()
        os.mkdir(dst_dir, 0o700)
        with os.scandir(src_dir) as listing:
            for entry in listing:
                target = os.path.join(dst_dir, entry.name)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((entry.path, target))
                else:
                    limit -= copy_file(entry.path, target, limit)
    return limit


def write_new_file(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        while data:
            data = data[os.write(fd, data):]
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def remove_tree(root):
    """Removes what it can, including directories someone left without permissions. Confirms nothing."""
    directories = []
    pending = [root]
    while pending:
        path = pending.pop()
        directories.append(path)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        try:
            with os.scandir(path) as listing:
                for entry in listing:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                        else:
                            os.unlink(entry.path)
                    except OSError:
                        pass
        except OSError:
            pass
    for path in reversed(directories):
        try:
            os.rmdir(path)
        except OSError:
            pass


def is_gone(path):
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return True
    except OSError:
        pass
    return False


def prctl(option, value):
    if LIBC is not None:
        try:
            zero = ctypes.c_ulong(0)
            LIBC.prctl(ctypes.c_int(option), ctypes.c_ulong(value), zero, zero, zero)
        except (OSError, AttributeError, ctypes.ArgumentError):
            pass


def die_with_parent():
    prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG


class Vmm:
    """The Firecracker process and its process group. The serial console goes to /dev/null, the one sink
    that can neither block the guest nor carry a byte anywhere."""

    def __init__(self, firecracker, api_sock):
        self.process = subprocess.Popen(
            [firecracker, "--api-sock", api_sock],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            process_group=0, preexec_fn=die_with_parent,
        )
        self.pid = self.process.pid
        self._exited = False

    def exited(self):
        # WNOWAIT leaves the zombie in place, so the process group id cannot be reused before teardown.
        if not self._exited:
            try:
                self._exited = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            except ChildProcessError:
                self._exited = True
        return self._exited

    def kill(self):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except OSError:
            pass

    def reap(self):
        """Kills the group and waits, bounded. True once the VMM is reaped and the group is empty."""
        self.kill()
        reaped = False
        deadline = time.monotonic() + REAP_SEC
        while True:
            try:
                while True:
                    pid, _status = os.waitpid(-self.pid, os.WNOHANG)
                    if pid == 0:
                        break
                    reaped = reaped or pid == self.pid
            except ChildProcessError:
                pass
            try:
                os.killpg(self.pid, 0)
            except ProcessLookupError:
                return reaped
            except OSError:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)


def api_put(api_sock, path, body, vmm):
    """One call on the Firecracker API socket. Raises StartFailed unless it is answered with a 2xx."""
    payload = json.dumps(body).encode()
    request = (
        f"PUT {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n"
    ).encode() + payload
    deadline = time.monotonic() + API_STEP_SEC

    def give_up():
        return vmm.exited() or _stop_requested or time.monotonic() >= deadline

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(TICK_SEC)
        while True:
            try:
                sock.connect(api_sock)
                break
            except (FileNotFoundError, ConnectionRefusedError, BlockingIOError, TimeoutError):
                if give_up():
                    raise StartFailed(path) from None
                time.sleep(0.005)
        sent = 0
        while sent < len(request):
            try:
                sent += sock.send(request[sent:])
            except TimeoutError:
                if give_up():
                    raise StartFailed(path) from None
        response = b""
        while b"\r\n\r\n" not in response:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                if give_up():
                    raise StartFailed(path) from None
                continue
            if not chunk or len(response) > READ_SIZE:
                raise StartFailed(path)
            response += chunk
    if not re.match(rb"HTTP/1\.[01] 2[0-9][0-9]\b", response):
        raise StartFailed(path)


def parse_frame(body):
    """(kind, fields) when body is byte for byte the canonical JSON of one guest message, else None."""
    for kind, names, pattern in FRAME_FORMS:
        match = pattern.fullmatch(body)
        if match is None:
            continue
        fields = dict(zip(names, match.groups()))
        for name in COUNT_FIELDS.intersection(fields):
            fields[name] = int(fields[name])
            if fields[name] > MAX_INT:
                return None
        return kind, fields
    return None


def reply(body):
    return len(body).to_bytes(4, "big") + body


class Session:
    """Section 7. A single poll loop: bounded reads, queued writes, three timers off one monotonic clock."""

    def __init__(self, manifest, nonce, frozen, listener, vmm, started_at):
        budgets = manifest["budgets"]
        self.listener = listener
        self.vmm = vmm
        self.started_at = started_at
        self.job = manifest["job_id"].encode()
        self.nonce = nonce.encode()
        self.ready = reply(canonical({"frozen": frozen, "t": "ready"}))
        self.prohibited = {tool.encode() for tool in manifest["prohibited_tools"]}
        self.authority = {tool.encode() for tool in manifest["authority_tools"]}
        self.declared = {tool.encode() for tool in manifest["declared_tools"]}
        self.max_calls = budgets["max_calls"]
        self.max_frame = budgets["max_frame_bytes"]
        self.max_total = budgets["max_total_bytes"]
        self.max_evidence = budgets["max_evidence_bytes"]
        self.hello_sec = budgets["hello_timeout_sec"]
        self.idle_sec = budgets["frame_idle_sec"]
        self.wall_sec = budgets["wall_clock_sec"]
        self.conn = None
        self.conn_fd = -1
        self.accepted = False
        self.writable = True
        self.inbuf = bytearray()
        self.outbuf = bytearray()
        self.reason = None
        self.bytes_in = 0
        self.frames = 0
        self.calls = 0
        self.evidence_bytes = 0
        self.evidence_chunks = 0
        self.head = ZERO_HEAD.encode()
        self.seq = 0
        self.first_frame_seen = False
        self.guest_hello = False
        self.final_seen = False
        self.final_at = 0.0
        self.frame_ended = 0.0
        self.tripped_tool = ""

    def run(self):
        """Returns the reason the session ended with. On anything but complete, the VMM is killed here."""
        poller = select.poll()
        listener_fd = self.listener.fileno()
        poller.register(listener_fd, select.POLLIN)
        while self.reason is None:
            # Sampled before the poll, so everything the VMM wrote before it exited is visible to the poll.
            exited = self.vmm.exited()
            deadline, expiry = self.next_deadline()
            if self.conn is not None:
                poller.register(self.conn_fd, select.POLLIN | (select.POLLOUT if self.outbuf else 0))
            wait = 0 if exited else min(TICK_SEC, max(0.0, deadline - time.monotonic()))
            events = dict(poller.poll(math.ceil(wait * 1000)))
            window_over = False
            if time.monotonic() >= deadline:
                if expiry is not None:
                    self.reason = expiry
                    break
                window_over = True
            if self.conn is not None and self.conn_fd in events:
                self.service_connection(events[self.conn_fd], poller)
            if self.reason is None and listener_fd in events:
                self.service_listener()
            if self.reason is None and (exited or window_over) and not events:
                self.reason = "complete" if self.final_seen else "no_final"
            if self.reason is None and _stop_requested:
                self.reason = "complete" if self.final_seen else "no_final"
        if self.reason != "complete":
            self.outbuf += reply(b'{"t":"trip"}')
            self.flush()
            self.vmm.kill()
        return self.reason

    def next_deadline(self):
        """(when, reason), earliest first. After final only the wait for the VMM's exit is left."""
        if self.final_seen:
            return self.final_at + AFTER_FINAL_SEC, None
        if self.guest_hello:
            running = (self.frame_ended + self.idle_sec, "timeout_frame")
        else:
            running = (self.started_at + self.hello_sec, "timeout_hello")
        return min(running, (self.started_at + self.wall_sec, "timeout_wall"))

    def service_listener(self):
        # The listener stays open and polled to the end: a second connection counts whenever it comes.
        if self.accepted:
            self.reason = "second_connection"
            return
        try:
            self.conn, _peer = self.listener.accept()
        except (BlockingIOError, InterruptedError, ConnectionAbortedError):
            return
        self.conn.setblocking(False)
        self.conn_fd = self.conn.fileno()
        self.accepted = True

    def service_connection(self, flags, poller):
        if flags & select.POLLOUT:
            self.flush()
        if not flags & ~select.POLLOUT:
            return
        try:
            data = self.conn.recv(READ_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            poller.unregister(self.conn_fd)
            self.conn.close()
            self.conn = None
            if not self.final_seen:
                self.reason = "no_final"
            return
        if self.final_seen:
            self.reason = "frame_after_final"
            return
        self.inbuf += data
        self.consume()
        if self.reason is None and self.final_seen and self.inbuf:
            self.reason = "frame_after_final"
        self.flush()

    def consume(self):
        """Applies section 7 to the complete frames in the buffer, stopping at the one that decides.
        Whatever is queued behind it is neither processed nor counted."""
        buffer = self.inbuf
        pos = 0
        size = len(buffer)
        while self.reason is None and not self.final_seen and size - pos >= 4:
            length = int.from_bytes(buffer[pos:pos + 4], "big")
            if length == 0:
                self.reason = "frame_malformed"
            elif length > self.max_frame:
                self.reason = "frame_too_large"
            elif self.bytes_in + 4 + length > self.max_total:
                self.reason = "budget_bytes"
            elif size - pos - 4 < length:
                break
            else:
                body = bytes(buffer[pos + 4:pos + 4 + length])
                pos += 4 + length
                self.apply_frame(body, 4 + length)
        del buffer[:pos]

    def apply_frame(self, body, frame_bytes):
        parsed = parse_frame(body)
        if parsed is None:
            self.reason = "frame_malformed"
            return
        kind, fields = parsed
        self.frames += 1
        self.bytes_in += frame_bytes
        self.frame_ended = time.monotonic()
        self.reason = self.apply_message(kind, fields)
        if self.reason is not None and kind == "propose":
            self.tripped_tool = hashlib.sha256(fields["tool"]).hexdigest()

    def apply_message(self, kind, fields):
        """Steps 4 to 6 for a frame that passed step 3. Returns the reason if this frame ends the session."""
        if not self.first_frame_seen:
            self.first_frame_seen = True
            if kind != "hello" or fields["job"] != self.job or fields["v"] != 1:
                return "bad_hello"
            if fields["nonce"] != self.nonce:
                return "bad_nonce"
            self.guest_hello = True
            self.outbuf += self.ready
            return None
        if kind == "hello":
            return "frame_malformed"
        if fields["seq"] != self.seq + 1:
            return "seq_gap"
        self.seq = fields["seq"]
        if kind == "propose":
            return self.apply_propose(fields)
        if kind == "evidence":
            return self.apply_evidence(fields)
        return self.apply_final(fields)

    def apply_propose(self, fields):
        tool = fields["tool"]
        if tool in self.prohibited:
            return "prohibited_tool"
        if tool in self.authority:
            return "authority_expansion"
        if tool not in self.declared:
            return "undeclared_tool"
        if self.calls >= self.max_calls:
            return "budget_calls"
        self.calls += 1
        self.outbuf += reply(b'{"decision":"allow","seq":%d,"t":"decision"}' % fields["seq"])
        return None

    def apply_evidence(self, fields):
        if fields["prev"] != self.head:
            return "chain_mismatch"
        if self.evidence_bytes + fields["bytes"] > self.max_evidence:
            return "budget_evidence"
        self.head = hashlib.sha256(fields["prev"] + fields["chunk_sha256"]).hexdigest().encode()
        self.evidence_chunks += 1
        self.evidence_bytes += fields["bytes"]
        self.outbuf += reply(b'{"seq":%d,"t":"ack"}' % fields["seq"])
        return None

    def apply_final(self, fields):
        if fields["evidence_root"] != self.head:
            return "chain_mismatch"
        if (fields["calls"] != self.calls or fields["evidence_chunks"] != self.evidence_chunks
                or fields["evidence_bytes"] != self.evidence_bytes):
            return "counter_mismatch"
        self.final_seen = True
        self.final_at = time.monotonic()
        self.outbuf += reply(b'{"t":"bye"}')
        return None

    def flush(self):
        """Writes what the socket takes now. A guest that stops reading only makes the queue wait; the queue
        is bounded by one short reply per frame the byte budget admitted."""
        if not self.outbuf or self.conn is None or not self.writable:
            return
        try:
            sent = self.conn.send(self.outbuf)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.writable = False
            self.outbuf.clear()
            return
        del self.outbuf[:sent]


class Gate:
    """One run: the checks before boot, the boot, the session, teardown and the receipt."""

    def __init__(self, options, key):
        self.key = key
        self.job_dir = options["--job"].rstrip("/") or options["--job"]
        self.out_dir = options["--out"]
        self.lock_path = options.get("--lock", DEFAULT_LOCK)
        self.run_root = options.get("--run-root", DEFAULT_RUN_ROOT)
        if self.run_root:
            self.run_root = os.path.abspath(self.run_root)
        self.job_id = ""
        self.frozen = ""
        self.target = ""
        self.assets = dict.fromkeys(ASSET_NAMES, "")
        self.workdir = None
        self.listener = None
        self.vmm = None
        self.vmm_started = False
        self.session = None
        # Whatever raises during a stage is that stage's failure, so a defect here still ends in a receipt.
        self.on_crash = "manifest_invalid"

    def evaluate(self):
        """Sections 4, 6 and 7. Returns the reason the run ended with."""
        self.target = target_digest(self.job_dir)
        manifest, manifest_raw, job_size = self.check_job()
        if manifest is None:
            return "manifest_invalid"
        self.job_id = manifest["job_id"]
        self.frozen = hashlib.sha256(canonical(manifest)).hexdigest()
        if self.target != manifest["target_sha256"]:
            return "target_mismatch"
        self.on_crash = "asset_mismatch"
        locked = check_lock(self.lock_path)
        if locked is None:
            return "asset_mismatch"
        paths, self.assets = locked
        self.on_crash = "vmm_start_failed"
        nonce = secrets.token_hex(32)
        started_at = self.boot(manifest, manifest_raw, job_size, nonce, paths)
        self.on_crash = "no_final"
        self.session = Session(manifest, nonce, self.frozen, self.listener, self.vmm, started_at)
        return self.session.run()

    def check_job(self):
        try:
            job_size = scan_job(self.job_dir)
            raw = read_bounded(os.path.join(self.job_dir, "manifest.json"), MANIFEST_BYTES_LIMIT)
            if raw is None:
                return None, None, None
            manifest = strict_json(raw)
            if not valid_manifest(manifest):
                return None, None, None
            return manifest, raw, job_size
        except (OSError, ValueError, RecursionError, MemoryError):
            return None, None, None

    def boot(self, manifest, manifest_raw, job_size, nonce, paths):
        """Section 6. Returns the monotonic time InstanceStart was accepted; raises on any failure."""
        os.makedirs(self.run_root, 0o700, exist_ok=True)
        self.workdir = os.path.join(self.run_root, f"{self.job_id}-{secrets.token_hex(6)}")
        os.mkdir(self.workdir, 0o700)
        image = self.build_job_image(manifest, manifest_raw, job_size, nonce)
        api_sock = os.path.join(self.workdir, "api.sock")
        vsock = os.path.join(self.workdir, "v.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(vsock + "_5005")
        self.listener.listen(16)
        self.listener.setblocking(False)
        self.vmm = Vmm(paths["firecracker"], api_sock)
        calls = (
            ("/boot-source", {"kernel_image_path": paths["kernel"],
                              "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init"}),
            ("/drives/rootfs", {"drive_id": "rootfs", "path_on_host": paths["rootfs"],
                                "is_root_device": True, "is_read_only": True}),
            ("/drives/job", {"drive_id": "job", "path_on_host": image,
                             "is_root_device": False, "is_read_only": True}),
            ("/machine-config", {"vcpu_count": manifest["vm"]["vcpus"], "mem_size_mib": manifest["vm"]["mem_mib"]}),
            ("/vsock", {"guest_cid": 3, "uds_path": vsock}),
            ("/actions", {"action_type": "InstanceStart"}),
        )
        for path, body in calls:
            api_put(api_sock, path, body, self.vmm)
        self.vmm_started = True
        return time.monotonic()

    def build_job_image(self, manifest, manifest_raw, job_size, nonce):
        tree = os.path.join(self.workdir, "tree")
        image = os.path.join(self.workdir, "job.ext4")
        os.mkdir(tree, 0o700)
        write_new_file(os.path.join(tree, "manifest.json"), manifest_raw)
        write_new_file(os.path.join(tree, "session.json"), canonical({"job": self.job_id, "nonce": nonce}))
        left = JOB_BYTES_LIMIT - len(manifest_raw)
        left = copy_job_tree(os.path.join(self.job_dir, "target"), os.path.join(tree, "target"), left)
        copy_job_tree(os.path.join(self.job_dir, "payload"), os.path.join(tree, "payload"), left)
        if hash_regular(os.path.join(tree, "target", "skill.md")) != self.target:
            raise StartFailed("target changed after it was hashed")
        # Sparse, so only what mke2fs writes takes space. The default inode ratio is 4 KiB below 512 MiB
        # and 16 KiB above, which the per-entry term covers either way.
        total, entries = job_size
        size = 64 * 1024 * 1024 + 4 * total + 16 * 1024 * entries
        fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(fd, size)
        finally:
            os.close(fd)
        search = os.pathsep.join((os.environ.get("PATH", ""), "/usr/sbin", "/sbin", "/usr/bin", "/bin"))
        mke2fs = shutil.which("mke2fs", path=search)
        if mke2fs is None:
            raise StartFailed("mke2fs")
        subprocess.run(
            [mke2fs, "-q", "-t", "ext4", "-d", tree, image],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=MKE2FS_SEC, check=True,
        )
        remove_tree(tree)
        return image

    def teardown(self):
        """Section 9. Returns the three witnesses, read from outside rather than from what teardown did."""
        for sock in (self.session.conn if self.session else None, self.listener):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        vmm_reaped = True
        if self.vmm is not None:
            try:
                vmm_reaped = self.vmm.reap()
            except Exception:
                vmm_reaped = False
        sockets_removed = workdir_removed = True
        if self.workdir is not None:
            for _attempt in range(3):
                try:
                    remove_tree(self.workdir)
                except Exception:
                    pass
                workdir_removed = is_gone(self.workdir)
                if workdir_removed:
                    break
                time.sleep(0.02)
            sockets = ("api.sock", "v.sock", "v.sock_5005")
            sockets_removed = all(is_gone(os.path.join(self.workdir, name)) for name in sockets)
        return {"vmm_reaped": vmm_reaped, "sockets_removed": sockets_removed, "workdir_removed": workdir_removed}

    def receipt(self, decision, reason, cleanup):
        session = self.session
        body = {
            "assets": self.assets,
            "counters": {
                "bytes_in": session.bytes_in if session else 0,
                "calls_allowed": session.calls if session else 0,
                "evidence_bytes": session.evidence_bytes if session else 0,
                "evidence_chunks": session.evidence_chunks if session else 0,
                "frames": session.frames if session else 0,
            },
            "decision": decision,
            "evidence_root": session.head.decode() if session else ZERO_HEAD,
            "exit_code": EXIT_CODES[decision],
            "frozen_sha256": self.frozen,
            "job_id": self.job_id,
            "reason": reason,
            "schema": RECEIPT_SCHEMA,
            "target_sha256": self.target,
            "tripped_tool_sha256": session.tripped_tool if session else "",
            "witnesses": {
                "final_seen": session.final_seen if session else False,
                "guest_hello": session.guest_hello if session else False,
                "vmm_started": self.vmm_started,
                **cleanup,
            },
        }
        body["hmac"] = hmac.new(self.key, canonical(body), hashlib.sha256).hexdigest()
        return canonical(body)

    def write_receipt(self, data):
        temp = os.path.join(self.out_dir, f".receipt-{secrets.token_hex(8)}.tmp")
        path = os.path.join(self.out_dir, "receipt.json")
        try:
            write_new_file(temp, data, 0o600)
            fd = os.open(temp, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.replace(temp, path)
            except IsADirectoryError:
                os.rmdir(path)
                os.replace(temp, path)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise

    def finish(self, reason):
        cleanup = self.teardown()
        decision = DECISION_OF[reason]
        if not all(cleanup.values()):
            decision = "CLEANUP_UNVERIFIED"
        try:
            self.write_receipt(self.receipt(decision, reason, cleanup))
        except Exception:
            # Without a receipt there is no evidence, and missing evidence is never ALLOW.
            if decision == "ALLOW":
                decision = "CLEANUP_UNVERIFIED"
        write_fd(1, f"{decision} {reason}\n")
        return EXIT_CODES[decision]


def usable_output_dir(path):
    """True if a receipt can be written there. Probing up front means a bad --out never costs a VM."""
    probe = os.path.join(path, f".probe-{secrets.token_hex(8)}")
    try:
        if not os.path.isdir(path):
            return False
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.unlink(probe)
        return True
    except (OSError, ValueError):
        return False


def request_stop(_signum, _frame):
    global _stop_requested
    _stop_requested = True


def command_run(options):
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, request_stop)
    # A parent's SIG_IGN would survive exec and make the kernel reap the VMM behind our back.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    os.umask(0o077)
    prctl(36, 1)  # PR_SET_CHILD_SUBREAPER: anything orphaned in the VMM's group is ours to reap
    for path in (options["--out"], options.get("--run-root", DEFAULT_RUN_ROOT)):
        try:
            os.makedirs(path, 0o700, exist_ok=True)
        except (OSError, ValueError):
            pass
    key = load_key(options["--key-file"])
    if key is None:
        write_fd(1, "INFRASTRUCTURE_FAILED key_invalid\n")
        return EXIT_CODES["INFRASTRUCTURE_FAILED"]
    if not usable_output_dir(options["--out"]):
        write_fd(2, "fcgate: --out is not a writable directory\n")
        return EXIT_USAGE
    gate = Gate(options, key)
    try:
        reason = gate.evaluate()
    except BaseException:
        reason = (gate.session.reason if gate.session else None) or gate.on_crash
    return gate.finish(reason)


def has_shape(value, shape):
    if isinstance(shape, dict):
        return (type(value) is dict and value.keys() == shape.keys()
                and all(has_shape(value[key], shape[key]) for key in shape))
    return type(value) is shape


def receipt_is_valid(options):
    """Section 12."""
    key = load_key(options["--key-file"])
    if key is None:
        return False
    raw = read_bounded(options["--receipt"], RECEIPT_BYTES_LIMIT)
    if raw is None:
        return False
    receipt = strict_json(raw)
    if not has_shape(receipt, RECEIPT_SHAPE) or canonical(receipt) != raw:
        return False
    signature = receipt.pop("hmac")
    expected = hmac.new(key, canonical(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    if receipt["schema"] != RECEIPT_SCHEMA or not HEX64_RE.fullmatch(receipt["evidence_root"]):
        return False
    for value in (receipt["frozen_sha256"], receipt["target_sha256"], receipt["tripped_tool_sha256"],
                  *receipt["assets"].values()):
        if value and not HEX64_RE.fullmatch(value):
            return False
    if receipt["job_id"] and not JOB_ID_RE.fullmatch(receipt["job_id"]):
        return False
    decision = receipt["decision"]
    if decision not in EXIT_CODES or receipt["exit_code"] != EXIT_CODES[decision]:
        return False
    if receipt["reason"] not in REASONS[decision]:
        return False
    witnesses = receipt["witnesses"]
    clean = witnesses["vmm_reaped"] and witnesses["sockets_removed"] and witnesses["workdir_removed"]
    if decision == "CLEANUP_UNVERIFIED":
        return not clean
    if not clean:
        return False
    return decision != "ALLOW" or all(witnesses.values())


def command_verify(options):
    try:
        valid = receipt_is_valid(options)
    except BaseException:
        valid = False
    write_fd(1, "VALID\n" if valid else "INVALID\n")
    return 0 if valid else 1


COMMANDS = {
    "run": (command_run, {"--job", "--out", "--key-file"}, {"--lock", "--run-root"}),
    "verify": (command_verify, {"--receipt", "--key-file"}, set()),
}


def parse_args(argv):
    """Not argparse: its exit code 2 means DENY here, and --help would exit 0, which means ALLOW."""
    if not argv or argv[0] not in COMMANDS:
        raise UsageError
    _handler, required, optional = COMMANDS[argv[0]]
    options = {}
    words = iter(argv[1:])
    for word in words:
        flag, has_value, value = word.partition("=")
        if not has_value:
            value = next(words, None)
            if value is None or value.startswith("--"):
                raise UsageError
        if flag not in required and flag not in optional or flag in options:
            raise UsageError
        options[flag] = value
    if not required <= options.keys():
        raise UsageError
    return argv[0], options


def main(argv):
    try:
        command, options = parse_args(argv)
    except UsageError:
        write_fd(2, USAGE)
        return EXIT_USAGE
    return COMMANDS[command][0](options)


if __name__ == "__main__":
    # os._exit: the receipt is on disk and the line is out, and no finalizer gets to say anything else.
    code = 6
    try:
        code = main(sys.argv[1:])
    except BaseException:
        write_fd(1, "CLEANUP_UNVERIFIED no_final\n")
    os._exit(code)
