"""Every graded case. Each one's docstring is one line citing the part of SPEC.md that determines it."""
import hashlib
import hmac
import json
import os
import struct

from harness import (BYTEWISE, CLOSE, CONNECT, CONNECT2, CONSOLE, CONSOLE_FORK, CONSOLE_FOREVER, CRASH, DEFAULT_RUN_ROOT,
                     EXIT_CODES, FLOOD, FOREVER, MIB, PERSIST, PRE_BOOT_REASONS, RAW, RECV, REPLY, SEND, SHOW, SLEEP, TABLE,
                     ZERO, Check, Expect, OneOf, Ses, State, Stop, agent_chown, agent_file, canon, evidence_body, final_body,
                     framed, guest_source, hello_body, if_counted_as_call, make_agent_dir, new_job_id, new_key, propose_body,
                     sha, snapshot, app_snapshot)

CASES = []


class CaseDef:
    def __init__(self, name, group, doc, function):
        self.name, self.group, self.doc, self.function = name, group, doc, function


def add_case(name, group, doc, function):
    CASES.append(CaseDef(name, group, " ".join(doc.split()), function))


def case(group):
    def register(function):
        add_case(function.__name__, group, function.__doc__, function)
        return function
    return register


def allow(c, ses, extra=0.0, **kwargs):
    return Expect("ALLOW", "complete", ses, max_elapsed=c.fast(extra), **kwargs)


def ended(c, decision, reason, ses, extra=0.0, **kwargs):
    kwargs.setdefault("max_elapsed", c.fast(extra))
    return Expect(decision, reason, ses, **kwargs)


def incomplete(c, reason, ses, **kwargs):
    return ended(c, "EVALUATION_INCOMPLETE", reason, ses, **kwargs)


def hello_ready(ses):
    return [CONNECT, SEND(ses.hello()), RECV()]


def step(body):
    return [SEND(body), RECV()]


def late_clean_session(job):
    """What a guest does after outlasting a timer: a clean session that a host without the timer would ALLOW."""
    late = Ses(job)
    return [CONNECT, SEND(late.hello()), RECV(), SEND(late.final()), RECV()]


def clean_steps(ses):
    """Two calls and two evidence chunks, each waiting for the host's reply."""
    return [*hello_ready(ses), *step(ses.propose("list_docs")), *step(ses.propose("read_doc", b"overview")),
            *step(ses.evidence(b"first chunk")), *step(ses.evidence(b"second chunk")), SEND(ses.final()), RECV()]


# ===================================================================================================
# Usage
# ===================================================================================================

def expect_usage(c, arguments, label):
    code, stdout, stderr = c.call(arguments)
    if code != 64 or stdout != b"":
        c.fail("%s: expected exit 64 and empty stdout, got exit %s stdout %r" % (label, code, stdout[:80]))
        raise Stop()
    if b"Traceback (most recent call last)" in stderr:
        c.fail("%s: traceback" % label)
        raise Stop()


@case("usage")
def usage_no_arguments(c):
    """§2: no arguments, or an unknown subcommand, is a usage error: exit 64 and nothing on stdout."""
    expect_usage(c, [], "no arguments")
    expect_usage(c, ["launch"], "unknown subcommand")


@case("usage")
def usage_run_errors(c):
    """§2: run missing a required option, or with an unknown one, is a usage error and starts nothing."""
    job = c.job()
    job.write()
    lock, _ = c.logging_lock()
    base = {"--job": job.path, "--out": c.out, "--key-file": c.keyfile}
    for missing in base:
        arguments = ["run", "--lock", lock, "--run-root", c.run_root]
        for flag, value in base.items():
            if flag != missing:
                arguments += [flag, value]
        expect_usage(c, arguments, "run without " + missing)
    arguments = ["run", "--lock", lock, "--run-root", c.run_root, "--no-such-option", "x"]
    for flag, value in base.items():
        arguments += [flag, value]
    expect_usage(c, arguments, "run with an unknown option")
    if c.vmm_log():
        c.fail("a VMM was started for a usage error")
    if os.path.exists(os.path.join(c.out, "receipt.json")):
        c.fail("a receipt was written for a usage error")


@case("usage")
def usage_verify_errors(c):
    """§2: verify missing a required option, or with an unknown one, is a usage error."""
    receipt = os.path.join(c.aux, "receipt.json")
    agent_file(receipt, b"{}", 0o600)
    expect_usage(c, ["verify"], "verify with no options")
    expect_usage(c, ["verify", "--receipt", receipt], "verify without --key-file")
    expect_usage(c, ["verify", "--key-file", c.keyfile], "verify without --receipt")
    expect_usage(c, ["verify", "--receipt", receipt, "--key-file", c.keyfile, "--no-such-option", "x"],
                 "verify with an unknown option")


# ===================================================================================================
# Before boot: keys
# ===================================================================================================

def key_invalid(c, keyfile, key=None, job=None, lock=None):
    """Runs a well-formed job with a key that must be refused: exit 5, no receipt, no VMM."""
    job = job or c.job()
    lock = lock or c.logging_lock()[0]
    c.gate(job, Expect("INFRASTRUCTURE_FAILED", "key_invalid", vm=False, receipt=False), lock=lock, keyfile=keyfile,
           key=key or b"")


@case("key")
def key_symlink(c):
    """§10: a key file that is a symlink to a good key is key_invalid, with no receipt."""
    real = os.path.join(c.aux, "realkey")
    key = new_key()
    agent_file(real, key, 0o600)
    link = os.path.join(c.aux, "keylink")
    os.symlink(real, link)
    agent_chown(link)
    key_invalid(c, link, key)


@case("key")
def key_mode_0644(c):
    """§10: a key with group and other read bits is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    key = new_key()
    agent_file(path, key, 0o644)
    key_invalid(c, path, key)


@case("key")
def key_any_group_or_other_bit(c):
    """§10: any single group or other permission bit makes the key invalid."""
    for mode in (0o640, 0o620, 0o610, 0o604, 0o602, 0o601):
        s = c.sub("mode %o" % mode)
        path = os.path.join(s.aux, "k")
        key = new_key()
        agent_file(path, key, mode)
        key_invalid(s, path, key)
        if c.problems:
            return


@case("key")
def key_too_short(c):
    """§10: a key of 31 bytes is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    key = new_key(31)
    agent_file(path, key, 0o600)
    key_invalid(c, path, key)


@case("key")
def key_empty(c):
    """§10: an empty key file is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    agent_file(path, b"", 0o600)
    key_invalid(c, path)


@case("key")
def key_too_long(c):
    """§10: a key of 4097 bytes is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    key = new_key(4097)
    agent_file(path, key, 0o600)
    key_invalid(c, path, key)


@case("key")
def key_one_repeated_byte(c):
    """§10: a key made of one repeated byte is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    agent_file(path, b"\x41" * 64, 0o600)
    key_invalid(c, path, b"\x41" * 64)


@case("key")
def key_missing(c):
    """§10: a key file that does not exist is key_invalid, with no receipt."""
    key_invalid(c, os.path.join(c.aux, "no-such-key"))


@case("key")
def key_is_directory(c):
    """§10: a directory is not a regular file: key_invalid, with no receipt."""
    path = os.path.join(c.aux, "keydir")
    make_agent_dir(path, 0o700)
    key_invalid(c, path)


@case("key")
def key_is_fifo(c):
    """§10: a FIFO is not a regular file: key_invalid at once, with no receipt, and no hang."""
    path = os.path.join(c.aux, "keypipe")
    os.mkfifo(path, 0o600)
    agent_chown(path)
    key_invalid(c, path)


@case("key")
def key_not_owned(c):
    """§10: a key owned by another user is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    with open(path, "wb") as handle:
        handle.write(new_key())
    os.chmod(path, 0o600)
    key_invalid(c, path)


@case("key")
def key_before_manifest(c):
    """§4: the key is checked first: a bad key with a bad manifest is key_invalid, with no receipt."""
    path = os.path.join(c.aux, "k")
    agent_file(path, new_key(8), 0o600)
    job = c.job()
    job.manifest["extra"] = 1
    key_invalid(c, path, job=job)


def valid_key_run(c, key, mode=0o600):
    """A valid key on a job that stops before boot, so the receipt's HMAC proves how the key was used."""
    path = os.path.join(c.aux, "k")
    agent_file(path, key, mode)
    job = c.job()
    job.manifest["extra"] = 1
    lock, _ = c.logging_lock()
    c.gate(job, manifest_invalid_expect(job), lock=lock, keyfile=path, key=key)


@case("key")
def key_exactly_32_bytes(c):
    """§10/§11: a 32-byte key is valid and the receipt is signed with it."""
    valid_key_run(c, new_key(32))


@case("key")
def key_exactly_4096_bytes(c):
    """§10/§11: a 4096-byte key is valid and the receipt is signed with it."""
    valid_key_run(c, new_key(4096))


@case("key")
def key_mode_0400(c):
    """§10: owner-read-only has no group or other bits, so the key is valid."""
    valid_key_run(c, new_key(32), 0o400)


@case("key")
def key_bytes_used_raw(c):
    """§10/§11: the key is the file's bytes: 32 identical bytes plus a newline is valid and signs as it stands."""
    valid_key_run(c, b"A" * 32 + b"\n")


# ===================================================================================================
# Before boot: job directory and manifest
# ===================================================================================================

def manifest_invalid_expect(job):
    """§11: job_id and frozen are empty for an invalid manifest. Step 2 stops before step 3, so §11 leaves open
    whether the target was hashed; a wrong hash is still wrong."""
    return Expect("INFRASTRUCTURE_FAILED", "manifest_invalid", vm=False, job_id="", frozen="",
                  target=OneOf("", job.target_hash))


def job_dir_invalid_expect(job, target=None):
    """A sound manifest in a job directory that §3 rejects. §11 ties the empty strings to 'the manifest is invalid',
    so whether a parsed job_id is recorded here is left open."""
    return Expect("INFRASTRUCTURE_FAILED", "manifest_invalid", vm=False, job_id=OneOf("", job.job_id),
                  frozen=OneOf("", job.frozen), target=target if target is not None else OneOf("", job.target_hash))


def run_preboot(c, job, expect, **kwargs):
    lock, _ = c.logging_lock()
    return c.gate(job, expect, lock=lock, **kwargs)


def bad_manifests(c, variants):
    """Each variant must be manifest_invalid. The first failure ends the case."""
    for label, mutate in variants:
        s = c.sub(label)
        job = s.job()
        mutate(job.manifest)
        run_preboot(s, job, manifest_invalid_expect(job))
        if c.problems:
            return


def setter(path, value):
    def apply(manifest):
        node = manifest
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return apply


def deleter(path):
    def apply(manifest):
        node = manifest
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return apply


@case("manifest")
def manifest_unknown_key(c):
    """§3: an unknown key at any level (top, budgets, vm) is manifest_invalid."""
    bad_manifests(c, [("top", setter(["zzz"], 1)), ("budgets", setter(["budgets", "zzz"], 1)),
                      ("vm", setter(["vm", "zzz"], 1))])


@case("manifest")
def manifest_missing_key(c):
    """§3: a missing key at any level is manifest_invalid."""
    top = ["schema", "job_id", "target_sha256", "declared_tools", "prohibited_tools", "authority_tools", "budgets", "vm"]
    budgets = ["max_calls", "max_frame_bytes", "max_total_bytes", "max_evidence_bytes", "hello_timeout_sec",
               "frame_idle_sec", "wall_clock_sec"]
    variants = [(name, deleter([name])) for name in top]
    variants += [(name, deleter(["budgets", name])) for name in budgets]
    variants += [(name, deleter(["vm", name])) for name in ("vcpus", "mem_mib")]
    bad_manifests(c, variants)


@case("manifest")
def manifest_duplicate_key(c):
    """§3: a duplicate key at any level is manifest_invalid."""
    for label, old, new in (("top", b'"schema"', b'"schema": "fcgate-job/v1",\n  "schema"'),
                            ("budgets", b'"max_calls"', b'"max_calls": 8,\n    "max_calls"'),
                            ("vm", b'"mem_mib"', b'"mem_mib": 128,\n    "mem_mib"')):
        s = c.sub(label)
        job = s.job()
        job.raw_manifest = job.manifest_bytes().replace(old, new, 1)
        run_preboot(s, job, manifest_invalid_expect(job))
        if c.problems:
            return


@case("manifest")
def manifest_schema_wrong(c):
    """§3: schema must be exactly fcgate-job/v1."""
    bad_manifests(c, [("v2", setter(["schema"], "fcgate-job/v2")), ("empty", setter(["schema"], ""))])


@case("manifest")
def manifest_job_id_format(c):
    """§3: job_id must match ^job-[a-z0-9]{6,32}$."""
    bad_manifests(c, [("uppercase", setter(["job_id"], "job-ABC123")), ("five", setter(["job_id"], "job-abc12")),
                      ("thirty-three", setter(["job_id"], "job-" + "a" * 33)), ("prefix", setter(["job_id"], "jobabc123")),
                      ("newline", setter(["job_id"], "job-abc123\n"))])


@case("manifest")
def manifest_job_id_path_traversal(c):
    """§3: a job_id with path traversal is manifest_invalid and creates nothing outside the output directory."""
    job = c.job()
    escape = "fcv" + new_job_id(8)[4:]
    job.manifest["job_id"] = "../../../../tmp/" + escape
    before_parent = set(os.listdir(c.shm))
    run_preboot(c, job, manifest_invalid_expect(job))
    if os.path.lexists("/tmp/" + escape):
        c.fail("the traversal job_id created a path in /tmp")
    extra = set(os.listdir(c.shm)) - before_parent - {"r"}
    if extra:
        c.fail("files next to the run root: %r" % sorted(extra)[:3])


@case("manifest")
def manifest_target_hash_format(c):
    """§3: target_sha256 must be 64 lowercase hex characters."""
    good = "ab" * 32
    bad_manifests(c, [("uppercase", setter(["target_sha256"], good.upper())), ("short", setter(["target_sha256"], good[:-1])),
                      ("non-hex", setter(["target_sha256"], "g" * 64))])


@case("manifest")
def manifest_tool_name_format(c):
    """§3: every tool name must match ^[a-z][a-z0-9_]{0,63}$."""
    bad_manifests(c, [("uppercase", setter(["declared_tools"], ["Read_doc"])),
                      ("leading digit", setter(["declared_tools"], ["1read"])),
                      ("sixty-five", setter(["prohibited_tools"], ["a" * 65])),
                      ("empty", setter(["authority_tools"], [""])),
                      ("hyphen", setter(["declared_tools"], ["read-doc"]))])


@case("manifest")
def manifest_tool_lists(c):
    """§3: no duplicates inside a list, no name in two lists, and each list is an array of strings."""
    bad_manifests(c, [("duplicate", setter(["declared_tools"], ["read_doc", "read_doc"])),
                      ("two lists", setter(["authority_tools"], ["read_doc"])),
                      ("not a string", setter(["declared_tools"], [1])),
                      ("not an array", setter(["prohibited_tools"], "read_secret"))])


@case("manifest")
def manifest_wrong_types(c):
    """§3: budgets and vm values are integers, true and false are not, and wrong types are invalid at every level."""
    bad_manifests(c, [("boolean budget", setter(["budgets", "max_calls"], True)),
                      ("false budget", setter(["budgets", "max_evidence_bytes"], False)),
                      ("float budget", setter(["budgets", "frame_idle_sec"], 10.0)),
                      ("string budget", setter(["budgets", "wall_clock_sec"], "60")),
                      ("null budget", setter(["budgets", "max_total_bytes"], None)),
                      ("boolean vcpus", setter(["vm", "vcpus"], True)),
                      ("float memory", setter(["vm", "mem_mib"], 128.0)),
                      ("budgets not object", setter(["budgets"], [])),
                      ("vm not object", setter(["vm"], 1)),
                      ("job_id not string", setter(["job_id"], 7))])


@case("manifest")
def manifest_budget_ranges(c):
    """§3: each budget just outside its stated range is manifest_invalid."""
    limits = {"max_calls": (0, 1000), "max_frame_bytes": (64, 1048576), "max_total_bytes": (64, 67108864),
              "max_evidence_bytes": (0, 1073741824), "hello_timeout_sec": (1, 600), "frame_idle_sec": (1, 600),
              "wall_clock_sec": (1, 3600)}
    variants = []
    for name, (low, high) in limits.items():
        variants.append(("%s low" % name, setter(["budgets", name], low - 1)))
        variants.append(("%s high" % name, setter(["budgets", name], high + 1)))
    bad_manifests(c, variants)


@case("manifest")
def manifest_vm_ranges(c):
    """§3: vcpus outside 1 to 4 or mem_mib outside 64 to 2048 is manifest_invalid."""
    bad_manifests(c, [("vcpus 0", setter(["vm", "vcpus"], 0)), ("vcpus 5", setter(["vm", "vcpus"], 5)),
                      ("mem 63", setter(["vm", "mem_mib"], 63)), ("mem 2049", setter(["vm", "mem_mib"], 2049))])


def raw_manifest_invalid(c, data):
    job = c.job()
    job.raw_manifest = data
    run_preboot(c, job, manifest_invalid_expect(job))


@case("manifest")
def manifest_oversize(c):
    """§3: a manifest of 64 KiB + 1 byte is manifest_invalid even though its JSON is sound."""
    job = c.job()
    body = job.manifest_bytes()
    job.raw_manifest = body + b" " * (64 * 1024 + 1 - len(body))
    run_preboot(c, job, manifest_invalid_expect(job))


@case("manifest")
def manifest_not_json(c):
    """§3: bytes that are not JSON, or not a JSON object, are manifest_invalid."""
    for label, data in (("garbage", b"\x00\x01garbage"), ("array", b"[1,2,3]"), ("string", b'"manifest"'), ("empty", b""),
                        ("invalid utf-8", b'{"schema":"\xff\xfe"}'), ("truncated", b'{"schema":"fcgate-job/v1",')):
        s = c.sub(label)
        raw_manifest_invalid(s, data)
        if c.problems:
            return


@case("manifest")
def manifest_deep_nesting(c):
    """§1/§3: deep nesting within the 64 KiB limit is manifest_invalid, with no traceback."""
    raw_manifest_invalid(c, b"[" * 30000 + b"]" * 30000)


@case("manifest")
def manifest_number_traps(c):
    """§3: NaN, Infinity, a 5000-digit integer and a huge exponent in a budget are manifest_invalid, with no traceback."""
    for label, text in (("nan", b"NaN"), ("infinity", b"Infinity"), ("digits", b"9" * 5000), ("exponent", b"1e999")):
        s = c.sub(label)
        job = s.job()
        job.raw_manifest = job.manifest_bytes().replace(b'"max_calls": 8', b'"max_calls": ' + text, 1)
        run_preboot(s, job, manifest_invalid_expect(job))
        if c.problems:
            return


def symlinked(relative, target):
    def build(path):
        full = os.path.join(path, relative)
        if os.path.lexists(full):
            os.unlink(full)
        os.symlink(target, full)
    return build


@case("job")
def job_symlink_inside(c):
    """§3: a symlink inside the job directory is manifest_invalid and no VMM runs."""
    job = c.job()
    job.nodes.append(symlinked("payload/link", "/etc/hostname"))
    run_preboot(c, job, job_dir_invalid_expect(job))


@case("job")
def job_symlink_to_directory(c):
    """§3: a symlink to a directory inside the job directory is manifest_invalid and no VMM runs."""
    job = c.job()
    job.nodes.append(symlinked("payload/link", "/etc"))
    run_preboot(c, job, job_dir_invalid_expect(job))


@case("job")
def job_symlink_as_named_file(c):
    """§3: manifest.json, target/skill.md or payload/run being a symlink is manifest_invalid."""
    for label, relative in (("manifest", "manifest.json"), ("target", "target/skill.md"), ("run", "payload/run")):
        s = c.sub(label)
        job = s.job()
        real = os.path.join(s.aux, "realfile")
        data = {"manifest.json": job.manifest_bytes(), "target/skill.md": job.target, "payload/run": job.program}[relative]
        agent_file(real, data)
        job.nodes.append(symlinked(relative, real))
        run_preboot(s, job, job_dir_invalid_expect(job))
        if c.problems:
            return


@case("job")
def job_fifo_inside(c):
    """§3: a FIFO in the job directory is manifest_invalid at once, without blocking on it."""
    job = c.job()
    job.nodes.append(lambda path: os.mkfifo(os.path.join(path, "payload", "pipe")))
    run_preboot(c, job, job_dir_invalid_expect(job))


@case("job")
def job_contents_over_limit(c):
    """§3: file contents above 16 MiB are manifest_invalid and no VMM runs."""
    job = c.job()
    job.files["payload/pad.bin"] = b"\0" * (16 * MIB + 1024)
    run_preboot(c, job, job_dir_invalid_expect(job))


@case("job")
def job_missing_target(c):
    """§3: a missing target/skill.md is manifest_invalid, and no target hash could be computed."""
    job = c.job()
    job.skip.add("target/skill.md")
    run_preboot(c, job, job_dir_invalid_expect(job, target=""))


@case("job")
def job_missing_payload_run(c):
    """§3: a missing payload/run is manifest_invalid."""
    job = c.job()
    job.skip.add("payload/run")
    run_preboot(c, job, job_dir_invalid_expect(job))


@case("job")
def job_missing_manifest(c):
    """§3: a missing manifest.json is manifest_invalid, with empty job_id and frozen_sha256."""
    job = c.job()
    job.skip.add("manifest.json")
    run_preboot(c, job, manifest_invalid_expect(job))


@case("job")
def job_manifest_not_regular(c):
    """§3: manifest.json must be a regular file; a directory of that name is manifest_invalid."""
    job = c.job()
    job.skip.add("manifest.json")
    job.nodes.append(lambda path: os.mkdir(os.path.join(path, "manifest.json")))
    run_preboot(c, job, manifest_invalid_expect(job))


@case("job")
def job_directory_missing(c):
    """§3/§4: a job path that does not exist is manifest_invalid and still gets a signed receipt."""
    lock, _ = c.logging_lock()
    c.gate(None, Expect("INFRASTRUCTURE_FAILED", "manifest_invalid", vm=False, job_id="", frozen="", target=""), lock=lock)


@case("job")
def order_manifest_before_target(c):
    """§4: step 2 comes before step 3: a bad manifest with a wrong target hash is manifest_invalid."""
    job = c.job()
    job.manifest["target_sha256"] = sha(b"something else")
    job.manifest["vm"]["vcpus"] = 9
    run_preboot(c, job, manifest_invalid_expect(job))


# ===================================================================================================
# Before boot: target and lock
# ===================================================================================================

@case("lock")
def target_hash_mismatch(c):
    """§4 step 3: a wrong target hash is RESCOPE_REQUIRED target_mismatch; the receipt holds the computed hash."""
    job = c.job()
    job.manifest["target_sha256"] = sha(b"something else")
    run_preboot(c, job, Expect("RESCOPE_REQUIRED", "target_mismatch", vm=False))


@case("lock")
def order_target_before_lock(c):
    """§4: step 3 comes before step 4: a wrong target with a broken lock is target_mismatch, with empty assets."""
    job = c.job()
    job.manifest["target_sha256"] = sha(b"something else")
    c.gate(job, Expect("RESCOPE_REQUIRED", "target_mismatch", vm=False), lock=os.path.join(c.aux, "no-such-lock.json"))


def asset_mismatch(c, lock):
    job = c.job()
    job.play(*clean_steps(Ses(job)))
    c.gate(job, Expect("INFRASTRUCTURE_FAILED", "asset_mismatch", vm=False), lock=lock)


def lock_with(c, change):
    """A lock whose VMM logs starts, altered by `change`, so any boot attempt is visible."""
    path, _ = c.logging_lock()
    with open(path) as handle:
        entries = json.load(handle)
    change(entries)
    agent_file(path, json.dumps(entries).encode("ascii"))
    return path


@case("lock")
def lock_wrong_rootfs_hash(c):
    """§4 step 4: a lock with a wrong rootfs hash is asset_mismatch and no VMM runs."""
    asset_mismatch(c, lock_with(c, lambda entries: entries["rootfs"].update(sha256="ab" * 32)))


@case("lock")
def lock_wrong_kernel_hash(c):
    """§4 step 4: a lock with a wrong kernel hash is asset_mismatch and no VMM runs."""
    asset_mismatch(c, lock_with(c, lambda entries: entries["kernel"].update(sha256="ab" * 32)))


@case("lock")
def lock_wrong_firecracker_hash(c):
    """§4 step 4: a lock with a wrong firecracker hash is asset_mismatch and no VMM runs."""
    asset_mismatch(c, lock_with(c, lambda entries: entries["firecracker"].update(sha256="ab" * 32)))


@case("lock")
def lock_missing(c):
    """§4 step 4: a lock file that does not exist is asset_mismatch and no VMM runs."""
    asset_mismatch(c, os.path.join(c.aux, "no-such-lock.json"))


@case("lock")
def lock_garbage(c):
    """§4 step 4: a lock that is not JSON is asset_mismatch and no VMM runs."""
    path = os.path.join(c.aux, "garbage.json")
    agent_file(path, b"\x00\xffnot json")
    asset_mismatch(c, path)


@case("lock")
def lock_entry_missing(c):
    """§4 step 4: a lock without its kernel entry is malformed: asset_mismatch and no VMM runs."""
    asset_mismatch(c, lock_with(c, lambda entries: entries.pop("kernel")))


@case("lock")
def lock_listed_file_missing(c):
    """§4 step 4: a listed file that does not exist is asset_mismatch and no VMM runs."""
    missing = os.path.join(c.aux, "no-such-kernel")
    asset_mismatch(c, lock_with(c, lambda entries: entries["kernel"].update(path=missing)))


# ===================================================================================================
# Receipts: fcgate verify on files built here, signed here
# ===================================================================================================

def base_receipt(decision="ALLOW", reason="complete", exit_code=0, **fields):
    receipt = {
        "assets": {"firecracker": sha(b"f"), "kernel": sha(b"k"), "rootfs": sha(b"r")},
        "counters": {"bytes_in": 400, "calls_allowed": 1, "evidence_bytes": 10, "evidence_chunks": 1, "frames": 4},
        "decision": decision, "evidence_root": sha(b"e"), "exit_code": exit_code, "frozen_sha256": sha(b"m"),
        "job_id": "job-abc123", "reason": reason, "schema": "fcgate-receipt/v1", "target_sha256": sha(b"t"),
        "tripped_tool_sha256": "",
        "witnesses": {"final_seen": True, "guest_hello": True, "sockets_removed": True, "vmm_reaped": True,
                      "vmm_started": True, "workdir_removed": True},
    }
    receipt.update(fields)
    return receipt


def sign(key, receipt):
    unsigned = {name: value for name, value in receipt.items() if name != "hmac"}
    signed = dict(unsigned)
    signed["hmac"] = hmac.new(key, canon(unsigned), hashlib.sha256).hexdigest()
    return signed


def signed_bytes(key, receipt):
    return canon(sign(key, receipt))


def row_receipt(decision, reason):
    """A receipt that satisfies §12 for this row of the §2 table, with every field as a real run of that row would have it."""
    before_boot = reason in PRE_BOOT_REASONS or reason == "vmm_start_failed"
    no_hello = before_boot or reason in ("bad_hello", "bad_nonce", "timeout_hello")
    seen_final = reason in ("complete", "frame_after_final")
    witnesses = {"final_seen": seen_final, "guest_hello": not no_hello, "sockets_removed": True, "vmm_reaped": True,
                 "vmm_started": not before_boot, "workdir_removed": True}
    receipt = base_receipt(decision, reason, EXIT_CODES[decision], witnesses=witnesses)
    if before_boot or no_hello:
        receipt["counters"] = {"bytes_in": 0, "calls_allowed": 0, "evidence_bytes": 0, "evidence_chunks": 0, "frames": 0}
        receipt["evidence_root"] = ZERO
    if reason in ("prohibited_tool", "undeclared_tool", "authority_expansion", "budget_calls"):
        receipt["tripped_tool_sha256"] = sha(b"read_secret")
    if reason in ("manifest_invalid", "target_mismatch", "asset_mismatch"):
        receipt["assets"] = {"firecracker": "", "kernel": "", "rootfs": ""}
    if reason == "manifest_invalid":
        receipt.update(job_id="", frozen_sha256="", target_sha256="")
    return receipt


def check_verify(c, label, data, valid, keyfile=None, key=None):
    """Writes the receipt bytes, runs fcgate verify, and requires the exact answer."""
    path = os.path.join(c.aux, "receipt.json")
    if os.path.lexists(path):
        os.unlink(path)
    agent_file(path, data, 0o600)
    check_verify_path(c, label, path, valid, keyfile, key)


def check_verify_path(c, label, path, valid, keyfile=None, key=None):
    code, stdout, stderr = c.verify_call(path, keyfile or c.keyfile)
    wanted_code, wanted = (0, b"VALID") if valid else (1, b"INVALID")
    if code != wanted_code or stdout not in (wanted + b"\n", wanted):
        c.fail("%s: expected %s exit %d, got %r exit %s" % (label, wanted.decode(), wanted_code, stdout[:60], code))
        raise Stop()
    if b"Traceback (most recent call last)" in stderr:
        c.fail("%s: traceback" % label)
        raise Stop()
    key = key if key is not None else c.key
    for needle in (key, key.hex().encode()):
        if needle and (needle in stdout or needle in stderr):
            c.fail("%s: key material in output" % label)
            raise Stop()


@case("receipt")
def verify_accepts_every_row(c):
    """§12: a correctly signed receipt for every row of the §2 table is VALID, with VALID on stdout and exit 0."""
    for decision, (_, reasons) in TABLE.items():
        for reason in reasons:
            if reason == "key_invalid":
                continue  # nothing can sign this one, so no gate ever meets it
            check_verify(c, "%s %s" % (decision, reason), signed_bytes(c.key, row_receipt(decision, reason)), True)


@case("receipt")
def verify_accepts_cleanup_rows(c):
    """§2/§12: CLEANUP_UNVERIFIED with any session reason and one cleanup witness false is VALID."""
    reasons = [reason for _, row in TABLE.values() for reason in row
               if reason not in PRE_BOOT_REASONS and reason != "vmm_start_failed"]
    names = ("vmm_reaped", "sockets_removed", "workdir_removed")
    for index, reason in enumerate(reasons):
        receipt = row_receipt("CLEANUP_UNVERIFIED", reason)
        receipt["witnesses"][names[index % 3]] = False
        check_verify(c, "CLEANUP_UNVERIFIED " + reason, signed_bytes(c.key, receipt), True)


@case("receipt")
def verify_wrong_key(c):
    """§12: a receipt signed under another key is INVALID with exit 1."""
    other = new_key()
    check_verify(c, "wrong key", signed_bytes(other, base_receipt()), False)


def tamper_list(receipt):
    """Every leaf field, altered once, keeping its type and format."""
    def other_hex(value):
        return ("0" if value[0] != "0" else "1") + value[1:]
    changes = []
    for name in ("firecracker", "kernel", "rootfs"):
        changes.append(("assets." + name, lambda r, n=name: r["assets"].update({n: other_hex(r["assets"][n])})))
    for name in ("bytes_in", "calls_allowed", "evidence_bytes", "evidence_chunks", "frames"):
        changes.append(("counters." + name, lambda r, n=name: r["counters"].update({n: r["counters"][n] + 1})))
    for name in ("final_seen", "guest_hello", "sockets_removed", "vmm_reaped", "vmm_started", "workdir_removed"):
        changes.append(("witnesses." + name, lambda r, n=name: r["witnesses"].update({n: not r["witnesses"][n]})))
    for name in ("evidence_root", "frozen_sha256", "target_sha256", "hmac"):
        changes.append((name, lambda r, n=name: r.update({n: other_hex(r[n])})))
    changes.append(("decision", lambda r: r.update(decision="DENY" if r["decision"] != "DENY" else "ALLOW")))
    changes.append(("exit_code", lambda r: r.update(exit_code=(r["exit_code"] + 2) % 7)))
    changes.append(("job_id", lambda r: r.update(job_id=r["job_id"] + "x")))
    changes.append(("reason", lambda r: r.update(reason="no_final" if r["reason"] != "no_final" else "complete")))
    changes.append(("schema", lambda r: r.update(schema="fcgate-receipt/v2")))
    changes.append(("tripped_tool_sha256", lambda r: r.update(tripped_tool_sha256=sha(b"read_secret"))))
    return changes


@case("receipt")
def verify_each_single_field_tamper(c):
    """§12: changing any single field of a signed receipt, without signing again, is INVALID."""
    good = sign(c.key, base_receipt())
    for label, change in tamper_list(good):
        altered = json.loads(canon(good))
        change(altered)
        check_verify(c, "tamper " + label, canon(altered), False)


@case("receipt")
def verify_trailing_newline(c):
    """§11/§12: a correct receipt plus a trailing newline is not canonical, so INVALID."""
    check_verify(c, "trailing newline", signed_bytes(c.key, base_receipt()) + b"\n", False)


@case("receipt")
def verify_noncanonical_formatting(c):
    """§5/§12: the same object formatted any other way is INVALID although the signature matches the content."""
    good = sign(c.key, base_receipt())
    data = canon(good)
    variants = [("indented", json.dumps(good, indent=1, sort_keys=True).encode()),
                ("spaces", json.dumps(good, sort_keys=True).encode()),
                ("unsorted", json.dumps(good, sort_keys=False, separators=(",", ":")).encode()),
                ("leading space", b" " + data),
                ("trailing space", data + b" "),
                ("duplicate key", data.replace(b'"reason":', b'"reason":"complete","reason":', 1)),
                ("float", data.replace(b'"exit_code":0', b'"exit_code":0.0', 1)),
                ("leading zero", data.replace(b'"frames":4', b'"frames":04', 1)),
                ("escape", data.replace(b'"job_id":"job-', b'"job_id":"job\\u002d', 1))]
    for label, variant in variants:
        check_verify(c, label, variant, False)


@case("receipt")
def verify_integer_limits(c):
    """§5/§12: an integer above 2^53 - 1, or a negative one, is not canonical JSON even when correctly signed."""
    for label, value in (("above the limit", 2 ** 53), ("negative", -1)):
        receipt = base_receipt()
        receipt["counters"]["bytes_in"] = value
        check_verify(c, label, signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_nonprintable_string(c):
    """§5/§12: a string with a byte outside printable ASCII or any escape sequence is not canonical, even when signed."""
    for label, text in (("raw DEL byte", b"\x7f"), ("escaped DEL", b"\\u007f"), ("escaped quote", b'\\"')):
        unsigned = canon(base_receipt(job_id="job-abc@@@")).replace(b"@@@", text)
        digest = hmac.new(c.key, unsigned, hashlib.sha256).hexdigest()
        data = unsigned.replace(b'"job_id"', ('"hmac":"%s","job_id"' % digest).encode(), 1)
        check_verify(c, label, data, False)


@case("receipt")
def verify_wrong_keys_or_types(c):
    """§12: exactly the keys and types of §11: extra keys, missing keys and wrong types are INVALID when signed."""
    def variant(change):
        receipt = base_receipt()
        change(receipt)
        return signed_bytes(c.key, receipt)
    cases = [("extra top", lambda r: r.update(extra="x")), ("extra asset", lambda r: r["assets"].update(extra="x")),
             ("extra counter", lambda r: r["counters"].update(extra=1)), ("extra witness", lambda r: r["witnesses"].update(extra=True)),
             ("missing top", lambda r: r.pop("schema")), ("missing asset", lambda r: r["assets"].pop("kernel")),
             ("missing counter", lambda r: r["counters"].pop("frames")), ("missing witness", lambda r: r["witnesses"].pop("final_seen")),
             ("counter string", lambda r: r["counters"].update(frames="4")), ("counter boolean", lambda r: r["counters"].update(frames=True)),
             ("witness integer", lambda r: r["witnesses"].update(final_seen=1)), ("exit_code boolean", lambda r: r.update(exit_code=False)),
             ("exit_code string", lambda r: r.update(exit_code="0")), ("job_id integer", lambda r: r.update(job_id=7)),
             ("assets array", lambda r: r.update(assets=[])), ("witnesses string", lambda r: r.update(witnesses="true"))]
    for label, change in cases:
        check_verify(c, label, variant(change), False)


@case("receipt")
def verify_garbage(c):
    """§12: garbage, any JSON that is not the receipt object, and a whitespace-only file are INVALID, with no traceback."""
    for label, data in (("random bytes", os.urandom(512)), ("text", b"not a receipt"), ("array", b"[]"), ("empty object", b"{}"),
                        ("string", b'"x"'), ("null", b"null"), ("whitespace", b"   \n"), ("deep", b"[" * 100000),
                        ("invalid utf-8", b'{"a":"\xff\xfe"}'), ("huge integer", b'{"a":' + b"9" * 5000 + b"}")):
        check_verify(c, label, data, False)


@case("receipt")
def verify_empty_file(c):
    """§12: an empty file is INVALID with exit 1."""
    check_verify(c, "empty", b"", False)


@case("receipt")
def verify_over_one_mib(c):
    """§12: a correctly signed receipt above 1 MiB is INVALID, and so is plain padding above 1 MiB."""
    check_verify(c, "signed", signed_bytes(c.key, base_receipt(job_id="job-" + "a" * (MIB + 16))), False)
    check_verify(c, "padding", b" " * (MIB + 16), False)


@case("receipt")
def verify_missing_file(c):
    """§12: a receipt path that does not exist is INVALID with exit 1."""
    check_verify_path(c, "missing", os.path.join(c.aux, "no-such-receipt.json"), False)


@case("receipt")
def verify_not_a_regular_file(c):
    """§12: a directory, a FIFO or a device as the receipt is INVALID at once, with no hang."""
    pipe = os.path.join(c.aux, "pipe.json")
    os.mkfifo(pipe, 0o600)
    agent_chown(pipe)
    check_verify_path(c, "fifo", pipe, False)
    check_verify_path(c, "directory", c.aux, False)
    check_verify_path(c, "device", "/dev/zero", False)


@case("receipt")
def verify_uppercase_hmac(c):
    """§5/§11/§12: the correct hmac in uppercase is not lowercase hex, so INVALID."""
    good = sign(c.key, base_receipt())
    good["hmac"] = good["hmac"].upper()
    check_verify(c, "uppercase", canon(good), False)


@case("receipt")
def verify_allow_with_false_witness(c):
    """§12: a correctly signed ALLOW with any one of its six witnesses false is INVALID."""
    for name in ("final_seen", "guest_hello", "sockets_removed", "vmm_reaped", "vmm_started", "workdir_removed"):
        receipt = base_receipt()
        receipt["witnesses"][name] = False
        check_verify(c, name, signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_decision_and_exit_disagree(c):
    """§12: a correctly signed receipt whose decision and exit_code disagree is INVALID."""
    for decision, reason, code in (("ALLOW", "complete", 2), ("DENY", "prohibited_tool", 0), ("DENY", "prohibited_tool", 3),
                                   ("RESCOPE_REQUIRED", "authority_expansion", 4), ("EVALUATION_INCOMPLETE", "no_final", 5),
                                   ("INFRASTRUCTURE_FAILED", "asset_mismatch", 6), ("EVALUATION_INCOMPLETE", "no_final", 0),
                                   ("ALLOW", "complete", 64)):
        receipt = row_receipt(decision, reason)
        receipt["exit_code"] = code
        check_verify(c, "%s exit %d" % (decision, code), signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_decision_and_reason_disagree(c):
    """§12: a correctly signed receipt whose decision and reason disagree with the table is INVALID."""
    for decision, reason in (("ALLOW", "prohibited_tool"), ("DENY", "complete"), ("DENY", "no_final"),
                             ("RESCOPE_REQUIRED", "budget_calls"), ("EVALUATION_INCOMPLETE", "complete"),
                             ("INFRASTRUCTURE_FAILED", "no_final"), ("DENY", "made_up_reason"), ("MAYBE", "complete")):
        receipt = base_receipt(decision, reason, EXIT_CODES.get(decision, 0))
        receipt["witnesses"]["final_seen"] = decision == "ALLOW"
        check_verify(c, "%s %s" % (decision, reason), signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_cleanup_with_all_witnesses_true(c):
    """§12: a correctly signed CLEANUP_UNVERIFIED with all three cleanup witnesses true is INVALID."""
    for reason in ("complete", "prohibited_tool", "no_final"):
        check_verify(c, reason, signed_bytes(c.key, base_receipt("CLEANUP_UNVERIFIED", reason, 6)), False)


@case("receipt")
def verify_cleanup_with_pre_boot_reason(c):
    """§2/§12: CLEANUP_UNVERIFIED with a section 4 reason disagrees with the table, so INVALID when signed."""
    for reason in PRE_BOOT_REASONS:
        receipt = base_receipt("CLEANUP_UNVERIFIED", reason, 6)
        receipt["witnesses"]["workdir_removed"] = False
        check_verify(c, reason, signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_other_decision_with_false_cleanup(c):
    """§12: a decision other than CLEANUP_UNVERIFIED with any cleanup witness false is INVALID when signed."""
    for name in ("vmm_reaped", "sockets_removed", "workdir_removed"):
        receipt = row_receipt("DENY", "prohibited_tool")
        receipt["witnesses"][name] = False
        check_verify(c, "DENY " + name, signed_bytes(c.key, receipt), False)
        receipt = row_receipt("EVALUATION_INCOMPLETE", "no_final")
        receipt["witnesses"][name] = False
        check_verify(c, "EVALUATION_INCOMPLETE " + name, signed_bytes(c.key, receipt), False)


@case("receipt")
def verify_bad_key_file(c):
    """§12: a key file that fails §10 makes verify INVALID even for a receipt signed with those very bytes."""
    key = new_key()
    data = signed_bytes(key, base_receipt())
    loose = os.path.join(c.aux, "loose")
    agent_file(loose, key, 0o644)
    check_verify(c, "mode 0644", data, False, keyfile=loose, key=key)
    real = os.path.join(c.aux, "real")
    agent_file(real, key, 0o600)
    link = os.path.join(c.aux, "link")
    os.symlink(real, link)
    agent_chown(link)
    check_verify(c, "symlink", data, False, keyfile=link, key=key)
    short = new_key(16)
    short_path = os.path.join(c.aux, "short")
    agent_file(short_path, short, 0o600)
    check_verify(c, "short", signed_bytes(short, base_receipt()), False, keyfile=short_path, key=short)
    same = b"\x42" * 40
    same_path = os.path.join(c.aux, "same")
    agent_file(same_path, same, 0o600)
    check_verify(c, "repeated byte", signed_bytes(same, base_receipt()), False, keyfile=same_path, key=same)
    check_verify(c, "missing", data, False, keyfile=os.path.join(c.aux, "no-such-key"), key=key)


# ===================================================================================================
# Clean sessions
# ===================================================================================================

@case("clean")
def clean_minimal(c):
    """§7/§8: hello then final, with no calls and no evidence, is ALLOW complete with exact counters."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    run = c.gate(job, allow(c, s), hard=120.0)
    if not c.problems and not State.baseline_set:
        State.baseline_set = True
        State.t_allow = max(15.0, min(45.0, 3.0 * run.elapsed))


@case("clean")
def clean_three_calls_five_evidence(c):
    """§7: 3 calls and 5 evidence chunks give exact counters and the exact evidence_root."""
    job = c.job()
    s = Ses(job)
    steps = hello_ready(s)
    steps += step(s.propose("list_docs"))
    steps += step(s.evidence(b"chunk one"))
    steps += step(s.propose("read_doc", b"overview"))
    steps += step(s.evidence(b"chunk two" * 40))
    steps += step(s.evidence(b""))
    steps += step(s.propose("read_doc", b"details"))
    steps += step(s.evidence(b"chunk four"))
    steps += step(s.evidence(os.urandom(2000)))
    job.play(*steps, SEND(s.final()), RECV())
    c.forbid("read_doc", "list_docs")  # §1: tool names cross only as hashes
    c.gate(job, allow(c, s))


@case("clean")
def clean_exactly_max_calls(c):
    """§7 step 6: exactly max_calls calls are allowed."""
    job = c.job()
    job.budgets(max_calls=4)
    s = Ses(job)
    steps = hello_ready(s)
    for _ in range(4):
        steps += step(s.propose())
    job.play(*steps, SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_max_calls_zero(c):
    """§3/§7: max_calls of 0 is valid, and a session with no calls still completes."""
    job = c.job()
    job.budgets(max_calls=0)
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk")), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_evidence_at_budget(c):
    """§7 step 6: evidence adding up to exactly max_evidence_bytes does not exceed it."""
    job = c.job()
    job.budgets(max_evidence_bytes=1000)
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"a" * 600)), *step(s.evidence(b"b" * 400)), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_evidence_budget_zero(c):
    """§3/§7: max_evidence_bytes of 0 is valid, and a 0-byte chunk does not exceed it but still counts as a chunk."""
    job = c.job()
    job.budgets(max_evidence_bytes=0)
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"")), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_byte_by_byte(c):
    """§5/§7: frames sent one byte per write within the idle limit are ordinary frames."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, BYTEWISE(s.hello()), RECV(), BYTEWISE(s.propose()), RECV(), BYTEWISE(s.evidence(b"chunk")), RECV(),
             BYTEWISE(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_slow_bytes_within_idle(c):
    """§7: a frame trickled over about 3 s, inside an 8 s idle limit, is accepted."""
    job = c.job()
    job.budgets(frame_idle_sec=8)
    s = Ses(job)
    job.play(*hello_ready(s), BYTEWISE(s.propose(), delay=0.025), RECV(), SEND(s.final()), RECV())
    c.gate(job, allow(c, s, extra=4.0))


@case("clean")
def clean_pipelined(c):
    """§5/§7: hello, calls, evidence and final in one write, without waiting for replies, are all processed in order."""
    job = c.job()
    s = Ses(job)
    frames = [s.hello(), s.propose(), s.evidence(b"one"), s.propose("list_docs"), s.evidence(b"two"), s.final()]
    job.play(CONNECT, SEND(*frames), RECV(len(frames)))
    c.gate(job, allow(c, s))


def flood_chunk(canary):
    data = canary.encode()
    return (b"\x1b[38;5;213m\x1b]0;" + data + b"\x07ALLOW complete\n" + data + b"\x00\xff\xfe\x1b[2J\x1bc\x08 "
            + b'{"decision":"ALLOW"}' + b"A" * 3000 + b"\n")


FLOOD_MARKS = (b"\x1b[38;5;213m", b"\x1b]0;", b"\x00\xff\xfe", b"\x1b[2J")


@case("clean")
def clean_console_flood_then_session(c):
    """§1/§6: at least 1 MiB on the console, with planted canary and escape bytes, neither blocks nor leaks; then ALLOW."""
    job = c.job()
    job.budgets(hello_timeout_sec=150, wall_clock_sec=400)
    s = Ses(job)
    c.forbid(*FLOOD_MARKS)
    job.play(CONSOLE(flood_chunk(c.canary), 1100000), *clean_steps(s))
    c.gate(job, allow(c, s, extra=150.0))


@case("clean")
def clean_console_flood_during_session(c):
    """§1/§6: a console flood running alongside the whole session neither blocks it nor leaks; then ALLOW."""
    job = c.job()
    s = Ses(job)
    c.forbid(*FLOOD_MARKS)
    job.play(CONSOLE_FORK(flood_chunk(c.canary)), *clean_steps(s))
    c.gate(job, allow(c, s, extra=10.0))


@case("clean")
def clean_target_and_payload_canary(c):
    """§1: target and payload bytes carrying a canary, shown on the console by the guest, reach no output; then ALLOW."""
    job = c.job()
    job.set_target(b"# Skill\n" + c.canary.encode() + b"\n")
    job.files["payload/extra.txt"] = b"extra " + c.canary.encode() + b"\n"
    s = Ses(job)
    job.play(SHOW("target/skill.md", "payload/extra.txt", "payload/run"), *hello_ready(s),
             *step(s.propose("read_doc", c.canary.encode())), *step(s.evidence(c.canary.encode())), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


def probe_facts(vcpus, mem):
    return {"boot": {"given": "console=ttyS0 reboot=k panic=1 pci=off init=/init", "mmio": 3, "other": []},
            "mem_mib": mem, "net": ["lo"], "release": "6.1.188", "vcpus": vcpus, "vda_ro": "1", "vdb_ro": "1",
            "virtio": ["0x0002", "0x0002", "0x0013"]}


def probe_case(c, vcpus, mem):
    job = c.job()
    job.manifest["vm"] = {"vcpus": vcpus, "mem_mib": mem}
    job.use_program(guest_source("vmprobe.py"))
    s = Ses(job)
    s.hello()
    s.evidence(canon(probe_facts(vcpus, mem)))
    s.final()
    c.gate(job, allow(c, s))


@case("clean")
def clean_vm_probe(c):
    """§6: evidence_root matches only on kernel 6.1.188 with the spec's boot args, 1 vCPU, 128 MiB, both drives read-only, no NIC."""
    probe_case(c, 1, 128)


@case("clean")
def clean_vm_probe_two_cpus(c):
    """§6: the same probe with vcpus=2 and mem_mib=256 proves the manifest's machine config is honored."""
    probe_case(c, 2, 256)


@case("clean")
def clean_vm_probe_four_cpus_low_memory(c):
    """§3/§6: the probe at vcpus=4 and mem_mib=64, the top and bottom of the valid ranges, is honored too."""
    probe_case(c, 4, 64)


@case("clean")
def clean_job_image_tree(c):
    """§3/§6: nested and empty payload files, the target, the manifest and session.json all reach the guest intact."""
    job = c.job()
    job.use_program(guest_source("treeprobe.py"))
    job.files["payload/sub/deep/data.bin"] = os.urandom(100000)
    job.files["payload/sub/note.txt"] = b"note\n"
    job.files["payload/empty"] = b""
    listing = {"payload/run": sha(job.program), "target/skill.md": sha(job.target)}
    for name, data in job.files.items():
        listing[name] = sha(data)
    s = Ses(job)
    s.hello()
    s.evidence(canon({"files": listing, "session_ok": True}))
    s.evidence(job.frozen.encode("ascii"))
    s.final()
    c.gate(job, allow(c, s))


@case("clean")
def clean_host_replies_exact(c):
    """§5/§7: ready, decision, ack and bye are byte for byte the canonical messages; a wrong one spoils the session."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.hello()), REPLY(canon({"frozen": job.frozen, "t": "ready"})),
             SEND(s.propose()), REPLY(canon({"decision": "allow", "seq": 1, "t": "decision"})),
             SEND(s.evidence(b"chunk")), REPLY(canon({"seq": 2, "t": "ack"})),
             SEND(s.propose("list_docs")), REPLY(canon({"decision": "allow", "seq": 3, "t": "decision"})),
             SEND(s.final()), REPLY(canon({"t": "bye"})))
    c.gate(job, allow(c, s))


@case("clean")
def clean_total_bytes_at_budget(c):
    """§7 step 2: guest bytes adding up to exactly max_total_bytes do not exceed it."""
    job = c.job()
    s = Ses(job)
    steps = [*hello_ready(s), *step(s.propose()), *step(s.evidence(b"chunk")), SEND(s.final()), RECV()]
    job.budgets(max_total_bytes=s.bytes_in)
    job.play(*steps)
    c.gate(job, allow(c, s))


@case("clean")
def clean_frame_at_limit(c):
    """§7 step 1: a frame of exactly max_frame_bytes is not above the limit."""
    job = c.job()
    s = Ses(job)
    hello = s.hello()
    evidence = s.evidence(b"chunk")
    final = s.final()
    job.budgets(max_frame_bytes=max(s.real_len(hello), s.real_len(evidence), s.real_len(final)))
    job.play(CONNECT, SEND(hello), RECV(), SEND(evidence), RECV(), SEND(final), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_budgets_at_upper_bounds(c):
    """§3: every budget at the top of its range is valid; a claim of exactly max_evidence_bytes is accepted."""
    job = c.job()
    job.budgets(max_calls=1000, max_frame_bytes=1048576, max_total_bytes=67108864, max_evidence_bytes=1073741824,
                hello_timeout_sec=600, frame_idle_sec=600, wall_clock_sec=3600)
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk", claim=1073741824)), *step(s.propose()), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_empty_tool_lists(c):
    """§3: all three tool lists may be empty; a session with no calls still completes."""
    job = c.job()
    job.manifest.update(declared_tools=[], prohibited_tools=[], authority_tools=[])
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_idle_timer_resets_each_frame(c):
    """§7: frame_idle_sec runs per frame: frames 2.5 s apart with a 6 s limit pass though the session outlasts it."""
    job = c.job()
    job.budgets(frame_idle_sec=6)
    s = Ses(job)
    job.play(*hello_ready(s), SLEEP(2.5), *step(s.propose()), SLEEP(2.5), *step(s.evidence(b"chunk")), SLEEP(2.5),
             SEND(s.final()), RECV())
    c.gate(job, allow(c, s, extra=8.0))


@case("clean")
def clean_no_idle_timer_before_hello(c):
    """§7: before the first frame there is no previous frame, so only hello_timeout_sec runs: a slow hello passes."""
    job = c.job()
    job.budgets(frame_idle_sec=3, hello_timeout_sec=40)
    s = Ses(job)
    job.play(CONNECT, SLEEP(5), SEND(s.hello()), RECV(), SEND(s.final()), RECV())
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_timers_stop_at_final(c):
    """§7: wall_clock_sec ends when final is accepted: a guest that stays up after bye still gets ALLOW."""
    job = c.job()
    job.budgets(wall_clock_sec=c.booted_by(), frame_idle_sec=3, hello_timeout_sec=c.booted_by())
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), FOREVER)
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_guest_stays_up_after_bye(c):
    """§7: after bye the host waits for VMM exit or 5 s; a guest that never exits gets ALLOW, within 5 s plus 10 s slack."""
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s), FOREVER)
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_guest_closes_right_after_final(c):
    """§7: end of the connection after final is normal, even when the guest never reads bye; then ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), CLOSE, FOREVER)
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_kernel_crash_after_bye(c):
    """§7: once final is accepted, a guest kernel crash is only the VMM exiting, so the session is still ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), CRASH)
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_console_flood_after_bye(c):
    """§6/§7: a console flood after bye stays on the console, so ALLOW after the 5 s window, with no leak."""
    job = c.job()
    s = Ses(job)
    c.forbid(*FLOOD_MARKS)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), CONSOLE_FOREVER(flood_chunk(c.canary)))
    c.gate(job, allow(c, s, extra=5.0))


@case("clean")
def clean_job_id_shortest(c):
    """§3: a job_id with 6 characters after the prefix is valid."""
    job = c.job(job_id=new_job_id(6))
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_job_id_longest(c):
    """§3/§6: a job_id with 32 characters after the prefix is valid and fits the socket paths."""
    job = c.job(job_id=new_job_id(32))
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_manifest_any_formatting(c):
    """§3: the manifest may use any JSON formatting; frozen_sha256 is from the parsed value, not the file's bytes."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.final()), RECV())
    text = json.dumps(job.manifest, indent=7, sort_keys=False).encode("ascii").replace(b"\n", b"\r\n")
    job.raw_manifest = text.replace(b'"read_doc"', b'"re\\u0061d_doc"', 1) + b"\r\n\r\n"
    c.gate(job, allow(c, s))


@case("clean")
def clean_manifest_exactly_64kib(c):
    """§3: a manifest of exactly 64 KiB is valid."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    body = job.manifest_bytes()
    job.raw_manifest = body + b" " * (64 * 1024 - len(body))
    c.gate(job, allow(c, s))


@case("clean")
def clean_contents_exactly_16mib(c):
    """§3: file contents totalling exactly 16 MiB, counting every file, are valid and reach the guest."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV())
    job.files["payload/pad.bin"] = b""
    job.files["payload/pad.bin"] = os.urandom(16 * MIB - job.content_size())
    c.gate(job, allow(c, s))


@case("clean")
def clean_counts_at_integer_limit(c):
    """§5: a count of exactly 2^53 - 1 is canonical, and args_bytes has no budget, so the call is allowed."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose("read_doc", b"", claim=2 ** 53 - 1)), SEND(s.final()), RECV())
    c.gate(job, allow(c, s))


@case("clean")
def clean_spec_defaults(c):
    """§2: without --lock and --run-root the gate uses /opt/lab/assets.lock.json and /dev/shm/fcgate, leaving it empty."""
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, allow(c, s), run_root=None)
    if os.path.isdir(DEFAULT_RUN_ROOT):
        c.check_dir_mode(DEFAULT_RUN_ROOT, "default run root")


@case("clean")
def clean_modes_under_open_umask(c):
    """§2/§11: with umask 000, a created --out and --run-root are mode 0700 and the receipt is mode 0600."""
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, allow(c, s), umask=0)
    c.check_dir_mode(c.out, "output directory")
    if os.path.isdir(c.run_root):
        c.check_dir_mode(c.run_root, "run root")


@case("clean")
def clean_work_directory_layout(c):
    """§6: the VMM runs as firecracker --api-sock <run-root>/<job_id>-<random>/api.sock, in its own group, workdir 0700."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SLEEP(2), SEND(s.final()), RECV())
    run = c.gate(job, allow(c, s, extra=2.0))
    apis = set()
    for info in c.sampler.seen.values():
        argv = info["argv"]
        if "--api-sock" in argv and argv.index("--api-sock") + 1 < len(argv):
            apis.add(argv[argv.index("--api-sock") + 1])
        if info["pgid"] == run.proc.pid:
            c.fail("the VMM shares the gate's process group")
        if info["workdir_mode"] is not None and info["workdir_mode"] != 0o700:
            c.fail("work directory mode %o" % info["workdir_mode"])
    if len(apis) != 1:
        c.fail("expected one VMM with --api-sock, saw %r" % sorted(apis))
        return
    api = apis.pop()
    workdir = os.path.dirname(api)
    if os.path.basename(api) != "api.sock" or os.path.dirname(workdir) != run.run_root:
        c.fail("API socket %r is not <run-root>/<job_id>-<random>/api.sock" % api)
    if not os.path.basename(workdir).startswith(job.job_id + "-") or os.path.basename(workdir) == job.job_id + "-":
        c.fail("work directory %r is not <job_id>-<random>" % os.path.basename(workdir))


@case("clean")
def clean_weird_file_names(c):
    """§3: payload file names are opaque: spaces, newlines, shell syntax and non-UTF-8 bytes change nothing; then ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    marker = "/tmp/fcv" + new_job_id(8)[4:]
    job.files["payload/with space"] = b"a"
    job.files["payload/new\nline"] = b"b"
    job.files["payload/$(touch %s)" % marker.replace("/", "_")] = b"c"
    job.files[b"payload/\xff\xfe-bytes"] = b"d"
    job.files["payload/-rf"] = b"e"
    c.gate(job, allow(c, s))


# ===================================================================================================
# Trips
# ===================================================================================================

def deny(c, reason, ses, **kwargs):
    return ended(c, "DENY", reason, ses, **kwargs)


def long_timers(job):
    """Timers far beyond the hard limit, so only the rule under test can end the run in time."""
    return job.budgets(hello_timeout_sec=120, frame_idle_sec=300, wall_clock_sec=600)


@case("trip")
def trip_prohibited_first(c):
    """§7 step 6: a prohibited tool as the first call is DENY prohibited_tool, with its hash in the receipt."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), PERSIST(s))
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_prohibited_after_clean_calls(c):
    """§7/§11: a prohibited tool after clean work counts frames, calls and evidence up to and including that frame."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), *step(s.evidence(b"chunk")), *step(s.propose("list_docs")),
             SEND(s.propose_trip("run_shell")), PERSIST(s))
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_prohibited_with_final_queued(c):
    """§7: a clean final queued behind a prohibited tool in one write is neither processed nor counted."""
    job = c.job()
    s = Ses(job)
    hello = s.hello()
    trip = s.propose_trip("read_secret")
    queued = [evidence_body(5, sha(b"chunk"), ZERO, 2), final_body(0, 0, 0, ZERO, 2)]
    job.play(CONNECT, SEND(hello), RECV(), SEND(trip, *queued), FOREVER)
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_prohibited_all_in_one_write(c):
    """§7: hello, a call, a prohibited tool and a final all in one write: the frames after the trip are not counted."""
    job = c.job()
    s = Ses(job)
    frames = [s.hello(), s.propose(), s.propose_trip("post_url"), final_body(1, 0, 0, ZERO, 3)]
    job.play(CONNECT, SEND(*frames), FOREVER)
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_prohibited_many_queued(c):
    """§7: two hundred valid frames queued behind a prohibited tool are neither processed nor counted."""
    job = c.job()
    job.budgets(max_calls=1000)
    s = Ses(job)
    hello = s.hello()
    trip = s.propose_trip("read_secret")
    queued = [propose_body("read_doc", b"", seq) for seq in range(2, 202)]
    job.play(CONNECT, SEND(hello), RECV(), SEND(trip, *queued), FOREVER)
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_prohibited_then_sleep_returns_fast(c):
    """§7: the VMM is killed at once on a prohibited tool, however long the guest would sleep and the timers run."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), FOREVER)
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def trip_undeclared_canary_name(c):
    """§1/§7/§11: an undeclared tool is DENY undeclared_tool; only its hash crosses and the raw name appears nowhere."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.propose_trip(c.canary)), PERSIST(s))
    c.gate(job, deny(c, "undeclared_tool", s))


@case("trip")
def trip_undeclared_with_empty_lists(c):
    """§3/§7: with all lists empty, any tool is DENY undeclared_tool."""
    job = c.job()
    job.manifest.update(declared_tools=[], prohibited_tools=[], authority_tools=[])
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_doc")), PERSIST(s))
    c.gate(job, deny(c, "undeclared_tool", s))


@case("trip")
def trip_authority_tool(c):
    """§7 step 6: an authority tool is RESCOPE_REQUIRED authority_expansion, with its hash in the receipt."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.propose_trip("change_policy")), PERSIST(s))
    c.gate(job, ended(c, "RESCOPE_REQUIRED", "authority_expansion", s))


@case("trip")
def trip_call_budget(c):
    """§7 step 6: max_calls + 1 declared calls is DENY budget_calls; the extra call's tool hash is in the receipt."""
    job = c.job()
    job.budgets(max_calls=3)
    s = Ses(job)
    steps = hello_ready(s)
    for _ in range(3):
        steps += step(s.propose())
    job.play(*steps, SEND(s.propose_trip("list_docs")), PERSIST(s))
    c.gate(job, deny(c, "budget_calls", s))


@case("trip")
def trip_call_budget_zero(c):
    """§7 step 6: with max_calls of 0, the first declared call is DENY budget_calls."""
    job = c.job()
    job.budgets(max_calls=0)
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_doc")), PERSIST(s))
    c.gate(job, deny(c, "budget_calls", s))


@case("trip")
def order_prohibited_before_call_budget(c):
    """§7 step 6: prohibited is checked before the call budget."""
    job = c.job()
    job.budgets(max_calls=0)
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), PERSIST(s))
    c.gate(job, deny(c, "prohibited_tool", s))


@case("trip")
def order_authority_before_call_budget(c):
    """§7 step 6: authority is checked before the call budget."""
    job = c.job()
    job.budgets(max_calls=0)
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("change_policy")), PERSIST(s))
    c.gate(job, ended(c, "RESCOPE_REQUIRED", "authority_expansion", s))


@case("trip")
def order_undeclared_before_call_budget(c):
    """§7 step 6: undeclared is checked before the call budget."""
    job = c.job()
    job.budgets(max_calls=0)
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("something_else")), PERSIST(s))
    c.gate(job, deny(c, "undeclared_tool", s))


@case("trip")
def trip_total_bytes(c):
    """§7 step 2: the frame that would pass max_total_bytes is DENY budget_bytes and is not counted."""
    job = c.job()
    s = Ses(job)
    steps = [*hello_ready(s), *step(s.propose()), *step(s.propose())]
    over = propose_body("read_doc", b"", 3)
    job.budgets(max_total_bytes=s.bytes_in + 4 + len(over) - 1)
    job.play(*steps, SEND(over), PERSIST(s, follow=if_counted_as_call(s)))
    c.gate(job, deny(c, "budget_bytes", s))


@case("trip")
def trip_total_bytes_from_header_alone(c):
    """§7 step 2: budget_bytes is decided without reading the body: a header alone returns fast."""
    job = long_timers(c.job())
    job.budgets(max_total_bytes=1500)
    s = Ses(job)
    job.play(*hello_ready(s), RAW(struct.pack(">I", 2000)), FOREVER)
    c.gate(job, deny(c, "budget_bytes", s))


@case("trip")
def trip_total_bytes_on_hello(c):
    """§3/§7 step 2: with max_total_bytes of 64 the hello itself is budget_bytes, not counted, and no hello was accepted."""
    job = c.job()
    job.budgets(max_total_bytes=64)
    s = Ses(job)
    job.play(CONNECT, SEND(hello_body()), PERSIST(s))
    c.gate(job, deny(c, "budget_bytes", s))


@case("trip")
def trip_total_bytes_flood_without_reading(c):
    """§7: valid evidence frames flooded in one write, no reply ever read, trip budget_bytes at the exact frame."""
    job = c.job()
    budget = 512 * 1024
    job.budgets(max_total_bytes=budget, max_evidence_bytes=1 << 30)
    s = Ses(job)
    frames = [s.hello()]
    chunk = sha(b"flood")
    while True:
        over = evidence_body(5, chunk, s.head, s.seq + 1)
        if s.bytes_in + 4 + len(over) > budget:
            break
        frames.append(s.evidence(b"flood"))
    if_accepted = final_body(s.calls, s.evidence_bytes + 5, s.chunks + 1, sha((s.head + chunk).encode("ascii")), s.seq + 2)
    # The host needs time to drain the write before this guest may act on any reply.
    job.play(CONNECT, SEND(*frames, over), SLEEP(10), PERSIST(s, follow=if_accepted))
    c.gate(job, deny(c, "budget_bytes", s, extra=5.0))


@case("trip")
def trip_evidence_budget(c):
    """§7 step 6: one byte over max_evidence_bytes is DENY budget_evidence; the frame counts, its chunk does not."""
    job = c.job()
    job.budgets(max_evidence_bytes=100)
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"a" * 60)), SEND(s.evidence_trip(b"b" * 41)), PERSIST(s))
    c.gate(job, deny(c, "budget_evidence", s))


@case("trip")
def trip_evidence_budget_huge_claim(c):
    """§5/§7: a claimed chunk of 2^53 - 1 bytes is canonical and is DENY budget_evidence."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.evidence_trip(b"x", claim=2 ** 53 - 1)), PERSIST(s))
    c.gate(job, deny(c, "budget_evidence", s))


# ===================================================================================================
# Violations: hello
# ===================================================================================================

@case("hello")
def hello_never_connects(c):
    """§7: a guest that never connects is timeout_hello at hello_timeout_sec."""
    job = c.job()
    job.budgets(hello_timeout_sec=3)
    s = Ses(job)
    job.play(SLEEP(8), *late_clean_session(job))
    c.gate(job, incomplete(c, "timeout_hello", s, **c.timer(3)))


@case("hello")
def hello_connects_then_silent(c):
    """§7: a guest that connects and says nothing is timeout_hello."""
    job = c.job()
    job.budgets(hello_timeout_sec=3)
    s = Ses(job)
    late = Ses(job)
    job.play(CONNECT, SLEEP(8), SEND(late.hello()), RECV(), SEND(late.final()), RECV())
    c.gate(job, incomplete(c, "timeout_hello", s, **c.timer(3)))


@case("hello")
def hello_trickled_past_its_timer(c):
    """§7: hello_timeout_sec runs until a complete hello has arrived, so trickling does not extend it."""
    job = c.job()
    job.budgets(hello_timeout_sec=4, frame_idle_sec=300)
    s = Ses(job)
    job.play(CONNECT, BYTEWISE(hello_body(), delay=0.25), RECV(), SEND(final_body(0, 0, 0, ZERO, 1)), RECV())
    c.gate(job, incomplete(c, "timeout_hello", s, **c.timer(4)))


@case("hello")
def hello_bad_nonce(c):
    """§7 step 4: a well-formed hello with the wrong nonce is bad_nonce; the frame counts and no hello was accepted."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(nonce=sha(b"wrong nonce"))), PERSIST(s))
    c.gate(job, incomplete(c, "bad_nonce", s))


@case("hello")
def hello_wrong_job(c):
    """§7 step 4: a hello naming another job is bad_hello; the frame counts and its job text reaches no output."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(job=c.canary)), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_empty_job(c):
    """§5/§7: a job of 0 characters is well-formed, and differs from job_id, so bad_hello."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(job="")), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_job_128_characters(c):
    """§5/§7: a job of 128 characters is well-formed, and differs from job_id, so bad_hello and counted."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(job="j" * 128)), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_job_129_characters(c):
    """§5/§7: a job of 129 characters breaks its format, so frame_malformed and not counted."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(hello_body(job="j" * 129)), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


@case("hello")
def hello_version_two(c):
    """§7 step 4: v=2 is bad_hello."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(v=2)), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_version_zero(c):
    """§7 step 4: v=0 is bad_hello."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.bad_hello(v=0)), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_propose_first(c):
    """§7 step 4/§11: propose before hello is bad_hello; it passed step 3, so it counts; a propose ended the session."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.propose_trip("read_doc")), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_evidence_first(c):
    """§7 step 4: evidence before hello is bad_hello, and the frame counts."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.evidence_trip(b"chunk")), PERSIST(s))
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_final_first(c):
    """§7 step 4: a final with all-zero counts before any hello is bad_hello, never ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(s.final_trip()), FOREVER)
    c.gate(job, incomplete(c, "bad_hello", s))


@case("hello")
def hello_second_hello(c):
    """§7 step 4: a hello after the first frame is frame_malformed, decided at step 4, so it passed step 3 and counts."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.bad_hello()), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


def first_frame_malformed(c, body):
    job = c.job()
    s = Ses(job)
    job.play(CONNECT, SEND(body), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


HELLO = hello_body()
MALFORMED_HELLOS = [
    ("hello_whitespace", "§5/§7 step 3: whitespace in a first frame is frame_malformed, not bad_hello, and is not counted.",
     HELLO.replace(b'"t":"hello"', b'"t": "hello"')),
    ("hello_unsorted_keys", "§5/§7 step 3: unsorted keys in a first frame are frame_malformed, not counted.",
     b'{"nonce":"@NONCE@","job":"@JOB@","t":"hello","v":1}'),
    ("hello_duplicate_key", "§5/§7 step 3: a duplicate key in a first frame is frame_malformed, not counted.",
     HELLO.replace(b'"v":1', b'"v":1,"v":1')),
    ("hello_float_version", "§5/§7 step 3: v as a float is frame_malformed, not bad_hello.",
     HELLO.replace(b'"v":1', b'"v":1.0')),
    ("hello_boolean_version", "§5/§7 step 3: v as true is frame_malformed, since true is not an integer.",
     HELLO.replace(b'"v":1', b'"v":true')),
    ("hello_version_over_limit", "§5/§7 step 3: v of 2^53 is above the integer limit: frame_malformed, not bad_hello.",
     HELLO.replace(b'"v":1', b'"v":9007199254740992')),
    ("hello_unknown_key", "§5/§7 step 3: an unknown key in hello is frame_malformed.",
     HELLO.replace(b'"t":"hello"', b'"t":"hello","u":1')),
    ("hello_missing_nonce", "§5/§7 step 3: a hello without its nonce is frame_malformed.",
     b'{"job":"@JOB@","t":"hello","v":1}'),
    ("hello_nonce_uppercase", "§5/§7 step 3: the right nonce in uppercase breaks hex64: frame_malformed, not bad_nonce.",
     HELLO.replace(b"@NONCE@", b"@NONCEUP@")),
    ("hello_nonce_short", "§5/§7 step 3: a 63-character nonce breaks hex64: frame_malformed, not bad_nonce.",
     hello_body(nonce="a" * 63)),
    ("hello_job_with_del_byte", "§5/§7 step 3: a job holding a raw DEL byte is not printable ASCII: frame_malformed.",
     HELLO.replace(b"@JOB@", b"job\x7f")),
    ("hello_job_with_escaped_del", "§5/§7 step 3: a job holding the escape for DEL has an escape sequence: frame_malformed.",
     HELLO.replace(b"@JOB@", b"job\\u007f")),
    ("hello_job_with_escaped_quote", "§5/§7 step 3: a job holding an escaped quote has an escape sequence: frame_malformed.",
     HELLO.replace(b"@JOB@", b'job\\"x')),
    ("hello_job_with_escape", "§5/§7 step 3: the right job spelled with an escape sequence is not canonical: frame_malformed.",
     HELLO.replace(b"@JOB@", b"\\u006a@JOBTAIL@")),
    ("hello_garbage", "§5/§7 step 3: binary garbage as the first frame is frame_malformed.",
     b"\x00\x01\x02\xfe\xff garbage"),
]


def malformed_first_case(body):
    def run(c):
        first_frame_malformed(c, body)
    return run


for _name, _doc, _body in MALFORMED_HELLOS:
    add_case(_name, "hello", _doc, malformed_first_case(_body))


@case("hello")
def hello_job_with_escape_bytes(c):
    """§1/§5: a job holding ESC and BEL bytes around a canary is frame_malformed, and none of it reaches any output."""
    job = c.job()
    s = Ses(job)
    mark = b"\x1b]0;"
    c.forbid(mark)
    job.play(CONNECT, SEND(HELLO.replace(b"@JOB@", mark + c.canary.encode() + b"\x07")), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


# ===================================================================================================
# Violations: frame headers
# ===================================================================================================

@case("header")
def header_oversize_all_ones(c):
    """§7 step 1: length 0xFFFFFFFF is frame_too_large from the header alone, returning fast."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), RAW(b"\xff\xff\xff\xff"), FOREVER)
    c.gate(job, incomplete(c, "frame_too_large", s))


@case("header")
def header_oversize_first_frame(c):
    """§7 step 1: length 0xFFFFFFFF as the very first frame is frame_too_large, not counted, returning fast."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(CONNECT, RAW(b"\xff\xff\xff\xff"), FOREVER)
    c.gate(job, incomplete(c, "frame_too_large", s))


@case("header")
def header_one_over_limit(c):
    """§7 step 1: a frame one byte above max_frame_bytes is frame_too_large without its body being read."""
    job = long_timers(c.job())
    job.budgets(max_frame_bytes=1000)
    s = Ses(job)
    job.play(*hello_ready(s), RAW(struct.pack(">I", 1001)), FOREVER)
    c.gate(job, incomplete(c, "frame_too_large", s))


@case("header")
def header_too_large_before_total_budget(c):
    """§3/§7: step 1 comes before step 2: with both limits at 64, the hello is frame_too_large, not budget_bytes."""
    job = c.job()
    job.budgets(max_frame_bytes=64, max_total_bytes=64)
    s = Ses(job)
    job.play(CONNECT, SEND(hello_body()), PERSIST(s))
    c.gate(job, incomplete(c, "frame_too_large", s))


@case("header")
def header_zero_length(c):
    """§7 step 1: a zero-length frame mid-session is frame_malformed and is not counted."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), RAW(b"\x00\x00\x00\x00"), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


@case("header")
def header_zero_length_first(c):
    """§7 step 1: a zero-length first frame is frame_malformed, not bad_hello."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(CONNECT, RAW(b"\x00\x00\x00\x00"), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


@case("header")
def header_partial_frame_then_close(c):
    """§7: half a frame and then a closed connection is no_final, and the partial frame is not counted."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), RAW(struct.pack(">I", 64) + b'{"args'), CLOSE, FOREVER)
    c.gate(job, incomplete(c, "no_final", s))


@case("header")
def header_partial_header_then_close(c):
    """§7: half a header and then a closed connection is no_final."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), RAW(b"\x00\x00"), CLOSE, FOREVER)
    c.gate(job, incomplete(c, "no_final", s))


@case("header")
def header_partial_frame_then_stall(c):
    """§7: half a frame and then silence is timeout_frame, and the partial frame is not counted."""
    job = c.job()
    job.budgets(frame_idle_sec=3)
    s = Ses(job)
    whole = propose_body()
    steps = hello_ready(s)
    job.play(*steps, RAW(struct.pack(">I", len(whole)) + whole[:6]), SLEEP(8), RAW(whole[6:]), RECV(),
             SEND(final_body(1, 0, 0, ZERO, 2)), RECV())
    c.gate(job, incomplete(c, "timeout_frame", s, **c.timer(3)))


# ===================================================================================================
# Violations: frame bodies, mid-session
# ===================================================================================================

PROPOSE = propose_body()
EMPTY_HASH = sha(b"").encode()
MALFORMED_BODIES = [
    ("whitespace", "whitespace in the body", PROPOSE.replace(b'"seq":1', b'"seq": 1')),
    ("trailing_newline", "a trailing newline", PROPOSE + b"\n"),
    ("leading_space", "a leading space", b" " + PROPOSE),
    ("unsorted_keys", "unsorted keys",
     b'{"seq":1,"args_bytes":0,"args_sha256":"' + EMPTY_HASH + b'","t":"propose","tool":"read_doc"}'),
    ("duplicate_key", "a duplicate key", PROPOSE.replace(b'"seq":1', b'"seq":1,"seq":1')),
    ("float", "a float where a count belongs", PROPOSE.replace(b'"seq":1', b'"seq":1.0')),
    ("exponent", "an exponent in an integer", PROPOSE.replace(b'"seq":1', b'"seq":1e0')),
    ("leading_zero", "a leading zero", PROPOSE.replace(b'"seq":1', b'"seq":01')),
    ("negative", "a sign on an integer", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":-1')),
    ("boolean", "a boolean where an integer belongs", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":true')),
    ("null_value", "a null", PROPOSE.replace(b'"tool":"read_doc"', b'"tool":null')),
    ("array_value", "an array", PROPOSE.replace(b'"tool":"read_doc"', b'"tool":["read_doc"]')),
    ("string_for_integer", "a string where a count belongs", PROPOSE.replace(b'"seq":1', b'"seq":"1"')),
    ("integer_over_limit", "an integer of 2^53", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":9007199254740992')),
    ("huge_digits", "a 5000-digit integer", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":' + b"9" * 5000)),
    ("nan", "NaN", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":NaN')),
    ("infinity", "Infinity", PROPOSE.replace(b'"args_bytes":0', b'"args_bytes":Infinity')),
    ("invalid_utf8", "invalid UTF-8", PROPOSE.replace(b'"tool":"read_doc"', b'"tool":"read\xff\xfedoc"')),
    ("non_ascii", "valid UTF-8 that is not ASCII", PROPOSE.replace(b'"tool":"read_doc"', b'"tool":"r\xc3\xa9ad_doc"')),
    ("unknown_key", "an unknown key", PROPOSE.replace(b'"t":"propose"', b'"t":"propose","u":1')),
    ("missing_key", "a missing key", b'{"seq":1,"t":"propose","tool":"read_doc"}'),
    ("escape_sequence", "an escape sequence that decodes to a valid tool", PROPOSE.replace(b"read_doc", b"read\\u005fdoc")),
    ("escaped_quote_in_tool", "an escape in a tool name that re-encodes unchanged", PROPOSE.replace(b"read_doc", b'read\\"doc')),
    ("hash_uppercase", "a hash in uppercase", PROPOSE.replace(EMPTY_HASH, EMPTY_HASH.upper())),
    ("hash_short", "a hash that is too short", PROPOSE.replace(EMPTY_HASH, EMPTY_HASH[:-1])),
    ("unknown_type", "an unknown message type", b'{"t":"ping"}'),
    ("host_message", "a message only the host may send", canon({"seq": 1, "t": "ack"})),
    ("host_bye", "bye from the guest", canon({"t": "bye"})),
    ("deep_arrays", "deep array nesting within the size limit", b"[" * 30000 + b"]" * 30000),
    ("deep_objects", "deep object nesting within the size limit", b'{"a":' * 10000 + b"1" + b"}" * 10000),
    ("top_level_array", "a top-level array", b"[1,2,3]"),
    ("top_level_string", "a top-level string", b'"hello"'),
    ("two_objects", "two objects in one frame", PROPOSE + PROPOSE),
    ("nul_byte", "a NUL byte after the object", PROPOSE + b"\x00"),
    ("binary", "binary garbage", b"\xde\xad\xbe\xef" * 16),
]
MALFORMED_TOOLS = [
    ("tool_uppercase", "an uppercase tool name", b"Read_doc"),
    ("tool_leading_digit", "a tool name with a leading digit", b"1read"),
    ("tool_too_long", "a 65-character tool name", b"a" * 65),
    ("tool_empty", "an empty tool name", b""),
    ("tool_with_space", "a tool name with a space", b"read doc"),
]


def malformed_mid_case(body, tripped=""):
    def run(c):
        job = c.job()
        s = Ses(job)
        job.play(*hello_ready(s), SEND(body), PERSIST(s, follow=if_counted_as_call(s)))
        c.gate(job, incomplete(c, "frame_malformed", s, tripped=tripped))
    return run


@case("body")
def body_tool_name_carrying_canary(c):
    """§1/§5: a tool name breaking its format and carrying a canary is frame_malformed, and the raw name reaches no output."""
    job = c.job()
    s = Ses(job)
    name = c.canary.upper()
    c.forbid(name)
    job.play(*hello_ready(s), SEND(propose_body(name)), PERSIST(s, follow=if_counted_as_call(s)))
    c.gate(job, incomplete(c, "frame_malformed", s, tripped=OneOf("", sha(name.encode()))))


@case("body")
def body_unknown_type_carrying_canary(c):
    """§1/§5: a message of unknown type carrying a canary is frame_malformed, and the canary reaches no output."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(canon({"t": c.canary})), PERSIST(s))
    c.gate(job, incomplete(c, "frame_malformed", s))


@case("body")
def body_final_other_status(c):
    """§5/§7 step 3: a final whose status is not complete is frame_malformed, not counted, never ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(final_body(0, 0, 0, ZERO, 1, status="done")), FOREVER)
    c.gate(job, incomplete(c, "frame_malformed", s))


for _name, _what, _body in MALFORMED_BODIES:
    add_case("body_" + _name, "body", "§5/§7 step 3: %s is frame_malformed and is not counted." % _what,
             malformed_mid_case(_body))
for _name, _what, _tool in MALFORMED_TOOLS:
    # §11 ties the hash to "a propose frame"; for a name breaking its format it does not say whether the frame is one.
    add_case("body_" + _name, "body", "§5/§7 step 3: %s is frame_malformed and is not counted." % _what,
             malformed_mid_case(PROPOSE.replace(b'"tool":"read_doc"', b'"tool":"' + _tool + b'"'),
                                tripped=OneOf("", sha(_tool))))


# ===================================================================================================
# Violations: sequence, chain, counters
# ===================================================================================================

@case("seq")
def seq_gap(c):
    """§7 step 5: a seq that skips ahead is seq_gap, and the frame counts."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.evidence_trip(b"chunk", seq=3)), PERSIST(s))
    c.gate(job, incomplete(c, "seq_gap", s))


@case("seq")
def seq_first_is_two(c):
    """§7 step 5: the first frame after hello must have seq 1."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.evidence_trip(b"chunk", seq=2)), PERSIST(s))
    c.gate(job, incomplete(c, "seq_gap", s))


@case("seq")
def seq_first_is_zero(c):
    """§7 step 5: a first frame with seq 0 is seq_gap."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.evidence_trip(b"chunk", seq=0)), PERSIST(s))
    c.gate(job, incomplete(c, "seq_gap", s))


@case("seq")
def seq_replay(c):
    """§7 step 5/§11: a repeated seq is seq_gap; the frame counts, and a propose frame ended the session."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.propose_trip("read_doc", seq=1)), PERSIST(s))
    c.gate(job, incomplete(c, "seq_gap", s))


@case("seq")
def seq_final_skips(c):
    """§7 step 5: a final with a seq that skips ahead is seq_gap, never ALLOW."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.final_trip(seq=9)), FOREVER)
    c.gate(job, incomplete(c, "seq_gap", s))


@case("seq")
def order_seq_before_tool_rules(c):
    """§7: step 5 comes before step 6: a prohibited tool with a bad seq is seq_gap, not prohibited_tool."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret", seq=5)), PERSIST(s))
    c.gate(job, incomplete(c, "seq_gap", s))


@case("chain")
def chain_wrong_prev(c):
    """§7 step 6: evidence whose prev is not the head is chain_mismatch; the head and chunk counts stay."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"good")), SEND(s.evidence_trip(b"bad", prev=sha(b"elsewhere"))), PERSIST(s))
    c.gate(job, incomplete(c, "chain_mismatch", s))


@case("chain")
def order_chain_before_evidence_budget(c):
    """§7 step 6: prev is checked before the evidence budget."""
    job = c.job()
    job.budgets(max_evidence_bytes=10)
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.evidence_trip(b"x" * 100, prev=sha(b"elsewhere"))), PERSIST(s))
    c.gate(job, incomplete(c, "chain_mismatch", s))


@case("chain")
def final_wrong_root(c):
    """§7 step 6: a final with the wrong evidence_root is chain_mismatch, and final was not accepted."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk")), SEND(s.final_trip(root=sha(b"elsewhere"))), FOREVER)
    c.gate(job, incomplete(c, "chain_mismatch", s))


@case("chain")
def final_empty_root_after_evidence(c):
    """§7 step 6: a final claiming the all-zero root after real evidence is chain_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk")), SEND(s.final_trip(root=ZERO, chunks=0, evidence_bytes=0)), FOREVER)
    c.gate(job, incomplete(c, "chain_mismatch", s))


@case("chain")
def order_root_before_counters(c):
    """§7 step 6: evidence_root is checked before the counts: a final wrong in both is chain_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.final_trip(root=sha(b"elsewhere"), calls=5)), FOREVER)
    c.gate(job, incomplete(c, "chain_mismatch", s))


@case("counts")
def final_lies_about_calls(c):
    """§7 step 6: a final claiming the wrong number of calls is counter_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), SEND(s.final_trip(calls=2)), FOREVER)
    c.gate(job, incomplete(c, "counter_mismatch", s))


@case("counts")
def final_hides_calls(c):
    """§7 step 6: a final claiming fewer calls than were made is counter_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), *step(s.propose()), SEND(s.final_trip(calls=1)), FOREVER)
    c.gate(job, incomplete(c, "counter_mismatch", s))


@case("counts")
def final_lies_about_evidence_bytes(c):
    """§7 step 6: a final claiming the wrong evidence byte count is counter_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk")), SEND(s.final_trip(evidence_bytes=6)), FOREVER)
    c.gate(job, incomplete(c, "counter_mismatch", s))


@case("counts")
def final_lies_about_chunks(c):
    """§7 step 6: a final claiming the wrong chunk count is counter_mismatch."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.evidence(b"chunk")), SEND(s.final_trip(chunks=2)), FOREVER)
    c.gate(job, incomplete(c, "counter_mismatch", s))


# ===================================================================================================
# Violations: after final, second connections
# ===================================================================================================

@case("after")
def after_final_one_byte(c):
    """§7: one byte after bye is frame_after_final; final stays seen and the byte is not counted."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), RAW(b"\x00"), FOREVER)
    c.gate(job, incomplete(c, "frame_after_final", s))


@case("after")
def after_final_late_byte(c):
    """§7: a byte 2.5 s after bye is still inside the 5 s window: frame_after_final."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), SLEEP(2.5), RAW(b"Z"), FOREVER)
    c.gate(job, incomplete(c, "frame_after_final", s, extra=3.0))


@case("after")
def after_final_byte_in_same_write(c):
    """§7: a byte queued right behind final, in one write, is still a byte after final: frame_after_final."""
    job = c.job()
    s = Ses(job)
    hello = s.hello()
    final = s.final()
    job.play(CONNECT, SEND(hello), RECV(), RAW(framed(final) + b"\x00"), FOREVER)
    c.gate(job, incomplete(c, "frame_after_final", s))


@case("after")
def after_final_whole_frame(c):
    """§7: a whole valid frame after bye is frame_after_final; §7 decides on the first byte and §11 only counts step 3."""
    job = c.job()
    s = Ses(job)
    steps = [*hello_ready(s), SEND(s.final()), RECV()]
    frames, sent = s.frames, s.bytes_in
    extra = propose_body("read_doc", b"", s.seq + 1)
    exact = s.counters()
    # A gate that reads the frame before deciding, and counts it, is not graded down on the counters alone.
    both = dict(exact, frames=frames + 1, bytes_in=sent + 4 + len(extra))
    job.play(*steps, SEND(extra), FOREVER)
    c.gate(job, incomplete(c, "frame_after_final", s, counters=OneOf(exact, both)))


@case("after")
def second_connection_during_session(c):
    """§7: a second connection during the session is second_connection."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), CONNECT2, SLEEP(3), SEND(final_body(1, 0, 0, ZERO, 2)), RECV())
    c.gate(job, incomplete(c, "second_connection", s))


@case("after")
def second_connection_before_hello(c):
    """§7: a second connection before any frame is second_connection, with nothing counted."""
    job = c.job()
    s = Ses(job)
    late = Ses(job)
    job.play(CONNECT, CONNECT2, SLEEP(3), SEND(late.hello()), RECV(), SEND(late.final()), RECV())
    c.gate(job, incomplete(c, "second_connection", s))


@case("after")
def second_connection_after_final(c):
    """§7: a second connection right after bye is second_connection, and final stays seen."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), CONNECT2, FOREVER)
    c.gate(job, incomplete(c, "second_connection", s))


@case("after")
def second_connection_late_after_final(c):
    """§7: a second connection 2.5 s after bye is still before teardown: second_connection."""
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.final()), RECV(), SLEEP(2.5), CONNECT2, FOREVER)
    c.gate(job, incomplete(c, "second_connection", s, extra=3.0))


# ===================================================================================================
# Violations: guest stops, crashes, stalls or floods
# ===================================================================================================

@case("stop")
def stop_exit_without_connecting(c):
    """§7: a guest that exits without ever connecting ends the VMM before final: no_final, not timeout_hello."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play()
    c.gate(job, incomplete(c, "no_final", s))


@case("stop")
def stop_connect_then_close(c):
    """§7: a connection that ends before any frame is no_final, even with the VMM still up."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(CONNECT, CLOSE, FOREVER)
    c.gate(job, incomplete(c, "no_final", s))


@case("stop")
def stop_exit_without_final(c):
    """§7: a guest that exits after clean work, without final, is no_final with exact counters."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), *step(s.evidence(b"chunk")))
    c.gate(job, incomplete(c, "no_final", s))


@case("stop")
def stop_kernel_crash_before_final(c):
    """§1/§7: a kernel crash through /proc/sysrq-trigger before final ends the VMM: no_final with exact counters."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*hello_ready(s), *step(s.propose()), CRASH)
    c.gate(job, incomplete(c, "no_final", s))


@case("stop")
def stop_kernel_crash_before_hello(c):
    """§1/§7: a kernel crash before any connection ends the VMM: no_final, with nothing counted."""
    job = long_timers(c.job())
    s = Ses(job)
    job.play(CRASH)
    c.gate(job, incomplete(c, "no_final", s))


@case("stop")
def stop_stall_after_hello(c):
    """§7: silence after hello is timeout_frame at frame_idle_sec."""
    job = c.job()
    job.budgets(frame_idle_sec=3)
    s = Ses(job)
    job.play(*hello_ready(s), SLEEP(8), SEND(final_body(0, 0, 0, ZERO, 1)), RECV())
    c.gate(job, incomplete(c, "timeout_frame", s, **c.timer(3)))


@case("stop")
def stop_slow_trickle(c):
    """§7: trickling bytes does not extend frame_idle_sec: a frame needing 15 s under a 3 s limit is timeout_frame."""
    job = c.job()
    job.budgets(frame_idle_sec=3)
    s = Ses(job)
    trickled = propose_body("read_doc", b"", 1)
    finish = final_body(1, 0, 0, ZERO, 2)
    job.play(*hello_ready(s), BYTEWISE(trickled, delay=15.0 / (4 + len(trickled))), RECV(), SEND(finish), RECV())
    c.gate(job, incomplete(c, "timeout_frame", s, **c.timer(3)))


@case("stop")
def stop_steady_calls_hit_wall(c):
    """§7: valid calls every second keep the idle timer happy but not the wall clock: timeout_wall."""
    job = c.job()
    wall = c.booted_by() + 1
    job.budgets(wall_clock_sec=wall, frame_idle_sec=4, max_calls=1000)
    s = Ses(job)
    steps = hello_ready(s)
    calls = wall + 8
    for _ in range(calls):
        steps += step(s.propose())
        steps.append(SLEEP(1))
    job.play(*steps, SEND(final_body(calls, 0, 0, ZERO, calls + 1)), RECV())

    def counters_fit(counters):
        calls = counters["calls_allowed"]
        model = Ses(job)
        model.hello()
        for _ in range(calls):
            model.propose()
        return calls >= 1 and counters == model.counters()
    c.gate(job, incomplete(c, "timeout_wall", s, counters=Check(counters_fit, "frames and bytes that fit the calls allowed"),
                           **c.timer(wall)))


@case("stop")
def stop_wall_before_hello(c):
    """§7: whichever timer expires first decides: wall_clock_sec below hello_timeout_sec is timeout_wall."""
    job = c.job()
    job.budgets(wall_clock_sec=3, hello_timeout_sec=60)
    s = Ses(job)
    job.play(SLEEP(8), *late_clean_session(job))
    c.gate(job, incomplete(c, "timeout_wall", s, **c.timer(3)))


@case("stop")
def stop_wall_during_quiet_session(c):
    """§7: whichever timer expires first decides: wall_clock_sec below frame_idle_sec is timeout_wall after hello."""
    job = c.job()
    wall = c.booted_by() + 3
    job.budgets(wall_clock_sec=wall, frame_idle_sec=120)
    s = Ses(job)
    job.play(*hello_ready(s), SLEEP(wall + 6), SEND(final_body(0, 0, 0, ZERO, 1)), RECV())
    c.gate(job, incomplete(c, "timeout_wall", s, **c.timer(wall)))


@case("stop")
def stop_never_reads_then_floods(c):
    """§7: a clean session whose replies are never read, then a flood of bytes, ends frame_after_final with exact counters."""
    job = c.job()
    job.budgets(max_calls=300, max_total_bytes=4 * MIB)
    s = Ses(job)
    frames = [s.hello()]
    for index in range(300):
        frames.append(s.propose("read_doc", b"args %d" % index))
    for index in range(100):
        frames.append(s.evidence(b"chunk %d" % index))
    frames.append(s.final())
    job.play(CONNECT, SEND(*frames), FLOOD)
    c.gate(job, incomplete(c, "frame_after_final", s, extra=5.0))


# ===================================================================================================
# VMM start and teardown, with wrappers listed in the lock under their own hash
# ===================================================================================================

def api_requests(path):
    """Rebuilds the gate's API requests from the proxy's log, in the order they were sent."""
    streams = {}
    with open(path) as handle:
        for line in handle:
            entry = json.loads(line)
            streams.setdefault(entry["c"], []).append((entry["t"], bytes.fromhex(entry["b"])))
    requests = []
    for pieces in streams.values():
        buffer = b""
        starts = []
        offset = 0
        for moment, data in pieces:
            starts.append((offset, moment))
            buffer += data
            offset += len(data)
        position = 0
        while True:
            end = buffer.find(b"\r\n\r\n", position)
            if end < 0:
                break
            head = buffer[position:end].decode("ascii", "replace").split("\r\n")
            parts = head[0].split(" ")
            length = 0
            for header in head[1:]:
                name, _, value = header.partition(":")
                if name.strip().lower() == "content-length":
                    length = int(value.strip())
            body = buffer[end + 4:end + 4 + length]
            moment = [t for start, t in starts if start <= position][-1]
            requests.append((moment, parts[0], parts[1] if len(parts) > 1 else "", body))
            position = end + 4 + length
    requests.sort(key=lambda item: item[0])
    return requests


@case("vmm")
def vmm_exact_api_calls(c):
    """§6: the VMM is configured with exactly the six PUT calls, in order, with the exact bodies and the manifest's values."""
    wrapper = c.wrapper("api_proxy.py")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    job.manifest["vm"] = {"vcpus": 2, "mem_mib": 192}
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, allow(c, s, assets=assets), lock=lock)
    workdir = next((line[8:] for line in c.vmm_log() if line.startswith("workdir ")), None)
    log_path = os.path.join(c.aux, "api.log")
    if workdir is None or not os.path.exists(log_path):
        c.fail("the API proxy recorded nothing")
        return
    calls = [request for request in api_requests(log_path) if request[1] != "GET"]
    wanted = [
        ("/boot-source", {"kernel_image_path": State.asset_paths["kernel"],
                          "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init"}),
        ("/drives/rootfs", {"drive_id": "rootfs", "path_on_host": State.asset_paths["rootfs"], "is_root_device": True,
                            "is_read_only": True}),
        ("/drives/job", {"drive_id": "job", "path_on_host": Check(lambda p: isinstance(p, str) and p.startswith(workdir + "/"),
                                                                 "a path in the work directory"),
                         "is_root_device": False, "is_read_only": True}),
        ("/machine-config", {"vcpu_count": 2, "mem_size_mib": 192}),
        ("/vsock", {"guest_cid": 3, "uds_path": workdir + "/v.sock"}),
        ("/actions", {"action_type": "InstanceStart"}),
    ]
    if [(method, path) for _, method, path, _ in calls] != [("PUT", path) for path, _ in wanted]:
        c.fail("API calls were %r" % [(method, path) for _, method, path, _ in calls])
        return
    for (_, _, path, body), (_, expected) in zip(calls, wanted):
        try:
            parsed = json.loads(body)
        except ValueError:
            c.fail("%s body is not JSON" % path)
            continue
        if not (isinstance(parsed, dict) and set(parsed) == set(expected) and all(expected[k] == parsed[k] for k in expected)):
            c.fail("%s body differs: %r" % (path, parsed))


@case("vmm")
def vmm_exits_at_once(c):
    """§6/§11: a VMM that exits at once is vmm_start_failed: exit 5, vmm_started false, cleanup true, never ALLOW."""
    wrapper = c.wrapper("exit_now.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    job.play(*clean_steps(Ses(job)))
    c.gate(job, Expect("INFRASTRUCTURE_FAILED", "vmm_start_failed", vm=False, vmm="yes", assets=assets), lock=lock)


@case("vmm")
def vmm_rejects_garbage_kernel(c):
    """§4/§6: the lock's kernel path is used: a garbage kernel with the right hash makes InstanceStart fail: vmm_start_failed."""
    garbage = os.path.join(c.aux, "garbage-kernel")
    agent_file(garbage, os.urandom(MIB))
    lock, assets = c.write_lock(firecracker=c.wrapper("logging.sh"), kernel=garbage)
    job = c.job()
    job.play(*clean_steps(Ses(job)))
    c.gate(job, Expect("INFRASTRUCTURE_FAILED", "vmm_start_failed", vm=False, vmm="yes", assets=assets), lock=lock)


@case("vmm")
def vmm_boots_garbage_rootfs(c):
    """§4/§6/§7: the lock's rootfs path is used: a garbage rootfs panics the guest and ends the VMM: no_final."""
    garbage = os.path.join(c.aux, "garbage-rootfs")
    agent_file(garbage, os.urandom(MIB))
    lock, assets = c.write_lock(rootfs=garbage)
    job = long_timers(c.job())
    s = Ses(job)
    job.play(*clean_steps(Ses(job)))
    c.gate(job, incomplete(c, "no_final", s, assets=assets), lock=lock)


@case("vmm")
def vmm_path_from_lock(c):
    """§4: the lock's firecracker path is used, with its own hash in the receipt; the session then runs as usual."""
    wrapper = c.wrapper("logging.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, allow(c, s, assets=assets), lock=lock)
    if not [line for line in c.vmm_log() if line.startswith("start")]:
        c.fail("the VMM listed in the lock was not the one started")


def child_gone(c):
    for line in c.vmm_log():
        if line.startswith("child "):
            pid = int(line.split()[1])
            if os.path.exists("/proc/%d" % pid):
                with open("/proc/%d/stat" % pid, "rb") as handle:
                    data = handle.read()
                if data[data.rindex(b")") + 2:data.rindex(b")") + 3] not in b"ZX":
                    c.fail("a same-group child is still alive")


def clean_or_reported(c, decision, reason, ses, assets):
    """§9: the group is dead either way. A killed child the gate cannot reap can still count as in the group, so
    the decision stands, or CLEANUP_UNVERIFIED says so. A live process fails the case in the common checks."""
    def choose(run):
        if run.stdout.split()[:1] == [b"CLEANUP_UNVERIFIED"]:
            return Expect("CLEANUP_UNVERIFIED", reason, ses, assets=assets, max_elapsed=c.fast(),
                          witnesses={"vmm_reaped": False})
        return Expect(decision, reason, ses, assets=assets, max_elapsed=c.fast())
    return choose


@case("teardown")
def teardown_group_child_after_allow(c):
    """§9: a same-group child of the VMM dies with the group after a clean session: ALLOW, or an honest exit 6."""
    wrapper = c.wrapper("child_exec.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, clean_or_reported(c, "ALLOW", "complete", s, assets), lock=lock, hard=c.fast() + 5.0)
    child_gone(c)


@case("teardown")
def teardown_group_child_after_deny(c):
    """§9: a VMM beside a same-group child, all in one group: on a trip the group dies: DENY, or an honest exit 6."""
    wrapper = c.wrapper("child_noexec.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), FOREVER)
    c.gate(job, clean_or_reported(c, "DENY", "prohibited_tool", s, assets), lock=lock, hard=c.fast() + 5.0)
    child_gone(c)


def gone_or_reported(c, decision, reason, ses, assets, extra=0.0):
    """§9: either the work directory is gone and the decision stands, or it remains and CLEANUP_UNVERIFIED says so."""
    def choose(run):
        workdir = next((line[8:] for line in c.vmm_log() if line.startswith("workdir ")), None)
        if workdir is None:
            c.fail("the wrapper never saw the work directory")
        if workdir and os.path.lexists(workdir):
            sockets = [name for name in ("api.sock", "v.sock", "v.sock_5005") if os.path.lexists(os.path.join(workdir, name))]
            return Expect("CLEANUP_UNVERIFIED", reason, ses, assets=assets, residue=True, max_elapsed=c.fast(extra),
                          witnesses={"workdir_removed": False, "sockets_removed": not sockets})
        return Expect(decision, reason, ses, assets=assets, max_elapsed=c.fast(extra))
    return choose


@case("teardown")
def teardown_mode_000_directory_allow(c):
    """§9: a mode-000 directory under the work directory after a clean session: gone with ALLOW, or kept with exit 6."""
    wrapper = c.wrapper("plant000.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, gone_or_reported(c, "ALLOW", "complete", s, assets), lock=lock, hard=c.fast() + 5.0)


@case("teardown")
def teardown_mode_000_directory_deny(c):
    """§9: a mode-000 directory after a trip: gone with DENY, or kept with exit 6 and the reason kept."""
    wrapper = c.wrapper("plant000.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), FOREVER)
    c.gate(job, gone_or_reported(c, "DENY", "prohibited_tool", s, assets), lock=lock, hard=c.fast() + 5.0)


def planter(c):
    """Once the wrapper reports the work directory, plants a root-owned tree the agent user cannot remove."""
    planted = []

    def tick():
        if planted:
            return
        for line in c.vmm_log():
            if line.startswith("workdir "):
                workdir = line[8:]
                held = os.path.join(workdir, "held")
                os.mkdir(held, 0o755)
                with open(os.path.join(held, "file"), "wb") as handle:
                    handle.write(b"x")
                agent_file(os.path.join(c.aux, "planted"), b"")
                planted.append(workdir)
                return
    return tick, planted


def root_held(c, reason, ses, assets):
    def choose(run):
        workdir = next((line[8:] for line in c.vmm_log() if line.startswith("workdir ")), None)
        sockets = [name for name in ("api.sock", "v.sock", "v.sock_5005")
                   if workdir and os.path.lexists(os.path.join(workdir, name))]
        return Expect("CLEANUP_UNVERIFIED", reason, ses, assets=assets, residue=True, max_elapsed=c.fast(),
                      witnesses={"workdir_removed": False, "sockets_removed": not sockets})
    return choose


@case("teardown")
def teardown_undeletable_residue_after_clean_session(c):
    """§9: when the work directory cannot be removed, a clean session is CLEANUP_UNVERIFIED complete, exit 6, never ALLOW."""
    wrapper = c.wrapper("plant_wait.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    tick, _ = planter(c)
    c.gate(job, root_held(c, "complete", s, assets), lock=lock, hard=c.fast() + 5.0, tick=tick)


@case("teardown")
def teardown_undeletable_residue_after_trip(c):
    """§9: when the work directory cannot be removed after a trip, it is CLEANUP_UNVERIFIED and the reason is kept."""
    wrapper = c.wrapper("plant_wait.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    s = Ses(job)
    job.play(*hello_ready(s), SEND(s.propose_trip("read_secret")), FOREVER)
    tick, _ = planter(c)
    c.gate(job, root_held(c, "prohibited_tool", s, assets), lock=lock, hard=c.fast() + 5.0, tick=tick)


@case("teardown")
def teardown_read_only_job_tree(c):
    """§9: read-only directories copied from the job must not defeat cleanup silently: gone with ALLOW, or reported."""
    wrapper = c.wrapper("log_workdir.sh")
    lock, assets = c.write_lock(firecracker=wrapper)
    job = c.job()
    job.files["payload/locked/file.txt"] = b"data\n"

    def lock_down(path):
        os.chmod(os.path.join(path, "payload", "locked", "file.txt"), 0o400)
        os.chmod(os.path.join(path, "payload", "locked"), 0o500)
    job.nodes.append(lock_down)
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, gone_or_reported(c, "ALLOW", "complete", s, assets), lock=lock, hard=c.fast() + 5.0)


# ===================================================================================================
# Receipts, on real runs
# ===================================================================================================

@case("repeat")
def real_receipt_tampering(c):
    """§12: a real receipt is VALID; the same bytes under another key, with a tampered field or a newline, are INVALID."""
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    run = c.gate(job, allow(c, s))
    if c.problems or run.receipt is None:
        return
    check_verify(c, "real receipt", run.receipt, True)
    check_verify(c, "newline", run.receipt + b"\n", False)
    other = os.path.join(c.aux, "otherkey")
    other_key = new_key()
    agent_file(other, other_key, 0o600)
    check_verify(c, "other key", run.receipt, False, keyfile=other, key=other_key)
    original = json.loads(run.receipt)
    for label, change in tamper_list(original):
        altered = json.loads(run.receipt)
        change(altered)
        check_verify(c, "tamper " + label, canon(altered), False)


@case("repeat")
def repeat_stale_garbage_replaced(c):
    """§11: an earlier file at receipt.json, even read-only, is replaced by a correct mode-0600 receipt."""
    make_agent_dir(c.out, 0o755)
    agent_file(os.path.join(c.out, "receipt.json"), b"stale", 0o444)
    job = c.job()
    s = Ses(job)
    job.play(*clean_steps(s))
    c.gate(job, allow(c, s))


@case("repeat")
def repeat_second_run_replaces_allow(c):
    """§11: a DENY run in an output directory holding an earlier ALLOW receipt replaces it; ALLOW must not survive."""
    first = c.job(name="first")
    s1 = Ses(first)
    first.play(*clean_steps(s1))
    c.gate(first, allow(c, s1))
    second = c.job(name="second")
    s2 = Ses(second)
    second.play(*hello_ready(s2), SEND(s2.propose_trip("read_secret")), FOREVER)
    c.gate(second, deny(c, "prohibited_tool", s2))


@case("repeat")
def repeat_nonce_fresh_per_run(c):
    """§6: the session nonce is 64 lowercase hex and fresh per run: the same job twice ends with different evidence roots."""
    job = c.job()
    job.use_program(guest_source("noncecheck.py"))
    s = Ses(job)
    s.hello()
    s.evidence(b"0" * 64)
    s.final()
    fresh = Check(lambda root: root != ZERO, "a non-zero evidence root")
    first = c.gate(job, allow(c, s, root=fresh))
    second = c.gate(job, allow(c, s, root=fresh), out=c.out + "2")
    if first.receipt and second.receipt and not c.problems:
        if json.loads(first.receipt)["evidence_root"] == json.loads(second.receipt)["evidence_root"]:
            c.fail("two runs of one job produced the same evidence root, so the nonce was not fresh")


def parallel_pair(c, job_a, job_b):
    """Runs a slow clean session beside a quick trip, in one run root, so the trip's teardown lands mid-session."""
    a, b = Ses(job_a), Ses(job_b)
    job_a.play(*hello_ready(a), SLEEP(6), *step(a.propose()), *step(a.evidence(b"chunk")), SEND(a.final()), RECV())
    job_b.play(*hello_ready(b), SEND(b.propose_trip("read_secret")), FOREVER)
    before = snapshot()
    app_before = app_snapshot()
    run_a = c.start(job_a, out=c.out + "_a")
    run_b = c.start(job_b, out=c.out + "_b")
    c.wait([run_a, run_b], c.fast(6.0) + 5.0)
    c.check(run_a, allow(c, a, extra=6.0))
    c.check(run_b, deny(c, "prohibited_tool", b, extra=6.0))
    c.after([run_a, run_b], before, app_before)


@case("repeat")
def parallel_allow_and_deny(c):
    """§13: two runs at once in one run root, one ALLOW and one DENY, do not interfere with each other."""
    parallel_pair(c, c.job(name="job_a"), c.job(name="job_b"))


@case("repeat")
def parallel_same_job_id(c):
    """§6/§13: two runs of one job_id at once get separate random work directories and do not interfere."""
    job_id = new_job_id()
    parallel_pair(c, c.job(job_id=job_id, name="job_a"), c.job(job_id=job_id, name="job_b"))
    paths = set()
    for info in c.sampler.seen.values():
        argv = info["argv"]
        if "--api-sock" in argv:
            paths.add(argv[argv.index("--api-sock") + 1])
    if len(paths) != 2:
        c.fail("expected two separate work directories, saw %d" % len(paths))
