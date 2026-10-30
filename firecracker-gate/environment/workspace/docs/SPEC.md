# fcgate specification, version 1

`fcgate` supervises one untrusted program inside one disposable Firecracker microVM and reports a
signed decision about what that program did. This document is the contract. Where it says "must",
the behavior is graded.

## 1. Trust model

- The host, `fcgate`, the lock file and the key file are trusted.
- Everything from the guest is untrusted. The guest program runs as root inside the VM. It may lie in
  any field, send malformed bytes, stall, flood, crash its own kernel, write anything to the serial
  console, or stop at any moment.
- Missing evidence is failure. `ALLOW` means the whole session finished, every rule held and cleanup
  was confirmed. Anything short of that is not `ALLOW`.
- Bytes that originate in the guest or in the job's target and payload must never reach `fcgate`'s
  stdout or stderr, any file in the output directory, or any log. Only the validated numbers and
  hashes defined below may cross. Tool names, declared ones included, cross only as hashes.
- A crash in `fcgate` is a defect, not a decision. On any input from the guest, `fcgate` must finish
  teardown, write its receipt and exit with the code the rules below give. No traceback.

## 2. Command line

```
fcgate run --job DIR --out DIR --key-file FILE [--lock FILE] [--run-root DIR]
fcgate verify --receipt FILE --key-file FILE
```

Defaults: `--lock /opt/lab/assets.lock.json`, `--run-root /dev/shm/fcgate`. `--out` and `--run-root`
are created if missing, mode 0700.

`run` prints exactly one line to stdout, `DECISION reason`, and exits with the decision's code:

| Decision | Exit | Reasons |
|---|---|---|
| `ALLOW` | 0 | `complete` |
| `DENY` | 2 | `prohibited_tool`, `undeclared_tool`, `budget_calls`, `budget_bytes`, `budget_evidence` |
| `RESCOPE_REQUIRED` | 3 | `authority_expansion`, `target_mismatch` |
| `EVALUATION_INCOMPLETE` | 4 | `bad_hello`, `bad_nonce`, `frame_too_large`, `frame_malformed`, `seq_gap`, `chain_mismatch`, `counter_mismatch`, `frame_after_final`, `second_connection`, `timeout_hello`, `timeout_frame`, `timeout_wall`, `no_final` |
| `INFRASTRUCTURE_FAILED` | 5 | `key_invalid`, `manifest_invalid`, `asset_mismatch`, `vmm_start_failed` |
| `CLEANUP_UNVERIFIED` | 6 | any reason above except the four of section 4 (`key_invalid`, `manifest_invalid`, `target_mismatch`, `asset_mismatch`); see section 9 |

Usage errors exit 64 and print nothing to stdout. Exit codes 0 and 2 through 6 are reserved for the
table.

## 3. Job directory

```
manifest.json
target/skill.md        opaque; the host hashes it and copies it, and never interprets it
payload/run            entry program; the guest runs it as: python3 /job/payload/run
payload/...            any further files
```

The job directory holds only regular files and directories. Anything else, such as a symlink, makes
the job `manifest_invalid`. File contents total at most 16 MiB, or the job is `manifest_invalid`. A
missing `target/skill.md` or `payload/run` is `manifest_invalid`.

`manifest.json` is a regular file of at most 64 KiB holding a JSON object with exactly these keys:

```json
{
  "schema": "fcgate-job/v1",
  "job_id": "job-abc123",
  "target_sha256": "<64 lowercase hex: SHA-256 of target/skill.md>",
  "declared_tools": ["read_doc", "list_docs"],
  "prohibited_tools": ["read_secret", "run_shell", "post_url", "install_package"],
  "authority_tools": ["change_policy"],
  "budgets": {
    "max_calls": 8,
    "max_frame_bytes": 65536,
    "max_total_bytes": 1048576,
    "max_evidence_bytes": 1048576,
    "hello_timeout_sec": 20,
    "frame_idle_sec": 10,
    "wall_clock_sec": 60
  },
  "vm": {"vcpus": 1, "mem_mib": 128}
}
```

Validation, any failure being `manifest_invalid`:

- `schema` is exactly `fcgate-job/v1`. `job_id` matches `^job-[a-z0-9]{6,32}$`.
- `target_sha256` is 64 lowercase hex characters.
- Each tool list is an array of strings matching `^[a-z][a-z0-9_]{0,63}$`, with no duplicates inside a
  list and no name in two lists. A list may be empty.
- Budgets are integers, and `true` or `false` is not an integer. Ranges: `max_calls` 0 to 1000,
  `max_frame_bytes` 64 to 1048576, `max_total_bytes` 64 to 67108864, `max_evidence_bytes` 0 to
  1073741824, `hello_timeout_sec` 1 to 600, `frame_idle_sec` 1 to 600, `wall_clock_sec` 1 to 3600.
- `vm.vcpus` is an integer 1 to 4. `vm.mem_mib` is an integer 64 to 2048.
- Duplicate keys, unknown keys, missing keys and wrong types are invalid at every level.

The manifest file may use any JSON formatting. `frozen_sha256` is the SHA-256 of the canonical
encoding (section 5) of the parsed manifest.

## 4. Before boot

Run these checks in order. The first failure ends the run and no VMM is started.

1. Key file (section 10). Failure prints `INFRASTRUCTURE_FAILED key_invalid`, exits 5 and writes no
   receipt, because nothing can sign one.
2. Job directory and manifest (section 3): `manifest_invalid`.
3. SHA-256 of `target/skill.md` against `target_sha256`. A mismatch is `RESCOPE_REQUIRED target_mismatch`.
4. Lock file: `asset_mismatch` if the lock is unreadable or malformed, or if any listed file is
   missing or does not hash to its listed value. The lock has this form, and `fcgate` must use the
   paths it lists rather than fixed ones:

```json
{"firecracker": {"path": "/usr/local/bin/firecracker", "sha256": "<hex>"},
 "kernel": {"path": "/opt/lab/vmlinux", "sha256": "<hex>"},
 "rootfs": {"path": "/opt/lab/rootfs.ext4", "sha256": "<hex>"}}
```

Failures at steps 2 to 4 still write a signed receipt.

## 5. Canonical JSON and frames

Canonical JSON means: object keys sorted by code point; no whitespace; integers in decimal with no
sign, exponent, fraction or leading zero, and at most 2^53 - 1; strings holding only printable ASCII
(0x20 to 0x7E) and no backslash, because no escape sequences exist. Receipts also use `true` and `false`. No other form exists: no floats, no
null, no arrays in frames.

A frame is a 4-byte big-endian unsigned length L followed by L bytes of body. A body must be, byte
for byte, the canonical JSON of one message below. Any other body is `frame_malformed`, which
includes whitespace, unsorted keys, duplicate keys, floats, `NaN`, non-ASCII bytes, invalid UTF-8,
unknown or missing keys, wrong types (`true` is not an integer), and a string that breaks its format.

`hex64` is 64 lowercase hex characters. `name` matches `^[a-z][a-z0-9_]{0,63}$`. `count` is an integer.

Guest to host:

```
{"job":<printable ASCII, 0 to 128 chars>,"nonce":<hex64>,"t":"hello","v":<count>}
{"args_bytes":<count>,"args_sha256":<hex64>,"seq":<count>,"t":"propose","tool":<name>}
{"bytes":<count>,"chunk_sha256":<hex64>,"prev":<hex64>,"seq":<count>,"t":"evidence"}
{"calls":<count>,"evidence_bytes":<count>,"evidence_chunks":<count>,"evidence_root":<hex64>,"seq":<count>,"status":"complete","t":"final"}
```

Host to guest:

```
{"frozen":<hex64>,"t":"ready"}
{"decision":"allow","seq":<count>,"t":"decision"}
{"seq":<count>,"t":"ack"}
{"t":"bye"}
{"t":"trip"}
```

## 6. Booting the VM

- Create a fresh work directory `<run-root>/<job_id>-<random>`, mode 0700. All run files live there.
- Build the job image, an ext4 file made with `mke2fs -q -t ext4 -d TREE FILE`. TREE holds copies of
  `manifest.json`, `target/` and `payload/`, plus `session.json`: the canonical JSON of
  `{"job":<job_id>,"nonce":<N>}`, where N is 64 lowercase hex from the OS random source, fresh per run.
- Start `firecracker --api-sock <workdir>/api.sock` in its own process group and configure it over
  the API socket with exactly these calls, in this order:

```
PUT /boot-source   {"kernel_image_path": <lock kernel path>, "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init"}
PUT /drives/rootfs {"drive_id": "rootfs", "path_on_host": <lock rootfs path>, "is_root_device": true, "is_read_only": true}
PUT /drives/job    {"drive_id": "job", "path_on_host": <job image>, "is_root_device": false, "is_read_only": true}
PUT /machine-config {"vcpu_count": <vm.vcpus>, "mem_size_mib": <vm.mem_mib>}
PUT /vsock         {"guest_cid": 3, "uds_path": "<workdir>/v.sock"}
PUT /actions       {"action_type": "InstanceStart"}
```

- GET requests used to wait for readiness are allowed and do not count as calls. No other call is.
- No network interface may be attached.
- Listen on the Unix socket `<workdir>/v.sock_5005` before `InstanceStart`. A guest `connect()` to
  host CID 2, port 5005 arrives there.
- The serial console appears on the VMM's stdout and is controlled by the guest. It must never reach
  `fcgate`'s outputs and must never be able to block the guest or `fcgate`.
- Any failure to start or configure the VMM, including the VMM exiting before `InstanceStart` is
  accepted, is `INFRASTRUCTURE_FAILED vmm_start_failed`.

The guest's `/init` mounts `/dev/vdb` read-only at `/job` and a tmpfs at `/tmp`, runs the payload as
root, then reboots. With `reboot=k` a guest reboot ends the VMM process.

## 7. The session

Exactly one connection is the session. A second connection at any time before teardown, including
after the final frame, ends the session with `second_connection`.

For each frame from the guest, apply these steps in order. The first one that fails decides.

1. L of 0 is `frame_malformed`. L above `max_frame_bytes` is `frame_too_large`. Both are decided from
   the header alone, without reading a body.
2. If the running total of guest bytes (each counted frame's 4 + L) plus this frame's 4 + L would exceed
   `max_total_bytes`, the result is `budget_bytes`, without reading the body.
3. Read the body. A body that is not canonical and valid under section 5 is `frame_malformed`.
4. The first frame must be `hello`, otherwise `bad_hello`. `job` differing from `job_id`, or `v`
   differing from 1, is `bad_hello`. `nonce` differing from the session nonce is `bad_nonce`. On a valid
   hello the host sends `ready` with `frozen_sha256`. A `hello` after the first frame is `frame_malformed`
   and, having passed step 3, it counts in `frames`.
5. `seq` must be exactly one more than the previous frame's `seq`, and the first after hello is 1.
   Otherwise `seq_gap`.
6. Then by type:
   - `propose`, checked in this order: `tool` in `prohibited_tools` is `prohibited_tool`; in
     `authority_tools` is `authority_expansion`; not in `declared_tools` is `undeclared_tool`; a
     declared tool when `max_calls` calls are already allowed is `budget_calls`. Otherwise count the
     call and send `decision` with that `seq`.
   - `evidence`: `prev` must equal the current head, or `chain_mismatch`. The head starts as 64 zeros.
     If accumulated evidence bytes plus `bytes` would exceed `max_evidence_bytes`, the result is
     `budget_evidence`. Otherwise the new head is the lowercase hex SHA-256 of the 128 ASCII bytes
     `prev` + `chunk_sha256`; add to the chunk and byte counts and send `ack` with that `seq`.
   - `final`: `evidence_root` differing from the head is `chain_mismatch`. `calls`, `evidence_chunks`
     or `evidence_bytes` differing from the host's own counts is `counter_mismatch`. Otherwise the
     session is complete: send `bye`.

After `bye`, wait until the VMM exits or 5 seconds pass. Any further byte on the connection in that
window is `frame_after_final`. The end of the connection is normal, and so is a VMM still running when
the 5 seconds end: teardown kills it and the session stays complete.

Timeouts. `hello_timeout_sec` runs from `InstanceStart` until a complete hello has arrived, and expiry
is `timeout_hello`. `frame_idle_sec` runs from the end of the previous frame until the next frame is
complete, so trickling bytes does not extend it, and expiry is `timeout_frame`. It does not run before
hello. `wall_clock_sec` runs
from `InstanceStart` until `final` is accepted, and expiry is `timeout_wall`. Whichever expires first
decides. Enforce them to within a second.

End of the connection, or exit of the VMM, before `final` is accepted is `no_final`.

When any rule ends the session without completing it, the host sends `trip` if it can do so without
blocking, kills the VMM at once and stops reading. Bytes already queued behind the deciding frame are
neither processed nor counted. `fcgate` must exit within 5 seconds of the session ending, whatever the
guest does.

## 8. Decisions

The first rule to fire decides the reason, and the table in section 2 gives the decision. A complete
session with cleanup confirmed is `ALLOW complete`.

## 9. Teardown

Teardown runs after every run in which a VMM process was started, on every path. Send SIGKILL to the
VMM's process group, reap it, remove the work directory, then confirm from outside:

- `vmm_reaped`: the VMM was reaped and no process remains in its process group.
- `sockets_removed`: the API and vsock sockets no longer exist.
- `workdir_removed`: the work directory no longer exists.

If any of these is false, the decision becomes `CLEANUP_UNVERIFIED`, exit 6, and `reason` keeps the
reason the session ended with. No process and no file from the run may remain after `fcgate` exits,
other than `receipt.json` in the output directory. If you cannot remove something, say so through this
decision. Never report it clean.

## 10. Keys

The key file must be a regular file and not a symlink, owned by the current user, with no group or
other permission bits, 32 to 4096 bytes long, and not made of one repeated byte. The key must never
appear in any output.

## 11. The receipt

`<out>/receipt.json` is written on every run that has a valid key, replacing any earlier receipt
atomically, mode 0600, and it is the only file `fcgate` leaves in the output directory. Its bytes are
exactly the canonical JSON of this object, with no trailing newline:

```json
{"assets":{"firecracker":"<hex>","kernel":"<hex>","rootfs":"<hex>"},
 "counters":{"bytes_in":0,"calls_allowed":0,"evidence_bytes":0,"evidence_chunks":0,"frames":0},
 "decision":"ALLOW","evidence_root":"<hex64>","exit_code":0,"frozen_sha256":"<hex64>","hmac":"<hex64>",
 "job_id":"job-abc123","reason":"complete","schema":"fcgate-receipt/v1","target_sha256":"<hex64>",
 "tripped_tool_sha256":"",
 "witnesses":{"final_seen":true,"guest_hello":true,"sockets_removed":true,"vmm_reaped":true,"vmm_started":true,"workdir_removed":true}}
```

- `hmac` is the lowercase hex HMAC-SHA256, under the key, of the canonical JSON of the object without
  the `hmac` key.
- `frames` counts frames that passed step 3 of section 7, including the one that ended the session.
  `bytes_in` is the sum of 4 + L over those frames. The other counters are the host's own counts.
- `evidence_root` is the head when the session ended, or 64 zeros if there was no evidence.
- `tripped_tool_sha256` is the lowercase hex SHA-256 of the tool name when a `propose` frame that passed
  step 3 of section 7 ended the session, at step 4, 5 or 6, otherwise the empty string.
- `vmm_started` is true once `InstanceStart` was accepted. `guest_hello` is true once a valid hello was
  accepted. `final_seen` is true once a `final` passed section 7 step 6.
- `assets` holds the lock hashes once all were confirmed, otherwise three empty strings.
- `target_sha256` is the hash actually computed from the file, or the empty string if it could not be.
- `job_id` and `frozen_sha256` are empty strings when the manifest is invalid.
- When no VMM process was started, `vmm_reaped`, `sockets_removed` and `workdir_removed` are true, unless
  a work directory was created and cannot be removed: then `workdir_removed` is false and the decision
  is `CLEANUP_UNVERIFIED`.

## 12. Verifying a receipt

`fcgate verify` prints `VALID` and exits 0 only if all of these hold. Otherwise it prints `INVALID` and
exits 1, on every input, with no traceback:

- The key file passes section 10 and the receipt is a regular file of at most 1 MiB.
- Its bytes are canonical JSON with exactly the keys and types of section 11, and `hmac` matches,
  compared in constant time.
- `decision`, `exit_code` and `reason` agree with the table in section 2.
- `ALLOW` has reason `complete` and all six witnesses true. A decision other than `CLEANUP_UNVERIFIED`
  has the three cleanup witnesses true. `CLEANUP_UNVERIFIED` has at least one of them false.

## 13. Not required

The jailer, cgroups, root and network devices are not used. Parallel runs of `fcgate` must not
interfere with each other.

## 14. Your workspace

`/app/examples` holds four sample jobs and `/app/tools/run_examples.py` runs your gate over them.
`/app/tools/mkjob.py` builds a job directory from a payload file. The guest helper `labguest` is
importable by payloads and its source is at `/opt/lab/labguest.py`. Graded guests are not limited to
that helper or to the behavior of the examples.
