# Build Cindermote

`/app` is a checkout of Cindermote, a fail-closed containment runtime for untrusted AI-agent material, with all of its Python source removed. Cindermote detonates a passive `skill.md` or a single URL inside a disposable Firecracker microVM, lets only bounded classifications, hashes and signed receipts cross back to the host, seals the full guest transcript to an offline key, and refuses to report success when any evidence is missing.

Everything else is still there:

- the documentation;
- the JSON schemas and policy files;
- the image definitions and shell scripts;
- the launcher `bin/cindermote`;
- the package bridge `cindermote/__init__.py`;
- the public test suite.

Build the implementation: every module the documentation and tests describe, so that Cindermote behaves as they specify. The system spans:

- evidence cryptography: RFC 9180 HPKE (DHKEM X25519, HKDF-SHA256, ChaCha20-Poly1305), libsodium secretstream framing, canonical JSON and hashing;
- signed contract and receipt envelopes, receipt verification that never raises on malformed input, the policy gate, and the agent-probe broker that trips on prohibited or undeclared tool use;
- the pinned-DNS CONNECT egress proxy and its privilege-separated worker;
- the Firecracker API client, the jailer and microVM lifecycle, rootfs asset verification, and the browser-probe contract and evidence;
- the guest agents that run inside the VM;
- the legacy namespace sandbox, canary probes, observer and the Cinder Incident Gate;
- the doctrine registry check, the CLI and logging.

## Layout

Designing the code is part of the task. The tests import modules by path, such as `agent_probe/hpke.py`, `broker/browser_egress_proxy.py`, `mote/detonate.py` and `incident_gate.py`, and use the classes, functions and constants they need. `docs/FIELD_ATLAS.md`, `docs/SEAM_REGISTRY.md` and `docs/CAPABILITY_MANIFEST.md` map components to files.

Grading carries only these top-level entries of `/app` into the test run, so put your code under them:

- the packages `agent_probe/`, `bin/`, `broker/`, `canaries/`, `cindermote/`, `gate/`, `guest/`, `mote/`, `observer/` and `scripts/`;
- the top-level modules `capability_brokers.py`, `cindermote_api.py`, `cindermote_vertical_spine.py`, `cli.py`, `collapse_mesh.py`, `incident_gate.py`, `kernel_laws.py`, `mcp_guest_controller.py`, `mcp_probe_suite.py`, `mcp_target.py`, `mflog.py` and `semantic_loops.py`;
- the existing documentation and data.

## Evidence-cryptography interfaces

Some graded tests call the evidence-cryptography modules directly, so implement these interfaces exactly.

- `agent_probe/hpke.py`: RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305.
  - `HpkeError(ValueError)`.
  - `generate_key_pair() -> tuple[bytes, bytes]` returns `(private_key, public_key)`, each 32 raw bytes.
  - `seal_base(recipient_public_key, plaintext, *, info, aad, ephemeral_private_key=None) -> SealedBox`, where `SealedBox` is a frozen dataclass with fields `enc` and `ciphertext`.
  - `open_base(recipient_private_key, enc, ciphertext, *, info, aad) -> bytes`.
  - The RFC 9180 internals `_extract_and_expand(dh, kem_context) -> bytes` (the DHKEM shared secret) and `_key_schedule(shared_secret, info) -> tuple[bytes, bytes]` (the base-mode `key` and `base_nonce`).
- `agent_probe/secretstream.py`: libsodium `crypto_secretstream_xchacha20poly1305` through ctypes.
  - `SecretStreamError(RuntimeError)` and `MAX_CHUNK_BYTES = 64 * 1024`.
  - `random_key() -> bytearray` returns a 32-byte key; `memzero(key: bytearray) -> None` zeroes it in place.
  - `EncryptedChunk` is a frozen dataclass with fields `sequence`, `aad`, `ciphertext` and `final`.
  - `PushStream(key)` exposes the stream `header` and has `push(plaintext, *, aad, final=False) -> EncryptedChunk`.
  - `pull_all(key, header, chunks) -> list[bytes]`.
- `agent_probe/crypto.py`: `CryptoEngine` delegates to the two modules through static methods:
  - `generate_hpke_keypair()`;
  - `hpke_seal(recipient_public_key, plaintext, *, info=b"", aad=b"", ephemeral_private_key=None)`;
  - `hpke_open(recipient_private_key, enc, ciphertext, *, info=b"", aad=b"")`;
  - `secretstream_create_key()`, `secretstream_push_stream(key)` and `secretstream_pull_all(key, header, chunks)`.
- Every failure is reported through the module's own exception type:
  - `HpkeError` for wrong-length keys and any failed open;
  - `SecretStreamError` for a wrong-length key, a push after the final chunk, an oversized chunk, and a transcript whose final-chunk flag disagrees with the authenticated tag.

## What you have

- Documentation: `README.md`, `RUNBOOK.md`, `VALIDATION.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `docs/` and `policy/README.md`. `docs/audits/evidence/` holds real signed receipts, evidence and logs produced by the original.
- The public test suite in `/app/tests`. Run it with `cd /app && python3 -m pytest -q tests`. Tests that need KVM, root, a writable cgroup v2 hierarchy, Linux namespaces or live provider credentials skip in this container and are not graded.
- Python 3.11 with `cryptography`, `pytest` and `pytest-cov` installed in `/opt/venv` (already on `PATH`), and the system libsodium (`libsodium.so.23`).

## How you are graded

When you stop, the test suite runs against `/app` as an unprivileged user. It consists of the public tests plus a small held-out set that exercises the evidence-cryptography interfaces above against RFC 9180 and libsodium. Your score is the fraction of graded tests that pass.

Some tests are not graded: those that the starting tree passes, those a tree with every module present but no function bodies would pass, and those a tree whose functions all return `None` would pass. Partial credit counts: each part that works earns its tests even if others do not.

- Your copies of the public tests are replaced by pristine ones before grading, and any pytest configuration or `conftest.py` you add is ignored, so changing tests does not help.
- Each test has a time limit, so a function that hangs fails its own test rather than the whole run.

## Constraints

- The machine has no internet access. Everything you need is in `/app` and in your knowledge of the standards involved.
- Work only inside `/app`; nothing outside it is graded. Keep the tree importable as you go and save your work often. The session can end without warning, and whatever is in `/app` at that moment is what gets graded.
