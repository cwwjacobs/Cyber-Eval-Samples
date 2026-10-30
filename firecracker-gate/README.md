# firecracker-gate

A cybersecurity task in the Harbor format used by FrontierSWE. The agent builds, from a spec, a
fail-closed gate around a real Firecracker microVM: it boots the guest, brokers the guest's tool
requests over vsock, stops the VM on a prohibited or undeclared tool, treats missing evidence as
failure, leaves nothing behind, and signs a receipt that holds only numbers and hashes.

The verifier runs the agent's program on real VMs against 269 cases, in a separate container. The
guests run as root and misbehave on the protocol: they lie in every field, send malformed bytes,
stall, flood and crash their own kernels. Score is the fraction of cases that are exactly right, and
one wrong `ALLOW` zeroes it. The guests only misbehave on the documented protocol. Nothing here
attacks the hypervisor or the host.

## Requirements

A Linux Docker host with `/dev/kvm`. The task adds only that device: no privileged flag, no added
capabilities, no host root and no change to swap. On a host without KVM the container will not start.

```
harbor run -p firecracker-gate -a oracle   # 1.000
harbor run -p firecracker-gate -a nop      # 0.000
```

A full verifier run takes about 6.5 minutes.

## What has and has not been measured

The reference and the verifier were written independently, each from the spec alone, and agreed on all
269 cases the first time they met.

One blind run gives a first reading on difficulty: Claude Opus 5.5 at xhigh effort, through Harbor's
claude-code agent, with no access to the tests or the reference, stopped on its own after 84 minutes and
scored 0.993 (267 of 269) with no wrong `ALLOW`. Two conclusions follow, for one run only. The task is
fair, because a third blind implementation nearly matches the verifier. And it is not a 20-hour problem
for a frontier agent, because the spec states nearly every rule. A strong engineer without AI help is
estimated at 20 hours or more; that figure is an estimate and has not been measured.

After that run, 15 lines of the spec were clarified without changing what it requires, and the two
cases it missed were widened to accept an honest `CLEANUP_UNVERIFIED` when a killed child remains
unreaped and nothing is alive.

## Layout

| Path | Purpose |
|---|---|
| `instruction.md` | What the agent is told |
| `environment/workspace/docs/SPEC.md` | The contract |
| `environment/guest/` | The guest's init and helper, baked into the read-only root image |
| `environment/workspace/examples/` | Four sample jobs the agent can run |
| `tests/` | The verifier: `cases.py` holds every case and `harness.py` runs them |
| `solution/` | The reference gate, about 1,100 lines of Python |

Firecracker 1.17.0 and the Linux 6.1.188 guest kernel are downloaded at image build, pinned by SHA-256.
