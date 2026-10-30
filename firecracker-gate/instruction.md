# Build fcgate: a fail-closed gate around a real Firecracker microVM

You have up to 20 hours. This machine has `/dev/kvm`, Firecracker 1.17.0 at
`/usr/local/bin/firecracker`, a Linux 6.1.188 guest kernel and a read-only guest root image under
`/opt/lab`, and no outbound network. You run as an unprivileged user.

Build `/app/fcgate`: one executable that runs one untrusted program inside one disposable microVM,
brokers the program's tool requests over vsock, stops the VM the moment it requests a prohibited or
undeclared tool, treats missing evidence as failure, leaves nothing behind, and signs a receipt that
holds only numbers and hashes.

`/app/docs/SPEC.md` is the whole contract. Read all of it before you design anything. Use Python 3.11
with the standard library, or C. `/app/examples` and `/app/tools/run_examples.py` let you try it on
real VMs as you go.

Your gate will be graded by running it on real microVMs, unattended, against guest programs you have
not seen. Those programs run as root inside the VM and do whatever they like there: they lie in every
field, send malformed bytes, stall, flood, crash their own kernel. The sample jobs show the protocol,
not the limits of what a guest may do, so hold every rule in the spec for any input.

Score is the fraction of graded runs where the decision, the exit code, the receipt and the cleanup
are all exactly right. A gate that answers `ALLOW` to even one guest that should not get it scores
zero, however much else it gets right. Only `/app/fcgate` and the files it needs under `/app` carry
over to grading.
