# Guest program: reports what this VM really is, as one evidence chunk. The verifier can predict the
# resulting evidence_root only if the VM matches the spec and the manifest.
import os

import labguest


def text(path):
    with open(path) as handle:
        return handle.read()


def attempt(function):
    try:
        return function()
    except Exception as error:  # noqa: BLE001 - any failure simply changes the reported fact
        return "error " + type(error).__name__


def cpu_count():
    count = 0
    for part in text("/sys/devices/system/cpu/online").strip().split(","):
        first, _, last = part.partition("-")
        count += int(last or first) - int(first) + 1
    return count


def ram_mib():
    top = 0
    for line in text("/proc/iomem").splitlines():
        if line.endswith(": System RAM"):
            top = max(top, int(line.split(" :")[0].split("-")[1], 16))
    return (top + 1) >> 20


def boot_args():
    tokens = text("/proc/cmdline").split()
    size = 5
    # The VMM itself appends these tokens after the boot arguments it was given.
    added = [t for t in tokens[size:] if not (t in ("pci=off", "root=/dev/vda", "ro") or t.startswith("virtio_mmio.device="))]
    return {"given": " ".join(tokens[:size]), "other": added,
            "mmio": len([t for t in tokens if t.startswith("virtio_mmio.device=")])}


def virtio_ids():
    base = "/sys/bus/virtio/devices"
    return sorted(text(os.path.join(base, name, "device")).strip() for name in os.listdir(base))


facts = {
    "boot": attempt(boot_args),
    "mem_mib": attempt(ram_mib),
    "net": attempt(lambda: sorted(os.listdir("/sys/class/net"))),
    "release": attempt(lambda: os.uname().release),
    "vcpus": attempt(cpu_count),
    "vda_ro": attempt(lambda: text("/sys/block/vda/ro").strip()),
    "vdb_ro": attempt(lambda: text("/sys/block/vdb/ro").strip()),
    "virtio": attempt(virtio_ids),
}
session = labguest.Session()
session.hello()
session.evidence(labguest.canonical(facts))
session.final()
