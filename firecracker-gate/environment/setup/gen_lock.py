#!/usr/bin/env python3
"""Write /opt/lab/assets.lock.json from the assets in this image."""
import hashlib
import json

ASSETS = {"firecracker": "/usr/local/bin/firecracker", "kernel": "/opt/lab/vmlinux", "rootfs": "/opt/lab/rootfs.ext4"}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


lock = {name: {"path": path, "sha256": sha256(path)} for name, path in ASSETS.items()}
with open("/opt/lab/assets.lock.json", "w") as handle:
    json.dump(lock, handle, indent=1, sort_keys=True)
