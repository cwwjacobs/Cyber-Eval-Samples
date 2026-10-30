#!/usr/bin/python3 -S
# Runs the real VMM on a private API socket and forwards the gate's API traffic to it unchanged,
# logging what the gate sent. It stays out of the way otherwise and exits with the VMM.
import json
import os
import socket
import subprocess
import sys
import threading
import time

AUX = "@AUX@"
REAL = "@REAL@"
LOG_LOCK = threading.Lock()


def log(connection, data):
    with LOG_LOCK:
        with open(os.path.join(AUX, "api.log"), "a") as handle:
            handle.write(json.dumps({"c": connection, "t": time.monotonic(), "b": data.hex()}) + "\n")


def pump(source, sink, connection):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            if connection is not None:
                log(connection, data)
            sink.sendall(data)
    except OSError:
        pass
    for end in (source, sink):
        try:
            end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def serve(listener, private):
    number = 0
    while True:
        client, _ = listener.accept()
        number += 1
        upstream = socket.socket(socket.AF_UNIX)
        upstream.connect(private)
        threading.Thread(target=pump, args=(client, upstream, number), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, None), daemon=True).start()


def main():
    arguments = sys.argv[1:]
    public = arguments[arguments.index("--api-sock") + 1]
    with open(os.path.join(AUX, "vmm.log"), "a") as handle:
        handle.write("start %d\nworkdir %s\n" % (os.getpid(), os.path.dirname(public)))
    private = os.path.join(os.path.dirname(public), "real-api.sock")
    child = subprocess.Popen([REAL, "--api-sock", private], stdin=subprocess.DEVNULL)
    for _ in range(1000):
        if os.path.exists(private) or child.poll() is not None:
            break
        time.sleep(0.005)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(public)
    listener.listen(16)
    threading.Thread(target=serve, args=(listener, private), daemon=True).start()
    os._exit(child.wait())


main()
