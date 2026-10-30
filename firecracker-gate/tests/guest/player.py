# Guest program: replays a scripted session. The verifier appends a call to run() with the script.
# The connection comes only from labguest.connect() and session data only from
# labguest.session_info(). Everything after that is raw bytes on the socket or the guest's own console.
import os
import struct
import sys
import time

import labguest


def forever():
    while True:
        time.sleep(3600)


class Player:
    def __init__(self):
        self.sock = None
        self.others = []

    def subst(self, data):
        if b"@JOB" in data or b"@NONCE" in data:
            info = labguest.session_info()
            job, nonce = info["job"].encode(), info["nonce"].encode()
            data = data.replace(b"@JOBTAIL@", job[1:]).replace(b"@JOB@", job)
            data = data.replace(b"@NONCEUP@", nonce.upper()).replace(b"@NONCE@", nonce)
        return data

    def framed(self, bodies):
        out = []
        for item in bodies:
            body = self.subst(bytes.fromhex(item))
            out.append(struct.pack(">I", len(body)) + body)
        return out

    def read(self, count):
        data = b""
        while len(data) < count:
            piece = self.sock.recv(count - len(data))
            if not piece:
                return None
            data += piece
        return data

    def read_frame(self):
        header = self.read(4)
        if header is None:
            return None
        return self.read(struct.unpack(">I", header)[0])

    def poison(self):
        # The host's reply was not what the spec pins, so this session must not end in ALLOW.
        self.sock.sendall(struct.pack(">I", 1) + b"!")
        forever()

    def op_connect(self):
        self.sock = labguest.connect()

    def op_connect2(self):
        self.others.append(labguest.connect())

    def op_send(self, bodies):
        self.sock.sendall(b"".join(self.framed(bodies)))

    def op_raw(self, data):
        self.sock.sendall(self.subst(bytes.fromhex(data)))

    def op_recv(self, count):
        for _ in range(count):
            if self.read_frame() is None:
                return

    def op_reply(self, expected):
        if self.read_frame() != bytes.fromhex(expected):
            self.poison()

    def op_bytewise(self, bodies, delay):
        for frame in self.framed(bodies):
            for index in range(len(frame)):
                self.sock.sendall(frame[index:index + 1])
                if delay:
                    time.sleep(delay)

    def op_persist(self, wait, replied, silent):
        # The frame just sent must have ended the session, so a correct host has stopped by now. If the
        # host is somehow still here, finish normally with the final that fits what it did.
        self.sock.settimeout(wait)
        try:
            answer = self.read_frame()
        except TimeoutError:
            answer = None
        self.sock.settimeout(None)
        self.op_send([replied if answer is not None else silent])
        self.op_recv(1)
        time.sleep(1)

    def op_close(self):
        self.sock.close()

    def op_sleep(self, seconds):
        time.sleep(seconds)

    def op_forever(self):
        forever()

    def op_flood(self):
        block = b"\xa5" * 65536
        while True:
            self.sock.sendall(block)

    def op_console(self, chunk, total):
        data = bytes.fromhex(chunk)
        written = 0
        while written < total:
            written += os.write(1, data)

    def op_console_forever(self, chunk):
        data = bytes.fromhex(chunk)
        while True:
            os.write(1, data)

    def op_console_fork(self, chunk):
        if os.fork() == 0:
            self.op_console_forever(chunk)

    def op_show(self, names):
        # Writes job files to the guest's own console. They must never leave the VM.
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for name in names:
            with open(os.path.join(root, name), "rb") as handle:
                os.write(1, handle.read())

    def op_crash(self):
        with open("/proc/sysrq-trigger", "w") as handle:
            handle.write("c")
        forever()


def run(script):
    player = Player()
    try:
        for step in script:
            getattr(player, "op_" + step[0])(*step[1:])
    except OSError:
        # The host ended the connection. Stay up, so that ending the VM stays the host's job.
        forever()
    sys.stdout.flush()
