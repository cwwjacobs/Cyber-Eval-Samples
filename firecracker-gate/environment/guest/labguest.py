"""Guest-side helper for payloads. Runs inside the VM, speaks the session protocol."""
import hashlib
import json
import socket
import struct

HOST_CID = 2
PORT = 5005
ZERO = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def session_info():
    with open("/job/session.json", "rb") as handle:
        return json.loads(handle.read())


def manifest():
    with open("/job/manifest.json", "rb") as handle:
        return json.loads(handle.read())


def connect():
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((HOST_CID, PORT))
    return sock


def send_raw(sock, body):
    sock.sendall(struct.pack(">I", len(body)) + body)


def send_frame(sock, obj):
    send_raw(sock, canonical(obj))


def recv_frame(sock):
    def read(count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    header = read(4)
    if header is None:
        return None
    body = read(struct.unpack(">I", header)[0])
    return None if body is None else json.loads(body)


class Session:
    """A well-behaved session. Each call waits for the host's reply and returns it."""

    def __init__(self):
        self.sock = connect()
        self.seq = 0
        self.head = ZERO
        self.calls = 0
        self.chunks = 0
        self.evidence_bytes = 0

    def hello(self):
        info = session_info()
        send_frame(self.sock, {"job": info["job"], "nonce": info["nonce"], "t": "hello", "v": 1})
        return recv_frame(self.sock)

    def _next_seq(self):
        self.seq += 1
        return self.seq

    def propose(self, tool, args=b""):
        send_frame(self.sock, {"args_bytes": len(args), "args_sha256": hashlib.sha256(args).hexdigest(),
                               "seq": self._next_seq(), "t": "propose", "tool": tool})
        reply = recv_frame(self.sock)
        if reply and reply.get("t") == "decision":
            self.calls += 1
        return reply

    def evidence(self, data):
        chunk = hashlib.sha256(data).hexdigest()
        send_frame(self.sock, {"bytes": len(data), "chunk_sha256": chunk, "prev": self.head,
                               "seq": self._next_seq(), "t": "evidence"})
        reply = recv_frame(self.sock)
        if reply and reply.get("t") == "ack":
            self.head = hashlib.sha256((self.head + chunk).encode("ascii")).hexdigest()
            self.chunks += 1
            self.evidence_bytes += len(data)
        return reply

    def final(self):
        send_frame(self.sock, {"calls": self.calls, "evidence_bytes": self.evidence_bytes,
                               "evidence_chunks": self.chunks, "evidence_root": self.head,
                               "seq": self._next_seq(), "status": "complete", "t": "final"})
        return recv_frame(self.sock)
