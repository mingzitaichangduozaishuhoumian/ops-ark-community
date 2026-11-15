"""Unprivileged byte relay; every channel opens a new guest-loopback SSH socket."""

import socket
import struct
import sys
import threading
from contextlib import suppress

HEADER = struct.Struct("!cII")
MAX_CHUNK = 65536


def run():
    connections = {}
    lock = threading.Lock()
    output_lock = threading.Lock()

    def send(kind, identifier, data=b""):
        with output_lock:
            sys.stdout.buffer.write(HEADER.pack(kind, identifier, len(data)) + data)
            sys.stdout.buffer.flush()

    def receive(identifier, connection):
        try:
            while data := connection.recv(MAX_CHUNK):
                send(b"D", identifier, data)
        except OSError:
            pass
        finally:
            with lock:
                connections.pop(identifier, None)
            connection.close()
            with suppress(OSError):
                send(b"C", identifier)

    sys.stdout.buffer.write(b"READY\n")
    sys.stdout.buffer.flush()
    try:
        while header := sys.stdin.buffer.read(HEADER.size):
            if len(header) != HEADER.size:
                raise ValueError("Truncated relay header")
            kind, identifier, length = HEADER.unpack(header)
            if kind not in {b"O", b"D", b"E", b"C"} or length > MAX_CHUNK:
                raise ValueError("Invalid relay frame")
            data = sys.stdin.buffer.read(length)
            if len(data) != length or kind != b"D" and data:
                raise ValueError("Truncated or unexpected relay payload")
            with lock:
                connection = connections.get(identifier)
            if kind == b"O":
                if connection is not None or len(connections) >= 16:
                    raise ValueError("Relay channel limit")
                connection = socket.create_connection(("127.0.0.1", 22), timeout=5)
                connection.settimeout(90)
                with lock:
                    connections[identifier] = connection
                threading.Thread(target=receive, args=(identifier, connection), daemon=True).start()
            elif connection is not None:
                with suppress(OSError):
                    if kind == b"D":
                        connection.sendall(data)
                    elif kind == b"E":
                        connection.shutdown(socket.SHUT_WR)
                    else:
                        connection.shutdown(socket.SHUT_RDWR)
    finally:
        with lock:
            remaining = list(connections.values())
        for connection in remaining:
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()


if __name__ == "__main__":
    run()
