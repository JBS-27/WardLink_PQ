"""Length-prefixed frames so a sensor message cannot stick to the next one."""

from __future__ import annotations

import socket

from wardlink.crypto import ChannelError

MAX_FRAME = 20_000
BODY_TIMEOUT = 5.0
HELLO = b"H"
WELCOME = b"W"
DATA = b"D"
NOTE = b"N"
REJECT = b"R"


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if not payload or len(payload) > MAX_FRAME:
        raise ChannelError("frame size is not allowed")
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def recv_frame(sock: socket.socket, timeout: float | None = None, body_timeout: float = BODY_TIMEOUT) -> bytes | None:
    """Return the next frame, or None if no frame started within `timeout`.

    Once a frame has started, the rest must arrive within `body_timeout`; a
    sender that stalls half-way is dropped instead of freezing the reader.
    """
    sock.settimeout(timeout)
    try:
        first = sock.recv(4)
    except TimeoutError:
        return None
    if not first:
        raise ConnectionError("connection closed")
    sock.settimeout(body_timeout)
    try:
        header = first + _recvexact(sock, 4 - len(first))
        length = int.from_bytes(header, "big")
        if length < 1 or length > MAX_FRAME:
            raise ChannelError("frame length is not allowed")
        return _recvexact(sock, length)
    except TimeoutError:
        raise ConnectionError("sender stalled in the middle of a frame") from None


def _recvexact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)
