# secure_link.py
from __future__ import annotations
from typing import Optional

from crypto_util import aesgcm_encrypt, aesgcm_decrypt
from protocol import jdump

from state import DaemonState


class SecureLink:
    """
    Uses established MGMT session keys to encrypt/decrypt overlay messages.
    """
    def __init__(self, name: str, state: DaemonState, transport, logger):
        self.name = name
        self.state = state
        self.transport = transport
        self.logger = logger

    def link_send(self, peer: str, mtype: str, payload: bytes, meta: Optional[dict] = None):
        with self.state.lock:
            sess = self.state.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session to {peer}")

        aad = f"{mtype}:{self.name}->{peer}:{sess.sid}".encode()
        nonce, ct = aesgcm_encrypt(sess.key, payload, aad=aad)

        msg = {
            "t": mtype, "sid": sess.sid,
            "from": self.name, "to": peer,
            "nonce": nonce.hex(), "ct": ct.hex(),
            "meta": meta or {},
        }
        self.transport.send_peer(peer, jdump(msg))

    def link_decrypt(self, msg: dict) -> bytes:
        peer = msg["from"]
        with self.state.lock:
            sess = self.state.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session from {peer}")

        aad = f"{msg['t']}:{peer}->{self.name}:{sess.sid}".encode()
        return aesgcm_decrypt(
            sess.key,
            bytes.fromhex(msg["nonce"]),
            bytes.fromhex(msg["ct"]),
            aad=aad
        )