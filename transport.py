# transport.py
from __future__ import annotations
from typing import Optional, Tuple

from config import USERS
from protocol import (
    T_I1, T_I2, T_OKX2, T_PROXY_BLOB,
)
# MGMT types referenced by daemon dispatch; resolve_peer should be generic


class Transport:
    """
    L3-ish layer: address book, strict endpoint match, and SAFE peer resolution.
    """
    def __init__(self, name: str, sock, logger):
        self.name = name
        self.sock = sock
        self.logger = logger

    def peer_addr(self, peer: str) -> Tuple[str, int]:
        return USERS[peer]["ip"], USERS[peer]["port"]

    def send_peer(self, peer: str, payload: bytes):
        if peer == self.name:
            self.logger.error(f"[BUG] attempt to send to self peer={peer} DROP")
            return
        ip, port = self.peer_addr(peer)
        self.sock.sendto(payload, (ip, port))

    def peer_from_src(self, src: Tuple[str, int]) -> Optional[str]:
        sip, sport = src
        for u, rec in USERS.items():
            if rec["ip"] == sip and rec["port"] == sport:
                return u
        return None

    def resolve_peer(self, t: str, p: dict, src: Tuple[str, int]) -> Optional[str]:
        """
        - Secure overlay messages: STRICT ip+port only.
        - MGMT/ERROR: allow IP-only fallback (NO trust to claimed 'from').
        """
        secure_types = {T_I1, T_I2, T_OKX2, T_PROXY_BLOB}
        if t in secure_types:
            return self.peer_from_src(src)

        peer = self.peer_from_src(src)
        if peer:
            return peer

        sip, _ = src
        for u, rec in USERS.items():
            if rec["ip"] == sip:
                to = p.get("to")
                if to and to != self.name:
                    return None
                self.logger.warning(f"[ADDR] peer fixed by IP-only: peer={u} src={src} t={t}")
                return u

        return None