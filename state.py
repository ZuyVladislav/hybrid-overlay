# state.py
from __future__ import annotations
import threading
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import x25519


@dataclass
class PendingHS:
    priv: x25519.X25519PrivateKey
    nr: bytes
    ni: bytes
    i_pub: bytes
    label: str


@dataclass
class MgmtSession:
    peer: str
    sid: str
    key: bytes


@dataclass
class ConnState:
    conn_id: str
    src: str
    dst: str
    x1: str
    x2: str
    ike_init_len: int
    ike_auth_len: int
    retries_left: int
    okx2_event: threading.Event
    done_event: threading.Event
    okx2_payload: Optional[bytes] = None
    last_error: Optional[dict] = None


@dataclass
class DaemonState:
    lock: threading.Lock

    # sessions / responder pending
    sessions: Dict[str, MgmtSession]
    pending: Dict[str, PendingHS]

    # mailboxes (receiver thread sets, ensure_session waits)
    hs_initresp: Dict[str, dict]
    hs_authresp: Dict[str, dict]
    hs_init_ev: Dict[str, threading.Event]
    hs_auth_ev: Dict[str, threading.Event]

    # OKX2 mailbox by conn_id
    okx2_ev: Dict[str, threading.Event]
    okx2_data: Dict[str, bytes]
    okx2_x2name: Dict[str, str]

    # active conns (initiator only)
    conns: Dict[str, ConnState]
    ensure_inflight: Dict[str, threading.Event]