# -*- coding: utf-8 -*-
"""
node_daemon.py (clean build)

Key properties:
- Single UDP receiver thread -> no recvfrom() race.
- Hop-to-hop mgmt session: 4-step exchange, X25519 + HKDF-SHA256 + AESGCM.
- A chooses X1 randomly (exclude only A). X1 chooses X2 randomly (exclude only X1).
- X2==B case is detected on X2 when it sees dst==self AND role==X2 -> reject + ERROR back + A retries.
- OK(X2) is delivered as secure payload X2->X1 (KD2) then X1->A (KD1).
- No sleep polling for OKX2 / HS responses: mailbox events.

Requires: config.py, crypto_util.py, logging_util.py, protocol.py
"""

import argparse
import secrets
import socket
import threading
import time
import random
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, List

from cryptography.hazmat.primitives.asymmetric import x25519

from config import USERS, UDP_TIMEOUT_S, RETRIES, I3_LEN
from logging_util import setup_logger
from crypto_util import (
    aesgcm_encrypt, aesgcm_decrypt,
    hkdf_sha256,
    xpub_bytes, xpub_from_bytes,
)
from protocol import (
    jdump, jload, err,
    T_MGMT_INIT, T_MGMT_INIT_RESP, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_I1, T_I2, T_OKX2,
    T_PROXY_BLOB,
    T_LOCAL_CONNECT,
    T_ERROR,
)

# =========================
# Structures
# =========================

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
    okx2_payload: Optional[bytes] = None  # raw OK bytes (Epk+Salt, etc)
    last_error: Optional[dict] = None


# =========================
# Daemon
# =========================

class NodeDaemon:
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(name)

        port = USERS[name]["port"]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(0.2)

        self.lock = threading.Lock()
        self.running = True

        # sessions / pending responder state
        self.sessions: Dict[str, MgmtSession] = {}
        self.pending: Dict[str, PendingHS] = {}

        # ---- Mailboxes (only receiver thread reads socket) ----
        # handshake mailbox by sid
        self.hs_initresp: Dict[str, dict] = {}
        self.hs_authresp: Dict[str, dict] = {}
        self.hs_init_ev: Dict[str, threading.Event] = {}
        self.hs_auth_ev: Dict[str, threading.Event] = {}

        # OKX2 mailbox by requester (A) and conn_id
        self.okx2_ev: Dict[str, threading.Event] = {}          # conn_id -> Event
        self.okx2_data: Dict[str, bytes] = {}                  # conn_id -> OK bytes
        self.okx2_x2name: Dict[str, str] = {}                  # conn_id -> chosen X2 (for visibility)

        # active connections (initiator only)
        self.conns: Dict[str, ConnState] = {}

    # ---------- address book ----------
    def peer_addr(self, peer: str) -> Tuple[str, int]:
        return USERS[peer]["ip"], USERS[peer]["port"]

    def send_peer(self, peer: str, payload: bytes):
        ip, port = self.peer_addr(peer)
        self.sock.sendto(payload, (ip, port))

    def peer_from_src(self, src: Tuple[str, int]) -> Optional[str]:
        sip, sport = src
        for u, rec in USERS.items():
            if rec["ip"] == sip and rec["port"] == sport:
                return u
        return None

    # ---------- JSON ----------
    def safe_load(self, data: bytes) -> Optional[dict]:
        try:
            return jload(data)
        except Exception:
            self.logger.warning("Malformed packet (non-json)")
            return None

    # ---------- mgmt KDF ----------
    def mgmt_kdf(self, shared: bytes, ni: bytes, nr: bytes, label: str) -> bytes:
        salt = ni + nr
        info = b"mgmt|ikev2-like|" + label.encode("utf-8")
        return hkdf_sha256(shared, salt=salt, info=info, length=32)

    # ---------- recv ----------
    def recv_one(self) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        try:
            data, src = self.sock.recvfrom(65535)
            return data, src
        except socket.timeout:
            return None

    # =========================
    # Link crypto
    # =========================

    def link_send(self, peer: str, mtype: str, payload: bytes, meta: dict = None):
        with self.lock:
            sess = self.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session to {peer}")

        aad = f"{mtype}:{self.name}->{peer}:{sess.sid}".encode()
        nonce, ct = aesgcm_encrypt(sess.key, payload, aad=aad)

        msg = {"t": mtype, "sid": sess.sid, "from": self.name, "to": peer,
               "nonce": nonce.hex(), "ct": ct.hex(), "meta": meta or {}}
        self.send_peer(peer, jdump(msg))

    def link_decrypt(self, msg: dict) -> bytes:
        peer = msg["from"]
        with self.lock:
            sess = self.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session from {peer}")

        aad = f"{msg['t']}:{peer}->{self.name}:{sess.sid}".encode()
        return aesgcm_decrypt(sess.key, bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), aad=aad)

    # =========================
    # One and only packet dispatcher (called from receiver loop)
    # =========================

    def handle_packet(self, data: bytes, src: Tuple[str, int]):
        peer = self.peer_from_src(src)
        p = self.safe_load(data)
        if not p:
            return

        t = p.get("t")

        # --- LOCAL control ---
        if t == T_LOCAL_CONNECT:
            self.on_local_connect(p, src)
            return

        # --- MGMT handshake responder side ---
        if t == T_MGMT_INIT:
            self.on_mgmt_init(p, peer)
            return

        if t == T_MGMT_AUTH:
            self.on_mgmt_auth(p, peer)
            return

        # --- MGMT handshake initiator side mailbox ---
        if t == T_MGMT_INIT_RESP:
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_initresp[sid] = p
                    ev = self.hs_init_ev.get(sid)
                if ev:
                    ev.set()
            return

        if t == T_MGMT_AUTH_RESP:
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_authresp[sid] = p
                    ev = self.hs_auth_ev.get(sid)
                if ev:
                    ev.set()
            return

        # --- errors are plaintext ---
        if t == T_ERROR:
            self.on_error(p, peer)
            return

        # --- secure messages ---
        if t in (T_I1, T_I2, T_OKX2, T_PROXY_BLOB):
            self.on_secure_msg(p, peer)
            return

        self.logger.info(f"[DROP] unknown t={t} from={peer}")

    # =========================
    # MGMT responder
    # =========================

    def on_mgmt_init(self, p: dict, peer: Optional[str]):
        if not peer:
            return
        sid = p["sid"]
        i_pub = bytes.fromhex(p["ke"])
        ni = bytes.fromhex(p["ni"])

        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = xpub_bytes(r_priv.public_key())
        nr = secrets.token_bytes(16)

        label = f"{peer}-{self.name}"
        with self.lock:
            self.pending[sid] = PendingHS(priv=r_priv, nr=nr, ni=ni, i_pub=i_pub, label=label)

        resp = jdump({
            "t": T_MGMT_INIT_RESP, "sid": sid, "from": self.name, "to": peer,
            "nr": nr.hex(), "ke": r_pub.hex()
        })
        self.send_peer(peer, resp)
        self.logger.info(f"[MGMT] <- {peer} INIT; -> INIT_RESP sid={sid}")

    def on_mgmt_auth(self, p: dict, peer: Optional[str]):
        if not peer:
            return
        sid = p["sid"]

        with self.lock:
            st = self.pending.get(sid)
        if not st:
            self.logger.warning(f"[MGMT] AUTH unknown sid={sid}")
            return

        shared = st.priv.exchange(xpub_from_bytes(st.i_pub))
        kd = self.mgmt_kdf(shared, st.ni, st.nr, label=st.label)

        aad = f"AUTH:{st.label}:{peer}->{self.name}:{sid}".encode()
        try:
            _ = aesgcm_decrypt(kd, bytes.fromhex(p["nonce"]), bytes.fromhex(p["ct"]), aad=aad)
        except Exception as e:
            self.logger.error(f"[MGMT] AUTH decrypt fail sid={sid}: {e}")
            self.send_peer(peer, err("AUTH_FAIL", "mgmt auth decrypt failed"))
            return

        # AUTH_RESP
        aad2 = f"AUTH:{st.label}:{self.name}->{peer}:{sid}".encode()
        auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
        n2, c2 = aesgcm_encrypt(kd, auth_plain, aad=aad2)

        resp = jdump({"t": T_MGMT_AUTH_RESP, "sid": sid, "from": self.name, "to": peer,
                      "nonce": n2.hex(), "ct": c2.hex()})
        self.send_peer(peer, resp)

        with self.lock:
            self.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)
            self.pending.pop(sid, None)

        self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")

    # =========================
    # MGMT initiator (ensure_session) using mailbox events
    # =========================

    def ensure_session(self, peer: str) -> bool:
        with self.lock:
            if peer in self.sessions:
                return True

        label = f"{self.name}-{peer}"

        for attempt in range(RETRIES):
            sid = secrets.token_hex(8)
            init_ev = threading.Event()
            auth_ev = threading.Event()
            with self.lock:
                self.hs_init_ev[sid] = init_ev
                self.hs_auth_ev[sid] = auth_ev
                self.hs_initresp.pop(sid, None)
                self.hs_authresp.pop(sid, None)

            i_priv = x25519.X25519PrivateKey.generate()
            i_pub = xpub_bytes(i_priv.public_key())
            ni = secrets.token_bytes(16)

            init_msg = jdump({
                "t": T_MGMT_INIT, "sid": sid, "from": self.name, "to": peer,
                "ni": ni.hex(), "ke": i_pub.hex()
            })
            self.send_peer(peer, init_msg)
            self.logger.info(f"[MGMT] -> {peer} INIT sid={sid} attempt={attempt+1}")

            # wait INIT_RESP
            if not init_ev.wait(UDP_TIMEOUT_S):
                self.logger.warning(f"[MGMT] timeout INIT_RESP from {peer} sid={sid}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp = self.hs_initresp.get(sid)

            if not resp or resp.get("from") != peer or resp.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad INIT_RESP mailbox sid={sid}")
                self._cleanup_hs(sid)
                continue

            nr = bytes.fromhex(resp["nr"])
            r_pub = bytes.fromhex(resp["ke"])
            shared = i_priv.exchange(xpub_from_bytes(r_pub))
            kd = self.mgmt_kdf(shared, ni, nr, label=label)

            # send AUTH
            aad = f"AUTH:{label}:{self.name}->{peer}:{sid}".encode()
            auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
            n1, c1 = aesgcm_encrypt(kd, auth_plain, aad=aad)
            auth_msg = jdump({"t": T_MGMT_AUTH, "sid": sid, "from": self.name, "to": peer,
                              "nonce": n1.hex(), "ct": c1.hex()})
            self.send_peer(peer, auth_msg)

            # wait AUTH_RESP
            if not auth_ev.wait(UDP_TIMEOUT_S):
                self.logger.warning(f"[MGMT] timeout AUTH_RESP from {peer} sid={sid}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp2 = self.hs_authresp.get(sid)

            if not resp2 or resp2.get("from") != peer or resp2.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad AUTH_RESP mailbox sid={sid}")
                self._cleanup_hs(sid)
                continue

            aad2 = f"AUTH:{label}:{peer}->{self.name}:{sid}".encode()
            try:
                _ = aesgcm_decrypt(kd, bytes.fromhex(resp2["nonce"]), bytes.fromhex(resp2["ct"]), aad=aad2)
            except Exception as e:
                self.logger.error(f"[MGMT] AUTH_RESP decrypt fail: {e}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                self.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)

            self._cleanup_hs(sid)
            self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")
            return True

        return False

    def _cleanup_hs(self, sid: str):
        with self.lock:
            self.hs_init_ev.pop(sid, None)
            self.hs_auth_ev.pop(sid, None)
            self.hs_initresp.pop(sid, None)
            self.hs_authresp.pop(sid, None)

    # =========================
    # Secure messages (I1/I2/OKX2/PROXY)
    # =========================

    def on_secure_msg(self, p: dict, peer: Optional[str]):
        if not peer:
            return
        t = p["t"]
        try:
            plain = self.link_decrypt(p)
        except Exception as e:
            self.logger.error(f"[SEC] decrypt fail t={t} from={peer}: {e}")
            return

        if t == T_I1:
            self.handle_I1(peer, plain)
        elif t == T_I2:
            self.handle_I2(peer, plain)
        elif t == T_OKX2:
            self.handle_OKX2(peer, plain)
        elif t == T_PROXY_BLOB:
            self.handle_PROXY(peer, plain, p.get("meta") or {})

    # ---- helpers for parsing I1/I2/OK ----
    @staticmethod
    def _kv_parse(s: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        parts = s.split("|")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # I1: A->X1 (Enc_KD1): "CONN=<id>|REQ=<A>|DST=<B>"
    def handle_I1(self, peer: str, plain: bytes):
        s = plain.rstrip(b"\x00").decode(errors="ignore")
        self.logger.info(f"[I1] from={peer} '{s}'")
        kv = self._kv_parse(s)
        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        dst = kv.get("DST", "")

        if not conn_id or not req or not dst:
            self.logger.error("[I1] bad fields")
            return
        if req not in USERS or dst not in USERS:
            self.logger.error("[I1] unknown REQ/DST")
            return

        # X1 chooses X2 randomly excluding only itself (A/B allowed!)
        all_users = list(USERS.keys())
        cand_x2 = [u for u in all_users if u != self.name]
        x2 = random.choice(cand_x2)

        if not self.ensure_session(x2):
            self.logger.error(f"[I1] cannot establish session to X2={x2}")
            # send plaintext error back to req via peer
            self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_SESSION_X2", msg=f"cannot ensure {x2}")
            return

        # I2: X1->X2 (Enc_KD2): "CONN=<id>|REQ=<A>|DST=<B>|X2=<X2>"
        i2 = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode().ljust(128, b"\x00")
        self.link_send(x2, T_I2, i2)
        self.logger.info(f"[I1] choose X2={x2}; -> I2 to {x2} for REQ={req}, DST={dst}")

    # I2: X1->X2 (Enc_KD2)
    def handle_I2(self, peer: str, plain: bytes):
        s = plain.rstrip(b"\x00").decode(errors="ignore")
        self.logger.info(f"[I2] from={peer} '{s}'")
        kv = self._kv_parse(s)
        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        dst = kv.get("DST", "")
        x2 = kv.get("X2", "")

        if not conn_id or not req or not dst or not x2:
            self.logger.error("[I2] bad fields")
            return

        # OK(X2): generate ephemeral public material (demo: 32+16)
        ok = secrets.token_bytes(32) + secrets.token_bytes(16)  # Epk + Salt (demo)
        payload = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}|".encode() + ok

        # send OKX2 back to X1 over KD2 (peer is X1)
        self.link_send(peer, T_OKX2, payload)
        self.logger.info(f"[OKX2] -> {peer} CONN={conn_id} for REQ={req} ok_len={len(ok)}")

    # OKX2: X2->X1 (KD2) then X1->A (KD1)
    def handle_OKX2(self, peer: str, plain: bytes):
        # header ends at first b"|"
        if b"|" not in plain:
            self.logger.warning("[OKX2] bad format")
            return
        hdr, ok = plain.split(b"|", 1)
        hdr_s = hdr.decode(errors="ignore")
        kv = self._kv_parse(hdr_s)

        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        x2 = kv.get("X2", "")

        self.logger.info(f"[OKX2] from={peer} CONN={conn_id} REQ={req} X2={x2} ok_len={len(ok)}")

        # forward to requester if I'm not requester
        if self.name != req:
            if req not in USERS:
                return
            if req not in self.sessions and not self.ensure_session(req):
                self.logger.error(f"[OKX2] cannot ensure session to {req}")
                return
            self.link_send(req, T_OKX2, plain)
            self.logger.info(f"[OKX2] fwd {self.name}->{req} CONN={conn_id}")
            return

        # I'm requester(A): signal conn mailbox by conn_id
        with self.lock:
            ev = self.okx2_ev.get(conn_id)
            self.okx2_data[conn_id] = ok
            self.okx2_x2name[conn_id] = x2
        if ev:
            ev.set()

    # PROXY_BLOB forward path: src->x1->x2->dst; back path: dst->x2->x1->src
    def handle_PROXY(self, peer: str, plain: bytes, meta: dict):
        conn_id = meta.get("conn_id", "")
        src_u = meta.get("src", "")
        dst_u = meta.get("dst", "")
        x1_u = meta.get("x1", "")
        x2_u = meta.get("x2", "")
        idx = int(meta.get("idx", 0))
        direction = meta.get("dir", "fwd")  # "fwd" or "back"
        phase = meta.get("phase", "UNK")

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        if idx < 0 or idx >= len(route) or route[idx] != self.name:
            self.logger.warning(f"[PROXY] route mismatch idx={idx} dir={direction} route={route}")
            return

        # ---- Mode B reject: if I'm X2 AND I'm also DST -> reject
        if self.name == x2_u and self.name == dst_u and direction == "fwd":
            self.logger.warning(f"[PROXY] REJECT X2==DST ({self.name}) CONN={conn_id}")
            self.send_error_back(conn_id, src_u, x1_u, phase, code="DEST_IS_X2", msg="X2 became destination; drop+retry")
            return

        # reached destination on forward direction
        if direction == "fwd" and self.name == dst_u and idx == 3:
            self.logger.info(f"[PROXY] ARRIVE DST={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
            # emulate response (in real impl: actual IKE response blob)
            resp = plain
            meta2 = dict(meta)
            meta2["dir"] = "back"
            meta2["idx"] = 0  # at dst start of back-route
            self.forward_proxy(resp, meta2)
            return

        self.forward_proxy(plain, meta)

    def forward_proxy(self, payload: bytes, meta: dict):
        src_u = meta["src"]; dst_u = meta["dst"]; x1_u = meta["x1"]; x2_u = meta["x2"]
        idx = int(meta["idx"])
        direction = meta.get("dir", "fwd")
        phase = meta.get("phase", "UNK")
        conn_id = meta.get("conn_id", "")

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        nxt_idx = idx + 1
        if nxt_idx >= len(route):
            return
        nxt = route[nxt_idx]

        if nxt not in self.sessions and not self.ensure_session(nxt):
            self.logger.error(f"[PROXY] cannot ensure session to {nxt}")
            self.send_error_back(conn_id, src_u, x1_u, phase, code="NO_SESSION_NEXT", msg=f"cannot ensure {nxt}")
            return

        meta2 = dict(meta)
        meta2["idx"] = nxt_idx
        self.link_send(nxt, T_PROXY_BLOB, payload, meta=meta2)
        self.logger.info(f"[PROXY] {direction} {self.name}->{nxt} idx={nxt_idx} phase={phase} CONN={conn_id}")

    # =========================
    # Plaintext ERROR forward (overlay control plane)
    # =========================

    def send_error_back(self, conn_id: str, src_u: str, x1_u: str, phase: str, code: str, msg: str):
        # We send plaintext ERROR towards src via chain: current -> x1 -> src (minimal)
        back_route = [self.name, x1_u, src_u] if self.name != x1_u else [self.name, src_u]
        if len(back_route) < 2:
            return
        nxt = back_route[1]
        payload = err(code, msg, meta={
            "conn_id": conn_id,
            "src": src_u,
            "x1": x1_u,
            "phase": phase,
            "idx": 1,
            "route": back_route
        })
        self.send_peer(nxt, payload)

    def on_error(self, p: dict, peer: Optional[str]):
        code = p.get("code", "ERR")
        msg = p.get("msg", "")
        meta = p.get("meta") or {}
        conn_id = meta.get("conn_id", "")
        self.logger.error(f"[ERROR] code={code} msg='{msg}' from={peer} CONN={conn_id}")

        # forward along meta.route if present
        route = meta.get("route", [])
        idx = int(meta.get("idx", 0))
        if isinstance(route, list) and route and idx < len(route) - 1:
            nxt = route[idx + 1]
            meta2 = dict(meta); meta2["idx"] = idx + 1
            fwd = {"t": T_ERROR, "code": code, "msg": msg, "meta": meta2}
            self.send_peer(nxt, jdump(fwd))
            return

        # if I'm initiator and this conn exists -> signal done_event
        if conn_id and conn_id in self.conns:
            st = self.conns[conn_id]
            st.last_error = {"code": code, "msg": msg}
            st.done_event.set()

    # =========================
    # LOCAL_CONNECT + Initiator routine
    # =========================

    def on_local_connect(self, p: dict, src: Tuple[str, int]):
        # only localhost control
        if src[0] not in ("127.0.0.1", "::1", "localhost"):
            self.logger.warning("[LOCAL] reject non-local")
            return

        user = p.get("user")
        password = p.get("pass")
        dst = p.get("dst")
        ike_init_len = int(p.get("ike_init_len", 499))
        ike_auth_len = int(p.get("ike_auth_len", 499))
        retries = int(p.get("retries", 5))

        if user != self.name:
            self.sock.sendto(err("BAD_SRC", "LOCAL_CONNECT user must equal daemon name"), src)
            return
        if user not in USERS or USERS[user]["password"] != password:
            self.sock.sendto(err("AUTH_FAIL", "bad user/password"), src)
            return
        if dst not in USERS:
            self.sock.sendto(err("BAD_DST", "unknown dst"), src)
            return

        # A chooses X1 randomly from all except itself (dst allowed!)
        all_users = list(USERS.keys())
        cand_x1 = [u for u in all_users if u != user]
        x1 = random.choice(cand_x1)

        conn_id = secrets.token_hex(8)

        ok_ev = threading.Event()
        done_ev = threading.Event()
        with self.lock:
            self.okx2_ev[conn_id] = ok_ev
            self.okx2_data.pop(conn_id, None)
            self.okx2_x2name.pop(conn_id, None)

        st = ConnState(
            conn_id=conn_id,
            src=user, dst=dst,
            x1=x1, x2="",
            ike_init_len=ike_init_len,
            ike_auth_len=ike_auth_len,
            retries_left=retries,
            okx2_event=ok_ev,
            done_event=done_ev,
        )
        self.conns[conn_id] = st

        th = threading.Thread(target=self.run_connection, args=(st,), daemon=True)
        th.start()

        self.sock.sendto(jdump({"ok": True, "conn_id": conn_id, "x1": x1, "msg": "started"}), src)

    def run_connection(self, st: ConnState):
        # Attempt loop (auto-retry on error or X2==DST reject)
        while st.retries_left >= 0:
            st.done_event.clear()
            st.okx2_event.clear()
            st.last_error = None

            # 1) ensure A<->X1 mgmt session
            if st.x1 not in self.sessions and not self.ensure_session(st.x1):
                self.logger.error(f"[CONN {st.conn_id}] cannot establish to X1={st.x1}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src)
                continue

            # 2) send I1 to X1: request OK(X2), X1 will pick X2 itself
            i1 = f"CONN={st.conn_id}|REQ={st.src}|DST={st.dst}".encode().ljust(128, b"\x00")
            self.link_send(st.x1, T_I1, i1)
            self.logger.info(f"[CONN {st.conn_id}] I1 sent to X1={st.x1} (X1 picks X2)")

            # 3) wait for OKX2 (arrives at A, includes chosen X2)
            if not st.okx2_event.wait(UDP_TIMEOUT_S * 6):
                self.logger.error(f"[CONN {st.conn_id}] timeout waiting OKX2")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src)
                continue

            with self.lock:
                ok = self.okx2_data.get(st.conn_id)
                x2 = self.okx2_x2name.get(st.conn_id, "")

            if not ok or not x2:
                self.logger.error(f"[CONN {st.conn_id}] OKX2 missing data")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src)
                continue

            st.x2 = x2
            self.logger.info(f"[CONN {st.conn_id}] got OKX2, chosen X2={st.x2}, ok_len={len(ok)}")

            # 4) Build container + proxy IKE blobs (demo payload; real impl would inject real IKE bytes)
            init_payload = self.make_container(st.dst, ike_len=st.ike_init_len)
            auth_payload = self.make_container(st.dst, ike_len=st.ike_auth_len)

            meta_base = {"conn_id": st.conn_id, "src": st.src, "dst": st.dst, "x1": st.x1, "x2": st.x2}
            meta_init = dict(meta_base); meta_init.update({"idx": 1, "dir": "fwd", "phase": "IKE_SA_INIT"})
            meta_auth = dict(meta_base); meta_auth.update({"idx": 1, "dir": "fwd", "phase": "IKE_AUTH"})

            # send to X1 (role idx=1)
            try:
                self.link_send(st.x1, T_PROXY_BLOB, init_payload, meta=meta_init)
                self.link_send(st.x1, T_PROXY_BLOB, auth_payload, meta=meta_auth)
            except Exception as e:
                self.logger.error(f"[CONN {st.conn_id}] send proxy fail: {e}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src)
                continue

            # 5) Wait for possible ERROR; if none within window -> success
            # (In demo we don't explicitly "SUCCESS ACK"; absence of ERROR is treated as OK.)
            if st.done_event.wait(UDP_TIMEOUT_S * 8):
                # got error
                self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src)
                continue

            self.logger.info(f"[CONN {st.conn_id}] SUCCESS: proxied INIT/AUTH; далее прямой ESP (вне overlay)")
            return

        self.logger.error(f"[CONN {st.conn_id}] give up (retries exhausted)")

    def _pick_new_x1(self, src: str) -> str:
        all_users = list(USERS.keys())
        cand = [u for u in all_users if u != src]
        return random.choice(cand)

    def make_container(self, dst_user: str, ike_len: int) -> bytes:
        """
        Container model (demo):
          IPv4(dst) (4) + port (2) + I3 (24) + IKE blob (ike_len)
        Here we don't have real IPv4 bytes; use random but keep lengths.
        """
        return secrets.token_bytes(4) + secrets.token_bytes(2) + secrets.token_bytes(I3_LEN) + secrets.token_bytes(ike_len)

    # =========================
    # Loop
    # =========================

    def serve_forever(self):
        self.logger.info(f"Daemon started as {self.name} on UDP/{USERS[self.name]['port']}")
        while self.running:
            got = self.recv_one()
            if not got:
                continue
            data, src = got
            self.handle_packet(data, src)

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, choices=list(USERS.keys()))
    args = ap.parse_args()

    d = NodeDaemon(args.name)
    try:
        d.serve_forever()
    except KeyboardInterrupt:
        d.stop()


if __name__ == "__main__":
    main()