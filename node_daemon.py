###№
import argparse
import random
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List
from ike_proxy import IkeProxy

from cryptography.hazmat.primitives.asymmetric import x25519

from config import USERS, UDP_TIMEOUT_S, RETRIES, I3_LEN, PRECONNECT_ENABLED
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
    okx2_payload: Optional[bytes] = None
    last_error: Optional[dict] = None


# =========================
# Daemon
# =========================

class NodeDaemon:
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(name)

        self.ike_route = None
        self.ike_proxy = IkeProxy(self._on_ike_local, self.logger)
        self.ike_proxy.start()

        if name not in USERS:
            raise RuntimeError(f"Unknown user {name} in config USERS")

        port = USERS[name]["port"]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # REUSEADDR helps after crashes; does not allow two active binds reliably on same IP:port (good).
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(0.2)

        self.lock = threading.Lock()
        self.running = True

        # sessions / pending responder state
        self.sessions: Dict[str, MgmtSession] = {}
        self.pending: Dict[str, PendingHS] = {}

        # ---- Mailboxes (only receiver thread reads socket) ----
        self.hs_initresp: Dict[str, dict] = {}
        self.hs_authresp: Dict[str, dict] = {}
        self.hs_init_ev: Dict[str, threading.Event] = {}
        self.hs_auth_ev: Dict[str, threading.Event] = {}

        # OKX2 mailbox by conn_id
        self.okx2_ev: Dict[str, threading.Event] = {}
        self.okx2_data: Dict[str, bytes] = {}
        self.okx2_x2name: Dict[str, str] = {}

        # active connections (initiator only)
        self.conns: Dict[str, ConnState] = {}
        self.ensure_inflight: Dict[str, threading.Event] = {}

        self.preconnect_thread: Optional[threading.Thread] = None

    # ---------- address book ----------
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

    # ---------- JSON ----------
    def safe_load(self, data: bytes) -> Optional[dict]:
        try:
            return jload(data)
        except Exception:
            self.logger.warning("Malformed packet (non-json)")
            return None

    def _on_ike_local(self, data: bytes, dport: int):
        if not self.ike_route:
            return

        meta = dict(self.ike_route)
        meta.update({
            "phase": "IKE_REAL",
            "ike_port": dport,
            "dir": "fwd",
            "idx": 1,
        })

        try:
            self.link_send(meta["x1"], T_PROXY_BLOB, data, meta=meta)
        except Exception as e:
            self.logger.error(f"[IKEP] inject into overlay failed: {e}")
            return

        self.logger.info(f"[IKEP] injected into overlay len={len(data)} dport={dport}")

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
    # One and only packet dispatcher
    # =========================

    def handle_packet(self, data: bytes, src: Tuple[str, int]):
        p = self.safe_load(data)
        if not p:
            return

        t = p.get("t")
        claimed = p.get("from")

        # ✅ LOCAL control-plane: принимаем всегда (идёт с 127.0.0.1:random_port)
        if t == T_LOCAL_CONNECT:
            self.on_local_connect(p, src)
            return

        peer = self.peer_from_src(src)

        # --- simple mgmt identity fix ---
        if peer is None and claimed in USERS:
            # if source IP matches known user, accept peer even if port differs
            if USERS[claimed]["ip"] == src[0]:
                if t in (
                        T_MGMT_INIT,
                        T_MGMT_AUTH,
                        T_MGMT_INIT_RESP,
                        T_MGMT_AUTH_RESP,
                        T_ERROR,
                ):
                    peer = claimed
                    self.logger.warning(
                        f"[ADDR] peer fixed by IP match: peer={peer} src={src} t={t}"
                    )
                else:
                    self.logger.warning(
                        f"[ADDR] drop secure msg from unknown endpoint src={src} claimed={claimed} t={t}"
                    )
                    return

        if peer is None:
            self.logger.warning(f"[ADDR] drop packet: src={src} claimed={claimed} t={t}")
            return
        # --- end fix ---

        # mgmt responder
        if t == T_MGMT_INIT:
            self.on_mgmt_init(p, peer)
            return
        if t == T_MGMT_AUTH:
            self.on_mgmt_auth(p, peer)
            return

        # mgmt initiator mailbox
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

        if t == T_ERROR:
            self.on_error(p, peer)
            return

        if t in (T_I1, T_I2, T_OKX2, T_PROXY_BLOB):
            self.on_secure_msg(p, peer)
            return

        self.logger.info(f"[DROP] unknown t={t} from={peer}")

    # =========================
    # MGMT responder
    # =========================

    def on_mgmt_init(self, p: dict, peer: Optional[str]):
        if not peer:
            # unknown sender endpoint (ip:port not in USERS)
            return
        sid = p["sid"]
        i_pub = bytes.fromhex(p["ke"])
        ni = bytes.fromhex(p["ni"])

        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = xpub_bytes(r_priv.public_key())
        nr = secrets.token_bytes(16)

        label = f"{peer}-{self.name}"  # initiator-responder
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
    # MGMT initiator (ensure_session)
    # =========================

    def ensure_session(self, peer: str, reason: str = "") -> bool:
        if peer == self.name:
            self.logger.error(f"[MGMT] ensure_session to self is forbidden, reason={reason}")
            return False
        with self.lock:
            if peer in self.sessions:
                return True
            inflight = self.ensure_inflight.get(peer)
            if inflight:
                wait_ev = inflight
            else:
                wait_ev = threading.Event()
                self.ensure_inflight[peer] = wait_ev

        if inflight:
            wait_ev.wait(UDP_TIMEOUT_S * RETRIES)
            with self.lock:
                return peer in self.sessions

        label = f"{self.name}-{peer}"  # initiator-responder

        for attempt in range(RETRIES):
            if attempt == 0:
                self.logger.info(f"[MGMT] ensure_session start {self.name}->{peer} reason={reason or 'unspecified'}")

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

            if not init_ev.wait(UDP_TIMEOUT_S):
                exp = self.peer_addr(peer)
                self.logger.warning(
                    f"[MGMT] timeout INIT_RESP from {peer} sid={sid} "
                    f"expected={exp} reason={reason or 'unspecified'}"
                )
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp = self.hs_initresp.get(sid)

            if not resp or resp.get("from") != peer or resp.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad INIT_RESP mailbox sid={sid} reason={reason or 'unspecified'}")
                self._cleanup_hs(sid)
                continue

            nr = bytes.fromhex(resp["nr"])
            r_pub = bytes.fromhex(resp["ke"])
            shared = i_priv.exchange(xpub_from_bytes(r_pub))
            kd = self.mgmt_kdf(shared, ni, nr, label=label)

            aad = f"AUTH:{label}:{self.name}->{peer}:{sid}".encode()
            auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
            n1, c1 = aesgcm_encrypt(kd, auth_plain, aad=aad)
            auth_msg = jdump({"t": T_MGMT_AUTH, "sid": sid, "from": self.name, "to": peer,
                              "nonce": n1.hex(), "ct": c1.hex()})
            self.send_peer(peer, auth_msg)

            if not auth_ev.wait(UDP_TIMEOUT_S):
                exp = self.peer_addr(peer)
                self.logger.warning(
                    f"[MGMT] timeout AUTH_RESP from {peer} sid={sid} "
                    f"expected={exp} reason={reason or 'unspecified'}"
                )
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp2 = self.hs_authresp.get(sid)

            if not resp2 or resp2.get("from") != peer or resp2.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad AUTH_RESP mailbox sid={sid} reason={reason or 'unspecified'}")
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
            self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid} reason={reason or 'unspecified'}")
            with self.lock:
                self.ensure_inflight.pop(peer, None)
                wait_ev.set()
            return True

        with self.lock:
            self.ensure_inflight.pop(peer, None)
            wait_ev.set()
        return False

    def _cleanup_hs(self, sid: str):
        with self.lock:
            self.hs_init_ev.pop(sid, None)
            self.hs_auth_ev.pop(sid, None)
            self.hs_initresp.pop(sid, None)
            self.hs_authresp.pop(sid, None)

    # =========================
    # Secure messages
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

    @staticmethod
    def _kv_parse(s: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in s.split("|"):
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

        # ✅ X1 chooses X2 excluding {X1, REQ, DST}
        cand_x2 = [u for u in USERS if u not in (self.name, req, dst)]
        if not cand_x2:
            self.sock.sendto(err("NO_X2_CAND", "no X2 candidates"), src)
            return
        x2 = random.choice(cand_x2)

        if not cand_x2:
            self.logger.error("[I1] no X2 candidates after exclusions")
            self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_X2_CAND", msg="no X2 candidates")
            return

        self.logger.info(f"[ROLE] X1={self.name} selected by A={req} for DST={dst} CONN={conn_id}")
        th = threading.Thread(
            target=self._try_route_x2,
            args=(conn_id, req, dst, cand_x2),
            daemon=True,
        )
        th.start()

    # I2: X1->X2
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

        # X2 == DST (B) — допустимая ситуация по генерации маршрута, но в твоей логике
        # X2 обязан явно сбросить установку и сообщить наверх "увидел себя".
        if self.name == dst:
            self.logger.warning(
                f"[I2] DROP (X2==DST): I am DST={dst} and was selected as X2. "
                f"CONN={conn_id} REQ={req} via X1={peer}"
            )
            # шлём ошибку назад (к A через X1), чтобы A сделал retry и было видно почему
            self.send_error_back(
                conn_id=conn_id,
                src_u=req,
                x1_u=peer,
                phase="I2",
                code="X2_IS_DST",
                msg="X2 увидел себя как DST (B) и сбросил соединение"
            )
            return

        # hard rejects (should not happen now, but keep safety)
        if self.name == dst:
            self.logger.warning(
                f"[I2] DROP: I am DST={dst} but was selected as X2. "
                f"CONN={conn_id} REQ={req} via X1={peer}"
            )
            self.send_error_back(conn_id, req, peer, phase="I2", code="X2_IS_DST",
                                 msg="X2 equals destination (B). Drop connection and retry.")
            return
        # ✅ Variant A: pre-establish X2<->DST (B) here (not in PROXY phase)
        with self.lock:
            has_dst_sess = dst in self.sessions
        if not has_dst_sess:
            if not self.ensure_session(dst, reason=f"X2->DST preconnect CONN={conn_id} REQ={req} via X1={peer}"):
                self.logger.error(f"[I2] cannot preconnect to DST={dst} as X2. CONN={conn_id}")
                self.send_error_back(
                    conn_id=conn_id,
                    src_u=req,
                    x1_u=peer,
                    phase="I2",
                    code="NO_SESSION_DST",
                    msg=f"X2 cannot ensure DST={dst} (preconnect failed)"
                )
                return
        ok = secrets.token_bytes(32) + secrets.token_bytes(16)
        header = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode()
        payload = header + b"|OK=" + ok

        self.link_send(peer, T_OKX2, payload)
        self.logger.info(f"[OKX2] -> {peer} CONN={conn_id} for REQ={req} ok_len={len(ok)}")

    # OKX2: X2->X1 (KD2) then X1->A (KD1)
    def handle_OKX2(self, peer: str, plain: bytes):
        marker = b"|OK="
        if marker not in plain:
            self.logger.warning("[OKX2] bad format (no |OK=)")
            return

        hdr_b, ok = plain.split(marker, 1)
        hdr_s = hdr_b.decode(errors="ignore")
        kv = self._kv_parse(hdr_s)

        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        x2 = kv.get("X2", "")

        self.logger.info(f"[OKX2] from={peer} CONN={conn_id} REQ={req} X2={x2} ok_len={len(ok)}")

        # forward to requester if I'm not requester
        if self.name != req:
            if req not in USERS:
                return
            if req not in self.sessions and not self.ensure_session(req, reason=f"OKX2 forward CONN={conn_id}"):
                self.logger.error(f"[OKX2] cannot ensure session to {req}")
                return
            self.link_send(req, T_OKX2, plain)
            self.logger.info(f"[OKX2] fwd {self.name}->{req} CONN={conn_id}")
            return

        # I'm requester(A)
        with self.lock:
            ev = self.okx2_ev.get(conn_id)
            self.okx2_data[conn_id] = ok
            self.okx2_x2name[conn_id] = x2
        if ev:
            ev.set()
        self.logger.info(f"[ROLE] A={self.name} got OKX2 from X2={x2} via {peer} CONN={conn_id}")

    # PROXY_BLOB forward path: src->x1->x2->dst; back path: dst->x2->x1->src
    def handle_PROXY(self, peer: str, plain: bytes, meta: dict):
        conn_id = meta.get("conn_id", "")
        src_u = meta.get("src", "")
        dst_u = meta.get("dst", "")
        x1_u = meta.get("x1", "")
        x2_u = meta.get("x2", "")
        idx = int(meta.get("idx", 0))
        direction = meta.get("dir", "fwd")
        phase = meta.get("phase", "UNK")
        if phase == "IKE_REAL":
            # reached destination (B)
            if direction == "fwd" and self.name == dst_u and idx == 3:
                self.logger.info(f"[IKEP] ARRIVE B={self.name} dport={meta.get('ike_port')} len={len(plain)}")
                self.ike_proxy.inject_to_charon(plain, int(meta.get("ike_port", 15000)))
                return

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        if idx < 0 or idx >= len(route) or route[idx] != self.name:
            self.logger.warning(f"[PROXY] route mismatch idx={idx} dir={direction} route={route}")
            return

        # reached destination on forward direction
        if direction == "fwd" and self.name == dst_u and idx == 3:
            self.logger.info(f"[PROXY] ARRIVE DST={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
            resp = plain
            meta2 = dict(meta)
            meta2["dir"] = "back"
            meta2["idx"] = 0
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

        # ✅ Variant A: never establish MGMT from PROXY phase to DST.
        # Expect X2<->DST to be pre-established in handle_I2().
        with self.lock:
            has_session = nxt in self.sessions

        if not has_session:
            if nxt == dst_u:
                self.logger.error(
                    f"[PROXY] NO_SESSION_DST (blocked establish in PROXY) "
                    f"{self.name}->{nxt} phase={phase} CONN={conn_id}"
                )
                self.send_error_back(
                    conn_id, src_u, x1_u, phase,
                    code="NO_SESSION_DST",
                    msg=f"no session to DST={nxt}; must be preconnected by X2"
                )
                return

            if not self.ensure_session(nxt, reason=f"PROXY {direction} phase={phase} CONN={conn_id}"):
                self.logger.error(f"[PROXY] cannot ensure session to {nxt}")
                self.send_error_back(conn_id, src_u, x1_u, phase, code="NO_SESSION_NEXT", msg=f"cannot ensure {nxt}")
                return

        meta2 = dict(meta)
        meta2["idx"] = nxt_idx
        if nxt == self.name:
            self.logger.error(f"[PROXY] BUG: next hop is self, drop. meta={meta}")
            return
        self.link_send(nxt, T_PROXY_BLOB, payload, meta=meta2)
        self.logger.info(
            f"[PROXY] {direction} {self.name}->{nxt} idx={nxt_idx} phase={phase} "
            f"route={src_u}->{x1_u}->{x2_u}->{dst_u} CONN={conn_id}"
        )

    # =========================
    # Plaintext ERROR forward
    # =========================

    def send_error_back(self, conn_id: str, src_u: str, x1_u: str, phase: str, code: str, msg: str):
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

        route = meta.get("route", [])
        idx = int(meta.get("idx", 0))
        if isinstance(route, list) and route and idx < len(route) - 1:
            nxt = route[idx + 1]
            meta2 = dict(meta); meta2["idx"] = idx + 1
            fwd = {"t": T_ERROR, "code": code, "msg": msg, "meta": meta2}
            self.send_peer(nxt, jdump(fwd))
            return

        if conn_id and conn_id in self.conns:
            st = self.conns[conn_id]
            st.last_error = {"code": code, "msg": msg}
            st.done_event.set()

    # =========================
    # LOCAL_CONNECT + Initiator
    # =========================

    def on_local_connect(self, p: dict, src: Tuple[str, int]):
        if src[0] not in ("127.0.0.1", "::1"):
            self.logger.warning("[LOCAL] reject non-local")
            return

        user = p.get("user")
        password = p.get("pass")
        dst = p.get("dst")
        ike_init_len = int(p.get("ike_init_len", 499))
        ike_auth_len = int(p.get("ike_auth_len", 499))
        retries = int(p.get("retries", 5))

        self.logger.info(
            f"[LOCAL] connect request from={src[0]} user={user} dst={dst} "
            f"ike_init_len={ike_init_len} ike_auth_len={ike_auth_len} retries={retries}"
        )

        if user != self.name:
            self.sock.sendto(err("BAD_SRC", "LOCAL_CONNECT user must equal daemon name"), src)
            return
        if user not in USERS or USERS[user]["password"] != password:
            self.sock.sendto(err("AUTH_FAIL", "bad user/password"), src)
            return
        if dst not in USERS:
            self.sock.sendto(err("BAD_DST", "unknown dst"), src)
            return

        # ✅ A picks X1
        cand_x1 = [u for u in USERS if u not in (user, dst)]
        if not cand_x1:
            self.sock.sendto(err("NO_X1_CAND", "no X1 candidates"), src)
            return
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
        self.logger.info(f"[ROLE] A={user} selected X1={x1} for DST={dst} CONN={conn_id}")

    def run_connection(self, st: ConnState):
        while st.retries_left >= 0:
            st.done_event.clear()
            st.okx2_event.clear()
            st.last_error = None

            # Ensure A<->X1
            if st.x1 not in self.sessions and not self.ensure_session(st.x1, reason=f"A->X1 CONN={st.conn_id}"):
                self.logger.error(f"[CONN {st.conn_id}] cannot establish to X1={st.x1}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            i1 = f"CONN={st.conn_id}|REQ={st.src}|DST={st.dst}".encode().ljust(128, b"\x00")
            self.link_send(st.x1, T_I1, i1)
            self.logger.info(f"[CONN {st.conn_id}] I1 sent to X1={st.x1} (X1 picks X2)")

            # Wait OKX2 or ERROR
            okx2_timeout = UDP_TIMEOUT_S * 6
            deadline = time.monotonic() + okx2_timeout
            while time.monotonic() < deadline:
                if st.okx2_event.wait(0.1):
                    break
                if st.done_event.is_set():
                    self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                    st.retries_left -= 1
                    st.x1 = self._pick_new_x1(st.src, st.dst)
                    break

            if st.done_event.is_set():
                continue

            if not st.okx2_event.is_set():
                self.logger.error(f"[CONN {st.conn_id}] timeout waiting OKX2")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            with self.lock:
                ok = self.okx2_data.get(st.conn_id)
                x2 = self.okx2_x2name.get(st.conn_id, "")

            if not ok or not x2:
                self.logger.error(f"[CONN {st.conn_id}] OKX2 missing data")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            st.x2 = x2
            self.logger.info(f"[CONN {st.conn_id}] got OKX2, chosen X2={st.x2}, ok_len={len(ok)}")
            self.ike_route = {
                "conn_id": st.conn_id,
                "src": st.src,
                "dst": st.dst,
                "x1": st.x1,
                "x2": st.x2,
            }
            self.logger.info(f"[IKEP] route armed for real IKE: {st.src}->{st.x1}->{st.x2}->{st.dst}")

            init_payload = self.make_container(st.dst, ike_len=st.ike_init_len)
            auth_payload = self.make_container(st.dst, ike_len=st.ike_auth_len)

            meta_base = {"conn_id": st.conn_id, "src": st.src, "dst": st.dst, "x1": st.x1, "x2": st.x2}
            meta_init = dict(meta_base); meta_init.update({"idx": 1, "dir": "fwd", "phase": "IKE_SA_INIT"})
            meta_auth = dict(meta_base); meta_auth.update({"idx": 1, "dir": "fwd", "phase": "IKE_AUTH"})

            try:
                self.link_send(st.x1, T_PROXY_BLOB, init_payload, meta=meta_init)
                self.link_send(st.x1, T_PROXY_BLOB, auth_payload, meta=meta_auth)
            except Exception as e:
                self.logger.error(f"[CONN {st.conn_id}] send proxy fail: {e}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            # if an ERROR arrives, done_event is set
            if st.done_event.wait(UDP_TIMEOUT_S * 8):
                self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            self.logger.info(f"[CONN {st.conn_id}] SUCCESS: proxied INIT/AUTH; далее прямой ESP (вне overlay)")
            return

        self.logger.error(f"[CONN {st.conn_id}] give up (retries exhausted)")

    def _pick_new_x1(self, src: str, dst: str) -> str:
        cand = [u for u in USERS.keys() if u not in (src, dst)]
        return random.choice(cand) if cand else src

    def make_container(self, dst_user: str, ike_len: int) -> bytes:
        return secrets.token_bytes(4) + secrets.token_bytes(2) + secrets.token_bytes(I3_LEN) + secrets.token_bytes(ike_len)

    # =========================
    # X1 route selection
    # =========================

    def _try_route_x2(self, conn_id: str, req: str, dst: str, cand_x2: List[str]):
        for x2 in cand_x2:
            self.logger.info(f"[I1] X1={self.name} try X2={x2} for REQ={req} DST={dst} CONN={conn_id}")

            if not self.ensure_session(x2, reason=f"X1->X2 CONN={conn_id} REQ={req} DST={dst}"):
                self.logger.warning(f"[I1] cannot establish session to X2={x2}, trying next")
                continue

            i2 = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode().ljust(128, b"\x00")
            self.link_send(x2, T_I2, i2)
            self.logger.info(f"[I1] choose X2={x2}; -> I2 to {x2} for REQ={req}, DST={dst} CONN={conn_id}")
            return

        self.logger.error("[I1] cannot establish session to any X2 candidate")
        self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_SESSION_X2", msg="cannot ensure any X2")

    # =========================
    # Loop
    # =========================

    def serve_forever(self):
        self.logger.info(f"Daemon started as {self.name} on UDP/{USERS[self.name]['port']}")
        if PRECONNECT_ENABLED and self.preconnect_thread is None:
            self.preconnect_thread = threading.Thread(target=self._preconnect_loop, daemon=True)
            self.preconnect_thread.start()

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

    def _preconnect_loop(self):
        time.sleep(random.uniform(0.2, 0.8))
        while self.running:
            peers = [u for u in USERS.keys() if u != self.name]
            random.shuffle(peers)
            for peer in peers:
                with self.lock:
                    has_session = peer in self.sessions or peer in self.ensure_inflight
                if has_session:
                    continue
                self.ensure_session(peer, reason="preconnect")
                time.sleep(0.05)
            time.sleep(0.5)


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
