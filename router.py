# router.py
from __future__ import annotations
import random
import secrets
import threading
import time
from typing import Dict, List, Tuple

from config import USERS, UDP_TIMEOUT_S, I3_LEN
from protocol import jdump, err, T_LOCAL_CONNECT, T_I1, T_I2, T_OKX2, T_PROXY_BLOB

from state import DaemonState, ConnState


class Router:
    """
    I1/I2/OKX2 + LOCAL_CONNECT initiator state machine.
    """
    def __init__(self, name: str, state: DaemonState, mgmt, secure_link, error_relay, transport, ike_route_ref, logger):
        self.name = name
        self.state = state
        self.mgmt = mgmt
        self.sec = secure_link
        self.err = error_relay
        self.transport = transport
        self._ike_route_ref = ike_route_ref  # dict-like ref owned by daemon
        self.logger = logger

    @staticmethod
    def _kv_parse(s: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in s.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # -------- LOCAL_CONNECT --------
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
            self.transport.sock.sendto(err("BAD_SRC", "LOCAL_CONNECT user must equal daemon name"), src)
            return
        if user not in USERS or USERS[user]["password"] != password:
            self.transport.sock.sendto(err("AUTH_FAIL", "bad user/password"), src)
            return
        if dst not in USERS:
            self.transport.sock.sendto(err("BAD_DST", "unknown dst"), src)
            return

        cand_x1 = [u for u in USERS if u not in (user, dst)]
        if not cand_x1:
            self.transport.sock.sendto(err("NO_X1_CAND", "no X1 candidates"), src)
            return
        x1 = random.choice(cand_x1)

        conn_id = secrets.token_hex(8)

        ok_ev = threading.Event()
        done_ev = threading.Event()
        with self.state.lock:
            self.state.okx2_ev[conn_id] = ok_ev
            self.state.okx2_data.pop(conn_id, None)
            self.state.okx2_x2name.pop(conn_id, None)

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
        self.state.conns[conn_id] = st

        th = threading.Thread(target=self.run_connection, args=(st,), daemon=True)
        th.start()

        self.transport.sock.sendto(jdump({"ok": True, "conn_id": conn_id, "x1": x1, "msg": "started"}), src)
        self.logger.info(f"[ROLE] A={user} selected X1={x1} for DST={dst} CONN={conn_id}")

    def _pick_new_x1(self, src: str, dst: str) -> str:
        cand = [u for u in USERS.keys() if u not in (src, dst)]
        return random.choice(cand) if cand else src

    def make_container(self, ike_len: int) -> bytes:
        return secrets.token_bytes(4) + secrets.token_bytes(2) + secrets.token_bytes(I3_LEN) + secrets.token_bytes(ike_len)

    def run_connection(self, st: ConnState):
        while st.retries_left >= 0:
            st.done_event.clear()
            st.okx2_event.clear()
            st.last_error = None

            if st.x1 not in self.state.sessions and not self.mgmt.ensure_session(st.x1, reason=f"A->X1 CONN={st.conn_id}"):
                self.logger.error(f"[CONN {st.conn_id}] cannot establish to X1={st.x1}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            i1 = f"CONN={st.conn_id}|REQ={st.src}|DST={st.dst}".encode().ljust(128, b"\x00")
            self.sec.link_send(st.x1, T_I1, i1)
            self.logger.info(f"[CONN {st.conn_id}] I1 sent to X1={st.x1} (X1 picks X2)")

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

            with self.state.lock:
                ok = self.state.okx2_data.get(st.conn_id)
                x2 = self.state.okx2_x2name.get(st.conn_id, "")

            if not ok or not x2:
                self.logger.error(f"[CONN {st.conn_id}] OKX2 missing data")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            st.x2 = x2
            self.logger.info(f"[CONN {st.conn_id}] got OKX2, chosen X2={st.x2}, ok_len={len(ok)}")

            # arm IKE route for daemon -> IkeProxy injection
            self._ike_route_ref.clear()
            self._ike_route_ref.update({
                "conn_id": st.conn_id,
                "src": st.src,
                "dst": st.dst,
                "x1": st.x1,
                "x2": st.x2,
            })
            self.logger.info(f"[IKEP] route armed for real IKE: {st.src}->{st.x1}->{st.x2}->{st.dst}")

            init_payload = self.make_container(st.ike_init_len)
            auth_payload = self.make_container(st.ike_auth_len)

            meta_base = {"conn_id": st.conn_id, "src": st.src, "dst": st.dst, "x1": st.x1, "x2": st.x2}
            meta_init = dict(meta_base); meta_init.update({"idx": 1, "dir": "fwd", "phase": "IKE_SA_INIT"})
            meta_auth = dict(meta_base); meta_auth.update({"idx": 1, "dir": "fwd", "phase": "IKE_AUTH"})

            try:
                self.sec.link_send(st.x1, T_PROXY_BLOB, init_payload, meta=meta_init)
                self.sec.link_send(st.x1, T_PROXY_BLOB, auth_payload, meta=meta_auth)
            except Exception as e:
                self.logger.error(f"[CONN {st.conn_id}] send proxy fail: {e}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            if st.done_event.wait(UDP_TIMEOUT_S * 8):
                self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            self.logger.info(f"[CONN {st.conn_id}] SUCCESS: proxied INIT/AUTH; далее прямой ESP (вне overlay)")
            return

        self.logger.error(f"[CONN {st.conn_id}] give up (retries exhausted)")

    # -------- I1/I2/OKX2 --------
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

        cand_x2 = [u for u in USERS if u not in (self.name, req, dst)]
        if not cand_x2:
            self.logger.error("[I1] no X2 candidates after exclusions")
            self.err.send_error_back(conn_id, req, self.name, phase="I1", code="NO_X2_CAND", msg="no X2 candidates")
            return

        self.logger.info(f"[ROLE] X1={self.name} selected by A={req} for DST={dst} CONN={conn_id}")
        th = threading.Thread(target=self._try_route_x2, args=(conn_id, req, dst, cand_x2), daemon=True)
        th.start()

    def _try_route_x2(self, conn_id: str, req: str, dst: str, cand_x2: List[str]):
        for x2 in cand_x2:
            self.logger.info(f"[I1] X1={self.name} try X2={x2} for REQ={req} DST={dst} CONN={conn_id}")

            if not self.mgmt.ensure_session(x2, reason=f"X1->X2 CONN={conn_id} REQ={req} DST={dst}"):
                self.logger.warning(f"[I1] cannot establish session to X2={x2}, trying next")
                continue

            i2 = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode().ljust(128, b"\x00")
            self.sec.link_send(x2, T_I2, i2)
            self.logger.info(f"[I1] choose X2={x2}; -> I2 to {x2} for REQ={req}, DST={dst} CONN={conn_id}")
            return

        self.logger.error("[I1] cannot establish session to any X2 candidate")
        self.err.send_error_back(conn_id, req, self.name, phase="I1", code="NO_SESSION_X2", msg="cannot ensure any X2")

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

        # If I am DST and got chosen as X2 => explicit error back
        if self.name == dst:
            self.logger.warning(f"[I2] DROP (X2==DST): I am DST={dst}. CONN={conn_id} REQ={req} via X1={peer}")
            self.err.send_error_back(
                conn_id=conn_id, src_u=req, x1_u=peer, phase="I2",
                code="X2_IS_DST", msg="X2 saw itself as DST and dropped"
            )
            return

        # Variant A: pre-establish X2<->DST here (not in PROXY phase)
        with self.state.lock:
            has_dst_sess = dst in self.state.sessions
        if not has_dst_sess:
            if not self.mgmt.ensure_session(dst, reason=f"X2->DST preconnect CONN={conn_id} REQ={req} via X1={peer}"):
                self.logger.error(f"[I2] cannot preconnect to DST={dst} as X2. CONN={conn_id}")
                self.err.send_error_back(
                    conn_id=conn_id, src_u=req, x1_u=peer, phase="I2",
                    code="NO_SESSION_DST", msg=f"X2 cannot ensure DST={dst} (preconnect failed)"
                )
                return

        ok = secrets.token_bytes(32) + secrets.token_bytes(16)
        header = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode()
        payload = header + b"|OK=" + ok
        self.sec.link_send(peer, T_OKX2, payload)
        self.logger.info(f"[OKX2] -> {peer} CONN={conn_id} for REQ={req} ok_len={len(ok)}")

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

        if self.name != req:
            if req not in USERS:
                return
            if req not in self.state.sessions and not self.mgmt.ensure_session(req, reason=f"OKX2 forward CONN={conn_id}"):
                self.logger.error(f"[OKX2] cannot ensure session to {req}")
                return
            self.sec.link_send(req, T_OKX2, plain)
            self.logger.info(f"[OKX2] fwd {self.name}->{req} CONN={conn_id}")
            return

        with self.state.lock:
            ev = self.state.okx2_ev.get(conn_id)
            self.state.okx2_data[conn_id] = ok
            self.state.okx2_x2name[conn_id] = x2
        if ev:
            ev.set()
        self.logger.info(f"[ROLE] A={self.name} got OKX2 from X2={x2} via {peer} CONN={conn_id}")