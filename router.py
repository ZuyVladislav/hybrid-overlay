# router.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import random
import secrets
import threading
import time
import subprocess
import binascii
import shlex
import json
from typing import Dict, List, Tuple, Any, Optional

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

    # ---------------------------------------------------------------------
    # Robust CHILD_SA extraction + install
    # ---------------------------------------------------------------------

    @staticmethod
    def _try_get(keys: List[str], src: dict):
        for k in keys:
            if k in src and src[k] is not None:
                return src[k]
        return None

    @staticmethod
    def _maybe_hex(v):
        """
        Приводит int/bytes/hexstr/decimalstr -> hexstr (без 0x), либо None.
        """
        if v is None:
            return None
        if isinstance(v, bytes):
            return binascii.hexlify(v).decode().lower()
        if isinstance(v, int):
            return format(v, "x").lower()
        if isinstance(v, str):
            s = v.strip().lower()
            if s.startswith("0x"):
                s = s[2:]
            # hex?
            try:
                int(s, 16)
                return s
            except Exception:
                # decimal?
                try:
                    return format(int(s), "x").lower()
                except Exception:
                    return None
        # fallback: stringify
        try:
            s = str(v).strip().lower()
            if s.startswith("0x"):
                s = s[2:]
            int(s, 16)
            return s
        except Exception:
            return None

    @staticmethod
    def _state_to_dict(st) -> dict:
        if st is None:
            return {}
        try:
            return dict(getattr(st, "__dict__", {}) or {})
        except Exception:
            return {}

    @staticmethod
    def _merge_sources(base: dict, extra: Optional[dict]) -> dict:
        if not extra or not isinstance(extra, dict):
            return base
        for k, v in extra.items():
            if v is not None and k not in base:
                base[k] = v
        return base

    @staticmethod
    def _maybe_parse_payload(maybe_payload) -> Optional[dict]:
        """
        Пытается привести payload к dict:
        - dict -> dict
        - bytes/str -> пробуем json.loads (мягко)
        Иначе None.
        """
        if maybe_payload is None:
            return None
        if isinstance(maybe_payload, dict):
            return maybe_payload
        if isinstance(maybe_payload, (bytes, bytearray)):
            try:
                s = maybe_payload.decode(errors="ignore").strip()
                if not s:
                    return None
                obj = json.loads(s)
                return obj if isinstance(obj, dict) else None
            except Exception:
                return None
        if isinstance(maybe_payload, str):
            try:
                s = maybe_payload.strip()
                if not s:
                    return None
                obj = json.loads(s)
                return obj if isinstance(obj, dict) else None
            except Exception:
                return None
        return None

    def find_and_install_child_sa(self, st: ConnState, maybe_payload=None, meta=None) -> bool:
        """
        Пытается найти spi/sk_e/sk_a/enc_alg/src_ip/dst_ip в st и maybe_payload/meta,
        поддерживает разные имена полей, нормализует в hex, и вызывает install_sa.sh.
        Возвращает True/False (успех установки SA).
        """
        conn_id = getattr(st, "conn_id", None) or (meta.get("conn_id") if isinstance(meta, dict) else None) or "NONE"

        # 0) Собираем максимально широкий "словарь источников"
        src: Dict[str, Any] = {}

        # st -> dict
        src.update(self._state_to_dict(st))

        # meta может давать адреса/alg/route
        if isinstance(meta, dict):
            for k, v in meta.items():
                if v is not None:
                    src[k] = v

        # maybe_payload (dict / bytes/str as json)
        payload_obj = self._maybe_parse_payload(maybe_payload)
        if isinstance(payload_obj, dict):
            for k, v in payload_obj.items():
                if v is not None and k not in src:
                    src[k] = v

        # fallback: self.state.child_sas (если существует) — ЧИТАЕМ ПОД LOCK
        try:
            with self.state.lock:
                child_sas = getattr(self.state, "child_sas", None)

            if isinstance(child_sas, dict):
                if conn_id in child_sas and isinstance(child_sas[conn_id], dict):
                    self._merge_sources(src, child_sas[conn_id])
                else:
                    if "spi" in child_sas or "spi_out" in child_sas:
                        self._merge_sources(src, child_sas)
        except Exception:
            pass

        # DEBUG: покажем, что вообще есть
        try:
            self.logger.debug(f"[CONN {conn_id}] find_child: probe keys={sorted(list(src.keys()))}")
        except Exception:
            pass

        # 1) Ищем spi
        spi = self._try_get(
            ["spi_out", "child_spi_out", "spi", "child_spi", "spi_out_hex", "child_spi_out_hex"],
            src
        )

        # 2) Ищем ключи шифрования/аутентификации
        sk_e = self._try_get(
            ["sk_e", "child_sk_e", "sk_enc", "child_sk_enc", "enc_key", "enc_key_hex"],
            src
        )
        sk_a = self._try_get(
            ["sk_a", "child_sk_a", "sk_auth", "child_sk_auth", "auth_key", "auth_key_hex"],
            src
        )

        # 3) Алгоритм шифрования
        enc_alg = self._try_get(
            ["enc", "enc_alg", "esp_alg", "enc_algo", "encryption", "cipher"],
            src
        )

        # 4) IP адреса
        src_ip = self._try_get(["src_ip", "src", "src_addr", "src_ip_addr", "local_ip"], src) or None
        dst_ip = self._try_get(["dst_ip", "dst", "dst_addr", "dst_ip_addr", "remote_ip"], src) or None

        # 5) Нормализуем spi -> hexstr
        spi_hex = None
        if spi is not None:
            if isinstance(spi, int):
                spi_hex = format(spi, "x").lower()
            elif isinstance(spi, bytes):
                spi_hex = binascii.hexlify(spi).decode().lower()
            elif isinstance(spi, str):
                s = spi.strip().lower()
                if s.startswith("0x"):
                    s = s[2:]
                try:
                    int(s, 16)
                    spi_hex = s
                except Exception:
                    try:
                        spi_hex = format(int(s), "x").lower()
                    except Exception:
                        spi_hex = None

        # SPI: гарантируем чётную длину (паддинг ведущим 0, если нужно)
        if spi_hex and (len(spi_hex) % 2) != 0:
            spi_hex = "0" + spi_hex

        enc_key_hex = self._maybe_hex(sk_e)
        auth_key_hex = self._maybe_hex(sk_a)

        self.logger.debug(
            f"[CONN {conn_id}] find_child: "
            f"spi={'yes' if spi_hex else 'no'} "
            f"enc_key={'yes' if enc_key_hex else 'no'} "
            f"auth_key={'yes' if auth_key_hex else 'no'} "
            f"enc_alg={enc_alg} src={src_ip} dst={dst_ip}"
        )

        if not (spi_hex and enc_key_hex and auth_key_hex):
            self.logger.warning(f"[CONN {conn_id}] CHILD_SA params not found (cannot install kernel SA)")
            return False

        # 6) Если IP отсутствуют — пробуем из st явно
        if not src_ip:
            src_ip = getattr(st, "src", None) or getattr(st, "local_ip", None)
        if not dst_ip:
            dst_ip = getattr(st, "dst", None) or getattr(st, "remote_ip", None)

        # 7) last fallback: route / src/dst usernames в meta
        if (not src_ip or not dst_ip) and isinstance(meta, dict):
            r = meta.get("route")
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                try:
                    if not src_ip:
                        src_ip = USERS[r[0]]["ip"]
                    if not dst_ip:
                        dst_ip = USERS[r[-1]]["ip"]
                except Exception:
                    pass

            if (not src_ip or not dst_ip):
                try:
                    if not src_ip and meta.get("src") in USERS:
                        src_ip = USERS[meta["src"]]["ip"]
                    if not dst_ip and meta.get("dst") in USERS:
                        dst_ip = USERS[meta["dst"]]["ip"]
                except Exception:
                    pass

        if not src_ip or not dst_ip:
            self.logger.warning(
                f"[CONN {conn_id}] cannot determine src/dst ip for install_sa, src_ip={src_ip} dst_ip={dst_ip}"
            )
            return False

        # 8) Вызов install_sa.sh
        try:
            spi_hex = spi_hex.lower()
            enc_key_hex = enc_key_hex.lower()
            auth_key_hex = auth_key_hex.lower()
            enc_alg = enc_alg or "aes128"  # подстрой под install_sa.sh/ядро при необходимости

            cmd = ["/usr/local/bin/install_sa.sh", str(src_ip), str(dst_ip), spi_hex, enc_key_hex, auth_key_hex, str(enc_alg)]
            self.logger.info(f"[CONN {conn_id}] calling install_sa: {' '.join(shlex.quote(x) for x in cmd)}")

            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5)
            out_text = out.decode(errors="ignore")
            self.logger.info(f"[CONN {conn_id}] install_sa: {out_text.strip()}")
            return True

        except subprocess.CalledProcessError as e:
            msg = ""
            try:
                msg = e.output.decode(errors="ignore") if e.output else str(e)
            except Exception:
                msg = str(e)
            self.logger.error(f"[CONN {conn_id}] install_sa failed (rc={e.returncode}): {msg}")
            return False
        except Exception as e:
            self.logger.exception(f"[CONN {conn_id}] install_sa exception: {e}")
            return False

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

            # --- Подстраховка: дать время CHILD_SA params появиться в состоянии ---
            wait_seconds = 5.0
            deadline_ts = time.time() + wait_seconds
            installed = False

            while time.time() < deadline_ts:
                try:
                    if self.find_and_install_child_sa(st, maybe_payload=None, meta=meta_base):
                        self.logger.info(f"[CONN {st.conn_id}] CHILD_SA installed into kernel")
                        installed = True
                        break
                except Exception as e:
                    self.logger.exception(f"[CONN {st.conn_id}] install attempt exception: {e}")
                time.sleep(0.1)

            if not installed:
                try:
                    ok_install = self.find_and_install_child_sa(st, maybe_payload=None, meta=meta_base)
                    if ok_install:
                        self.logger.info(f"[CONN {st.conn_id}] CHILD_SA installed into kernel (final attempt)")
                    else:
                        self.logger.info(f"[CONN {st.conn_id}] CHILD_SA not installed after {wait_seconds}s (no params available)")
                except Exception as e:
                    self.logger.exception(f"[CONN {st.conn_id}] final install attempt exception: {e}")

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