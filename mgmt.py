# mgmt.py
from __future__ import annotations

import secrets
import threading
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from config import UDP_TIMEOUT_S, RETRIES
from crypto_util import (
    aesgcm_encrypt, aesgcm_decrypt,
    hkdf_sha256,
    xpub_bytes, xpub_from_bytes,
)
from protocol import (
    jdump, err,
    T_MGMT_INIT, T_MGMT_INIT_RESP, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
)
from state import DaemonState, PendingHS, MgmtSession


class Mgmt:
    """
    MGMT (control-plane) handshake:
      INIT  (I -> R): sid, ni, ke_i
      INIT_RESP (R -> I): sid, nr, ke_r
      AUTH  (I -> R): sid, AESGCM(kd, ...)
      AUTH_RESP (R -> I): sid, AESGCM(kd, ...)
    """

    def __init__(self, name: str, state: DaemonState, transport, logger):
        self.name = name
        self.state = state
        self.transport = transport
        self.logger = logger

    # ---------- mgmt KDF ----------
    @staticmethod
    def mgmt_kdf(shared: bytes, ni: bytes, nr: bytes, label: str) -> bytes:
        salt = ni + nr
        info = b"mgmt|ikev2-like|" + label.encode("utf-8")
        return hkdf_sha256(shared, salt=salt, info=info, length=32)

    # =========================
    # MGMT responder
    # =========================
    def on_mgmt_init(self, p: dict, peer: Optional[str]):
        if not peer:
            return

        sid = p.get("sid")
        if not sid:
            return

        try:
            i_pub = bytes.fromhex(p["ke"])
            ni = bytes.fromhex(p["ni"])
        except Exception:
            self.logger.warning(f"[MGMT] bad INIT fields from={peer}")
            return

        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = xpub_bytes(r_priv.public_key())
        nr = secrets.token_bytes(16)

        label = f"{peer}-{self.name}"  # initiator-responder

        with self.state.lock:
            self.state.pending[sid] = PendingHS(
                priv=r_priv, nr=nr, ni=ni, i_pub=i_pub, label=label
            )

        resp = jdump({
            "t": T_MGMT_INIT_RESP, "sid": sid,
            "from": self.name, "to": peer,
            "nr": nr.hex(), "ke": r_pub.hex(),
        })
        self.transport.send_peer(peer, resp)
        self.logger.info(f"[MGMT] <- {peer} INIT; -> INIT_RESP sid={sid}")

    def on_mgmt_auth(self, p: dict, peer: Optional[str]):
        if not peer:
            return

        sid = p.get("sid")
        if not sid:
            return

        with self.state.lock:
            st = self.state.pending.get(sid)

        if not st:
            self.logger.warning(f"[MGMT] AUTH unknown sid={sid} from={peer}")
            return

        shared = st.priv.exchange(xpub_from_bytes(st.i_pub))
        kd = self.mgmt_kdf(shared, st.ni, st.nr, label=st.label)

        aad = f"AUTH:{st.label}:{peer}->{self.name}:{sid}".encode()
        try:
            _ = aesgcm_decrypt(
                kd,
                bytes.fromhex(p["nonce"]),
                bytes.fromhex(p["ct"]),
                aad=aad,
            )
        except Exception as e:
            self.logger.error(f"[MGMT] AUTH decrypt fail sid={sid} from={peer}: {e}")
            self.transport.send_peer(peer, err("AUTH_FAIL", "mgmt auth decrypt failed"))
            return

        aad2 = f"AUTH:{st.label}:{self.name}->{peer}:{sid}".encode()
        auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
        n2, c2 = aesgcm_encrypt(kd, auth_plain, aad=aad2)

        resp = jdump({
            "t": T_MGMT_AUTH_RESP, "sid": sid,
            "from": self.name, "to": peer,
            "nonce": n2.hex(), "ct": c2.hex(),
        })
        self.transport.send_peer(peer, resp)

        with self.state.lock:
            self.state.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)
            self.state.pending.pop(sid, None)

        self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")

    # =========================
    # MGMT initiator mailbox (RX path)
    # =========================
    def on_init_resp(self, p: dict):
        # important: do not accept чужие ответы
        if p.get("to") != self.name:
            return
        sid = p.get("sid")
        if not sid:
            return

        with self.state.lock:
            self.state.hs_initresp[sid] = p
            ev = self.state.hs_init_ev.get(sid)

        # Диагностика: если ev нет — значит sid не совпал или waiter уже очищен.
        self.logger.info(
            f"[MGMT] RX MGMT_INIT_RESP sid={sid} from={p.get('from')} to={p.get('to')} ev_exists={ev is not None}"
        )
        if ev:
            ev.set()
            self.logger.info(f"[MGMT] RX MGMT_INIT_RESP sid={sid} ev_set=1")
        else:
            self.logger.warning(f"[MGMT] RX MGMT_INIT_RESP sid={sid} ev_set=0 (no waiter)")

    def on_auth_resp(self, p: dict):
        if p.get("to") != self.name:
            return
        sid = p.get("sid")
        if not sid:
            return

        with self.state.lock:
            self.state.hs_authresp[sid] = p
            ev = self.state.hs_auth_ev.get(sid)

        self.logger.info(
            f"[MGMT] RX MGMT_AUTH_RESP sid={sid} from={p.get('from')} to={p.get('to')} ev_exists={ev is not None}"
        )
        if ev:
            ev.set()
            self.logger.info(f"[MGMT] RX MGMT_AUTH_RESP sid={sid} ev_set=1")
        else:
            self.logger.warning(f"[MGMT] RX MGMT_AUTH_RESP sid={sid} ev_set=0 (no waiter)")

    # =========================
    # MGMT initiator (ensure_session)
    # =========================
    def ensure_session(self, peer: str, reason: str = "") -> bool:
        """
        Establish MGMT session to peer if absent.
        Thread-safe: per-peer inflight barrier.
        """
        if peer == self.name:
            self.logger.error(f"[MGMT] ensure_session to self is forbidden, reason={reason}")
            return False

        # fast path + inflight
        with self.state.lock:
            if peer in self.state.sessions:
                return True

            inflight = self.state.ensure_inflight.get(peer)
            if inflight is None:
                inflight = threading.Event()
                self.state.ensure_inflight[peer] = inflight
                leader = True
            else:
                leader = False

        if not leader:
            inflight.wait(UDP_TIMEOUT_S * RETRIES * 2)
            with self.state.lock:
                return peer in self.state.sessions

        # leader does handshake
        label = f"{self.name}-{peer}"  # initiator-responder
        self.logger.info(f"[MGMT] ensure_session start {self.name}->{peer} reason={reason or 'unspecified'}")

        try:
            for attempt in range(RETRIES):
                sid = secrets.token_hex(8)
                init_ev = threading.Event()
                auth_ev = threading.Event()

                with self.state.lock:
                    self.state.hs_init_ev[sid] = init_ev
                    self.state.hs_auth_ev[sid] = auth_ev
                    # очистка на всякий (если вдруг sid совпал, что маловероятно, но ок)
                    self.state.hs_initresp.pop(sid, None)
                    self.state.hs_authresp.pop(sid, None)

                self.logger.info(f"[MGMT] WAIT INIT_RESP sid={sid} peer={peer} attempt={attempt+1}")

                i_priv = x25519.X25519PrivateKey.generate()
                i_pub = xpub_bytes(i_priv.public_key())
                ni = secrets.token_bytes(16)

                init_msg = jdump({
                    "t": T_MGMT_INIT, "sid": sid,
                    "from": self.name, "to": peer,
                    "ni": ni.hex(), "ke": i_pub.hex(),
                })
                self.transport.send_peer(peer, init_msg)

                if not init_ev.wait(UDP_TIMEOUT_S):
                    self.logger.warning(f"[MGMT] timeout INIT_RESP from {peer} sid={sid} reason={reason or 'unspecified'}")
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    resp = self.state.hs_initresp.get(sid)

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

                auth_msg = jdump({
                    "t": T_MGMT_AUTH, "sid": sid,
                    "from": self.name, "to": peer,
                    "nonce": n1.hex(), "ct": c1.hex(),
                })
                self.transport.send_peer(peer, auth_msg)

                if not auth_ev.wait(UDP_TIMEOUT_S):
                    self.logger.warning(f"[MGMT] timeout AUTH_RESP from {peer} sid={sid} reason={reason or 'unspecified'}")
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    resp2 = self.state.hs_authresp.get(sid)

                if not resp2 or resp2.get("from") != peer or resp2.get("to") != self.name:
                    self.logger.warning(f"[MGMT] bad AUTH_RESP mailbox sid={sid} reason={reason or 'unspecified'}")
                    self._cleanup_hs(sid)
                    continue

                aad2 = f"AUTH:{label}:{peer}->{self.name}:{sid}".encode()
                try:
                    _ = aesgcm_decrypt(
                        kd,
                        bytes.fromhex(resp2["nonce"]),
                        bytes.fromhex(resp2["ct"]),
                        aad=aad2,
                    )
                except Exception as e:
                    self.logger.error(f"[MGMT] AUTH_RESP decrypt fail sid={sid} from={peer}: {e}")
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    self.state.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)

                self._cleanup_hs(sid)
                self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid} reason={reason or 'unspecified'}")
                return True

            return False

        finally:
            # release inflight barrier for waiters
            with self.state.lock:
                ev = self.state.ensure_inflight.pop(peer, None)
            if ev:
                ev.set()

    def _cleanup_hs(self, sid: str):
        with self.state.lock:
            self.state.hs_init_ev.pop(sid, None)
            self.state.hs_auth_ev.pop(sid, None)
            self.state.hs_initresp.pop(sid, None)
            self.state.hs_authresp.pop(sid, None)