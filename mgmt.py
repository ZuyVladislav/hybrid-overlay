# mgmt.py
from __future__ import annotations

import secrets
import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519

from config import UDP_TIMEOUT_S, RETRIES
from crypto_util import (
    aesgcm_encrypt,
    aesgcm_decrypt,
    hkdf_sha256,
    xpub_bytes,
    xpub_from_bytes,
)
from protocol import (
    jdump,
    err,
    T_MGMT_INIT,
    T_MGMT_INIT_RESP,
    T_MGMT_AUTH,
    T_MGMT_AUTH_RESP,
)
from state import DaemonState, PendingHS, MgmtSession


class Mgmt:
    """
    MGMT-plane handshake (IKEv2-like):
      INIT  (I->R): ni, KEi, sid
      INIT_RESP(R->I): nr, KEr, sid
      AUTH  (I->R): AESGCM(kd, aad=AUTH:label:I->R:sid)
      AUTH_RESP(R->I): AESGCM(kd, aad=AUTH:label:R->I:sid)

    Mailbox pattern:
      - receiver thread calls on_init_resp/on_auth_resp
      - ensure_session waits on per-sid events
    """

    def __init__(self, name: str, state: DaemonState, transport, logger):
        self.name = name
        self.state = state
        self.transport = transport
        self.logger = logger

    # ---------- KDF ----------
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

        i_pub = bytes.fromhex(p["ke"])
        ni = bytes.fromhex(p["ni"])

        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = xpub_bytes(r_priv.public_key())
        nr = secrets.token_bytes(16)

        label = f"{peer}-{self.name}"  # initiator-responder label (responder side)

        with self.state.lock:
            self.state.pending[sid] = PendingHS(
                priv=r_priv, nr=nr, ni=ni, i_pub=i_pub, label=label
            )

        resp = jdump(
            {
                "t": T_MGMT_INIT_RESP,
                "sid": sid,
                "from": self.name,
                "to": peer,
                "nr": nr.hex(),
                "ke": r_pub.hex(),
            }
        )
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

        aad_in = f"AUTH:{st.label}:{peer}->{self.name}:{sid}".encode()
        try:
            _ = aesgcm_decrypt(
                kd,
                bytes.fromhex(p["nonce"]),
                bytes.fromhex(p["ct"]),
                aad=aad_in,
            )
        except Exception as e:
            self.logger.error(f"[MGMT] AUTH decrypt fail sid={sid} from={peer}: {e}")
            self.transport.send_peer(peer, err("AUTH_FAIL", "mgmt auth decrypt failed"))
            return

        aad_out = f"AUTH:{st.label}:{self.name}->{peer}:{sid}".encode()
        auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
        n2, c2 = aesgcm_encrypt(kd, auth_plain, aad=aad_out)

        resp = jdump(
            {
                "t": T_MGMT_AUTH_RESP,
                "sid": sid,
                "from": self.name,
                "to": peer,
                "nonce": n2.hex(),
                "ct": c2.hex(),
            }
        )
        self.transport.send_peer(peer, resp)

        with self.state.lock:
            self.state.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)
            self.state.pending.pop(sid, None)

        self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")

    # =========================
    # MGMT mailbox (receiver thread)
    # =========================
    def on_init_resp(self, p: dict):
        if p.get("to") != self.name:
            return
        sid = p.get("sid")
        if not sid:
            return

        with self.state.lock:
            self.state.hs_initresp[sid] = p
            ev = self.state.hs_init_ev.get(sid)

        ev_exists = ev is not None
        ev_set = 1 if ev_exists else 0
        self.logger.info(
            f"[MGMT] RX MGMT_INIT_RESP sid={sid} from={p.get('from')} to={p.get('to')} "
            f"ev_exists={ev_exists} ev_set={ev_set}"
        )
        if ev:
            ev.set()

    def on_auth_resp(self, p: dict):
        if p.get("to") != self.name:
            return
        sid = p.get("sid")
        if not sid:
            return

        with self.state.lock:
            self.state.hs_authresp[sid] = p
            ev = self.state.hs_auth_ev.get(sid)

        ev_exists = ev is not None
        ev_set = 1 if ev_exists else 0
        self.logger.info(
            f"[MGMT] RX MGMT_AUTH_RESP sid={sid} from={p.get('from')} to={p.get('to')} "
            f"ev_exists={ev_exists} ev_set={ev_set}"
        )
        if ev:
            ev.set()

    # =========================
    # MGMT initiator (ensure_session)
    # =========================
    def ensure_session(self, peer: str, reason: str = "") -> bool:
        if peer == self.name:
            self.logger.error(f"[MGMT] ensure_session to self forbidden reason={reason}")
            return False

        # inflight gate per peer (prevents parallel handshakes from same node)
        with self.state.lock:
            if peer in self.state.sessions:
                return True

            inflight_ev = self.state.ensure_inflight.get(peer)
            if inflight_ev is None:
                inflight_ev = threading.Event()
                self.state.ensure_inflight[peer] = inflight_ev
                i_am_owner = True
            else:
                i_am_owner = False

        if not i_am_owner:
            # someone else is already doing ensure_session(peer)
            inflight_ev.wait(UDP_TIMEOUT_S * RETRIES)
            with self.state.lock:
                return peer in self.state.sessions

        try:
            label = f"{self.name}-{peer}"  # initiator-responder label (initiator side)

            self.logger.info(
                f"[MGMT] ensure_session start {self.name}->{peer} "
                f"reason={reason or 'unspecified'}"
            )

            for attempt in range(1, RETRIES + 1):
                sid = secrets.token_hex(8)
                init_ev = threading.Event()
                auth_ev = threading.Event()

                with self.state.lock:
                    self.state.hs_init_ev[sid] = init_ev
                    self.state.hs_auth_ev[sid] = auth_ev
                    self.state.hs_initresp.pop(sid, None)
                    self.state.hs_authresp.pop(sid, None)

                # --- build INIT ---
                i_priv = x25519.X25519PrivateKey.generate()
                i_pub = xpub_bytes(i_priv.public_key())
                ni = secrets.token_bytes(16)

                init_msg = jdump(
                    {
                        "t": T_MGMT_INIT,
                        "sid": sid,
                        "from": self.name,
                        "to": peer,
                        "ni": ni.hex(),
                        "ke": i_pub.hex(),
                    }
                )
                self.transport.send_peer(peer, init_msg)
                self.logger.info(f"[MGMT] -> {peer} INIT sid={sid} attempt={attempt}")

                # --- wait INIT_RESP ---
                self.logger.info(f"[MGMT] WAIT INIT_RESP sid={sid} peer={peer} attempt={attempt}")
                if not init_ev.wait(UDP_TIMEOUT_S):
                    self.logger.warning(
                        f"[MGMT] timeout INIT_RESP from {peer} sid={sid} "
                        f"reason={reason or 'unspecified'}"
                    )
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    resp = self.state.hs_initresp.get(sid)

                if not resp or resp.get("from") != peer or resp.get("to") != self.name:
                    self.logger.warning(
                        f"[MGMT] bad INIT_RESP mailbox sid={sid} got_from={resp.get('from') if resp else None} "
                        f"got_to={resp.get('to') if resp else None} reason={reason or 'unspecified'}"
                    )
                    self._cleanup_hs(sid)
                    continue

                nr = bytes.fromhex(resp["nr"])
                r_pub = bytes.fromhex(resp["ke"])
                shared = i_priv.exchange(xpub_from_bytes(r_pub))
                kd = self.mgmt_kdf(shared, ni, nr, label=label)

                # --- send AUTH ---
                aad_out = f"AUTH:{label}:{self.name}->{peer}:{sid}".encode()
                auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
                n1, c1 = aesgcm_encrypt(kd, auth_plain, aad=aad_out)

                auth_msg = jdump(
                    {
                        "t": T_MGMT_AUTH,
                        "sid": sid,
                        "from": self.name,
                        "to": peer,
                        "nonce": n1.hex(),
                        "ct": c1.hex(),
                    }
                )
                self.transport.send_peer(peer, auth_msg)

                # --- wait AUTH_RESP ---
                self.logger.info(f"[MGMT] WAIT AUTH_RESP sid={sid} peer={peer} attempt={attempt}")
                if not auth_ev.wait(UDP_TIMEOUT_S):
                    self.logger.warning(
                        f"[MGMT] timeout AUTH_RESP from {peer} sid={sid} "
                        f"reason={reason or 'unspecified'}"
                    )
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    resp2 = self.state.hs_authresp.get(sid)

                if not resp2 or resp2.get("from") != peer or resp2.get("to") != self.name:
                    self.logger.warning(
                        f"[MGMT] bad AUTH_RESP mailbox sid={sid} got_from={resp2.get('from') if resp2 else None} "
                        f"got_to={resp2.get('to') if resp2 else None} reason={reason or 'unspecified'}"
                    )
                    self._cleanup_hs(sid)
                    continue

                # --- verify AUTH_RESP ---
                aad_in = f"AUTH:{label}:{peer}->{self.name}:{sid}".encode()
                try:
                    _ = aesgcm_decrypt(
                        kd,
                        bytes.fromhex(resp2["nonce"]),
                        bytes.fromhex(resp2["ct"]),
                        aad=aad_in,
                    )
                except Exception as e:
                    self.logger.error(f"[MGMT] AUTH_RESP decrypt fail sid={sid} from={peer}: {e}")
                    self._cleanup_hs(sid)
                    continue

                with self.state.lock:
                    self.state.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)

                self._cleanup_hs(sid)
                self.logger.info(
                    f"[MGMT] EST {self.name}<->{peer} sid={sid} reason={reason or 'unspecified'}"
                )
                return True

            return False

        finally:
            # release inflight gate
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