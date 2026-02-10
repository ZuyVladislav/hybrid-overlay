# daemon.py
from __future__ import annotations
import argparse
import random
import socket
import threading
import time

from config import USERS, PRECONNECT_ENABLED
from logging_util import setup_logger
from protocol import (
    jload,
    T_MGMT_INIT, T_MGMT_INIT_RESP, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_I1, T_I2, T_OKX2,
    T_PROXY_BLOB,
    T_LOCAL_CONNECT,
    T_ERROR,
)

from ike_proxy import IkeProxy
from state import DaemonState
from transport import Transport
from secure_link import SecureLink
from mgmt import Mgmt
from errors import ErrorRelay
from router import Router
from proxy import Proxy


class NodeDaemon:
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(name)

        if name not in USERS:
            raise RuntimeError(f"Unknown user {name} in config USERS")
        port = USERS[name]["port"]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(0.2)

        self.state = DaemonState(
            lock=threading.Lock(),
            sessions={},
            pending={},
            hs_initresp={},
            hs_authresp={},
            hs_init_ev={},
            hs_auth_ev={},
            okx2_ev={},
            okx2_data={},
            okx2_x2name={},
            conns={},
            ensure_inflight={},
        )

        self.transport = Transport(name, self.sock, self.logger)
        self.sec = SecureLink(name, self.state, self.transport, self.logger)
        self.mgmt = Mgmt(name, self.state, self.transport, self.logger)
        self.err = ErrorRelay(name, self.state, self.transport, self.logger)

        # shared dict ref for IkeProxy injection routing
        self.ike_route = {}
        self.ike_proxy = IkeProxy(self._on_ike_local, self.logger)
        self.ike_proxy.start()

        self.router = Router(
            name=name,
            state=self.state,
            mgmt=self.mgmt,
            secure_link=self.sec,
            error_relay=self.err,
            transport=self.transport,
            ike_route_ref=self.ike_route,
            logger=self.logger
        )
        self.proxy = Proxy(
            name=name,
            state=self.state,
            mgmt=self.mgmt,
            secure_link=self.sec,
            error_relay=self.err,
            ike_proxy=self.ike_proxy,
            logger=self.logger
        )

        self.running = True
        self.preconnect_thread = None

    def safe_load(self, data: bytes):
        try:
            return jload(data)
        except Exception:
            self.logger.warning("Malformed packet (non-json)")
            return None

    def recv_one(self):
        try:
            data, src = self.sock.recvfrom(65535)
            return data, src
        except socket.timeout:
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
            self.sec.link_send(meta["x1"], T_PROXY_BLOB, data, meta=meta)
        except Exception as e:
            self.logger.error(f"[IKEP] inject into overlay failed: {e}")
            return

        self.logger.info(f"[IKEP] injected into overlay len={len(data)} dport={dport}")

    def handle_packet(self, data: bytes, src):
        p = self.safe_load(data)
        if not p:
            return

        t = p.get("t")
        claimed = p.get("from")

        if t == T_LOCAL_CONNECT:
            self.router.on_local_connect(p, src)
            return

        peer = self.transport.resolve_peer(t, p, src)
        if peer is None:
            self.logger.warning(f"[ADDR] drop packet: src={src} claimed={claimed} t={t}")
            return

        # mgmt responder
        if t == T_MGMT_INIT:
            self.mgmt.on_mgmt_init(p, peer)
            return
        if t == T_MGMT_AUTH:
            self.mgmt.on_mgmt_auth(p, peer)
            return

        # mgmt mailbox
        if t == T_MGMT_INIT_RESP:
            self.mgmt.on_init_resp(p)
            return
        if t == T_MGMT_AUTH_RESP:
            self.mgmt.on_auth_resp(p)
            return

        if t == T_ERROR:
            self.err.on_error(p, peer)
            return

        # secure overlay messages
        if t in (T_I1, T_I2, T_OKX2, T_PROXY_BLOB):
            try:
                plain = self.sec.link_decrypt(p)
            except Exception as e:
                self.logger.error(f"[SEC] decrypt fail t={t} from={peer}: {e}")
                return

            if t == T_I1:
                self.router.handle_I1(peer, plain)
            elif t == T_I2:
                self.router.handle_I2(peer, plain)
            elif t == T_OKX2:
                self.router.handle_OKX2(peer, plain)
            elif t == T_PROXY_BLOB:
                self.proxy.handle_PROXY(peer, plain, p.get("meta") or {})
            return

        self.logger.info(f"[DROP] unknown t={t} from={peer}")

    def _preconnect_loop(self):
        time.sleep(random.uniform(0.2, 0.8))
        while self.running:
            peers = [u for u in USERS.keys() if u != self.name]
            random.shuffle(peers)
            for peer in peers:
                with self.state.lock:
                    has = peer in self.state.sessions or peer in self.state.ensure_inflight
                if has:
                    continue
                self.mgmt.ensure_session(peer, reason="preconnect")
                time.sleep(0.05)
            time.sleep(0.5)

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