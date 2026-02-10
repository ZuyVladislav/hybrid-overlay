# proxy.py
from __future__ import annotations
from typing import Optional

from protocol import T_PROXY_BLOB

from state import DaemonState


class Proxy:
    def __init__(self, name: str, state: DaemonState, mgmt, secure_link, error_relay, ike_proxy, logger):
        self.name = name
        self.state = state
        self.mgmt = mgmt
        self.sec = secure_link
        self.err = error_relay
        self.ike_proxy = ike_proxy
        self.logger = logger

    def handle_PROXY(self, peer: str, plain: bytes, meta: dict):
        conn_id = meta.get("conn_id", "")
        src_u = meta.get("src", "")
        dst_u = meta.get("dst", "")
        x1_u = meta.get("x1", "")
        x2_u = meta.get("x2", "")
        idx = int(meta.get("idx", 0))
        direction = meta.get("dir", "fwd")
        phase = meta.get("phase", "UNK")

        if phase == "IKE_REAL" and idx == 3 and (self.name == dst_u or self.name == src_u):
            ike_listen_port = int(meta.get("ike_port", 15000))
            peer_ip = meta.get("peer_ip")
            peer_port = meta.get("peer_port")
            orig_dst_ip = meta.get("orig_dst_ip")
            orig_dst_port = meta.get("orig_dst_port")

            self.logger.info(
                f"[IKEP] ARRIVE END={self.name} listen_port={ike_listen_port} len={len(plain)} "
                f"peer={peer_ip}:{peer_port} orig_dst={orig_dst_ip}:{orig_dst_port} dir={direction}"
            )

            if peer_ip and peer_port:
                local_dst = (orig_dst_ip, int(orig_dst_port)) if (orig_dst_ip and orig_dst_port) else None
                self.ike_proxy.inject_to_charon(
                    plain,
                    ike_listen_port,
                    peer_addr=(peer_ip, int(peer_port)),
                    local_dst=local_dst,
                )
            else:
                self.logger.warning("[IKEP] missing peer_ip/peer_port in meta; injecting without transparent src spoof")
                self.ike_proxy.inject_to_charon(plain, ike_listen_port)
            return

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        if idx < 0 or idx >= len(route) or route[idx] != self.name:
            self.logger.warning(f"[PROXY] route mismatch idx={idx} dir={direction} route={route}")
            return

        if direction == "fwd" and self.name == dst_u and idx == 3:
            self.logger.info(f"[PROXY] ARRIVE DST={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
            meta2 = dict(meta); meta2["dir"] = "back"; meta2["idx"] = 0
            self.forward_proxy(plain, meta2)
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

        with self.state.lock:
            has_session = nxt in self.state.sessions

        if not has_session:
            # Variant A: never establish session to DST during PROXY
            if nxt == dst_u:
                self.logger.error(f"[PROXY] NO_SESSION_DST (blocked in PROXY) {self.name}->{nxt} phase={phase} CONN={conn_id}")
                self.err.send_error_back(
                    conn_id, src_u, x1_u, phase,
                    code="NO_SESSION_DST",
                    msg=f"no session to DST={nxt}; must be preconnected by X2"
                )
                return

            if not self.mgmt.ensure_session(nxt, reason=f"PROXY {direction} phase={phase} CONN={conn_id}"):
                self.logger.error(f"[PROXY] cannot ensure session to {nxt}")
                self.err.send_error_back(conn_id, src_u, x1_u, phase, code="NO_SESSION_NEXT", msg=f"cannot ensure {nxt}")
                return

        meta2 = dict(meta); meta2["idx"] = nxt_idx
        if nxt == self.name:
            self.logger.error(f"[PROXY] BUG: next hop is self, drop. meta={meta}")
            return

        self.sec.link_send(nxt, T_PROXY_BLOB, payload, meta=meta2)
        self.logger.info(
            f"[PROXY] {direction} {self.name}->{nxt} idx={nxt_idx} phase={phase} "
            f"route={src_u}->{x1_u}->{x2_u}->{dst_u} CONN={conn_id}"
        )