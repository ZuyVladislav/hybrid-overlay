# errors.py
from __future__ import annotations
from typing import Optional

from protocol import err, jdump, T_ERROR
from state import DaemonState


class ErrorRelay:
    def __init__(self, name: str, state: DaemonState, transport, logger):
        self.name = name
        self.state = state
        self.transport = transport
        self.logger = logger

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
        self.transport.send_peer(nxt, payload)

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
            self.transport.send_peer(nxt, jdump(fwd))
            return

        if conn_id and conn_id in self.state.conns:
            st = self.state.conns[conn_id]
            st.last_error = {"code": code, "msg": msg}
            st.done_event.set()