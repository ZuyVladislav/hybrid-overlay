# mgmt.py
from __future__ import annotations
import threading
import uuid
import time
from typing import Optional, Dict

from protocol import (
    jdump, jload,
    T_MGMT_INIT, T_MGMT_INIT_RESP, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_ERROR
)
from config import USERS, UDP_TIMEOUT_S, RETRIES
from state import DaemonState


class Mgmt:
    def __init__(self, name: str, state: DaemonState, transport, logger):
        self.name = name
        self.state = state
        self.transport = transport
        self.logger = logger

    # Внешний вызов: обеспечить mgmt-сессию к peer (ленивая установка)
    def ensure_session(self, peer: str, reason: str = "PROXY", phase: Optional[str] = None, conn: Optional[str] = None) -> bool:
        """
        Попытаться установить mgmt-сессию к peer. Возвращает True если сессия установлена.
        Блокирующий вызов — он делает несколько попыток и ждёт ответа INIT_RESP.
        """
        if peer == self.name:
            return True

        with self.state.lock:
            st = self.state.sessions.get(peer)
            if st and st.get("established"):
                return True
            # если уже есть inflight - дождёмся
            inflight = self.state.ensure_inflight.get(peer)
            if inflight:
                self.logger.debug(f"[MGMT] ensure_session: waiting existing inflight for {peer}")
                # ждём до timeout
                ok = inflight.wait(UDP_TIMEOUT_S * RETRIES + 0.5)
                with self.state.lock:
                    st2 = self.state.sessions.get(peer)
                    return bool(st2 and st2.get("established"))

            # пометим inflight
            ev = threading.Event()
            self.state.ensure_inflight[peer] = ev

        sid = uuid.uuid4().hex[:16]
        attempt = 0
        success = False

        while attempt < RETRIES:
            attempt += 1
            self.logger.info(f"[MGMT] -> {peer} INIT sid={sid} attempt={attempt}")
            payload = {
                "t": T_MGMT_INIT,
                "sid": sid,
                "from": self.name,
                "to": peer,
                "meta": {"reason": reason, "phase": phase, "conn": conn}
            }
            try:
                self.transport.send_peer(peer, jdump(payload))
            except Exception as e:
                self.logger.warning(f"[MGMT] send INIT to {peer} failed: {e}")

            # подготовим ожидание
            ev_local = threading.Event()
            with self.state.lock:
                # hs_init_ev — словарь sid->Event (как в оригинальной реализации)
                self.state.hs_init_ev[sid] = ev_local

            waited = ev_local.wait(UDP_TIMEOUT_S)
            with self.state.lock:
                resp = self.state.hs_initresp.pop(sid, None)
                # убираем event
                self.state.hs_init_ev.pop(sid, None)

            if waited and resp:
                # Установим сессию
                addr_ip = resp.get("addr_ip") or USERS.get(peer, {}).get("ip")
                addr_port = int(resp.get("addr_port") or USERS.get(peer, {}).get("port"))
                if addr_ip is None or addr_port is None:
                    self.logger.warning(f"[MGMT] INIT_RESP from {peer} missed addr info, using config")
                    addr_ip = USERS.get(peer, {}).get("ip")
                    addr_port = USERS.get(peer, {}).get("port")

                with self.state.lock:
                    self.state.sessions[peer] = {"addr": (addr_ip, addr_port), "established": True}
                    # чистим inflight
                    self.state.ensure_inflight.pop(peer, None)

                self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")
                success = True
                break

            # если не дождались — повторим
            self.logger.warning(f"[MGMT] timeout INIT_RESP from {peer} sid={sid} attempt={attempt} (reason={reason})")

        # если не удалось — пометим неуспех и очистим inflight
        if not success:
            with self.state.lock:
                self.state.ensure_inflight.pop(peer, None)
            self.logger.error(f"[MGMT] cannot ensure session {peer} after {RETRIES} attempts")

        return success

    # Входящий INIT (responder)
    def on_mgmt_init(self, p: Dict, peer: Optional[str]):
        """
        Обрабатывает входящий MGMT INIT — отвечает INIT_RESP и отмечает сессию.
        p: словарь с полями 'sid', 'from' и т.д.
        peer: resolved peer name (transport.resolve_peer)
        """
        sid = p.get("sid")
        frm = p.get("from") or peer
        self.logger.info(f"[MGMT] <- {frm} INIT; -> INIT_RESP sid={sid}")
        # Ответим INIT_RESP с нашей адресной информацией
        my_ip = USERS[self.name]["ip"]
        my_port = USERS[self.name]["port"]
        resp = {
            "t": T_MGMT_INIT_RESP,
            "sid": sid,
            "from": self.name,
            "to": frm,
            "addr_ip": my_ip,
            "addr_port": my_port,
        }
        try:
            self.transport.send_peer(frm, jdump(resp))
        except Exception as e:
            self.logger.error(f"[MGMT] failed send INIT_RESP to {frm}: {e}")

        # Пометим сессию как установленную (responder-side)
        with self.state.lock:
            self.state.sessions[frm] = {"addr": (USERS[frm]["ip"], USERS[frm]["port"]), "established": True}
        self.logger.info(f"[MGMT] EST {self.name}<->{frm} sid={sid}")

    # Входящий INIT_RESP (инициатор ждёт этот ответ)
    def on_init_resp(self, p: Dict):
        sid = p.get("sid")
        frm = p.get("from")
        self.logger.info(f"[MGMT] RX {T_MGMT_INIT_RESP} sid={sid} from={frm}")
        with self.state.lock:
            self.state.hs_initresp[sid] = p
            ev = self.state.hs_init_ev.get(sid)
        if ev:
            try:
                ev.set()
            except Exception:
                pass

    # AUTH обработчики (на будущее) — пока реализованы как пассивные обработчики
    def on_mgmt_auth(self, p: Dict, peer: Optional[str]):
        sid = p.get("sid")
        frm = p.get("from") or peer
        self.logger.info(f"[MGMT] <- {frm} AUTH sid={sid}; -> AUTH_RESP sid={sid}")
        # простой эхо-ответ (если нужен более строгий обмен — сюда добавить логику)
        resp = {"t": T_MGMT_AUTH_RESP, "sid": sid, "from": self.name, "to": frm}
        try:
            self.transport.send_peer(frm, jdump(resp))
        except Exception as e:
            self.logger.error(f"[MGMT] failed send AUTH_RESP to {frm}: {e}")

        # отметим сессию
        with self.state.lock:
            self.state.sessions[frm] = {"addr": (USERS[frm]["ip"], USERS[frm]["port"]), "established": True}
        self.logger.info(f"[MGMT] EST {self.name}<->{frm} sid={sid}")

    def on_auth_resp(self, p: Dict):
        sid = p.get("sid")
        frm = p.get("from")
        self.logger.info(f"[MGMT] RX {T_MGMT_AUTH_RESP} sid={sid} from={frm}")
        with self.state.lock:
            self.state.hs_authresp[sid] = p
            ev = self.state.hs_auth_ev.get(sid)
        if ev:
            try:
                ev.set()
            except Exception:
                pass