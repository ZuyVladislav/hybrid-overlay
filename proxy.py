# proxy.py
from __future__ import annotations
import time
import threading
from typing import Optional, Dict, Any

from protocol import T_PROXY_BLOB

# Proxy — отвечает за пересылку T_PROXY_BLOB по цепочке узлов.
class Proxy:
    def __init__(self, name: str, state, mgmt, secure_link, error_relay, ike_proxy, logger):
        self.name = name
        self.state = state
        self.mgmt = mgmt
        self.sec = secure_link
        self.error_relay = error_relay
        self.ike_proxy = ike_proxy
        self.logger = logger
        self._lock = threading.Lock()

    def _determine_next_hop(self, meta: Dict[str, Any]) -> Optional[str]:
        """Определить следующий hop по meta и self.name.

        Ожидаемые поля meta: src, dst, x1, x2, dir (fwd|back), idx (опционально).
        Правила:
          fwd: src -> x1 -> x2 -> dst
          back: dst -> x2 -> x1 -> src
        """
        src = meta.get("src")
        dst = meta.get("dst")
        x1 = meta.get("x1")
        x2 = meta.get("x2")
        dir_ = meta.get("dir")

        if not all([src, dst, x1, x2, dir_]):
            self.logger.error(f"[PROXY] bad meta (missing fields): {meta}")
            return None

        cur = self.name

        if dir_ == "fwd":
            if cur == src:
                return x1
            if cur == x1:
                return x2
            if cur == x2:
                return dst
            # not in route
            self.logger.error(f"[PROXY] fwd: {cur} not in {src}->{x1}->{x2}->{dst}")
            return None

        if dir_ == "back":
            if cur == dst:
                return x2
            if cur == x2:
                return x1
            if cur == x1:
                return src
            self.logger.error(f"[PROXY] back: {cur} not in {src}->{x1}->{x2}->{dst}")
            return None

        self.logger.error(f"[PROXY] unknown dir: {dir_} in meta={meta}")
        return None

    def _send_error_back(self, conn_id: Optional[str], src: Optional[str],
                         x1: Optional[str], phase: Optional[str],
                         code: str, msg: str, prev_peer: Optional[str]):
        """Попытка корректно уведомить об ошибке:
           - если есть conn_id и error_relay.send_error_back -> использовать его
           - иначе — собрать пакет и либо отправить через error_relay.on_error, либо залогировать
        """
        try:
            if conn_id and hasattr(self.error_relay, "send_error_back"):
                try:
                    self.error_relay.send_error_back(conn_id, src or "", x1 or "", phase or "", code, msg)
                    self.logger.info(f"[PROXY] error sent back via error_relay.send_error_back conn={conn_id} code={code}")
                    return
                except Exception as e:
                    self.logger.exception(f"[PROXY] send_error_back raised: {e}")

            # fallback: если есть on_error, передадим туда сформированный p
            if hasattr(self.error_relay, "on_error"):
                p = {
                    "code": code,
                    "msg": msg,
                    "meta": {
                        "conn_id": conn_id or "",
                        "src": src or "",
                        "x1": x1 or "",
                        "phase": phase or "",
                        # строим минимальную маршрутную информацию, idx=1 чтобы error_relay мог двигать дальше
                        "idx": 1,
                        "route": [self.name, x1 or "", src or ""]
                    }
                }
                try:
                    # on_error принимает (p, peer)
                    self.error_relay.on_error(p, prev_peer)
                    self.logger.info(f"[PROXY] error handed to error_relay.on_error (peer={prev_peer})")
                    return
                except Exception as e:
                    self.logger.exception(f"[PROXY] error_relay.on_error raised: {e}")

            # last resort: просто логируем
            self.logger.error(f"[PROXY] cannot relay error (no suitable method). code={code} msg={msg} conn={conn_id}")

        except Exception as e:
            self.logger.exception(f"[PROXY] _send_error_back exception: {e}")

    def handle_PROXY(self, peer: str, plain: bytes, meta: Dict[str, Any]):
        """
        Обработка T_PROXY_BLOB.
        peer - имя узла-отправителя (overlay peer name).
        plain - расшифрованный blob (байты).
        meta - метаинформация маршрута.
        """
        try:
            src = meta.get("src")
            dst = meta.get("dst")
            x1 = meta.get("x1")
            x2 = meta.get("x2")
            dir_ = meta.get("dir")
            idx = meta.get("idx", 0)
            phase = meta.get("phase")
            conn_id = meta.get("conn_id")

            self.logger.info(
                f"[PROXY] RX peer={peer} len={len(plain)} meta.dir={dir_} meta.idx={idx} "
                f"src={src} dst={dst} x1={x1} x2={x2} phase={phase} conn={conn_id}"
            )

            next_peer = self._determine_next_hop(meta)
            if not next_peer:
                msg = f"cannot determine next hop for meta={meta}"
                self.logger.error(f"[PROXY] {msg}")
                # уведомляем назад (prev peer)
                self._send_error_back(conn_id, src, x1, phase, "NO_ROUTE", msg, prev_peer=peer)
                return

            # Защита от маршрута, в котором next_peer == self
            if next_peer == self.name:
                msg = f"invalid routing, next_peer == self ({self.name}) meta={meta}"
                self.logger.error(f"[PROXY] {msg}")
                self._send_error_back(conn_id, src, x1, phase, "NO_SESSION_NEXT", f"cannot ensure {self.name}", prev_peer=peer)
                return

            # Попытка обеспечить session к next_peer
            try:
                self.logger.debug(f"[PROXY] ensure_session to {next_peer} (reason=PROXY {dir_})")
                # Поддерживаем возможные варианты сигнатуры ensure_session
                try:
                    self.mgmt.ensure_session(next_peer, reason=f"PROXY {dir_}")
                except TypeError:
                    self.mgmt.ensure_session(next_peer)
            except Exception as e:
                self.logger.exception(f"[PROXY] mgmt.ensure_session({next_peer}) failed: {e}")

            # Небольшое ожидание с проверкой state.sessions
            session_ready = False
            wait_total = 0.0
            wait_step = 0.05
            max_wait = 0.6
            while wait_total < max_wait:
                with self.state.lock:
                    if next_peer in self.state.sessions:
                        session_ready = True
                        break
                time.sleep(wait_step)
                wait_total += wait_step

            if not session_ready:
                self.logger.warning(f"[PROXY] session to {next_peer} not ready after {max_wait:.2f}s; will attempt send anyway")

            # Подготовка meta для следующего хопа: инкремент idx (в большинстве логики idx указывает позицию)
            meta2 = dict(meta)
            try:
                meta2["idx"] = int(idx) + 1
            except Exception:
                meta2["idx"] = idx

            # Отправляем дальше
            try:
                self.sec.link_send(next_peer, T_PROXY_BLOB, plain, meta=meta2)
                self.logger.info(f"[PROXY] fwd {self.name}->{next_peer} dir={dir_} idx={meta2.get('idx')} phase={phase} conn={conn_id}")
            except Exception as e:
                self.logger.exception(f"[PROXY] link_send to {next_peer} failed: {e}")
                # уведомляем предыдущий узел об ошибке отправки
                self._send_error_back(conn_id, src, x1, phase, "SEND_FAIL", f"send to {next_peer} failed: {e}", prev_peer=peer)
                return

        except Exception as e:
            # Защита от падения worker'а
            self.logger.exception(f"[PROXY] handle_PROXY unexpected exception: {e}")
            try:
                self._send_error_back(meta.get("conn_id") if isinstance(meta, dict) else None,
                                      meta.get("src") if isinstance(meta, dict) else None,
                                      meta.get("x1") if isinstance(meta, dict) else None,
                                      meta.get("phase") if isinstance(meta, dict) else None,
                                      "INTERNAL_ERROR", f"proxy exception: {e}", prev_peer=peer)
            except Exception:
                pass