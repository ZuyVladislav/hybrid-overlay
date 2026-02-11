# proxy.py
from __future__ import annotations
import threading
import time
from typing import Optional, Dict, List

from protocol import jdump, jload, T_PROXY_BLOB, T_ERROR
from config import USERS
from state import DaemonState


class Proxy:
    def __init__(self, name: str, state: DaemonState, mgmt: object, secure_link, error_relay, ike_proxy, logger):
        """
        secure_link -- экземпляр SecureLink (у него должен быть .link_send(dest_x, t, data, meta=...) )
        mgmt -- экземпляр Mgmt (у него метод ensure_session(peer, ...))
        error_relay -- экземпляр ErrorRelay
        ike_proxy -- (не используется в примере, но принимаем для совместимости)
        """
        self.name = name
        self.state = state
        self.mgmt = mgmt
        self.sec = secure_link
        self.err = error_relay
        self.ikep = ike_proxy
        self.logger = logger

    def _parse_route(self, meta: Dict) -> Optional[List[str]]:
        """
        Возвращает route как список узлов, если возможно.
        Ожидает либо строку 'route' в meta (например 'User1->User3->User2->User4'),
        либо пытается восстановить из src/x1/x2/dst.
        """
        rt = meta.get("route")
        if rt:
            if isinstance(rt, str):
                parts = [p.strip() for p in rt.split("->") if p.strip()]
                if parts:
                    return parts
            elif isinstance(rt, list):
                return rt[:]
        # fallback: если есть src и dst и x1/x2, постараемся восстановить минимальный маршрут
        src = meta.get("src")
        dst = meta.get("dst")
        x1 = meta.get("x1")
        x2 = meta.get("x2")
        if src and dst:
            # простая эвристика: если есть x1/x2 — считаем маршрут src->x1->x2->dst или src->x2->x1->dst
            if x1 and x2:
                # устраним дубликаты, сохраним порядок
                cand = [src, x1, x2, dst]
                seen = set()
                res = []
                for c in cand:
                    if c and c not in seen:
                        res.append(c); seen.add(c)
                return res
            else:
                return [src, dst]
        return None

    def _compute_next(self, route: List[str], meta: Dict):
        """
        Вычисляет имя следующего пира, согласно описанию в тексте ответа.
        При ошибке возвращает None.
        """
        dir_ = meta.get("dir", "fwd")
        try:
            idx = int(meta.get("idx", 0))
        except Exception:
            idx = 0

        if dir_ == "fwd":
            # next = route[idx]
            if idx < 0 or idx >= len(route):
                return None
            return route[idx]
        else:  # back
            # рассчитываем next как route[len(route)-2 - idx]
            if len(route) < 2:
                return None
            pos = len(route) - 2 - idx
            if pos < 0 or pos >= len(route):
                return None
            return route[pos]

    def handle_PROXY(self, peer: str, plain: bytes, meta: Dict):
        """
        Главный обработчик PROXY_BLOB.
        plain: bytes — расшифрованное содержимое (payload).
        meta: словарь с управляющей информацией (route, idx, dir, src, dst, x1, x2, phase, conn_id,...)
        peer: resolved peer name (откуда пришёл контейнер)
        """
        try:
            conn_id = meta.get("conn_id")
            dir_ = meta.get("dir", "fwd")
            phase = meta.get("phase")
            src = meta.get("src")
            dst = meta.get("dst")
            idx = int(meta.get("idx", 0))
            route = self._parse_route(meta)
            if not route:
                self.logger.error(f"[PROXY] missing route in meta: {meta}")
                return

            self.logger.info(f"[PROXY] RX peer={peer} len={len(plain)} meta.dir={dir_} meta.idx={idx} src={src} dst={dst} x1={meta.get('x1')} x2={meta.get('x2')}")

            # Если dir=fwd и мы на месте назначения — ARRIVE
            if dir_ == "fwd" and idx >= len(route) - 1:
                self.logger.info(f"[PROXY] ARRIVE DST={dst} phase={phase} len={len(plain)} CONN={conn_id}")
                # здесь можно вызвать локальную обработку (например доставку в стек IKE), но
                # по контракту daemon уже вызывал proxy.handle_PROXY с plain и meta — дальше ваша логика
                return

            # вычисляем следующего пира
            next_peer = self._compute_next(route, meta)
            if not next_peer:
                self.logger.error(f"[PROXY] cannot compute next peer for meta={meta} route={route}")
                # посылаем ошибку назад если есть conn_id
                if conn_id:
                    self.err.send_error_back(conn_id, src, meta.get("x1"), phase, "NO_ROUTE", "cannot compute next hop")
                return

            # ensure mgmt session to next_peer (по требованию)
            ok = self.mgmt.ensure_session(next_peer, reason="PROXY "+dir_, phase=phase, conn=conn_id)
            if not ok:
                self.logger.error(f"[PROXY] cannot ensure session to {next_peer}")
                if conn_id:
                    # вернуть ошибку назад к источнику
                    self.err.send_error_back(conn_id, src, meta.get("x1"), phase, "NO_SESSION_NEXT", f"cannot ensure {next_peer}")
                return

            # Применяем инкремент idx для продвижения (на каждой пересылке увеличиваем шаг)
            next_meta = dict(meta)
            try:
                next_meta["idx"] = int(idx) + 1
            except Exception:
                next_meta["idx"] = idx + 1

            # Отправляем следующий контейнер через secure link
            # Используем secure_link.link_send(destination_x, T_PROXY_BLOB, payload, meta=next_meta)
            # Предполагается, что secure_link умеет принимать x-переменные (имена узлов), см. daemon._on_ike_local
            try:
                # Логируем debug для отслеживания шифрования/отправки
                self.logger.debug(f"[SEC] link_send to={next_peer} nonce_len=? ct_len={len(plain)} meta={next_meta}")
                self.sec.link_send(next_peer, T_PROXY_BLOB, plain, meta=next_meta)
                self.logger.info(f"[PROXY] fwd {self.name}->{next_peer} idx={next_meta.get('idx')} phase={phase} route={'->'.join(route)} CONN={conn_id}")
            except Exception as e:
                self.logger.exception(f"[PROXY] failed link_send to {next_peer}: {e}")
                if conn_id:
                    self.err.send_error_back(conn_id, src, meta.get("x1"), phase, "SEND_FAIL", str(e))
        except Exception as e:
            self.logger.exception(f"[PROXY] unexpected error: {e}")