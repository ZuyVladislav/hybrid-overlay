# -*- coding: utf-8 -*-
import socket
import struct
import threading
from typing import Callable, Optional, Tuple

# Мы перехватываем только UDP/500 через TPROXY и доставляем в userspace на 15000
IKE_PORTS = (15000,)
CHARON_PORTS = {15000: 500}  # map listen->charon (TPROXY listen port -> real IKE port)

# Linux socket options (IPv4)
IP_TRANSPARENT = 19          # allow binding non-local and receiving redirected packets
IP_RECVORIGDSTADDR = 20      # receive original dst addr/port in ancillary data


def _parse_orig_dst(ancdata) -> Optional[Tuple[str, int]]:
    """
    Extract original destination (ip, port) from ancillary data:
    cmsg level SOL_IP, type IP_RECVORIGDSTADDR, payload is sockaddr_in (16 bytes).
    Layout sockaddr_in (linux):
      uint16 family
      uint16 port (network order)
      uint32 addr (network order)
      8 bytes padding
    """
    for level, ctype, data in ancdata:
        if level == socket.SOL_IP and ctype == IP_RECVORIGDSTADDR and len(data) >= 16:
            # family = struct.unpack_from("!H", data, 0)[0]  # not used
            port = struct.unpack_from("!H", data, 2)[0]
            ip = socket.inet_ntoa(data[4:8])
            return ip, port
    return None


class IkeProxy:
    """
    Transparent IKEv2 UDP bridge:
      - receives IKE packets redirected by TPROXY to local :15000
      - preserves real src (peer_ip:peer_port) and original dst (local_ip:500)
      - passes packets to overlay transport
      - injects packets back into local charon as if they arrived from peer (src spoofing)
    """

    def __init__(self, on_local_packet: Callable, logger):
        """
        on_local_packet callback:
          preferred signature:
            on_local_packet(data: bytes, listen_port: int, src: (ip,port), orig_dst: (ip,port))
          legacy signature:
            on_local_packet(data: bytes, listen_port: int)
        """
        self.on_local_packet = on_local_packet
        self.logger = logger
        self.socks = []
        self._threads = []

    def start(self):
        for listen_port in IKE_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Required for TPROXY delivery + binding non-local src when injecting
            s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            s.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)

            # Bind to all; TPROXY delivers packets here
            s.bind(("0.0.0.0", listen_port))

            self.socks.append(s)
            t = threading.Thread(target=self._recv_loop, args=(s, listen_port), daemon=True)
            t.start()
            self._threads.append(t)

            self.logger.info(f"[IKEP] TPROXY listening on 0.0.0.0:{listen_port} (orig dst via RECVORIGDSTADDR)")

    def _recv_loop(self, sock: socket.socket, listen_port: int):
        while True:
            try:
                data, anc, flags, src = sock.recvmsg(65535, 1024)  # <-- ОБЕРНУЛИ
            except OSError as e:
                self.logger.error(f"[IKEP] recvmsg failed: {e}")
                continue
            orig_dst = _parse_orig_dst(anc)  # (local_ip, 500) expected

            self.logger.info(
                f"[IKEP] <- redirected IKE len={len(data)} "
                f"src={src[0]}:{src[1]} orig_dst={orig_dst} listen_port={listen_port}"
            )

            # Call user callback (prefer rich signature; keep legacy compatible)
            try:
                self.on_local_packet(data, listen_port, src, orig_dst)
            except TypeError:
                # legacy callback: (data, port)
                self.on_local_packet(data, listen_port)

    def inject_to_charon(self, data: bytes, listen_port: int, peer_addr: Tuple[str, int], local_dst: Optional[Tuple[str, int]] = None):
        """
        Inject packet into local charon so that it looks like it came from the real peer.
          peer_addr  = (peer_ip, peer_port)  <-- MUST match original src for best results
          local_dst  = (local_ip, 500)       <-- original dst; if None, will use 127.0.0.1
        """
        real_port = CHARON_PORTS.get(listen_port, 500)

        # Where to deliver to charon:
        # Best: use original local IP (e.g., 192.168.3.101) so charon sees correct dst.
        # Fallback: 127.0.0.1 (works sometimes, but can break strict endpoint expectations).
        if local_dst is None:
            dst_ip = local_dst[0]
            dst_port = real_port
        else:
            dst_ip, dst_port = local_dst[0], real_port  # force port=500 even if orig_dst shows 500 already

        peer_ip, peer_port = peer_addr

        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        tx.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)

        # IMPORTANT: bind only IP, not port 500
        try:
            tx.bind((peer_ip, 0))  # let kernel choose free port
        except OSError as e:
            self.logger.error(f"[IKEP] inject bind({peer_ip}:0) failed: {e}")
            tx.close()
            return

        try:
            tx.sendto(data, (dst_ip, dst_port))
            self.logger.info(
                f"[IKEP] -> charon inject len={len(data)} "
                f"src={peer_ip}:EPHEMERAL dst={dst_ip}:{dst_port}"
            )
        except OSError as e:
            self.logger.error(f"[IKEP] inject sendto({dst_ip}:{dst_port}) failed: {e}")
        finally:
            tx.close()