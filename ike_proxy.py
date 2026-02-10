# -*- coding: utf-8 -*-
import socket
import threading

IKE_PORTS = (15000, 15001)
CHARON_PORTS = {15000: 25000, 15001: 25001}  # map listen->charon

class IkeProxy:
    """
    Bridges real IKEv2 UDP packets between local charon and overlay transport.
    """

    def __init__(self, on_local_packet, logger):
        self.on_local_packet = on_local_packet
        self.logger = logger
        self.socks = []

    def start(self):
        for port in IKE_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", port))
            self.socks.append(s)
            t = threading.Thread(target=self._recv_loop, args=(s, port), daemon=True)
            t.start()
            self.logger.info(f"[IKEP] listening on 127.0.0.1:{port}")

    def _recv_loop(self, sock, port):
        while True:
            data, addr = sock.recvfrom(65535)
            self.logger.info(f"[IKEP] <- charon {addr} len={len(data)} dport={port}")
            self.on_local_packet(data, port)

    def inject_to_charon(self, data: bytes, port: int):
        real_port = CHARON_PORTS.get(port, 25000)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data, ("127.0.0.1", real_port))
        self.logger.info(f"[IKEP] -> charon 127.0.0.1:{real_port} len={len(data)}")