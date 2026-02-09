# -*- coding: utf-8 -*-

from typing import Dict

# ЕДИНЫЙ справочник пользователей (это же узлы сети)
# >>> СЮДА ВБИВАЕШЬ IP <<<
USERS: Dict[str, dict] = {
    "User1": {"ip": "192.168.3.101", "port": 9000, "password": "1111"},
    "User2": {"ip": "192.168.3.102", "port": 9000, "password": "2222"},
    "User3": {"ip": "192.168.3.103", "port": 9000, "password": "3333"},
    "User4": {"ip": "192.168.3.104", "port": 9000, "password": "4444"},
}

# Сетевые параметры
UDP_TIMEOUT_S = 2.0
RETRIES = 3
PRECONNECT_ENABLED = False

# Полезная нагрузка
I3_LEN = 24
