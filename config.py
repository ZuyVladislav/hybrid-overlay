# -*- coding: utf-8 -*-

from typing import Dict

# ЕДИНЫЙ справочник пользователей (это же узлы сети)
# >>> СЮДА ВБИВАЕШЬ IP <<<
USERS: Dict[str, dict] = {
    "User1": {"ip": "192.168.3.21", "port": 9000, "password": "1111"},
    "User2": {"ip": "192.168.3.22", "port": 9000, "password": "2222"},
    "User3": {"ip": "192.168.3.23", "port": 9000, "password": "3333"},
    "User4": {"ip": "192.168.3.24", "port": 9000, "password": "4444"},
}

# Сетевые параметры
UDP_TIMEOUT_S = 2.0
RETRIES = 3

# Полезная нагрузка
I3_LEN = 24