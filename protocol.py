# -*- coding: utf-8 -*-

import json
from typing import Any, Dict

PROTOCOL_VERSION = 1

def jdump(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def jload(b: bytes) -> Dict[str, Any]:
    return json.loads(b.decode("utf-8"))

# mgmt handshake (4-step)
T_MGMT_INIT      = "MGMT_INIT"
T_MGMT_INIT_RESP = "MGMT_INIT_RESP"
T_MGMT_AUTH      = "MGMT_AUTH"
T_MGMT_AUTH_RESP = "MGMT_AUTH_RESP"

# instruction flow
T_I1   = "I1"       # A->X1 (Enc_KD_AX1)
T_I2   = "I2"       # X1->X2 (Enc_KD_X1X2)
T_OKX2 = "OKX2"     # X2->X1 (Enc_KD_X1X2) then X1->A (Enc_KD_AX1)

# proxy
T_PROXY_BLOB = "PROXY_BLOB"

# local control
T_LOCAL_CONNECT = "LOCAL_CONNECT"

# error (plaintext)
T_ERROR = "ERROR"

def err(code: str, msg: str, meta: dict = None) -> bytes:
    return jdump({"v": PROTOCOL_VERSION, "t": T_ERROR, "code": code, "msg": msg, "meta": meta or {}})