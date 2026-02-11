# logging_util.py
# -*- coding: utf-8 -*-

import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(node_name: str) -> logging.Logger:
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(node_name)

    # DEBUG для отладки (восстановить INFO, когда всё отлажено)
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler (DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (rotating) (DEBUG)
    fh = RotatingFileHandler(
        f"logs/{node_name}.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger