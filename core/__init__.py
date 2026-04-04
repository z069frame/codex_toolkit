import json
import os

_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
_cfg = None


def load_config(path=None):
    global _cfg
    p = path or _CFG_PATH
    with open(p, "r", encoding="utf-8") as f:
        _cfg = json.load(f)
    return _cfg


def get_config():
    if _cfg is None:
        load_config()
    return _cfg
