import hmac, hashlib, json
from datetime import date, datetime
from typing import Any


def _normalize(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {key: _normalize(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_normalize(value) for value in obj]
    return obj


def canonicalize(obj: dict) -> str:
    return json.dumps(_normalize(obj), separators=(",", ":"), sort_keys=True)


def record_hash(obj: dict, secret: str) -> str:
    msg = canonicalize(obj).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()