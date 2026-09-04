from datetime import datetime, timezone
from typing import Union

RETENTION_DAYS = {
    "365_days": 365,
    "180_days": 180,
    "90_days": 90,
    "30_days": 30,
    "7_days": 7,
}


def get_retention_days(category: str) -> int:
    return RETENTION_DAYS.get(category, 90)


def _coerce_datetime(value: Union[str, datetime, None]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_expired(expiry_time: Union[str, datetime, None]) -> bool:
    return _coerce_datetime(expiry_time) < datetime.now(timezone.utc)