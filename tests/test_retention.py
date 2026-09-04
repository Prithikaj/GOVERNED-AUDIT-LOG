from datetime import datetime, timedelta, timezone

from api.retention import get_retention_days, is_expired


def test_retention_simulates_90_day_expiry():
    future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    assert get_retention_days("90_days") == 90
    assert not is_expired(future)
    assert is_expired(past)


def test_retention_categories():
    assert get_retention_days("365_days") == 365
    assert get_retention_days("180_days") == 180
    assert get_retention_days("30_days") == 30
    assert get_retention_days("7_days") == 7
    # Unknown category falls back to 90
    assert get_retention_days("unknown") == 90
