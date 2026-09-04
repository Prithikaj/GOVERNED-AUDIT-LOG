from api.main import verify_record
from api.storage import put_redacted


def test_verify_detects_manual_modification():
    item = {
        "record_id": "tamper-test",
        "user_id": "user-1",
        "agent_id": "agent-1",
        "timestamp": "2026-06-30T00:00:00Z",
        "redacted_prompt": "hello",
        "redacted_response": "world",
        "retention_category": "90_days",
        "expiry_time": "2030-01-01T00:00:00+00:00",
        "entry_hash": "placeholder",
    }

    put_redacted(item)
    result = verify_record("tamper-test")
    assert result["tampered"] is True

    item["entry_hash"] = "deadbeef"
    put_redacted(item)
    result = verify_record("tamper-test")
    assert result["tampered"] is True
