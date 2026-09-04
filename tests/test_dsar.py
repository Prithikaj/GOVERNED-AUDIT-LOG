"""
Tests for the DSAR (Data Subject Access Request) handler.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.main import ingest, dsar, DSARRequest
from api.models import LogIngest
from api.storage import get_redacted


def _ingest(user_id: str, prompt: str = "Hello world") -> str:
    result = ingest(
        LogIngest(
            prompt=prompt,
            response="OK",
            agent_id="agent-1",
            timestamp="2026-07-01T00:00:00Z",
            user_id=user_id,
        )
    )
    return result["record_id"]


def test_dsar_finds_records_for_user():
    user = "dsar-user-42"
    rid = _ingest(user)

    result = dsar(DSARRequest(user_id=user))

    found_ids = [s["record_id"] for s in result["summary"]]
    assert rid in found_ids, f"Expected {rid} in DSAR result, got {found_ids}"
    assert result["records_found"] >= 1


def test_dsar_marks_records_for_deletion():
    user = "dsar-delete-user"
    rid = _ingest(user)

    dsar(DSARRequest(user_id=user))

    item = get_redacted(rid)
    assert item is not None
    assert item.get("deletion_requested") is True


def test_dsar_returns_redacted_summary_not_raw_pii():
    user = "dsar-redact-check"
    _ingest(user, prompt=f"Email me at {user}@example.com please")

    result = dsar(DSARRequest(user_id=user))

    for entry in result["summary"]:
        # Raw PII value should not appear in the redacted prompt
        assert f"{user}@example.com" not in entry.get("redacted_prompt", "")


def test_dsar_no_records_returns_empty():
    result = dsar(DSARRequest(user_id="user-who-never-existed-xyz9999"))
    assert result["records_found"] == 0
    assert result["summary"] == []
