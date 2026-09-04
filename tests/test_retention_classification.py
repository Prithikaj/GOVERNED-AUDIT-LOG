"""
Tests for the agent-based retention classification policy.
"""

from workers.processor import _classify_retention, process_record


def test_legal_agent_gets_365_days():
    assert _classify_retention("agent-legal") == "365_days"


def test_financial_agent_gets_365_days():
    assert _classify_retention("agent-financial") == "365_days"


def test_hr_agent_gets_180_days():
    assert _classify_retention("agent-hr") == "180_days"


def test_support_agent_gets_90_days():
    assert _classify_retention("agent-support") == "90_days"


def test_internal_agent_gets_30_days():
    assert _classify_retention("agent-internal") == "30_days"


def test_test_agent_gets_7_days():
    assert _classify_retention("agent-test") == "7_days"


def test_unknown_agent_gets_default_90_days():
    assert _classify_retention("agent-unknown-xyz") == "90_days"


def test_prefix_match_works():
    # agent-legal-v2 should match agent-legal prefix
    assert _classify_retention("agent-legal-v2") == "365_days"


def test_process_record_uses_agent_classification():
    record = {
        "prompt": "Hello",
        "response": "Hi",
        "agent_id": "agent-legal",
        "timestamp": "2026-07-01T00:00:00Z",
        "user_id": "user-1",
    }
    result = process_record(record)
    assert result["retention_category"] == "365_days"
