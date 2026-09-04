from workers.processor import process_record


def test_redaction_replaces_pii_with_tokens():
    raw_record = {
        "record_id": "rec-redact",
        "prompt": "My name is John Doe and my email is john@example.com.",
        "response": "I can help John Doe with the order.",
        "agent_id": "agent-1",
        "timestamp": "2026-06-30T00:00:00Z",
        "user_id": "user-123",
    }

    item = process_record(raw_record)

    assert "John Doe" not in item["redacted_prompt"]
    assert "john@example.com" not in item["redacted_prompt"]
    assert "<PERSON:" in item["redacted_prompt"] or "<EMAIL_ADDRESS:" in item["redacted_prompt"]
    assert item["retention_category"] == "90_days"
