"""
Tests for the hash-chain feature: each ingested record must link to the
entry_hash of the previously stored record via its previous_hash field.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.main import ingest
from api.models import LogIngest
from api.storage import get_redacted


def _make_payload(label: str) -> LogIngest:
    return LogIngest(
        prompt=f"Hello from {label}",
        response="Noted.",
        agent_id="agent-1",
        timestamp="2026-07-01T00:00:00Z",
        user_id=f"user-{label}",
    )


def test_hash_chain_links_records():
    """Second record's previous_hash must equal first record's entry_hash."""
    r1 = ingest(_make_payload("chain-a"))
    r2 = ingest(_make_payload("chain-b"))

    rec1 = get_redacted(r1["record_id"])
    rec2 = get_redacted(r2["record_id"])

    assert rec1 is not None
    assert rec2 is not None
    assert rec2["previous_hash"] == rec1["entry_hash"], (
        f"Hash chain broken: rec2.previous_hash={rec2['previous_hash']!r} "
        f"!= rec1.entry_hash={rec1['entry_hash']!r}"
    )


def test_entry_hash_changes_on_tamper():
    """Modifying a stored record must cause a hash mismatch on verify."""
    from api.main import verify_record
    from api.storage import put_redacted

    r = ingest(_make_payload("tamper-chain"))
    item = get_redacted(r["record_id"])
    assert item is not None

    # Sanity: clean record should not be tampered
    result = verify_record(r["record_id"])
    assert result["tampered"] is False

    # Manually tamper the record
    item["redacted_prompt"] = "TAMPERED"
    put_redacted(item)

    result = verify_record(r["record_id"])
    assert result["tampered"] is True
