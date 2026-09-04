"""
Tests for the global audit log query — verifying that get_audit_entries()
without a record_id aggregates entries from ALL record audit files.
"""

from api.audit import log_access
from api.storage import get_audit_entries


def test_global_audit_query_returns_all_entries():
    """Entries logged for different records must all appear in the global scan."""
    log_access("user-global-1", "admin", "read_record", {"record_id": "global-rec-1"}, "global-rec-1")
    log_access("user-global-2", "viewer", "read_record", {"record_id": "global-rec-2"}, "global-rec-2")

    all_entries = get_audit_entries()  # no record_id → global

    user_ids = {e["user_id"] for e in all_entries}
    assert "user-global-1" in user_ids, "Entry for user-global-1 missing from global scan"
    assert "user-global-2" in user_ids, "Entry for user-global-2 missing from global scan"


def test_per_record_audit_query_is_scoped():
    """Entries for record A must NOT appear in the query for record B."""
    log_access("user-scope-a", "admin", "read_record", {"record_id": "scope-rec-a"}, "scope-rec-a")
    log_access("user-scope-b", "admin", "read_record", {"record_id": "scope-rec-b"}, "scope-rec-b")

    entries_a = get_audit_entries("scope-rec-a")
    entries_b = get_audit_entries("scope-rec-b")

    assert all(e["record_id"] == "scope-rec-a" for e in entries_a)
    assert all(e["record_id"] == "scope-rec-b" for e in entries_b)
    assert not any(e["record_id"] == "scope-rec-b" for e in entries_a)
