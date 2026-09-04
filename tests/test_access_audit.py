from api.audit import log_access
from api.storage import get_audit_entries


def test_access_audit_logs_user_and_query():
    log_access("alice", "admin", "read_record", {"record_id": "abc"}, "abc")
    entries = get_audit_entries("abc")

    assert entries
    assert entries[-1]["user_id"] == "alice"
    assert entries[-1]["record_id"] == "abc"
