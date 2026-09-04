from datetime import datetime, timezone
import uuid
from .storage import put_audit


def log_access(user_id: str, role: str, action: str, query: dict, record_id: str = None):
    item = {
        "audit_id": str(uuid.uuid4()),
        "user_id": user_id,
        "role": role,
        "action": action,
        "record_id": record_id or "none",
        "query": query,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    put_audit(item)
    return item