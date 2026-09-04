from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from .storage import get_redacted, get_audit_entries
from .config import DATA_DIR
import json
from pathlib import Path


def get_retention_report() -> Dict[str, Any]:
    """Generate a compliance report on retention status."""
    now = datetime.now(timezone.utc)
    
    redacted_dir = DATA_DIR / "redacted"
    if not redacted_dir.exists():
        return {
            "total_records": 0,
            "expired": 0,
            "expiring_soon": 0,
            "legal_hold": 0,
            "records": []
        }
    
    report = {
        "total_records": 0,
        "expired": 0,
        "expiring_soon": 0,  # Within 7 days
        "legal_hold": 0,
        "records": []
    }
    
    for path in redacted_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            report["total_records"] += 1
            
            expiry_str = item.get("expiry_time", "")
            if expiry_str:
                try:
                    expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                    days_left = (expiry - now).days
                    
                    if days_left < 0:
                        report["expired"] += 1
                        status = "EXPIRED"
                    elif days_left < 7:
                        report["expiring_soon"] += 1
                        status = "EXPIRING_SOON"
                    else:
                        status = "ACTIVE"
                    
                    legal_hold = item.get("legal_hold", False)
                    if legal_hold:
                        report["legal_hold"] += 1
                    
                    report["records"].append({
                        "record_id": item.get("record_id"),
                        "user_id": item.get("user_id"),
                        "agent_id": item.get("agent_id"),
                        "retention_category": item.get("retention_category"),
                        "expiry_time": expiry_str,
                        "days_left": days_left,
                        "status": status,
                        "legal_hold": legal_hold,
                        "created_at": item.get("created_at")
                    })
                except (ValueError, AttributeError):
                    pass
        except Exception:
            pass
    
    report["records"] = sorted(report["records"], key=lambda x: x.get("days_left", 999))
    
    return report


def get_access_audit(user_id: Optional[str] = None, record_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve access audit entries with optional filtering.

    When record_id is provided, only entries for that record are returned.
    Otherwise, ALL audit entries across all records are aggregated before
    applying the user_id filter and limit.
    """
    # Pass record_id to storage so it can do a targeted lookup if possible
    entries = get_audit_entries(record_id=record_id)

    if user_id:
        entries = [e for e in entries if e.get("user_id") == user_id]

    entries = sorted(entries, key=lambda x: x.get("created_at", ""), reverse=True)

    return entries[:limit]


def mark_legal_hold(record_id: str, hold: bool = True) -> Dict[str, Any]:
    """Mark a record for legal hold (prevents deletion)."""
    item = get_redacted(record_id)
    if not item:
        return {"error": "Record not found"}
    
    item["legal_hold"] = hold
    from .storage import put_redacted
    put_redacted(item)
    
    return {
        "record_id": record_id,
        "legal_hold": hold,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }


def get_metrics() -> Dict[str, Any]:
    """Return system metrics and health status."""
    redacted_dir = DATA_DIR / "redacted"
    audit_dir = DATA_DIR / "audit"

    redacted_count = len(list(redacted_dir.glob("*.json"))) if redacted_dir.exists() else 0

    audit_count = 0
    if audit_dir.exists():
        for p in audit_dir.glob("*.json"):
            try:
                entries = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(entries, list):
                    audit_count += len(entries)
            except Exception:
                pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "redacted_records": redacted_count,
        "audit_entries": audit_count,
        "status": "healthy",
        "data_dir": str(DATA_DIR),
        "local_storage": True
    }
