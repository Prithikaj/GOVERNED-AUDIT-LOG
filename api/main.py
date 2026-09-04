from typing import Any, Dict, Optional
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import uuid

from .models import LogIngest, PIIRevealRequest, Role
from .storage import get_redacted, get_audit_entries, mark_for_deletion, put_mapping, put_redacted, save_raw, list_redacted_for_user, get_mappings_for_record
from .audit import log_access
from .retention import is_expired
from .auth import get_user_from_header, log_pii_access
from .compliance import get_retention_report, get_access_audit, mark_legal_hold, get_metrics
from workers.hash_utils import record_hash
from workers.processor import process_record
from .config import HASH_SECRET

app = FastAPI(title="PS-7.2 Governed Audit Log", version="1.0.0")

# Add CORS and security headers middleware
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# Serve frontend
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if _FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")

@app.get("/", include_in_schema=False)
def root():
    index = _FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "PS-7.2 Governed Audit Log API", "docs": "/docs"}


class DSARRequest(BaseModel):
    user_id: str


def _as_dict(payload: Any) -> Dict[str, Any]:
    if hasattr(payload, "model_dump"):
        return payload.model_dump()
    return payload.dict()


def _hash_item(item: Dict[str, Any]) -> str:
    payload = {key: value for key, value in item.items() if key not in {"entry_hash", "previous_hash", "created_at"}}
    return record_hash(payload, HASH_SECRET)


def _get_latest_hash() -> Optional[str]:
    """Return the entry_hash of the most recently created redacted record (for hash chaining)."""
    from api.config import DATA_DIR
    redacted_dir = DATA_DIR / "redacted"
    if not redacted_dir.exists():
        return None
    import json as _json
    latest_item: Optional[Dict[str, Any]] = None
    latest_ts: str = ""
    for path in redacted_dir.glob("*.json"):
        try:
            item = _json.loads(path.read_text(encoding="utf-8"))
            ts = item.get("created_at", "")
            if ts > latest_ts:
                latest_ts = ts
                latest_item = item
        except Exception:
            pass
    return latest_item.get("entry_hash") if latest_item else None


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/ingest")
def ingest(payload: LogIngest):
    record_id = str(uuid.uuid4())
    raw_payload = _as_dict(payload)
    raw_key = save_raw(record_id, raw_payload)

    processed = process_record(raw_payload)
    processed["record_id"] = record_id
    processed["created_at"] = datetime.now(timezone.utc).isoformat()

    # --- Hash chain: link to the most recently stored record ---
    last_hash = _get_latest_hash()
    processed["previous_hash"] = last_hash

    # Compute entry_hash over the full record (excluding entry_hash itself)
    processed["entry_hash"] = _hash_item(processed)
    put_redacted(processed)

    for mapping in processed.get("pii_mappings", []):
        mapping_item = {
            "record_id": record_id,
            "token": mapping["token"],
            "value": mapping["value"],
            "entity_type": mapping["entity_type"],
        }
        put_mapping(mapping_item)

    return {
        "record_id": record_id,
        "raw_key": raw_key,
        "status": "accepted",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/records/{record_id}")
def get_record(record_id: str, authorization: Optional[str] = Header(None)):
    """Retrieve a redacted log record. Requires any authenticated role."""
    user = get_user_from_header(authorization)

    item = get_redacted(record_id)
    if not item:
        raise HTTPException(status_code=404, detail="Record not found")
    if is_expired(item.get("expiry_time")):
        raise HTTPException(status_code=410, detail="Record expired")

    log_access(user["user_id"], user["role"].value, "read_record", {"record_id": record_id}, record_id)
    return item


@app.get("/verify/{record_id}")
def verify_record(record_id: str):
    item = get_redacted(record_id)
    if not item:
        raise HTTPException(status_code=404, detail="Record not found")
    expected_hash = _hash_item(item)
    tampered = expected_hash != item.get("entry_hash")
    return {
        "record_id": record_id,
        "tampered": tampered,
        "expected_hash": expected_hash,
        "stored_hash": item.get("entry_hash"),
        "previous_hash": item.get("previous_hash"),
        "audit_entries": get_audit_entries(record_id),
    }


@app.get("/records/{record_id}/history")
def record_history(record_id: str, authorization: Optional[str] = Header(None)):
    """Return the hash-chain history for a record: its own hash, its previous_hash, and all access events."""
    user = get_user_from_header(authorization)

    item = get_redacted(record_id)
    if not item:
        raise HTTPException(status_code=404, detail="Record not found")

    expected_hash = _hash_item(item)
    tampered = expected_hash != item.get("entry_hash")

    log_access(user["user_id"], user["role"].value, "read_history", {"record_id": record_id}, record_id)

    return {
        "record_id": record_id,
        "created_at": item.get("created_at"),
        "entry_hash": item.get("entry_hash"),
        "previous_hash": item.get("previous_hash"),
        "tampered": tampered,
        "access_events": get_audit_entries(record_id),
    }


@app.post("/pii/reveal/{record_id}")
def reveal_pii(record_id: str, request: PIIRevealRequest, authorization: Optional[str] = Header(None)):
    """
    Reveal original PII for a record (requires compliance or admin role).
    Format: Authorization: Bearer user-123:compliance
    """
    user = get_user_from_header(authorization)
    
    if user["role"] not in [Role.COMPLIANCE, Role.ADMIN]:
        raise HTTPException(
            status_code=403,
            detail=f"Only compliance/admin can access PII. Your role: {user['role'].value}"
        )
    
    item = get_redacted(record_id)
    if not item:
        raise HTTPException(status_code=404, detail="Record not found")
    
    log_pii_access(user["user_id"], record_id, "reveal", request.reason_code)
    
    return {
        "record_id": record_id,
        "revealed_by": user["user_id"],
        "reason": request.reason_code,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "prompt": item.get("redacted_prompt"),
            "response": item.get("redacted_response"),
            "pii_mappings": item.get("pii_mappings", []),
        }
    }


@app.get("/audit/access-log")
def get_audit_log(
    user_id: Optional[str] = None,
    record_id: Optional[str] = None,
    limit: int = 100,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieve access audit logs (requires admin, compliance, or viewer role).
    """
    user = get_user_from_header(authorization)
    
    if user["role"] == Role.VIEWER:
        raise HTTPException(status_code=403, detail="Viewers cannot access audit logs")
    
    entries = get_access_audit(user_id=user_id, record_id=record_id, limit=limit)
    
    return {
        "total": len(entries),
        "filtered_by": {"user_id": user_id, "record_id": record_id},
        "entries": entries,
        "queried_by": user["user_id"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/compliance/retention-report")
def retention_report(authorization: Optional[str] = Header(None)):
    """
    Get retention status report (requires compliance or admin role).
    """
    user = get_user_from_header(authorization)
    
    if user["role"] not in [Role.COMPLIANCE, Role.ADMIN]:
        raise HTTPException(status_code=403, detail="Only compliance/admin can view retention reports")
    
    report = get_retention_report()
    
    return {
        **report,
        "generated_by": user["user_id"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/compliance/legal-hold/{record_id}")
def set_legal_hold(record_id: str, hold: bool = True, authorization: Optional[str] = Header(None)):
    """
    Mark a record for legal hold to prevent deletion (requires compliance or admin).
    """
    user = get_user_from_header(authorization)
    
    if user["role"] not in [Role.COMPLIANCE, Role.ADMIN]:
        raise HTTPException(status_code=403, detail="Only compliance/admin can set legal holds")
    
    result = mark_legal_hold(record_id, hold)
    
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    
    log_access(user["user_id"], user["role"].value, f"legal_hold_{hold}", {"record_id": record_id}, record_id)
    
    return {
        **result,
        "set_by": user["user_id"]
    }


@app.get("/metrics")
def metrics(authorization: Optional[str] = Header(None)):
    """
    Get system metrics and health status.
    """
    user = get_user_from_header(authorization)
    
    if user["role"] not in [Role.ADMIN, Role.COMPLIANCE]:
        raise HTTPException(status_code=403, detail="Only admin/compliance can view metrics")
    
    return {
        **get_metrics(),
        "requested_by": user["user_id"]
    }


@app.post("/dsar")
def dsar(request: DSARRequest):
    """
    Data Subject Access Request handler.

    Retrieves all log records referencing the user (both direct user_id matches
    and records linked via PII token mappings), produces a redacted summary,
    and marks every matched record for deletion on request.
    """
    related = list_redacted_for_user(request.user_id)

    summary = []
    for item in related:
        rid = item["record_id"]
        # Resolve tokens back to entity types (not raw values) for the DSAR report
        mappings = get_mappings_for_record(rid)
        token_info = [
            {"token": m["token"], "entity_type": m.get("entity_type", "UNKNOWN")}
            for m in mappings
        ]
        mark_for_deletion(rid)
        summary.append(
            {
                "record_id": rid,
                "agent_id": item.get("agent_id"),
                "timestamp": item.get("timestamp"),
                "redacted_prompt": item.get("redacted_prompt", ""),
                "redacted_response": item.get("redacted_response", ""),
                "pii_token_types": token_info,
                "retention_category": item.get("retention_category"),
                "expiry_time": item.get("expiry_time"),
                "deletion_requested": True,
            }
        )

    log_access(
        request.user_id, "dsar", "dsar_request",
        {"user_id": request.user_id, "records_found": len(related)},
    )

    return {
        "user_id": request.user_id,
        "records_found": len(related),
        "status": "marked_for_deletion",
        "summary": summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
