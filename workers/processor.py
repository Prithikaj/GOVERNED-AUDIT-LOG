import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from api.config import HASH_SECRET, TOKEN_SECRET
from workers.hash_utils import record_hash
from workers.presidio_client import detect_pii
from workers.tokenizer import tokenize

# ---------------------------------------------------------------------------
# Retention classification
# ---------------------------------------------------------------------------
# Maps agent_id prefixes / exact IDs to retention categories.
# Agents can be tagged by their regulatory tier via this lookup.
# Extend this mapping to cover your organisation's agent registry.
_AGENT_RETENTION_MAP: Dict[str, str] = {
    "agent-legal": "365_days",
    "agent-financial": "365_days",
    "agent-medical": "365_days",
    "agent-hr": "180_days",
    "agent-compliance": "180_days",
    "agent-support": "90_days",
    "agent-internal": "30_days",
    "agent-test": "7_days",
}

_DEFAULT_RETENTION = "90_days"

_RETENTION_DAYS: Dict[str, int] = {
    "365_days": 365,
    "180_days": 180,
    "90_days": 90,
    "30_days": 30,
    "7_days": 7,
}


def _classify_retention(agent_id: str) -> str:
    """
    Determine the retention category for a record based on the agent that
    produced it.  Exact match first, then prefix match.
    """
    agent_id_lower = (agent_id or "").lower()
    # Exact match
    if agent_id_lower in _AGENT_RETENTION_MAP:
        return _AGENT_RETENTION_MAP[agent_id_lower]
    # Prefix match (e.g. "agent-legal-v2" → "agent-legal")
    for prefix, category in _AGENT_RETENTION_MAP.items():
        if agent_id_lower.startswith(prefix):
            return category
    return _DEFAULT_RETENTION


def _entity_type(entity: Dict[str, Any]) -> str:
    return entity.get("type") or entity.get("entity_type") or "ENTITY"


def redact_text(text: str, entities: List[Dict[str, Any]], tenant_id: str = "default") -> Tuple[str, List[Dict[str, Any]]]:
    redacted = text
    mappings: List[Dict[str, Any]] = []
    for entity in entities:
        entity_text = entity.get("text") or ""
        if not entity_text:
            continue
        token = tokenize(entity_text, tenant_id, TOKEN_SECRET)
        entity_type = _entity_type(entity)
        redacted = redacted.replace(entity_text, f"<{entity_type}:{token}>")
        mappings.append({"token": token, "value": entity_text, "entity_type": entity_type})
    return redacted, mappings


def process_record(raw_record: Dict[str, Any]) -> Dict[str, Any]:
    prompt_ents = detect_pii(raw_record.get("prompt", ""))
    response_ents = detect_pii(raw_record.get("response", ""))

    red_prompt, prompt_mappings = redact_text(raw_record.get("prompt", ""), prompt_ents)
    red_resp, response_mappings = redact_text(raw_record.get("response", ""), response_ents)

    agent_id = raw_record.get("agent_id", "unknown")
    retention_category = _classify_retention(agent_id)
    retention_days = _RETENTION_DAYS.get(retention_category, 90)

    item = {
        "record_id": raw_record.get("record_id") or str(uuid.uuid4()),
        "user_id": raw_record.get("user_id", "unknown"),
        "agent_id": agent_id,
        "timestamp": raw_record.get("timestamp"),
        "redacted_prompt": red_prompt,
        "redacted_response": red_resp,
        "retention_category": retention_category,
        "expiry_time": (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat(),
        "pii_mappings": prompt_mappings + response_mappings,
    }
    item["entry_hash"] = record_hash(item, HASH_SECRET)
    return item


if __name__ == "__main__":
    print("worker ready")