import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import boto3  # type: ignore
except ImportError:  # pragma: no cover - dependency may be absent in offline environments
    boto3 = None

from .config import AUDIT_TABLE, AWS_REGION, DATA_DIR, LOCAL_STORAGE, MAPPING_TABLE, RAW_BUCKET, REDACTED_TABLE


def _normalize_for_storage(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _normalize_for_storage(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_for_storage(v) for v in value]
    return value


def _use_local_storage() -> bool:
    return LOCAL_STORAGE or boto3 is None or not os.getenv("AWS_ACCESS_KEY_ID")


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_raw(record_id: str, payload: Dict[str, Any]) -> str:
    payload = _normalize_for_storage(payload)
    if _use_local_storage():
        path = _ensure_dir(DATA_DIR / "raw") / f"{record_id}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return f"raw/{record_id}.json"

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    s3 = boto3.client("s3", region_name=AWS_REGION)
    key = f"raw/{record_id}.json"
    s3.put_object(Bucket=RAW_BUCKET, Key=key, Body=json.dumps(payload).encode("utf-8"), ServerSideEncryption="aws:kms")
    return key


def put_redacted(item: Dict[str, Any]) -> None:
    item = _normalize_for_storage(item)
    if _use_local_storage():
        _write_json(_ensure_dir(DATA_DIR / "redacted") / f"{item['record_id']}.json", item)
        return

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    ddb.Table(REDACTED_TABLE).put_item(Item=item)


def get_redacted(record_id: str) -> Optional[Dict[str, Any]]:
    if _use_local_storage():
        return _read_json(_ensure_dir(DATA_DIR / "redacted") / f"{record_id}.json")

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    response = ddb.Table(REDACTED_TABLE).get_item(Key={"record_id": record_id})
    return response.get("Item")


def put_mapping(item: Dict[str, Any]) -> None:
    item = _normalize_for_storage(item)
    if _use_local_storage():
        _write_json(_ensure_dir(DATA_DIR / "mappings") / f"{item['record_id']}-{item['token']}.json", item)
        return

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    ddb.Table(MAPPING_TABLE).put_item(Item=item)


def put_audit(item: Dict[str, Any]) -> None:
    item = _normalize_for_storage(item)
    if _use_local_storage():
        audit_path = _ensure_dir(DATA_DIR / "audit") / f"{item['record_id']}.json"
        entries: List[Dict[str, Any]] = []
        if audit_path.exists():
            entries = json.loads(audit_path.read_text(encoding="utf-8"))
        entries.append(item)
        audit_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    ddb.Table(AUDIT_TABLE).put_item(Item=item)


def get_audit_entries(record_id: Optional[str] = None) -> List[Dict[str, Any]]:
    if _use_local_storage():
        audit_dir = _ensure_dir(DATA_DIR / "audit")
        if record_id:
            # Return entries for a specific record from its dedicated file
            path = audit_dir / f"{record_id}.json"
            if not path.exists():
                return []
            return json.loads(path.read_text(encoding="utf-8"))
        else:
            # Aggregate entries from ALL per-record audit files
            all_entries: List[Dict[str, Any]] = []
            for path in audit_dir.glob("*.json"):
                try:
                    entries = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(entries, list):
                        all_entries.extend(entries)
                except Exception:
                    pass
            return all_entries

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = ddb.Table(AUDIT_TABLE)
    if record_id is None:
        response = table.scan()
    else:
        from boto3.dynamodb.conditions import Attr
        response = table.scan(FilterExpression=Attr("record_id").eq(record_id))
    return response.get("Items", [])


def mark_for_deletion(record_id: str) -> Optional[Dict[str, Any]]:
    item = get_redacted(record_id)
    if not item:
        return None
    item["deletion_requested"] = True
    item["deletion_requested_at"] = datetime.now(timezone.utc).isoformat()
    put_redacted(item)
    return item


def get_mappings_for_record(record_id: str) -> List[Dict[str, Any]]:
    """Return all PII token→value mappings for a given record."""
    if _use_local_storage():
        results: List[Dict[str, Any]] = []
        for path in (_ensure_dir(DATA_DIR / "mappings")).glob(f"{record_id}-*.json"):
            item = _read_json(path)
            if item:
                results.append(item)
        return results

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    from boto3.dynamodb.conditions import Attr
    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    response = ddb.Table(MAPPING_TABLE).scan(FilterExpression=Attr("record_id").eq(record_id))
    return response.get("Items", [])


def list_redacted_for_user(user_id: str) -> List[Dict[str, Any]]:
    """
    Find all redacted records that belong to a user.

    Searches by direct user_id field AND by cross-referencing PII token
    mappings — ensuring DSAR covers records where the user ID appears only
    as a tokenised PII value (e.g. when user_id was in the prompt text).
    """
    if _use_local_storage():
        redacted_dir = _ensure_dir(DATA_DIR / "redacted")
        mappings_dir = _ensure_dir(DATA_DIR / "mappings")

        # Direct match on user_id field
        records: Dict[str, Dict[str, Any]] = {}
        for path in redacted_dir.glob("*.json"):
            item = _read_json(path)
            if item and item.get("user_id") == user_id:
                records[item["record_id"]] = item

        # Cross-reference: find mapping files that contain user_id as a PII value
        for path in mappings_dir.glob("*.json"):
            mapping = _read_json(path)
            if mapping and mapping.get("value") == user_id:
                rid = mapping.get("record_id")
                if rid and rid not in records:
                    rec = _read_json(redacted_dir / f"{rid}.json")
                    if rec:
                        records[rid] = rec

        return list(records.values())

    if boto3 is None:
        raise RuntimeError("boto3 is required for cloud storage")

    from boto3.dynamodb.conditions import Attr
    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    response = ddb.Table(REDACTED_TABLE).scan(FilterExpression=Attr("user_id").eq(user_id))
    return response.get("Items", [])