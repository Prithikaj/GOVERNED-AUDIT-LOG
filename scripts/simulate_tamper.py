import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.storage import get_redacted, put_redacted


def simulate_tamper(record_id: str):
    item = get_redacted(record_id)
    if not item:
        raise ValueError("record not found")
    item["redacted_prompt"] = "tampered"
    put_redacted(item)
    print(json.dumps({"record_id": record_id, "status": "tampered"}, indent=2))


if __name__ == "__main__":
    simulate_tamper("demo-record")
