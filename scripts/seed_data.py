import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.main import ingest
from api.models import LogIngest


def seed_sample_data():
    payloads = [
        LogIngest(
            prompt="My name is John Doe and my email is john@example.com.",
            response="Hello John, I can help with your order.",
            agent_id="agent-1",
            timestamp="2026-06-30T00:00:00Z",
            user_id="user-123",
        ),
        LogIngest(
            prompt="Contact Jane Smith at jane@example.com.",
            response="I sent details to Jane.",
            agent_id="agent-2",
            timestamp="2026-06-30T01:00:00Z",
            user_id="user-123",
        ),
    ]
    for payload in payloads:
        print(ingest(payload))


if __name__ == "__main__":
    seed_sample_data()
