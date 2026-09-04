import os
from pathlib import Path

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
RAW_BUCKET = os.getenv("RAW_BUCKET", "ps72-raw-logs")
REDACTED_TABLE = os.getenv("REDACTED_TABLE", "ps72-redacted-logs")
MAPPING_TABLE = os.getenv("MAPPING_TABLE", "ps72-pii-mapping")
AUDIT_TABLE = os.getenv("AUDIT_TABLE", "ps72-access-audit")
QUEUE_URL = os.getenv("QUEUE_URL", "")
K_HASH_SECRET_NAME = os.getenv("K_HASH_SECRET_NAME", "ps72-hash-key")
K_TOKEN_SECRET_NAME = os.getenv("K_TOKEN_SECRET_NAME", "ps72-token-salt")
PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://localhost:3000")
DATA_DIR = Path(os.getenv("DATA_DIR", ".data")).resolve()
LOCAL_STORAGE = os.getenv("LOCAL_STORAGE", "true").lower() in {"1", "true", "yes", "on"}
HASH_SECRET = os.getenv("HASH_SECRET", "dev-hash-secret")
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "dev-token-secret")