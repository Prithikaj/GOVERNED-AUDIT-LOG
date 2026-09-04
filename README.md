# Governed Audit Log

Enterprise-grade audit log governance platform with **PII redaction**, **retention policies**, **access audit logging**, **tamper detection**, **RBAC**, and **DSAR handling**.

This project provides a FastAPI service for ingesting raw audit logs, redacting PII with Microsoft Presidio, hashing records for tamper detection, storing audit access entries, role-based access control (RBAC), compliance reporting, and supporting DSAR-style deletion workflows.

## Features
- **FastAPI REST API** with 10+ endpoints for audit log management
- **RBAC (Role-Based Access Control)** with 4 tiers: ADMIN, COMPLIANCE, DEVELOPER, VIEWER
- **PII Redaction** using Microsoft Presidio + regex fallback, with deterministic tokenization
- **Tamper Detection** via HMAC-SHA256 content hashing
- **Access Audit Logging** - every read/access logged with user, role, timestamp
- **Retention Policies** - 90-day default with expiry tracking and legal holds
- **DSAR Handler** - data subject access requests with record discovery and deletion marking
- **Compliance Reporting** - retention status, access logs, metrics
- **Local-first Storage** (JSON files) with optional AWS S3/DynamoDB for production
- **Presidio Integration** with lightweight fallback for PII detection (EMAIL, PERSON, PHONE, AADHAAR, PAN, SSN)

## Quick Start

### Local Development
1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the API locally:
   ```bash
   uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
   ```

4. Seed sample data:
   ```bash
   python scripts/seed_data.py
   ```

### Docker
```bash
docker compose up --build
```

### Tests
```bash
pytest -q
```

### AWS Deployment with Terraform
```bash
cd infra
terraform init
terraform plan
terraform apply -auto-approve
```

## RBAC Roles

| Role | Permissions | Use Case |
|------|-----------|----------|
| **ADMIN** | All operations + key rotation + system settings | System administrators, DevOps |
| **COMPLIANCE** | View PII (with justification), access audit logs, set legal holds, retention reports, metrics | Compliance officers, auditors, legal |
| **DEVELOPER** | Read redacted logs only, no PII access | Application developers, support engineers |
| **VIEWER** | Read redacted logs, no audit access | Business analysts, product managers |

### Authentication Header Format
All RBAC-protected endpoints require an `Authorization` header:
```
Authorization: Bearer user-123:compliance
```
Format: `Bearer <user_id>:<role>`

Valid roles: `admin`, `compliance`, `developer`, `viewer`

## API Endpoints

### Core Endpoints

#### 1. Health Check
```bash
GET /health
```
No authentication required. Returns API health status.

#### 2. Ingest Audit Log
```bash
POST /ingest
Content-Type: application/json
```
Request body:
```json
{
  "prompt": "string - user input/query",
  "response": "string - system response",
  "agent_id": "string - identifier for the agent/service",
  "timestamp": "ISO8601 timestamp",
  "user_id": "string - end user identifier"
}
```
Response:
```json
{
  "record_id": "UUID",
  "raw_key": "s3 key or local path",
  "status": "accepted",
  "timestamp": "ISO8601"
}
```

#### 3. Get Redacted Record
```bash
GET /records/{record_id}
Authorization: Bearer user-123:developer
```
Returns the record with PII replaced by tokens (e.g., `<EMAIL_ADDRESS:jZ6v3Cj1f504nbpxXJI9>`). Automatically logs access in audit trail.

#### 4. Verify Tamper Status
```bash
GET /verify/{record_id}
```
Recalculates the hash and compares with stored hash. Returns:
```json
{
  "record_id": "UUID",
  "tampered": false,
  "expected_hash": "hex string",
  "stored_hash": "hex string",
  "audit_entries": [...]
}
```

### PII Management (RBAC Protected)

#### 5. Reveal PII
```bash
POST /pii/reveal/{record_id}
Authorization: Bearer user-123:compliance
Content-Type: application/json
```
**Required role:** `compliance` or `admin`

Request body:
```json
{
  "justification": "string - min 10 chars explaining why PII access is needed",
  "reason_code": "string - legal|audit|compliance|support|other"
}
```
Response includes original PII mappings and timestamp. Automatically logs access as PII reveal.

### Audit & Compliance (RBAC Protected)

#### 6. Get Access Audit Log
```bash
GET /audit/access-log?user_id=...&record_id=...&limit=100
Authorization: Bearer user-123:compliance
```
**Required role:** `compliance`, `developer`, or `admin` (not `viewer`)

Query parameters (all optional):
- `user_id`: Filter by user who accessed records
- `record_id`: Filter by specific record
- `limit`: Max results (default 100, max 1000)

Response:
```json
{
  "total": 42,
  "filtered_by": {"user_id": "user-123", "record_id": null},
  "entries": [
    {
      "record_id": "UUID",
      "action": "read_record|reveal|legal_hold_true|legal_hold_false",
      "user_id": "user-123",
      "role": "developer",
      "timestamp": "ISO8601",
      "reason_code": null
    }
  ],
  "queried_by": "user-123",
  "timestamp": "ISO8601"
}
```

#### 7. Get Retention Report
```bash
GET /compliance/retention-report
Authorization: Bearer user-123:compliance
```
**Required role:** `compliance` or `admin`

Response:
```json
{
  "total_records": 500,
  "expired": 0,
  "expiring_soon": 3,
  "legal_hold": 2,
  "records": [
    {
      "record_id": "UUID",
      "user_id": "user-123",
      "agent_id": "agent-1",
      "retention_category": "90_days",
      "expiry_time": "2026-09-29T12:00:00Z",
      "days_left": 89,
      "status": "ACTIVE|EXPIRING_SOON|EXPIRED",
      "legal_hold": false,
      "created_at": "ISO8601"
    }
  ],
  "generated_by": "user-123",
  "timestamp": "ISO8601"
}
```

#### 8. Set Legal Hold
```bash
POST /compliance/legal-hold/{record_id}?hold=true
Authorization: Bearer user-123:compliance
```
**Required role:** `compliance` or `admin`

Query parameter `hold` (default true):
- `true`: Place legal hold (prevent deletion)
- `false`: Remove legal hold

Response:
```json
{
  "record_id": "UUID",
  "legal_hold": true,
  "updated_at": "ISO8601",
  "set_by": "user-123"
}
```

### Metrics & Health

#### 9. System Metrics
```bash
GET /metrics
Authorization: Bearer user-123:admin
```
**Required role:** `admin` or `compliance`

Response:
```json
{
  "timestamp": "ISO8601",
  "redacted_records": 500,
  "audit_entries": 1250,
  "status": "healthy",
  "data_dir": "/path/to/.data",
  "local_storage": true,
  "requested_by": "user-123"
}
```

### Data Subject Access Requests (DSAR)

#### 10. DSAR Handler
```bash
POST /dsar
Content-Type: application/json
```
Request body:
```json
{
  "user_id": "user-123"
}
```
Response:
```json
{
  "user_id": "user-123",
  "records_found": 42,
  "status": "marked_for_deletion",
  "summary": [
    {
      "record_id": "UUID",
      "agent_id": "agent-1",
      "created_at": "ISO8601",
      "expiry_time": "ISO8601"
    }
  ]
}
```
All matching records are marked with `deletion_requested=true` for scheduled cleanup.

## Example Requests

### 1. Ingest a record
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "prompt":"My email is john@example.com and SSN is 123-45-6789",
    "response":"Application submitted",
    "agent_id":"agent-1",
    "timestamp":"2026-06-30T12:00:00Z",
    "user_id":"user-john"
  }'
```

### 2. Get a redacted record (as developer)
```bash
curl http://localhost:8000/records/{record_id} \
  -H "Authorization: Bearer user-john:developer"
```

### 3. Reveal PII (as compliance officer)
```bash
curl -X POST http://localhost:8000/pii/reveal/{record_id} \
  -H "Authorization: Bearer user-john:compliance" \
  -H "Content-Type: application/json" \
  -d '{
    "justification":"Customer requested their personal data for verification",
    "reason_code":"SUBJECT_REQUEST"
  }'
```

### 4. Check retention status
```bash
curl http://localhost:8000/compliance/retention-report \
  -H "Authorization: Bearer user-john:compliance"
```

### 5. View audit log
```bash
curl "http://localhost:8000/audit/access-log?user_id=user-john&limit=50" \
  -H "Authorization: Bearer user-john:compliance"
```

### 6. Set legal hold
```bash
curl -X POST http://localhost:8000/compliance/legal-hold/{record_id}?hold=true \
  -H "Authorization: Bearer user-john:compliance"
```

### 7. Handle DSAR
```bash
curl -X POST http://localhost:8000/dsar \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-john"}'
```

## Architecture

### Data Flow

1. **Ingest**: Raw log payload received → stored as-is in S3/local → processed for PII detection
2. **Redaction**: Presidio/regex detects PII entities → deterministic tokens generated → redacted text stored → mappings logged
3. **Hashing**: Record canonicalized as JSON → HMAC-SHA256 with secret key → hash stored
4. **Access**: User requests record → access logged (user/role/action/timestamp) → record returned (or 403 if role denied)
5. **Audit**: Every read, PII reveal, and action logged in append-only audit trail
6. **Retention**: 90-day retention enforced → expired records blocked → legal holds override expiry

### Storage Layers

| Layer | Local | AWS | Purpose |
|-------|-------|-----|---------|
| Raw Logs | `.data/raw/` | S3 (encrypted) | Original, immutable payloads |
| Redacted Records | `.data/redacted/` | DynamoDB | Searchable, with tokens |
| PII Mappings | `.data/mappings/` | DynamoDB | Token-to-value reverse lookup |
| Audit Trail | `.data/audit/` | DynamoDB (append-only) | All access events |

## Project Structure

```
api/
  ├── main.py           # FastAPI app and 10+ endpoints
  ├── auth.py           # RBAC middleware: get_user_from_header, require_role
  ├── models.py         # Pydantic schemas: LogIngest, PIIRevealRequest, Role enum
  ├── storage.py        # Dual-mode storage: local JSON + AWS S3/DynamoDB
  ├── audit.py          # Access audit logging
  ├── retention.py      # Retention policy enforcement (90-day expiry)
  ├── config.py         # Config: env vars, secrets, AWS region
  └── compliance.py     # Compliance reporting: retention, audit, legal holds, metrics

workers/
  ├── processor.py      # Main PII detection + redaction pipeline
  ├── presidio_client.py # Microsoft Presidio integration + regex fallback
  ├── tokenizer.py      # Deterministic PII tokenization
  └── hash_utils.py     # HMAC-SHA256 hashing with datetime handling

tests/
  ├── test_redaction.py # PII replacement verification
  ├── test_hashing.py   # Tamper detection validation
  ├── test_retention.py # Expiry policy enforcement
  └── test_access_audit.py # Access logging verification

infra/
  └── main.tf, variables.tf, outputs.tf # AWS infrastructure as code

scripts/
  ├── seed_data.py      # Generate synthetic test records
  └── simulate_tamper.py # Test tamper detection
```

## Technology Stack

- **FastAPI 0.138.2** - Async REST framework
- **Uvicorn 0.49.0** - ASGI server with hot-reload
- **Pydantic 2.x** - Request/response validation
- **Microsoft Presidio 2.2.363** - PII detection (spaCy NER + regex)
- **boto3** - AWS SDK (S3, DynamoDB, KMS)
- **Docker** - Containerization
- **Terraform** - Infrastructure as code (AWS)
- **pytest** - Unit testing
- **Python 3.11** - Runtime environment

## Compliance & Security

✅ **PII Protection**: All sensitive data redacted in transit and at rest
✅ **Tamper Detection**: HMAC-SHA256 content hashing detects record modifications
✅ **Access Control**: RBAC enforces least privilege (4 roles with granular permissions)
✅ **Audit Trail**: Every access logged immutably for compliance
✅ **Retention**: 90-day expiry with legal hold override for litigation
✅ **DSAR Support**: Automated discovery and deletion marking
✅ **Encryption**: Optional AWS KMS for key management
✅ **Secure Headers**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection

## Testing

All tests passing (5 unit tests):
- `test_redaction.py` - Verifies PII is replaced with tokens, no raw data exposed
- `test_hashing.py` - Verifies hash changes when record changes (tamper detection)
- `test_retention.py` - Verifies expiry detection works correctly
- `test_access_audit.py` - Verifies audit entries created on reads

Run tests:
```bash
pytest -q
```

## Deployment

### Local
```bash
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

### Docker
```bash
docker compose up --build
```

### AWS (Terraform)
```bash
cd infra
terraform init
terraform apply -auto-approve
```

## Environment Variables

Key configuration variables (set in `.env` or system environment):

```
# AWS Configuration (optional - uses local storage if not set)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
RAW_BUCKET=my-raw-logs-bucket
REDACTED_TABLE=my-redacted-table
MAPPING_TABLE=my-mapping-table
AUDIT_TABLE=my-audit-table

# Secrets
HASH_SECRET=your-secret-key-here
TOKEN_SECRET=your-token-secret-here

# Services
PRESIDIO_URL=http://localhost:8081

# Storage
LOCAL_STORAGE=true (default: use .data/ directory)
DATA_DIR=.data
```

## Known Limitations & Future Enhancements

- **Key Rotation**: Not yet implemented (placeholder endpoints exist)
- **Search**: Full-text search on redacted logs not yet implemented
- **Advanced Metrics**: Monitoring and alerting integration pending
- **Multi-tenancy**: Single-tenant design; multi-tenant support planned
- **API Rate Limiting**: Not yet implemented
- **GraphQL**: REST-only; GraphQL support planned

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is proprietary and confidential.

## Support

For issues, questions, or contributions, please contact the development team.
