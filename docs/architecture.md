# PS-7.2 Governed Audit Log — Architecture

## Overview

The system applies data-governance policies to AI interaction audit logs themselves.
Every raw log record is ingested, PII-redacted, hashed, retention-tagged, and stored
before any reader can access it. Every read is itself logged.

```
Client
  │  POST /ingest  { prompt, response, agent_id, timestamp, user_id }
  ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI  (api/main.py)                                      │
│                                                              │
│  1. save_raw()   ──► .data/raw/{id}.json   (immutable copy) │
│  2. process_record()                                        │
│       ├─ detect_pii()  ──► Presidio HTTP / regex fallback   │
│       ├─ redact_text() ──► tokenize() (HMAC-SHA256)         │
│       ├─ _classify_retention(agent_id) → category + expiry  │
│       └─ record_hash()  ──► entry_hash (HMAC-SHA256)        │
│  3. _get_latest_hash()  ──► previous_hash (chain link)      │
│  4. put_redacted()  ──► .data/redacted/{id}.json            │
│  5. put_mapping()   ──► .data/mappings/{id}-{token}.json    │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Ingestion Pipeline (`/ingest`)
Accepts raw log records. Saves an immutable copy to `raw/`, processes PII
redaction, computes the retention window, builds the hash-chain link, and
stores the final redacted record.

### PII Redaction (`workers/presidio_client.py`, `workers/tokenizer.py`)
1. **Detection** — attempts to call a Presidio Analyzer HTTP server; falls
   back to a regex detector that covers: `PERSON`, `EMAIL_ADDRESS`, `US_SSN`,
   `PHONE_NUMBER`, `CREDIT_CARD`, `IP_ADDRESS`.
2. **Tokenisation** — each detected value is replaced with a deterministic
   HMAC-SHA256 token (`<ENTITY_TYPE:token>`). The token is reproducible for
   the same value + tenant, enabling reverse-lookup for authorised roles.
3. **Mapping storage** — one JSON file per token saved to `mappings/`; only
   compliance/admin roles can call `/pii/reveal/{id}`.

### Retention Policy Engine (`workers/processor.py`, `api/retention.py`)
Agent IDs are classified into retention tiers:

| Agent prefix       | Category   | Days |
|--------------------|------------|------|
| agent-legal        | 365_days   | 365  |
| agent-financial    | 365_days   | 365  |
| agent-medical      | 365_days   | 365  |
| agent-hr           | 180_days   | 180  |
| agent-compliance   | 180_days   | 180  |
| agent-support      | 90_days    | 90   |
| agent-internal     | 30_days    | 30   |
| agent-test         | 7_days     | 7    |
| *(default)*        | 90_days    | 90   |

`is_expired()` is checked on every read; expired records return HTTP 410.
Legal-hold records are exempt from automatic expiry.

### Tamper Detection (`workers/hash_utils.py`)
Each record stores an `entry_hash`: `HMAC-SHA256(canonicalised_json, HASH_SECRET)`.
`/verify/{id}` recomputes the hash over the current stored data and compares it
to `entry_hash` — any field modification is detected.

**Hash chain**: each new record's `previous_hash` field is set to the
`entry_hash` of the most recently stored record, forming a tamper-evident chain.

### Log Access Audit (`api/audit.py`, `api/storage.py`)
Every call to `/records/{id}`, `/pii/reveal/{id}`, and `/records/{id}/history`
appends an entry to `.data/audit/{record_id}.json`. The compliance endpoint
`/audit/access-log` aggregates across all records and supports filtering by
`user_id` and `record_id`.

### DSAR Handler (`/dsar`)
Given a `user_id`, the handler:
1. Scans redacted records for direct `user_id` matches.
2. Cross-references PII token mappings to catch records where the user appears
   only as a tokenised value.
3. Returns a redacted summary (no raw PII).
4. Marks every matched record `deletion_requested = true`.

### Role-Based Access Control (`api/auth.py`)
Authorization via `Authorization: Bearer <user_id>:<role>` header.

| Role        | Can read records | Reveal PII | Audit log | Retention report | Metrics |
|-------------|-----------------|------------|-----------|-----------------|---------|
| admin       | ✓               | ✓          | ✓         | ✓               | ✓       |
| compliance  | ✓               | ✓          | ✓         | ✓               | ✓       |
| developer   | ✓               | ✗          | ✓         | ✗               | ✗       |
| viewer      | ✓               | ✗          | ✗         | ✗               | ✗       |

## Storage

### Local mode (default, `LOCAL_STORAGE=true`)
```
.data/
  raw/          {record_id}.json          — original ingested payload
  redacted/     {record_id}.json          — processed, hashed, retention-tagged
  mappings/     {record_id}-{token}.json  — PII token ↔ value
  audit/        {record_id}.json          — append-only access event array
```

### Cloud mode (`LOCAL_STORAGE=false`)
| Data           | Service        | Table / Bucket        |
|----------------|----------------|-----------------------|
| Raw records    | S3             | `ps72-raw-logs`       |
| Redacted logs  | DynamoDB       | `ps72-redacted-logs`  |
| PII mappings   | DynamoDB       | `ps72-pii-mapping`    |
| Audit trail    | DynamoDB       | `ps72-access-audit`   |

Raw objects in S3 are encrypted with AWS KMS (`ServerSideEncryption: aws:kms`).

## API Endpoints

| Method | Path                           | Description                              |
|--------|-------------------------------|------------------------------------------|
| GET    | /health                        | Liveness check                           |
| POST   | /ingest                        | Ingest a raw log record                  |
| GET    | /records/{id}                  | Read a redacted record (access logged)   |
| GET    | /records/{id}/history          | Hash-chain history + access events       |
| GET    | /verify/{id}                   | Tamper-detection check                   |
| POST   | /pii/reveal/{id}               | Reveal original PII (compliance/admin)   |
| GET    | /audit/access-log              | Query access audit log                   |
| GET    | /compliance/retention-report   | Retention status report                  |
| POST   | /compliance/legal-hold/{id}    | Set/clear legal hold on a record         |
| GET    | /metrics                       | System health and record counts          |
| POST   | /dsar                          | Data Subject Access Request handler      |
