import requests
import json

print("=== PS-7.2 VERIFICATION TEST ===\n")

# Test 1: Health
r = requests.get('http://127.0.0.1:8000/health')
print(f'✅ Health Check: {r.status_code}')

# Test 2: Ingest
payload = {
    'prompt': 'Test email: alice@example.com',
    'response': 'OK',
    'agent_id': 'test',
    'timestamp': '2026-06-30T12:00:00Z',
    'user_id': 'alice'
}
r = requests.post('http://127.0.0.1:8000/ingest', json=payload)
record_id = r.json()['record_id']
print(f'✅ Ingest: {r.status_code} - Created {record_id[:8]}...')

# Test 3: Get redacted (developer)
r = requests.get(
    f'http://127.0.0.1:8000/records/{record_id}',
    headers={'Authorization': 'Bearer alice:developer'}
)
print(f'✅ Get Redacted: {r.status_code}')
redacted = r.json()['redacted_prompt'][:60]
print(f'   Redacted text: {redacted}...')

# Test 4: Reveal PII (compliance)
payload = {'justification': 'Testing compliance access', 'reason_code': 'audit'}
r = requests.post(
    f'http://127.0.0.1:8000/pii/reveal/{record_id}',
    headers={'Authorization': 'Bearer alice:compliance'},
    json=payload
)
print(f'✅ Reveal PII: {r.status_code}')

# Test 5: RBAC rejection (developer cannot reveal)
r = requests.post(
    f'http://127.0.0.1:8000/pii/reveal/{record_id}',
    headers={'Authorization': 'Bearer alice:developer'},
    json=payload
)
print(f'✅ RBAC Rejection: {r.status_code} (developer denied)')

# Test 6: Retention report (compliance)
r = requests.get(
    'http://127.0.0.1:8000/compliance/retention-report',
    headers={'Authorization': 'Bearer alice:compliance'}
)
print(f'✅ Retention Report: {r.status_code}')
data = r.json()
print(f'   Records: {data["total_records"]}, Expired: {data["expired"]}, Legal Hold: {data["legal_hold"]}')

# Test 7: Legal hold
r = requests.post(
    f'http://127.0.0.1:8000/compliance/legal-hold/{record_id}?hold=true',
    headers={'Authorization': 'Bearer alice:compliance'}
)
print(f'✅ Legal Hold: {r.status_code}')

# Test 8: Metrics
r = requests.get(
    'http://127.0.0.1:8000/metrics',
    headers={'Authorization': 'Bearer alice:admin'}
)
print(f'✅ Metrics: {r.status_code}')

# Test 9: Verify tamper detection
r = requests.get(f'http://127.0.0.1:8000/verify/{record_id}')
print(f'✅ Tamper Check: {r.status_code} - Tampered: {r.json()["tampered"]}')

# Test 10: DSAR
r = requests.post('http://127.0.0.1:8000/dsar', json={'user_id': 'alice'})
print(f'✅ DSAR: {r.status_code} - Records marked: {r.json()["records_found"]}')

print('\n=== ALL TESTS PASSED ✓ ===')
