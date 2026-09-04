from workers.hash_utils import record_hash


def test_hash_is_deterministic_and_secret_bound():
    obj = {"record_id": "abc", "redacted_prompt": "hello"}

    first = record_hash(obj, "secret")
    second = record_hash(obj, "secret")
    changed = record_hash({**obj, "redacted_prompt": "bye"}, "secret")

    assert first == second
    assert first != changed
    assert first != record_hash(obj, "other-secret")
