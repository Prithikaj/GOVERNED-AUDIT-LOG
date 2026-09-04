"""
Extended PII detection tests — validates that the fallback regex detector
correctly identifies SSN, phone numbers, credit-card numbers, and IP addresses
in addition to the baseline EMAIL and PERSON coverage.
"""

from workers.presidio_client import _fallback_detect_pii


def _types(text: str) -> set[str]:
    return {e["type"] for e in _fallback_detect_pii(text)}


def test_ssn_is_detected():
    result = _fallback_detect_pii("My SSN is 123-45-6789.")
    types = {e["type"] for e in result}
    assert "US_SSN" in types, f"Expected US_SSN in {types}"


def test_ssn_space_separator_is_detected():
    result = _fallback_detect_pii("SSN: 123 45 6789")
    assert any(e["type"] == "US_SSN" for e in result)


def test_email_is_detected():
    assert "EMAIL_ADDRESS" in _types("Contact alice@example.org for help.")


def test_person_name_is_detected():
    assert "PERSON" in _types("Hello, John Smith, how are you?")


def test_phone_number_is_detected():
    assert "PHONE_NUMBER" in _types("Call me at 555-867-5309.")


def test_credit_card_is_detected():
    assert "CREDIT_CARD" in _types("Card: 4111 1111 1111 1111 is valid.")


def test_ip_address_is_detected():
    assert "IP_ADDRESS" in _types("Request came from 192.168.1.100.")


def test_no_false_positives_on_plain_text():
    result = _fallback_detect_pii("The weather is nice today.")
    assert result == [], f"Unexpected entities: {result}"


def test_multiple_pii_in_single_string():
    text = "Jane Doe's email is jane@example.com and SSN is 987-65-4321."
    types = _types(text)
    assert "PERSON" in types
    assert "EMAIL_ADDRESS" in types
    assert "US_SSN" in types
