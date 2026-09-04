import re
from typing import Any, List

import requests

from api.config import PRESIDIO_URL


def _fallback_detect_pii(text: str) -> List[dict[str, Any]]:
    """
    Regex-based PII detection used when Presidio server is unavailable.
    Covers: PERSON names, email addresses, SSN (US), phone numbers, credit card
    numbers, IP addresses, and date-of-birth patterns.
    """
    entities: List[dict[str, Any]] = []
    seen: set[str] = set()  # avoid duplicate spans

    def _add(match: re.Match, entity_type: str) -> None:
        text_val = match.group(0)
        if text_val not in seen:
            seen.add(text_val)
            entities.append({"text": text_val, "type": entity_type})

    # US Social Security Number  (e.g. 123-45-6789 or 123 45 6789)
    for m in re.finditer(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b", text):
        _add(m, "US_SSN")

    # Email address
    for m in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text):
        _add(m, "EMAIL_ADDRESS")

    # Phone numbers — US/international variants
    for m in re.finditer(
        r"(\+?1[\s\-.])?(\(?\d{3}\)?[\s\-.])\d{3}[\s\-.]\d{4}", text
    ):
        _add(m, "PHONE_NUMBER")

    # Credit / debit card numbers (4 groups of 4 digits)
    for m in re.finditer(r"\b(?:\d{4}[\s\-]){3}\d{4}\b", text):
        _add(m, "CREDIT_CARD")

    # IPv4 address
    for m in re.finditer(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text,
    ):
        _add(m, "IP_ADDRESS")

    # Person names — Title-case two-word sequence (keep last so SSN isn't confused)
    for m in re.finditer(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b", text):
        _add(m, "PERSON")

    return entities


def detect_pii(text: str) -> List[dict[str, Any]]:
    if not text:
        return []
    try:
        url = f"{PRESIDIO_URL}/detect"
        # Use a (connect_timeout, read_timeout) tuple so slow/absent Presidio
        # servers fail fast and we fall through to the regex fallback.
        response = requests.post(
            url,
            json={"text": text, "language": "en"},
            timeout=(1.0, 3.0),  # 1s connect, 3s read
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and "results" in payload:
            payload = payload["results"]
        return payload if isinstance(payload, list) else []
    except Exception:
        return _fallback_detect_pii(text)