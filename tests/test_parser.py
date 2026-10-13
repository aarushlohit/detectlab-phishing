"""
Unit tests for MIME parser and evidence extractor.
"""

import pytest
import hashlib
from parser import parse_email, ParseError


def test_parse_valid_email():
    raw = (
        b"From: alice@example.test\r\n"
        b"To: bob@example.test\r\n"
        b"Subject: Test Email\r\n"
        b"Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Check this link: https://example.test/portal\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain; filename=\"payload.txt\"\r\n"
        b"Content-Disposition: attachment; filename=\"payload.txt\"\r\n\r\n"
        b"Hello Attachment World\r\n"
        b"--BOUNDARY--"
    )
    res = parse_email(raw)
    assert res["headers"]["from"] == "alice@example.test"
    assert res["headers"]["subject"] == "Test Email"
    assert res["auth"]["spf"] == "pass"
    assert res["auth"]["dkim"] == "pass"
    assert res["auth"]["dmarc"] == "pass"
    assert len(res["urls"]) == 1
    assert res["urls"][0]["url"] == "https://example.test/portal"

    assert len(res["attachments"]) == 1
    att = res["attachments"][0]
    assert att["filename"] == "payload.txt"
    assert att["size"] == len(b"Hello Attachment World")
    expected_hash = hashlib.sha256(b"Hello Attachment World").hexdigest()
    assert att["sha256"] == expected_hash


def test_missing_auth_headers_returns_unknown():
    raw = (
        b"From: user@example.test\r\n"
        b"To: other@example.test\r\n"
        b"Subject: No auth\r\n\r\n"
        b"Simple body"
    )
    res = parse_email(raw)
    assert res["auth"]["spf"] == "unknown"
    assert res["auth"]["dkim"] == "unknown"
    assert res["auth"]["dmarc"] == "unknown"


def test_empty_email_raises_parse_error():
    with pytest.raises(ParseError) as exc_info:
        parse_email(b"")
    assert exc_info.value.code == "MALFORMED_INPUT"


def test_malformed_email_missing_all_headers_raises_parse_error():
    raw = b"Just plain string with no email headers or mime structures\nsecond line"
    with pytest.raises(ParseError) as exc_info:
        parse_email(raw)
    assert exc_info.value.code == "MALFORMED_INPUT"


def test_attachment_sha256_matches_known_value():
    payload_bytes = b"DetectLab-Attachment-Verification-Bytes-12345"
    expected_sha = hashlib.sha256(payload_bytes).hexdigest()

    raw = (
        b"From: safe@example.test\r\n"
        b"To: user@example.test\r\n"
        b"Subject: Attachment hash test\r\n"
        b"Content-Type: multipart/mixed; boundary=\"B1\"\r\n\r\n"
        b"--B1\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"sample.pdf\"\r\n\r\n"
        + payload_bytes + b"\r\n--B1--"
    )
    res = parse_email(raw)
    assert len(res["attachments"]) == 1
    assert res["attachments"][0]["sha256"] == expected_sha
