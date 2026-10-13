"""
Unit tests for verdict engine and reason codes.
"""

from verdict import make_verdict


def test_auth_fail_gives_auth_fail_code():
    parsed = {
        "headers": {"from": "user@example.test"},
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "urls": [],
        "attachments": [],
    }
    res = make_verdict(parsed)
    assert "AUTH_FAIL" in res["reason_codes"]
    assert res["score"] >= 6
    assert res["verdict"] == "Suspicious"


def test_auth_pass_no_indicators_likely_benign():
    parsed = {
        "headers": {"from": "user@example.test"},
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "urls": [{"url": "https://example.test", "suspicious": False}],
        "attachments": [],
    }
    res = make_verdict(parsed)
    assert "AUTH_PASS" in res["reason_codes"]
    assert res["score"] == 0
    assert res["verdict"] == "Likely Benign"


def test_no_evidence_inconclusive():
    parsed = {
        "headers": {"from": "user@example.test"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "urls": [],
        "attachments": [],
    }
    res = make_verdict(parsed)
    assert res["verdict"] == "Inconclusive"
    assert "NO_EVIDENCE" in res["reason_codes"]
    assert res["score"] == 0


def test_multiple_indicators_trigger_suspicious_verdict():
    parsed = {
        "headers": {
            "from": '"PayPal Security" <attacker@evil.test>',
            "reply_to": "collector@other-evil.test",
        },
        "auth": {"spf": "fail", "dkim": "unknown", "dmarc": "unknown"},
        "urls": [{"url": "http://192.168.1.1/login", "suspicious": True}],
        "attachments": [{"filename": "invoice.pdf.exe", "sha256": "abc"}],
    }
    res = make_verdict(parsed)
    assert res["verdict"] == "Suspicious"
    assert "MULTIPLE_INDICATORS" in res["reason_codes"]
    assert "ATTACH_NOT_EXECUTED" in res["reason_codes"]


def test_vt_url_malicious_code():
    parsed = {
        "headers": {"from": "user@example.test"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "urls": [{"url": "http://evil.test/bad", "suspicious": False}],
        "attachments": [],
    }
    enrichment = {
        "urls": {
            "http://evil.test/bad": {"status": "malicious", "malicious": 10}
        },
        "files": {}
    }
    res = make_verdict(parsed, enrichment)
    assert "URL_VT_MALICIOUS" in res["reason_codes"]
    assert res["score"] >= 3


def test_vt_attachment_hash_malicious_code():
    parsed = {
        "headers": {"from": "user@example.test"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "urls": [],
        "attachments": [{"filename": "sample.pdf", "sha256": "badhash123"}],
    }
    enrichment = {
        "urls": {},
        "files": {
            "badhash123": {"status": "malicious", "malicious": 35}
        }
    }
    res = make_verdict(parsed, enrichment)
    assert "ATTACH_HASH_VT_MALICIOUS" in res["reason_codes"]
    assert "ATTACH_NOT_EXECUTED" in res["reason_codes"]
    assert res["score"] >= 4
