"""
Verdict engine for DetectLab Phishing Triage.

Calculates threat score, produces reason codes, and determines triage verdict:
- Suspicious (score >= 6)
- Inconclusive (score 1-5, or score 0 with no evidence)
- Likely Benign (score == 0 and at least one benign indicator)
"""

from __future__ import annotations

import os
from typing import Any
from email.utils import parseaddr


DANGEROUS_EXTS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".iso", ".hta", ".ps1", ".jar", ".wsf", ".msi", ".dll"
}

DOUBLE_EXT_PATTERN = [
    ".pdf.exe", ".docx.exe", ".xlsx.exe", ".zip.exe", ".jpg.exe", ".png.scr", ".txt.vbs", ".doc.vbs"
]


def _extract_domain(email_str: str) -> str:
    if not email_str:
        return ""
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def make_verdict(parsed: dict[str, Any], enrichment: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Evaluates parsed email structure and enrichment findings to output score, verdict, and reason codes.
    """
    score = 0
    reason_codes: list[str] = []
    evidence_summary: dict[str, Any] = {
        "auth_failures": [],
        "auth_passes": [],
        "header_issues": [],
        "url_threats": [],
        "attachment_threats": [],
    }

    # 1. Authentication evaluation
    auth = parsed.get("auth", {})
    spf = auth.get("spf", "unknown")
    dkim = auth.get("dkim", "unknown")
    dmarc = auth.get("dmarc", "unknown")

    has_auth_fail = False
    has_auth_pass = False

    if spf == "fail":
        score += 2
        has_auth_fail = True
        evidence_summary["auth_failures"].append("SPF fail")
    elif spf == "pass":
        has_auth_pass = True
        evidence_summary["auth_passes"].append("SPF pass")

    if dkim == "fail":
        score += 2
        has_auth_fail = True
        evidence_summary["auth_failures"].append("DKIM fail")
    elif dkim == "pass":
        has_auth_pass = True
        evidence_summary["auth_passes"].append("DKIM pass")

    if dmarc == "fail":
        score += 2
        has_auth_fail = True
        evidence_summary["auth_failures"].append("DMARC fail")
    elif dmarc == "pass":
        has_auth_pass = True
        evidence_summary["auth_passes"].append("DMARC pass")

    if has_auth_fail:
        reason_codes.append("AUTH_FAIL")
    elif has_auth_pass and not has_auth_fail:
        reason_codes.append("AUTH_PASS")

    # 2. Header analysis
    headers = parsed.get("headers", {})
    from_header = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    from_display, from_addr = parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    # Header mismatch: From vs Reply-To
    if reply_to and from_addr:
        _, reply_addr = parseaddr(reply_to)
        reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
        if reply_domain and from_domain and reply_domain != from_domain:
            score += 1
            if "HEADER_MISMATCH" not in reason_codes:
                reason_codes.append("HEADER_MISMATCH")
            evidence_summary["header_issues"].append(f"From domain ({from_domain}) != Reply-To ({reply_domain})")

    # Header mismatch: From vs Return-Path
    if return_path and from_addr:
        _, return_addr = parseaddr(return_path)
        return_domain = return_addr.split("@")[-1].lower() if "@" in return_addr else ""
        if return_domain and from_domain and return_domain != from_domain:
            score += 1
            if "HEADER_MISMATCH" not in reason_codes:
                reason_codes.append("HEADER_MISMATCH")
            evidence_summary["header_issues"].append(f"From domain ({from_domain}) != Return-Path ({return_domain})")

    # Display name spoofing (e.g. Display says 'PayPal Support' or 'support@paypal.com' but actual address is @evil.test)
    if from_display and from_domain:
        display_lower = from_display.lower()
        if any(brand in display_lower for brand in ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank"]):
            if not any(brand in from_domain for brand in ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank"]):
                score += 1
                reason_codes.append("DISPLAY_NAME_SPOOF")
                evidence_summary["header_issues"].append(f"Display name '{from_display}' does not match domain '{from_domain}'")
        elif "@" in display_lower and display_lower not in from_addr.lower():
            score += 1
            reason_codes.append("DISPLAY_NAME_SPOOF")
            evidence_summary["header_issues"].append("Email address embedded in display name differs from sender address")

    # 3. URL heuristic analysis
    urls = parsed.get("urls", [])
    for u in urls:
        if u.get("suspicious", False):
            score += 1
            if "URL_SUSPICIOUS" not in reason_codes:
                reason_codes.append("URL_SUSPICIOUS")
            evidence_summary["url_threats"].append(f"Heuristic flag on {u.get('url')}")

    # 4. Attachments heuristic analysis
    attachments = parsed.get("attachments", [])
    has_attachments = len(attachments) > 0

    for att in attachments:
        fname = (att.get("filename") or "").lower()
        _, ext = os.path.splitext(fname)

        if ext in DANGEROUS_EXTS:
            score += 1
            if "ATTACH_DANGEROUS_EXT" not in reason_codes:
                reason_codes.append("ATTACH_DANGEROUS_EXT")
            evidence_summary["attachment_threats"].append(f"Dangerous extension {ext} in {fname}")

        if any(fname.endswith(dext) for dext in DOUBLE_EXT_PATTERN) or fname.count(".") > 1 and ext in DANGEROUS_EXTS:
            score += 1
            if "ATTACH_DOUBLE_EXT" not in reason_codes:
                reason_codes.append("ATTACH_DOUBLE_EXT")
            evidence_summary["attachment_threats"].append(f"Double extension suspected in {fname}")

    # 5. VirusTotal enrichment analysis
    if enrichment:
        vt_status = enrichment.get("status", "ok")
        if vt_status == "disabled":
            reason_codes.append("VT_DISABLED")
        elif vt_status == "rate_limited":
            reason_codes.append("VT_RATE_LIMITED")
        elif vt_status == "error":
            reason_codes.append("VT_ERROR")

        # URL lookups
        url_vt = enrichment.get("urls", {})
        for url_str, vt_res in url_vt.items():
            st = vt_res.get("status")
            if st == "malicious":
                score += 3
                if "URL_VT_MALICIOUS" not in reason_codes:
                    reason_codes.append("URL_VT_MALICIOUS")
                evidence_summary["url_threats"].append(f"VirusTotal malicious URL: {url_str}")
            elif st == "suspicious":
                score += 2
                if "URL_VT_SUSPICIOUS" not in reason_codes:
                    reason_codes.append("URL_VT_SUSPICIOUS")
                evidence_summary["url_threats"].append(f"VirusTotal suspicious URL: {url_str}")

        # Attachment hashes
        file_vt = enrichment.get("files", {})
        for sha256_str, vt_res in file_vt.items():
            st = vt_res.get("status")
            if st == "malicious":
                score += 4
                if "ATTACH_HASH_VT_MALICIOUS" not in reason_codes:
                    reason_codes.append("ATTACH_HASH_VT_MALICIOUS")
                evidence_summary["attachment_threats"].append(f"VirusTotal malicious file hash: {sha256_str}")
            elif st == "suspicious":
                score += 2
                if "ATTACH_HASH_VT_SUSPICIOUS" not in reason_codes:
                    reason_codes.append("ATTACH_HASH_VT_SUSPICIOUS")
                evidence_summary["attachment_threats"].append(f"VirusTotal suspicious file hash: {sha256_str}")

    # Multiple indicators check
    distinct_indicator_categories = 0
    if has_auth_fail:
        distinct_indicator_categories += 1
    if any(code in reason_codes for code in ["HEADER_MISMATCH", "DISPLAY_NAME_SPOOF"]):
        distinct_indicator_categories += 1
    if any(code in reason_codes for code in ["URL_SUSPICIOUS", "URL_VT_MALICIOUS", "URL_VT_SUSPICIOUS"]):
        distinct_indicator_categories += 1
    if any(code in reason_codes for code in ["ATTACH_DANGEROUS_EXT", "ATTACH_DOUBLE_EXT", "ATTACH_HASH_VT_MALICIOUS", "ATTACH_HASH_VT_SUSPICIOUS"]):
        distinct_indicator_categories += 1

    if distinct_indicator_categories >= 2:
        reason_codes.append("MULTIPLE_INDICATORS")

    # Safety Notice: Always include ATTACH_NOT_EXECUTED when attachments exist
    if has_attachments:
        reason_codes.append("ATTACH_NOT_EXECUTED")

    # 6. Final verdict determination
    if score >= 6:
        verdict = "Suspicious"
    elif 1 <= score <= 5:
        verdict = "Inconclusive"
    else:  # score == 0
        has_benign_evidence = (
            has_auth_pass
            or (len(urls) > 0 and all(not u.get("suspicious") for u in urls))
            or (has_attachments and not any(code in reason_codes for code in ["ATTACH_DANGEROUS_EXT", "ATTACH_DOUBLE_EXT"]))
        )
        if has_benign_evidence:
            verdict = "Likely Benign"
        else:
            verdict = "Inconclusive"
            reason_codes.append("NO_EVIDENCE")

    return {
        "verdict": verdict,
        "reason_codes": reason_codes,
        "score": score,
        "evidence_summary": evidence_summary,
    }
