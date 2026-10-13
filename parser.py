"""
Core MIME email parser and evidence extractor for DetectLab Phishing Triage.

Security guarantees:
- Never executes attachments.
- Never renders HTML bodies.
- Safe in-memory decoding and SHA-256 calculation.
"""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
import hashlib
import re
from typing import Any


class ParseError(Exception):
    """Controlled exception for malformed or unprocessable input."""
    def __init__(self, message: str = "Malformed email input", code: str = "MALFORMED_INPUT"):
        super().__init__(message)
        self.code = code


# Regular expression to extract URLs (handles http, https)
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.VERBOSE
)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".iso", ".hta", ".ps1", ".jar", ".wsf", ".msi", ".dll"
}


def _clean_url(raw: str) -> str:
    cleaned = raw.strip().rstrip(").,;:>'\"")
    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "http://" + cleaned
    return cleaned


def _is_suspicious_url(url: str) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    lower = url.lower()

    # IP address hostname check
    ip_match = re.search(r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)", lower)
    if ip_match:
        reasons.append("url_ip_hostname")

    # High-risk login/credential tokens
    if any(k in lower for k in ["login", "verify", "secure", "update", "account", "banking", "wallet", "recover"]):
        # Check if paired with atypical TLD or hyphens
        if any(tld in lower for tld in [".xyz", ".top", ".buzz", ".club", ".work", ".test", ".ru", ".tk"]):
            reasons.append("credential_keywords_suspicious_tld")
        elif "-" in lower:
            reasons.append("credential_keywords_hyphenated")

    # At symbol in URL (userinfo spoofing)
    if "@" in url.split("?")[0]:
        reasons.append("url_at_symbol_obfuscation")

    return (len(reasons) > 0, reasons)


def _extract_auth_results(header_val: str | None) -> dict[str, str]:
    auth = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    }
    if not header_val:
        return auth

    header_lower = header_val.lower()

    # Helper matcher
    def find_status(mechanism: str) -> str:
        # e.g., spf=pass or dkim=fail (reason)
        pattern = rf"{mechanism}\s*=\s*([a-z]+)"
        match = re.search(pattern, header_lower)
        if match:
            status = match.group(1)
            if status in {"pass", "fail", "softfail", "neutral", "none"}:
                return status
            return "unknown"
        return "unknown"

    auth["spf"] = find_status("spf")
    auth["dkim"] = find_status("dkim")
    auth["dmarc"] = find_status("dmarc")

    return auth


def parse_email(raw_bytes: bytes) -> dict[str, Any]:
    """
    Parses raw .eml bytes into structured headers, auth, URLs, and attachment metadata.

    Raises:
        ParseError: If email is empty or completely unparseable.
    """
    if not raw_bytes or not raw_bytes.strip():
        raise ParseError("Email content is empty", code="MALFORMED_INPUT")

    parse_warnings: list[str] = []

    try:
        # Using default policy for robust header handling
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        raise ParseError(f"Failed to decode MIME data: {exc}", code="MALFORMED_INPUT") from exc

    if msg is None:
        raise ParseError("Message parser returned None", code="MALFORMED_INPUT")

    # Collect headers
    from_header = str(msg.get("from", "") or "").strip()
    to_header = str(msg.get("to", "") or "").strip()
    subject_header = str(msg.get("subject", "") or "").strip()
    date_header = str(msg.get("date", "") or "").strip()
    reply_to = str(msg.get("reply-to", "") or "").strip()
    return_path = str(msg.get("return-path", "") or "").strip()
    message_id = str(msg.get("message-id", "") or "").strip()

    received_headers = [str(r).strip() for r in msg.get_all("received", []) if r]

    # Validate essential headers presence
    if not from_header and not to_header and not subject_header and not received_headers:
        # Check if payload is malformed
        raise ParseError("Missing all standard email headers", code="MALFORMED_INPUT")

    headers = {
        "from": from_header,
        "to": to_header,
        "subject": subject_header,
        "date": date_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "received": received_headers,
    }

    # Authentication Results
    auth_header = msg.get("authentication-results")
    auth = _extract_auth_results(auth_header)

    # Body extraction & Attachments
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    try:
        for part in msg.walk():
            # Check content disposition
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            filename = part.get_filename()

            if content_disposition == "attachment" or (filename and content_disposition != "inline"):
                # Attachment handling - NEVER save bytes, NEVER execute
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b""
                
                safe_filename = filename or "unnamed_attachment"
                sha256 = hashlib.sha256(payload).hexdigest()
                size = len(payload)

                attachments.append({
                    "filename": safe_filename,
                    "type": content_type or "application/octet-stream",
                    "size": size,
                    "sha256": sha256,
                })
            else:
                if content_type == "text/plain":
                    try:
                        text_payload = part.get_payload(decode=True)
                        if text_payload:
                            body_text_parts.append(text_payload.decode(errors="replace"))
                    except Exception as err:
                        parse_warnings.append(f"Failed to decode text/plain part: {err}")
                elif content_type == "text/html":
                    try:
                        html_payload = part.get_payload(decode=True)
                        if html_payload:
                            body_html_parts.append(html_payload.decode(errors="replace"))
                    except Exception as err:
                        parse_warnings.append(f"Failed to decode text/html part: {err}")
    except Exception as exc:
        raise ParseError(f"Error during MIME part traversal: {exc}", code="MALFORMED_INPUT") from exc

    body_text = "\n".join(body_text_parts)
    body_html = "\n".join(body_html_parts)

    # URL extraction
    discovered_urls: dict[str, dict[str, Any]] = {}

    def extract_urls_from_text(source_text: str, source_type: str) -> None:
        for match in URL_REGEX.finditer(source_text):
            raw_matched = match.group(0)
            cleaned = _clean_url(raw_matched)
            if cleaned not in discovered_urls:
                is_susp, reasons = _is_suspicious_url(cleaned)
                discovered_urls[cleaned] = {
                    "url": cleaned,
                    "source": source_type,
                    "suspicious": is_susp,
                    "reasons": reasons,
                }

    if body_text:
        extract_urls_from_text(body_text, "text")
    if body_html:
        extract_urls_from_text(body_html, "html")

    return {
        "headers": headers,
        "auth": auth,
        "urls": list(discovered_urls.values()),
        "attachments": attachments,
        "body_text": body_text,
        "body_html": body_html,
        "parse_warnings": parse_warnings,
    }
