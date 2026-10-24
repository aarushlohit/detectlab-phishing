"""
Report builders for DetectLab Phishing Triage:
- JSON report generation
- Markdown report generation
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any


def to_json(parsed: dict[str, Any], verdict: dict[str, Any], enrichment: dict[str, Any] | None, filename: str = "email.eml") -> str:
    """
    Builds JSON report matching schema.
    """
    url_enrichment = enrichment.get("urls", {}) if enrichment else {}
    file_enrichment = enrichment.get("files", {}) if enrichment else {}

    enriched_urls = []
    for u in parsed.get("urls", []):
        url_obj = dict(u)
        vt_info = url_enrichment.get(u.get("url"))
        if vt_info:
            url_obj["vt"] = {
                "status": vt_info.get("status"),
                "malicious": vt_info.get("malicious", 0),
                "suspicious": vt_info.get("suspicious", 0),
                "permalink": vt_info.get("permalink", ""),
            }
        enriched_urls.append(url_obj)

    enriched_attachments = []
    for att in parsed.get("attachments", []):
        att_obj = dict(att)
        vt_info = file_enrichment.get(att.get("sha256"))
        if vt_info:
            att_obj["vt"] = {
                "status": vt_info.get("status"),
                "malicious": vt_info.get("malicious", 0),
                "suspicious": vt_info.get("suspicious", 0),
                "permalink": vt_info.get("permalink", ""),
            }
        enriched_attachments.append(att_obj)

    report_dict = {
        "file": filename,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "headers": parsed.get("headers", {}),
        "auth": parsed.get("auth", {}),
        "urls": enriched_urls,
        "attachments": enriched_attachments,
        "verdict": verdict.get("verdict", "Inconclusive"),
        "score": verdict.get("score", 0),
        "reason_codes": verdict.get("reason_codes", []),
        "parse_warnings": parsed.get("parse_warnings", []),
    }
    return json.dumps(report_dict, indent=2)


def to_markdown(parsed: dict[str, Any], verdict: dict[str, Any], enrichment: dict[str, Any] | None, filename: str = "email.eml") -> str:
    """
    Builds Markdown report with formatted tables and evidence summaries.
    """
    headers = parsed.get("headers", {})
    auth = parsed.get("auth", {})
    urls = parsed.get("urls", [])
    attachments = parsed.get("attachments", [])

    url_enrichment = enrichment.get("urls", {}) if enrichment else {}
    file_enrichment = enrichment.get("files", {}) if enrichment else {}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# DetectLab Phishing Triage Report",
        f"",
        f"- **File:** `{filename}`",
        f"- **Generated:** `{timestamp}`",
        f"- **Verdict:** **{verdict.get('verdict', 'Inconclusive')}**",
        f"- **Threat Score:** `{verdict.get('score', 0)}`",
        f"- **Reason Codes:** `{', '.join(verdict.get('reason_codes', []))}`",
        f"",
        f"---",
        f"",
        f"## 1. Email Headers",
        f"",
        f"| Header | Value |",
        f"|---|---|",
        f"| **From** | `{headers.get('from', '')}` |",
        f"| **To** | `{headers.get('to', '')}` |",
        f"| **Subject** | `{headers.get('subject', '')}` |",
        f"| **Date** | `{headers.get('date', '')}` |",
        f"| **Reply-To** | `{headers.get('reply_to', '')}` |",
        f"| **Return-Path** | `{headers.get('return_path', '')}` |",
        f"| **Message-ID** | `{headers.get('message_id', '')}` |",
        f"",
        f"## 2. Authentication Verification",
        f"",
        f"| Protocol | Status |",
        f"|---|---|",
        f"| **SPF** | `{auth.get('spf', 'unknown')}` |",
        f"| **DKIM** | `{auth.get('dkim', 'unknown')}` |",
        f"| **DMARC** | `{auth.get('dmarc', 'unknown')}` |",
        f"",
        f"## 3. Discovered URLs",
        f"",
    ]

    if not urls:
        lines.append("_No URLs found in email body._\n")
    else:
        lines.extend([
            f"| URL | Source | Heuristic Suspicious | VirusTotal Status |",
            f"|---|---|---|---|",
        ])
        for u in urls:
            url_str = u.get("url", "")
            src = u.get("source", "")
            susp = "⚠️ Yes" if u.get("suspicious") else "Clean"
            vt_info = url_enrichment.get(url_str)
            if vt_info:
                st = vt_info.get("status")
                m_count = vt_info.get("malicious", 0)
                vt_repr = f"**{st}** ({m_count} flags)" if m_count > 0 else f"{st}"
            elif enrichment and enrichment.get("status") == "skipped_local_suspicious":
                vt_repr = "Skipped (Local suspicious)"
            else:
                vt_repr = "Not queried"
            lines.append(f"| `{url_str}` | `{src}` | {susp} | {vt_repr} |")
        lines.append("")

    lines.extend([
        f"## 4. Attachments (Never Executed)",
        f"",
    ])

    if not attachments:
        lines.append("_No attachments present._\n")
    else:
        lines.extend([
            f"| Filename | MIME Type | Size (Bytes) | SHA-256 | VirusTotal Status |",
            f"|---|---|---|---|---|",
        ])
        for att in attachments:
            fname = att.get("filename", "")
            mime_type = att.get("type", "")
            size = att.get("size", 0)
            sha = att.get("sha256", "")
            vt_info = file_enrichment.get(sha)
            if vt_info:
                st = vt_info.get("status")
                m_count = vt_info.get("malicious", 0)
                vt_repr = f"**{st}** ({m_count} flags)" if m_count > 0 else f"{st}"
            elif enrichment and enrichment.get("status") == "skipped_local_suspicious":
                vt_repr = "Skipped (Local suspicious)"
            else:
                vt_repr = "Not queried"
            lines.append(f"| `{fname}` | `{mime_type}` | {size} | `{sha[:16]}...` | {vt_repr} |")
        lines.append("")

    lines.extend([
        f"---",
        f"**Security Assurance:** Attachments are strictly hashed in memory and never executed on the host.",
    ])

    return "\n".join(lines)
