#!/usr/bin/env python3
"""
CLI entry point for DetectLab Phishing Triage.

Usage:
  python triage.py samples/suspicious.eml
  python triage.py samples/suspicious.eml --json report.json
  python triage.py samples/suspicious.eml --md report.md
  python triage.py samples/suspicious.eml --no-vt
  python triage.py samples/suspicious.eml --vt --json report.json

Exit codes:
  0 = success
  1 = malformed input (safe failure)
  2 = file read error
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from parser import parse_email, ParseError
from verdict import make_verdict
from enrichment.cache import Cache
from enrichment.virustotal import VirusTotalClient
from report import to_json, to_markdown

# Configure stderr logger for safe diagnostic logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("triage")


def get_vt_api_key() -> str:
    # Support both VIRUSTOTAL_API_KEY and VIRUS_TOTAL_API_KEY
    return (os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VIRUS_TOTAL_API_KEY") or "").strip()


def run_enrichment(parsed: dict, api_key: str, cache_dir: str, timeout: int) -> dict:
    enrichment_result = {
        "status": "ok",
        "urls": {},
        "files": {},
    }

    if not api_key:
        enrichment_result["status"] = "disabled"
        return enrichment_result

    cache = Cache(cache_dir=cache_dir)
    vt_client = VirusTotalClient(api_key=api_key, timeout=timeout, cache=cache)

    rate_limited = False
    has_error = False

    # Look up all discovered URLs
    for u in parsed.get("urls", []):
        url_str = u.get("url")
        res = vt_client.lookup_url(url_str)
        enrichment_result["urls"][url_str] = res
        if res.get("error") == "rate_limited":
            rate_limited = True
        elif res.get("status") == "error":
            has_error = True

    # Look up all attachment hashes
    for att in parsed.get("attachments", []):
        sha256 = att.get("sha256")
        res = vt_client.lookup_file_hash(sha256)
        enrichment_result["files"][sha256] = res
        if res.get("error") == "rate_limited":
            rate_limited = True
        elif res.get("status") == "error":
            has_error = True

    if rate_limited:
        enrichment_result["status"] = "rate_limited"
    elif has_error:
        enrichment_result["status"] = "error"

    return enrichment_result


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="DetectLab Phishing Triage CLI — Safely analyze .eml files for phishing indicators."
    )
    parser.add_argument("eml", help="Path to .eml file to analyze")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to specified path")
    parser.add_argument("--md", dest="md_path", help="Write Markdown report to specified path")
    parser.add_argument("--vt", action="store_true", help="Force VirusTotal enrichment")
    parser.add_argument("--no-vt", action="store_true", help="Disable VirusTotal enrichment")
    parser.add_argument("--quiet", action="store_true", help="Only print verdict and reason codes")
    parser.add_argument("--verbose", action="store_true", help="Print full evidence and VT details")

    args = parser.parse_args()

    eml_path = Path(args.eml)
    if not eml_path.is_file():
        logger.error(f"File not found or unreadable: {eml_path}")
        return 2

    try:
        raw_bytes = eml_path.read_bytes()
    except Exception as exc:
        logger.error(f"Failed to read file {eml_path}: {exc}")
        return 2

    # Parse MIME email
    try:
        parsed = parse_email(raw_bytes)
    except ParseError as pe:
        logger.error(f"Parse error: {pe.code} - {pe}")
        print("Verdict: Inconclusive")
        print(f"Reason codes: {pe.code}")
        return 1
    except Exception as exc:
        logger.error(f"Unexpected parsing failure: {exc}")
        print("Verdict: Inconclusive")
        print("Reason codes: SAFE_PARSER_ERROR")
        return 1

    # VirusTotal enrichment determination - Local-First Architecture
    api_key = get_vt_api_key()
    vt_enabled_env = os.getenv("VT_ENABLED", "true").lower() in ("true", "1", "yes")

    # Local-first rule-based pre-evaluation
    local_verdict = make_verdict(parsed, {"status": "disabled", "urls": {}, "files": {}})
    local_is_suspicious = (local_verdict["verdict"] == "Suspicious")

    should_enrich = False
    enrichment_status = "disabled"

    if args.no_vt or not api_key or not vt_enabled_env:
        should_enrich = False
        enrichment_status = "disabled"
    elif args.vt:
        # Explicit request: force VirusTotal enrichment
        should_enrich = True
    elif local_is_suspicious:
        # Local-first: local rules already detected suspicious indicators; skip VirusTotal
        should_enrich = False
        enrichment_status = "skipped_local_suspicious"
        if args.verbose:
            logger.info("Local rules detected suspicious indicators. Skipping VirusTotal query.")
    else:
        # Local-first: local rules cannot detect suspicious indicators; send request to VirusTotal API
        should_enrich = True

    enrichment: dict | None = None
    if should_enrich:
        timeout = int(os.getenv("VT_TIMEOUT_SECONDS", "10"))
        cache_dir = os.getenv("VT_CACHE_DIR", ".vt_cache")
        enrichment = run_enrichment(parsed, api_key, cache_dir, timeout)
    else:
        enrichment = {"status": enrichment_status, "urls": {}, "files": {}}

    verdict_data = make_verdict(parsed, enrichment)

    # Output to stdout
    verdict = verdict_data["verdict"]
    score = verdict_data["score"]
    reason_codes_str = ", ".join(verdict_data["reason_codes"])

    print(f"Verdict: {verdict}")
    if not args.quiet:
        print(f"Score: {score}")
    print(f"Reason codes: {reason_codes_str}")

    if not args.quiet:
        print("\nHeaders:")
        h = parsed["headers"]
        print(f"  From: {h.get('from')}")
        if h.get('reply_to'):
            print(f"  Reply-To: {h.get('reply_to')}")
        if h.get('return_path'):
            print(f"  Return-Path: {h.get('return_path')}")
        print(f"  Subject: {h.get('subject')}")

        print("\nAuthentication:")
        a = parsed["auth"]
        print(f"  SPF: {a.get('spf')}")
        print(f"  DKIM: {a.get('dkim')}")
        print(f"  DMARC: {a.get('dmarc')}")

        if parsed["urls"]:
            print("\nURLs:")
            for u in parsed["urls"]:
                u_str = u["url"]
                susp = u["suspicious"]
                vt_info = enrichment.get("urls", {}).get(u_str) if enrichment else None
                vt_desc = ""
                if vt_info:
                    st = vt_info.get("status")
                    m = vt_info.get("malicious", 0)
                    total = m + vt_info.get("harmless", 0) + vt_info.get("suspicious", 0) + vt_info.get("undetected", 0)
                    vt_desc = f"  vt={st} ({m}/{total})" if total > 0 else f"  vt={st}"
                print(f"  {u_str}  suspicious={susp}{vt_desc}")

        if parsed["attachments"]:
            print("\nAttachments (not executed):")
            for att in parsed["attachments"]:
                fname = att["filename"]
                m_type = att["type"]
                sha = att["sha256"]
                vt_info = enrichment.get("files", {}).get(sha) if enrichment else None
                vt_desc = ""
                if vt_info:
                    st = vt_info.get("status")
                    m = vt_info.get("malicious", 0)
                    total = m + vt_info.get("harmless", 0) + vt_info.get("suspicious", 0) + vt_info.get("undetected", 0)
                    vt_desc = f"  vt={st} ({m}/{total})" if total > 0 else f"  vt={st}"
                print(f"  {fname}  type={m_type}  sha256={sha[:12]}...{vt_desc}")

    # Write reports if requested
    if args.json_path:
        json_content = to_json(parsed, verdict_data, enrichment, filename=eml_path.name)
        Path(args.json_path).write_text(json_content, encoding="utf-8")
        if args.verbose:
            print(f"\n[+] Saved JSON report to {args.json_path}")

    if args.md_path:
        md_content = to_markdown(parsed, verdict_data, enrichment, filename=eml_path.name)
        Path(args.md_path).write_text(md_content, encoding="utf-8")
        if args.verbose:
            print(f"\n[+] Saved Markdown report to {args.md_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
