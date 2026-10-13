"""
VirusTotal API v3 Client for DetectLab Phishing Triage.

Privacy rules:
- Only sends URLs and SHA-256 hashes to VirusTotal.
- Never uploads attachment bytes or .eml contents.
- Never sends email headers, body, or subject.
- Handles rate-limiting (429) with exponential backoff.
- On-disk TTL caching.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any
import requests

from enrichment.cache import Cache

logger = logging.getLogger(__name__)


def encode_url_id(url: str) -> str:
    """
    Encodes URL for VirusTotal v3 API:
    base64url-encoded URL without padding.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


class VirusTotalClient:
    def __init__(self, api_key: str, timeout: int = 10, cache: Cache | None = None):
        self.api_key = api_key.strip() if api_key else ""
        self.timeout = timeout
        self.cache = cache or Cache()
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "accept": "application/json",
        })

    def _request_with_retry(self, url: str) -> tuple[int, dict[str, Any] | None, str | None]:
        """
        Sends GET request with retry backoff on 429.
        Returns: (status_code, json_data, error_reason)
        """
        delays = [2, 4]
        for attempt in range(len(delays) + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 429:
                    if attempt < len(delays):
                        time.sleep(delays[attempt])
                        continue
                    return (429, None, "rate_limited")
                if resp.status_code == 200:
                    try:
                        return (200, resp.json(), None)
                    except Exception:
                        return (200, None, "invalid_json")
                if resp.status_code == 401:
                    return (401, None, "unauthorized")
                if resp.status_code == 404:
                    return (404, None, "not_found")
                return (resp.status_code, None, f"http_{resp.status_code}")
            except requests.Timeout:
                return (408, None, "timeout")
            except requests.RequestException as e:
                return (500, None, f"connection_error: {e}")

        return (429, None, "rate_limited")

    def _parse_analysis_stats(self, data: dict[str, Any] | None) -> dict[str, Any]:
        """
        Maps VT API v3 data block to standardized result format:
        {
          "status": "malicious|suspicious|harmless|undetected|unknown|error",
          "malicious": int,
          "suspicious": int,
          "harmless": int,
          "undetected": int,
          "permalink": str,
          "error": str | None
        }
        """
        attributes = data.get("data", {}).get("attributes", {}) if data else {}
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        permalink = attributes.get("permalink", "") or (
            f"https://www.virustotal.com/gui/url/{data.get('data', {}).get('id', '')}" if data else ""
        )

        if malicious > 0:
            status = "malicious"
        elif suspicious > 0:
            status = "suspicious"
        elif harmless > 0:
            status = "harmless"
        elif undetected > 0:
            status = "undetected"
        else:
            status = "unknown"

        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "permalink": permalink,
            "error": None,
        }

    def lookup_url(self, url: str) -> dict[str, Any]:
        """
        Queries VT API v3 for URL reputation. Caches results by URL SHA-256.
        """
        if not self.api_key:
            return {"status": "error", "error": "missing_api_key"}

        cached = self.cache.get("urls", url)
        if cached:
            return cached

        url_id = encode_url_id(url)
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        status_code, data, err = self._request_with_retry(endpoint)

        if status_code == 200 and data:
            res = self._parse_analysis_stats(data)
            self.cache.set("urls", url, res)
            return res
        elif status_code == 404:
            res = {
                "status": "unknown",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "permalink": "",
                "error": None,
            }
            self.cache.set("urls", url, res)
            return res
        else:
            return {
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "permalink": "",
                "error": err or "unknown_error",
            }

    def lookup_file_hash(self, sha256: str) -> dict[str, Any]:
        """
        Queries VT API v3 for attachment SHA-256 hash. Caches results.
        """
        if not self.api_key:
            return {"status": "error", "error": "missing_api_key"}

        cached = self.cache.get("files", sha256)
        if cached:
            return cached

        endpoint = f"https://www.virustotal.com/api/v3/files/{sha256}"
        status_code, data, err = self._request_with_retry(endpoint)

        if status_code == 200 and data:
            res = self._parse_analysis_stats(data)
            self.cache.set("files", sha256, res)
            return res
        elif status_code == 404:
            res = {
                "status": "unknown",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "permalink": "",
                "error": None,
            }
            self.cache.set("files", sha256, res)
            return res
        else:
            return {
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "permalink": "",
                "error": err or "unknown_error",
            }
