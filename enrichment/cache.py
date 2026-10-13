"""
On-disk TTL cache for VirusTotal lookups.
Keyed by SHA-256 of the target lookup key (URL or file hash).
Stores entries as JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, cache_dir: str = ".vt_cache", ttl_seconds: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, namespace: str, key: str) -> Path:
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        ns_dir = self.cache_dir / namespace
        ns_dir.mkdir(parents=True, exist_ok=True)
        return ns_dir / f"{key_hash}.json"

    def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        path = self._get_path(namespace, key)
        if not path.is_file():
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cached_at = data.get("_cached_at", 0)
            if time.time() - cached_at > self.ttl_seconds:
                # Expired
                try:
                    path.unlink()
                except OSError:
                    pass
                return None
            return data.get("payload")
        except Exception:
            return None

    def set(self, namespace: str, key: str, value: dict[str, Any]) -> None:
        path = self._get_path(namespace, key)
        record = {
            "_cached_at": time.time(),
            "_key": key,
            "payload": value,
        }
        try:
            tmp_path = path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(record, f)
            tmp_path.replace(path)
        except Exception:
            pass
