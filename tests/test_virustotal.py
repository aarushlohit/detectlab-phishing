"""
Unit tests for VirusTotal v3 client and caching.
"""

from unittest.mock import patch, MagicMock
import requests
from enrichment.virustotal import VirusTotalClient, encode_url_id
from enrichment.cache import Cache


def test_encode_url_id_base64url_no_padding():
    # Standard URL
    url = "https://example.com/test"
    encoded = encode_url_id(url)
    assert "=" not in encoded
    assert "/" not in encoded
    assert "+" not in encoded


def test_graceful_handling_when_api_key_missing():
    client = VirusTotalClient(api_key="")
    res_url = client.lookup_url("https://example.com")
    assert res_url["status"] == "error"
    assert res_url["error"] == "missing_api_key"

    res_file = client.lookup_file_hash("abc123")
    assert res_file["status"] == "error"
    assert res_file["error"] == "missing_api_key"


@patch("requests.Session.get")
def test_mock_200_response(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "id": "test_id",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 20,
                    "undetected": 10,
                },
                "permalink": "https://virustotal.com/gui/url/test_id"
            }
        }
    }
    mock_get.return_value = mock_resp

    cache = Cache(cache_dir=str(tmp_path / "cache"))
    client = VirusTotalClient(api_key="mock_key", cache=cache)

    res = client.lookup_url("http://example.com")
    assert res["status"] == "malicious"
    assert res["malicious"] == 5
    assert res["permalink"] == "https://virustotal.com/gui/url/test_id"


@patch("requests.Session.get")
def test_mock_404_response(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    cache = Cache(cache_dir=str(tmp_path / "cache"))
    client = VirusTotalClient(api_key="mock_key", cache=cache)

    res = client.lookup_url("http://new-domain-never-seen.test")
    assert res["status"] == "unknown"
    assert res["error"] is None


@patch("requests.Session.get")
def test_mock_401_unauthorized(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    cache = Cache(cache_dir=str(tmp_path / "cache"))
    client = VirusTotalClient(api_key="mock_key", cache=cache)

    res = client.lookup_url("http://example.com")
    assert res["status"] == "error"
    assert res["error"] == "unauthorized"


@patch("requests.Session.get")
def test_mock_timeout_handling(mock_get, tmp_path):
    mock_get.side_effect = requests.Timeout("Connection timed out")

    cache = Cache(cache_dir=str(tmp_path / "cache"))
    client = VirusTotalClient(api_key="mock_key", cache=cache)

    res = client.lookup_url("http://slow.example.com")
    assert res["status"] == "error"
    assert res["error"] == "timeout"


@patch("requests.Session.get")
def test_caching_behavior(mock_get, tmp_path):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "harmless": 50}
            }
        }
    }
    mock_get.return_value = mock_resp

    cache = Cache(cache_dir=str(tmp_path / "cache"))
    client = VirusTotalClient(api_key="mock_key", cache=cache)

    # First call: makes network request
    res1 = client.lookup_url("http://cache-test.test")
    assert res1["status"] == "harmless"
    assert mock_get.call_count == 1

    # Second call: served from disk cache
    res2 = client.lookup_url("http://cache-test.test")
    assert res2["status"] == "harmless"
    assert mock_get.call_count == 1
