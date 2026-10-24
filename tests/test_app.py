"""
Tests for Flask web application and authentication flow.
"""

import io
import pytest
from app import app, db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_landing_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"DetectLab" in response.data
    assert b"Automated Phishing Analysis" in response.data
    assert b"Launch Triage Chat" in response.data or b"Dashboard" in response.data


def test_user_registration_and_redirect_to_dashboard(client):
    import uuid
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "password123"

    # Register should redirect to dashboard
    reg_resp = client.post("/register", data={"username": username, "password": password}, follow_redirects=True)
    assert reg_resp.status_code == 200
    assert b"Welcome to DetectLab!" in reg_resp.data
    assert b"RFC 822 Email Forensics" in reg_resp.data or b"Triage" in reg_resp.data

    # Logout
    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"Sign in" in logout_resp.data

    # Login should redirect to dashboard
    login_resp = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
    assert login_resp.status_code == 200
    assert f"Welcome back, {username}!".encode() in login_resp.data


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Please sign in to access the triage dashboard." in response.data
    assert b"Welcome Back" in response.data


def test_api_triage_upload(client):
    with open("samples/benign.eml", "rb") as f:
        eml_bytes = f.read()

    data = {
        "eml_file": (io.BytesIO(eml_bytes), "benign.eml"),
        "enable_vt": "0"
    }

    response = client.post("/api/triage", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["verdict"]["verdict"] == "Likely Benign"
    assert "ATTACH_NOT_EXECUTED" in json_data["verdict"]["reason_codes"]


def test_api_triage_malformed_rejected(client):
    data = {
        "eml_file": (io.BytesIO(b"random text without headers"), "malformed.eml"),
        "enable_vt": "0"
    }
    response = client.post("/api/triage", data=data, content_type="multipart/form-data")
    assert response.status_code == 422
    json_data = response.get_json()
    assert json_data["success"] is False
    assert "MALFORMED_INPUT" in json_data["error"]


def test_sample_route_serves_eml(client):
    response = client.get("/samples/suspicious.eml")
    assert response.status_code == 200
    assert b"PayPal Support" in response.data


def test_api_triage_local_first_skips_vt_when_suspicious(client, monkeypatch):
    from unittest.mock import MagicMock
    import app as app_module

    mock_enrich = MagicMock()
    monkeypatch.setattr(app_module, "run_enrichment", mock_enrich)

    with open("samples/suspicious.eml", "rb") as f:
        eml_bytes = f.read()

    data = {
        "eml_file": (io.BytesIO(eml_bytes), "suspicious.eml"),
        "explicit_vt": "0"
    }

    response = client.post("/api/triage", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["verdict"]["verdict"] == "Suspicious"
    assert "VT_SKIPPED_LOCAL_FIRST" in json_data["verdict"]["reason_codes"]
    assert json_data["enrichment"]["status"] == "skipped_local_suspicious"
    # Verify VirusTotal enrichment was NOT called because local rules detected suspicious
    mock_enrich.assert_not_called()


def test_api_triage_local_first_calls_vt_when_not_suspicious(client, monkeypatch):
    from unittest.mock import MagicMock
    import app as app_module

    mock_enrich = MagicMock(return_value={"status": "ok", "urls": {}, "files": {}})
    monkeypatch.setattr(app_module, "run_enrichment", mock_enrich)

    with open("samples/inconclusive.eml", "rb") as f:
        eml_bytes = f.read()

    data = {
        "eml_file": (io.BytesIO(eml_bytes), "inconclusive.eml"),
        "explicit_vt": "0"
    }

    response = client.post("/api/triage", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    # Local rules could not detect suspicious, so VT was called
    mock_enrich.assert_called_once()


def test_api_triage_explicit_vt_calls_vt_even_when_suspicious(client, monkeypatch):
    from unittest.mock import MagicMock
    import app as app_module

    mock_enrich = MagicMock(return_value={"status": "ok", "urls": {}, "files": {}})
    monkeypatch.setattr(app_module, "run_enrichment", mock_enrich)

    with open("samples/suspicious.eml", "rb") as f:
        eml_bytes = f.read()

    # User explicitly checks the VirusTotal checkbox
    data = {
        "eml_file": (io.BytesIO(eml_bytes), "suspicious.eml"),
        "explicit_vt": "1"
    }

    response = client.post("/api/triage", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["verdict"]["verdict"] == "Suspicious"
    # Even though suspicious, explicit_vt forces VT lookup
    mock_enrich.assert_called_once()

