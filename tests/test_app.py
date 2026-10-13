"""
Tests for Flask web application and authentication.
"""

import io
import pytest
from app import app, db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"DetectLab" in response.data
    assert b"What email would you like to inspect?" in response.data


def test_user_registration_and_login(client):
    username = "testanalyst2"
    password = "password123"

    # Register
    reg_resp = client.post("/register", data={"username": username, "password": password}, follow_redirects=True)
    assert reg_resp.status_code == 200

    # Login
    login_resp = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
    assert login_resp.status_code == 200
    assert b"testanalyst2" in login_resp.data

    # Logout
    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"Sign in" in logout_resp.data


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
