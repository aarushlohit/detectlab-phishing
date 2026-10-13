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
    assert b"Automated Phishing Analysis" in response.data


def test_user_registration_and_login(client):
    username = "testanalyst"
    password = "password123"

    # Register
    reg_resp = client.post("/register", data={"username": username, "password": password}, follow_redirects=True)
    assert reg_resp.status_code == 200

    # Login
    login_resp = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
    assert login_resp.status_code == 200
    assert b"Welcome back, testanalyst" in login_resp.data

    # Logout
    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"Sign in" in logout_resp.data


def test_file_upload_parsing(client):
    with open("samples/benign.eml", "rb") as f:
        eml_bytes = f.read()

    data = {
        "eml_file": (io.BytesIO(eml_bytes), "benign.eml"),
        "enable_vt": "0"
    }

    response = client.post("/parse", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"Likely Benign" in response.data
    assert b"ATTACH_NOT_EXECUTED" in response.data


def test_upload_invalid_extension_rejected(client):
    data = {
        "eml_file": (io.BytesIO(b"random content"), "sample.txt"),
    }
    response = client.post("/parse", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Only .eml files are accepted" in response.data
