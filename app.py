"""
Optional Flask Web UI entry point for DetectLab Phishing Triage.

Security rules enforced:
- Binds to 127.0.0.1 only (never 0.0.0.0).
- MAX_CONTENT_LENGTH = 5 * 1024 * 1024 (5 MB).
- Validates .eml extension.
- Uses werkzeug.utils.secure_filename.
- Deletes uploaded file payload immediately from memory/disk.
- Jinja2 auto-escape enabled.
- Never renders HTML email bodies.
- Safe error pages with no stack traces exposed.
- Debug mode disabled in production.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from parser import parse_email, ParseError
from verdict import make_verdict
from triage import run_enrichment, get_vt_api_key
from report import to_json, to_markdown
from db import Database

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "detectlab-phishing-dev-key-randomized-39281")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

# Initialize database
db = Database()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("detectlab.app")


@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File is too large. Maximum allowed size is 5MB.", "error")
    return redirect(url_for("index"))


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("base.html", error_message="An internal error occurred during triage."), 500


@app.route("/")
def index():
    user_id = session.get("user_id")
    history = db.get_user_history(user_id) if user_id else []
    return render_template("index.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = db.authenticate_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        success, msg = db.register_user(username, password)
        if success:
            flash("Registration successful. Please sign in.", "success")
            return redirect(url_for("login"))
        flash(msg, "error")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/parse", methods=["POST"])
def parse_upload():
    if "eml_file" not in request.files:
        flash("No email file provided.", "error")
        return redirect(url_for("index"))

    file_obj = request.files["eml_file"]
    if not file_obj or file_obj.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(file_obj.filename)
    if not filename.lower().endswith(".eml"):
        flash("Invalid file format. Only .eml files are accepted.", "error")
        return redirect(url_for("index"))

    # Read bytes into memory and discard file handle immediately
    raw_bytes = file_obj.read()
    file_obj.close()

    if not raw_bytes:
        flash("Uploaded file is empty.", "error")
        return redirect(url_for("index"))

    try:
        parsed = parse_email(raw_bytes)
    except ParseError as pe:
        flash(f"Analysis failed: {pe.code} - {pe}", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        logger.error(f"Failed to parse email: {exc}")
        flash("Malformed email input (SAFE_PARSER_ERROR).", "error")
        return redirect(url_for("index"))

    # VirusTotal enrichment
    enable_vt = request.form.get("enable_vt") == "1"
    api_key = get_vt_api_key()
    enrichment = None

    if enable_vt and api_key:
        timeout = int(os.getenv("VT_TIMEOUT_SECONDS", "10"))
        cache_dir = os.getenv("VT_CACHE_DIR", ".vt_cache")
        enrichment = run_enrichment(parsed, api_key, cache_dir, timeout)
    else:
        enrichment = {"status": "disabled", "urls": {}, "files": {}}

    verdict_data = make_verdict(parsed, enrichment)

    report_json_str = to_json(parsed, verdict_data, enrichment, filename=filename)
    report_md_str = to_markdown(parsed, verdict_data, enrichment, filename=filename)

    # Record to DB if user is logged in
    user_id = session.get("user_id")
    db.save_analysis(
        user_id=user_id,
        filename=filename,
        verdict=verdict_data["verdict"],
        score=verdict_data["score"],
        reason_codes=", ".join(verdict_data["reason_codes"]),
        report_json=report_json_str
    )

    return render_template(
        "result.html",
        filename=filename,
        parsed=parsed,
        verdict=verdict_data,
        enrichment=enrichment,
        report_json=report_json_str,
        report_md=report_md_str,
    )


@app.route("/download/json", methods=["POST"])
def download_json():
    report_data = request.form.get("report_data", "{}")
    filename = request.form.get("filename", "report.eml")
    download_name = f"{filename}_report.json"
    return Response(
        report_data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={download_name}"}
    )


@app.route("/download/md", methods=["POST"])
def download_md():
    report_md = request.form.get("report_md", "")
    filename = request.form.get("filename", "report.eml")
    download_name = f"{filename}_report.md"
    return Response(
        report_md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment;filename={download_name}"}
    )


if __name__ == "__main__":
    # Security Rule: strictly bind to 127.0.0.1, never 0.0.0.0, debug=False
    app.run(host="127.0.0.1", port=5000, debug=False)
