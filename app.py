"""
Flask Web UI entry point for DetectLab Phishing Triage.
Features interactive ChatGPT-style conversational triage canvas, sidebar history,
sample loading, user authentication, and on-the-fly report downloads.

Security guarantees:
- Binds strictly to 127.0.0.1.
- Never renders HTML bodies.
- Never executes attachments.
- Discards raw files immediately from memory.
- In-memory SHA-256 fingerprinting.
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
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    send_from_directory,
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

db = Database()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("detectlab.app")


@app.route("/")
@app.route("/workbench")
def index():
    user_id = session.get("user_id")
    history = db.get_user_history(user_id) if user_id else []
    return render_template("chat.html", history=history)

def workbench():
    return index()

@app.route("/landing")
def landing():
    user_id = session.get("user_id")
    history = db.get_user_history(user_id) if user_id else []
    return render_template("index.html", history=history)


@app.route("/samples/<filename>")
def serve_sample(filename):
    """Safely serves lab sample files for quick in-browser triage testing."""
    filename = secure_filename(filename)
    samples_dir = Path("samples")
    if (samples_dir / filename).is_file():
        return send_from_directory("samples", filename, as_attachment=False, mimetype="message/rfc822")
    return jsonify({"error": "Sample not found"}), 404


@app.route("/api/triage", methods=["POST"])
def api_triage():
    """Asynchronous endpoint used by the ChatGPT chat interface for live triage."""
    if "eml_file" not in request.files:
        return jsonify({"success": False, "error": "No email file provided."}), 400

    file_obj = request.files["eml_file"]
    if not file_obj or file_obj.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400

    filename = secure_filename(file_obj.filename)
    if not filename.lower().endswith(".eml"):
        return jsonify({"success": False, "error": "Invalid file format. Only .eml files are accepted."}), 400

    raw_bytes = file_obj.read()
    file_obj.close()

    if not raw_bytes:
        return jsonify({"success": False, "error": "Uploaded file is empty."}), 400

    try:
        parsed = parse_email(raw_bytes)
    except ParseError as pe:
        return jsonify({"success": False, "error": f"{pe.code}: {pe}"}), 422
    except Exception as exc:
        logger.error(f"Failed to parse email: {exc}")
        return jsonify({"success": False, "error": "SAFE_PARSER_ERROR: Malformed input"}), 422

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

    user_id = session.get("user_id")
    history_id = None
    try:
        db.save_analysis(
            user_id=user_id,
            filename=filename,
            verdict=verdict_data["verdict"],
            score=verdict_data["score"],
            reason_codes=", ".join(verdict_data["reason_codes"]),
            report_json=report_json_str
        )
    except Exception as e:
        logger.warning(f"Could not persist triage history: {e}")

    return jsonify({
        "success": True,
        "filename": filename,
        "parsed": parsed,
        "verdict": verdict_data,
        "enrichment": enrichment,
        "report_json": report_json_str,
        "report_md": report_md_str,
        "history_id": history_id,
    })


@app.route("/api/history/<int:history_id>")
def api_get_history(history_id: int):
    """Retrieves cached JSON report from history."""
    try:
        if db.engine_type == "mysql":
            conn = db._get_mysql_connection()
            with conn.cursor() as cur:
                cur.execute("SELECT filename, report_json FROM triage_history WHERE id = %s", (history_id,))
                row = cur.fetchone()
            conn.close()
        else:
            import sqlite3
            conn = sqlite3.connect(str(db.sqlite_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT filename, report_json FROM triage_history WHERE id = ?", (history_id,))
            row = cur.fetchone()
            conn.close()

        if row and row["report_json"]:
            data = json.loads(row["report_json"])
            # Format back to match api_triage response
            parsed = {
                "headers": data.get("headers", {}),
                "auth": data.get("auth", {}),
                "urls": data.get("urls", []),
                "attachments": data.get("attachments", []),
                "body_text": "",
            }
            verdict = {
                "verdict": data.get("verdict"),
                "score": data.get("score"),
                "reason_codes": data.get("reason_codes", []),
            }
            enrichment = {"urls": {}, "files": {}}
            for u in data.get("urls", []):
                if "vt" in u:
                    enrichment["urls"][u["url"]] = u["vt"]
            for a in data.get("attachments", []):
                if "vt" in a:
                    enrichment["files"][a["sha256"]] = a["vt"]

            report_md_str = to_markdown(parsed, verdict, enrichment, filename=row["filename"])

            return jsonify({
                "success": True,
                "filename": row["filename"],
                "parsed": parsed,
                "verdict": verdict,
                "enrichment": enrichment,
                "report_json": row["report_json"],
                "report_md": report_md_str,
            })
    except Exception as exc:
        logger.error(f"Error fetching history item {history_id}: {exc}")
    return jsonify({"success": False, "error": "History item not found"}), 404


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
            user = db.authenticate_user(username, password)
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
            flash("Welcome to DetectLab! Account created.", "success")
            return redirect(url_for("workbench"))
        flash(msg, "error")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


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


@app.route("/parse", methods=["POST"])
def parse_upload():
    """Form upload compatibility route."""
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

    raw_bytes = file_obj.read()
    file_obj.close()

    try:
        parsed = parse_email(raw_bytes)
    except ParseError as pe:
        flash(f"Analysis failed: {pe.code} - {pe}", "error")
        return redirect(url_for("index"))

    verdict_data = make_verdict(parsed, {"status": "disabled", "urls": {}, "files": {}})
    report_json_str = to_json(parsed, verdict_data, None, filename=filename)
    report_md_str = to_markdown(parsed, verdict_data, None, filename=filename)

    return render_template(
        "result.html",
        filename=filename,
        parsed=parsed,
        verdict=verdict_data,
        enrichment={"urls": {}, "files": {}},
        report_json=report_json_str,
        report_md=report_md_str,
    )
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

