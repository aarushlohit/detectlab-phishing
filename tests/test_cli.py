"""
Unit and integration tests for CLI interface (triage.py).
"""

import subprocess
import sys
import json
from pathlib import Path


def test_cli_benign_sample_exits_zero():
    cmd = [sys.executable, "triage.py", "samples/benign.eml", "--no-vt"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "Verdict: Likely Benign" in proc.stdout


def test_cli_malformed_sample_exits_one():
    cmd = [sys.executable, "triage.py", "samples/malformed.eml"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "MALFORMED_INPUT" in proc.stdout


def test_cli_json_export(tmp_path):
    json_path = tmp_path / "out.json"
    cmd = [sys.executable, "triage.py", "samples/benign.eml", "--no-vt", "--json", str(json_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert json_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["verdict"] == "Likely Benign"
    assert "headers" in data


def test_cli_md_export(tmp_path):
    md_path = tmp_path / "out.md"
    cmd = [sys.executable, "triage.py", "samples/suspicious.eml", "--no-vt", "--md", str(md_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert md_path.exists()

    content = md_path.read_text(encoding="utf-8")
    assert "# DetectLab Phishing Triage Report" in content
    assert "Urgent_Invoice.pdf.exe" in content


def test_cli_no_vt_flag():
    cmd = [sys.executable, "triage.py", "samples/suspicious.eml", "--no-vt"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "VT_DISABLED" in proc.stdout or "Reason codes:" in proc.stdout
