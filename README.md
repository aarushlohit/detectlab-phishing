# DetectLab Phishing Triage

> A safe, explainable phishing triage and evidence extraction tool designed for isolated cybersecurity lab environments.

DetectLab analyzes synthetic and authorized `.eml` email files without executing payload binaries or rendering dangerous HTML components. It extracts cryptographic signatures, authentication results (SPF, DKIM, DMARC), embedded links, and attachment hashes, enriching them via VirusTotal API v3.

---

## Key Features

- **Zero Attachment Execution:** Attachments are decoded strictly in-memory to compute SHA-256 digests. Raw bytes are never written to disk or executed.
- **No HTML Email Rendering:** HTML parts are parsed as raw text strings to prevent cross-site scripting or remote tracking beacons.
- **Deep Authentication Verification:** Extracts and normalizes `Authentication-Results` for SPF, DKIM, and DMARC status.
- **Heuristic Threat Detection:**
  - Display name vs domain spoofing (e.g. `PayPal Support <evil@bad.test>`)
  - `From` vs `Reply-To` / `Return-Path` mismatches
  - IP-based URLs and credential harvesting path patterns
  - Suspicious or double file extensions (`.pdf.exe`)
- **VirusTotal API v3 Enrichment:**
  - Automated reputation lookups for detected URLs and attachment SHA-256 hashes
  - Disk-backed TTL cache (`.vt_cache`) to prevent rate-limit exhaustion
  - Exponential backoff retry on HTTP 429
  - Strict privacy rules: **only** URLs and SHA-256 hashes are sent — headers, subject lines, bodies, and attachment bytes are never transmitted
- **Dual Interface:**
  - **CLI (Primary MVP):** Flexible, scriptable tool with colored terminal output, exit codes, and JSON/Markdown export options.
  - **Modern Web UI:** Clean white & orange interface featuring landing page aesthetics, user authentication (local MySQL with SQLite fallback), file upload triage, and downloadable reports.

---

## Repository Structure

```text
detectlab-phishing/
├── triage.py                 # Primary CLI entry point
├── app.py                    # Flask Web UI entry point
├── parser.py                 # Core MIME parsing & evidence extraction
├── verdict.py                # Threat scoring and reason codes engine
├── report.py                 # JSON & Markdown report generators
├── db.py                     # Database abstraction (MySQL / SQLite)
├── enrichment/
│   ├── virustotal.py         # VirusTotal API v3 client
│   └── cache.py              # On-disk TTL cache
├── templates/
│   ├── base.html             # Base layout
│   ├── index.html            # Landing page & triage workspace
│   ├── result.html           # Detailed evidence & verdict view
│   ├── login.html            # Analyst authentication
│   └── register.html         # User sign-up
├── static/
│   └── style.css             # White & orange modern interface styling
├── samples/
│   ├── benign.eml            # Authentic headers & clean attachments
│   ├── suspicious.eml        # Multi-factor threat sample
│   ├── inconclusive.eml      # Minimal email without verifiable indicators
│   └── malformed.eml         # Corrupted/invalid MIME structure
├── tests/
│   ├── test_parser.py
│   ├── test_verdict.py
│   ├── test_virustotal.py
│   ├── test_cli.py
│   └── test_app.py
├── .env.example
├── requirements.txt
└── pytest.ini
```

---

## Installation & Setup

### 1. Clone the repository & create a virtual environment

```bash
git clone https://github.com/aarushlohit/detectlab-phishing.git
cd detectlab-phishing

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` to set your VirusTotal API key and database settings:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VT_TIMEOUT_SECONDS=10
VT_CACHE_DIR=.vt_cache
VT_CACHE_TTL_SECONDS=86400
VT_ENABLED=true

# Database (MySQL by default; automatically uses SQLite if MySQL is unavailable)
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=detectlab_phishing

SECRET_KEY=generate_a_secure_random_key_here
```

---

## CLI Usage (Primary Interface)

Analyze any `.eml` sample:

```bash
# Basic triage
python triage.py samples/suspicious.eml

# Skip VirusTotal enrichment
python triage.py samples/suspicious.eml --no-vt

# Force VirusTotal enrichment and export reports
python triage.py samples/suspicious.eml --vt --json report.json --md report.md

# Quiet output (only verdict and reason codes)
python triage.py samples/benign.eml --quiet
```

### CLI Exit Codes

- `0`: Triage completed successfully
- `1`: Malformed input or controlled parser failure (`MALFORMED_INPUT`)
- `2`: File read / path error

---

## Web UI Usage

Start the local server:

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

- **Landing page:** Features security assurances, architecture details, and file drag-and-drop workspace.
- **Authentication:** Sign in or register to persist triage audit history in MySQL.
- **Reports:** Download structured JSON or Markdown reports directly from the results dashboard.

---

## Verdict Scoring & Reason Codes

| Indicator | Score | Reason Code |
|---|---|---|
| SPF Fail | +2 | `AUTH_FAIL` |
| DKIM Fail | +2 | `AUTH_FAIL` |
| DMARC Fail | +2 | `AUTH_FAIL` |
| SPF / DKIM / DMARC Pass | 0 | `AUTH_PASS` |
| From vs Reply-To / Return-Path mismatch | +1 | `HEADER_MISMATCH` |
| Display name spoofing | +1 | `DISPLAY_NAME_SPOOF` |
| Suspicious URL (heuristic) | +1 each | `URL_SUSPICIOUS` |
| VirusTotal URL malicious | +3 each | `URL_VT_MALICIOUS` |
| VirusTotal URL suspicious | +2 each | `URL_VT_SUSPICIOUS` |
| VirusTotal attachment hash malicious | +4 each | `ATTACH_HASH_VT_MALICIOUS` |
| VirusTotal attachment hash suspicious | +2 each | `ATTACH_HASH_VT_SUSPICIOUS` |
| Dangerous attachment extension (`.exe`, `.scr`, etc.) | +1 | `ATTACH_DANGEROUS_EXT` |
| Double extension (`.pdf.exe`) | +1 | `ATTACH_DOUBLE_EXT` |
| Attachment presence notice | 0 | `ATTACH_NOT_EXECUTED` |

### Thresholds

- **Score &ge; 6:** `Suspicious`
- **Score 1–5:** `Inconclusive`
- **Score 0 with benign indicators:** `Likely Benign`
- **Score 0 without verifiable data:** `Inconclusive` (`NO_EVIDENCE`)

---

## Safety & Security Rules

1. **Attachments are NEVER executed:** All inspections compute digests directly from memory.
2. **HTML email bodies are NEVER rendered:** Clean plaintext previews only.
3. **Privacy first:** Only URLs and SHA-256 hashes are sent to VirusTotal. Email text, headers, and files never leave your system.
4. **Isolated environment:** The web server strictly binds to `127.0.0.1`.
5. **No hardcoded secrets:** Loaded strictly from `.env`.

---

## Running Automated Tests

Run the test suite using pytest:

```bash
pytest -q
```

All 27 test cases cover MIME parsing, hash verification, edge cases, VirusTotal mocking, caching, CLI arguments, and Flask endpoints.

---

## License

MIT License. Designed for authorized cybersecurity education and laboratory research.
