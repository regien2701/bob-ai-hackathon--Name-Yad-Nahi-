# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- [ ] **Python 3.10 or higher** — check with `python --version` or `python3 --version`
- [ ] **pip** — bundled with Python 3.4+; check with `pip --version`
- [ ] **git** — check with `git --version`

No Docker, Node.js, or cloud account is required to run the application. IBM
watsonx.ai is **optional** — the app works fully offline using a template fallback
for BLUF generation.

---

## 1 — Clone the Repository

```bash
git clone https://github.com/ibm-hackathon/bob-ai-hackathon--Name-Yad-Nahi-.git
cd bob-ai-hackathon--Name-Yad-Nahi-
```

---

## 2 — Navigate to the Source Directory

All runnable code lives under `src/`:

```bash
cd src
```

---

## 3 — Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it:

**macOS / Linux:**
```bash
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
.venv\Scripts\activate.bat
```

Your prompt should now show `(.venv)` as a prefix.

---

## 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs Flask, SQLAlchemy, pandas, ibm-watsonx-ai, pytest, and all other
required packages. Expect the install to take 1–2 minutes on first run.

---

## 5 — Configure Environment Variables

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

Open `.env` in any text editor. The minimum required change is setting a Flask
secret key:

```dotenv
FLASK_SECRET_KEY=any-random-string-you-choose
```

All other values have sensible defaults and can be left as-is for a basic demo.

### Environment Variable Reference

| Variable | Description | Required |
|---|---|---|
| `FLASK_SECRET_KEY` | Secret key for Flask session signing | **Yes** — change from default |
| `FLASK_ENV` | `development` or `production` | No — defaults to `development` |
| `APP_PORT` | Port to listen on | No — defaults to `5000` |
| `WATSONX_API_KEY` | IBM watsonx.ai API key | No — template fallback used if absent |
| `WATSONX_PROJECT_ID` | watsonx.ai project ID | No — required only with API key |
| `WATSONX_URL` | watsonx.ai endpoint URL | No — defaults to `us-south.ml.cloud.ibm.com` |
| `WATSONX_MODEL_ID` | Granite model ID | No — defaults to `ibm/granite-13b-instruct-v2` |
| `SCORE_HIGH_THRESHOLD` | Risk score threshold for HIGH priority | No — defaults to `70` |
| `SCORE_MEDIUM_THRESHOLD` | Risk score threshold for MEDIUM priority | No — defaults to `40` |
| `CORRELATION_WINDOW_HOURS` | Hours within which alerts are correlated | No — defaults to `2` |
| `FP_WHITELIST_IPS` | Comma-separated IPs/CIDRs exempt from alerts | No |
| `INTERNAL_SCANNER_CIDR` | CIDR block for known internal scanners | No |

---

## 6 — Run the Application

```bash
python run.py
```

You should see output similar to:

```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

The database (`instance/threats.db`) is created automatically on first start.

---

## 7 — Open the Dashboard

Open your browser and navigate to:

```
http://localhost:5000
```

You will see the Summary Dashboard with all KPI cards at zero — no data has been
loaded yet.

---

## 8 — Quick Demo: Load Sample Data

**Option A — Browser button:**

1. Click **"Upload"** in the left sidebar (or navigate to `http://localhost:5000/upload`).
2. Click the **"Load Sample Data"** button.
3. The app will ingest 30+ synthetic threat alerts, score them, correlate them into
   incidents, and generate BLUF summaries using the template fallback.
4. Return to the Summary Dashboard to see the KPI cards, priority donut chart, and
   incident list populated with data.

**Option B — API call:**

```bash
curl -X POST http://localhost:5000/api/v1/alerts/sample
```

The response JSON will show how many alerts were ingested and how many incidents
were created.

---

## 9 — Optional: Enable IBM watsonx.ai BLUF Generation

To use the IBM Granite model for BLUF generation instead of the built-in template:

### 9.1 — Get your IBM Cloud API key

1. Log in to [https://cloud.ibm.com](https://cloud.ibm.com).
2. Go to **Manage → Access (IAM) → API keys**.
3. Click **Create an IBM Cloud API key** and copy the key value.

### 9.2 — Get your watsonx.ai Project ID

1. Go to [https://dataplatform.cloud.ibm.com](https://dataplatform.cloud.ibm.com).
2. Open or create a project.
3. Go to **Manage → General** and copy the **Project ID**.

### 9.3 — Update `.env`

```dotenv
WATSONX_API_KEY=your-actual-api-key
WATSONX_PROJECT_ID=your-actual-project-id
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL_ID=ibm/granite-13b-instruct-v2
```

Restart `python run.py`. The next time a HIGH-priority incident is created, the
`bluf_source` badge on the Incident Detail page will show **"watsonx"** instead of
**"template"**.

---

## 10 — Running Tests

From the `src/` directory (with the virtual environment active):

```bash
pytest tests/ -v
```

All tests run without a live watsonx API key — the watsonx client is mocked in
`tests/test_bluf.py`. You should see output ending in something like:

```
====== 30 passed in 4.21s ======
```

To run a specific test file:

```bash
pytest tests/test_scoring.py -v
pytest tests/test_api.py -v
```

---

## 11 — Resetting Demo Data

To clear all ingested alerts and incidents and start fresh:

**Option A — Browser button:**

Click **"Reset Data"** in the sidebar settings panel.

**Option B — API call:**

```bash
curl -X DELETE http://localhost:5000/api/v1/alerts/all
```

The database tables are truncated but the schema is preserved. You can immediately
load sample data again.

---

## 12 — Troubleshooting

| Issue | Likely Cause | Solution |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | Virtual environment not active or `pip install` not run | Activate `.venv` and run `pip install -r requirements.txt` |
| `sqlalchemy.exc.OperationalError: no such table: alerts` | Database not initialised | This should not happen — `run.py` calls `db.create_all()` automatically. Delete `instance/threats.db` and restart. |
| `Address already in use` on port 5000 | Another process is using port 5000 | Set `APP_PORT=5001` in `.env`, or stop the conflicting process |
| `401 Unauthorized` from watsonx.ai | Invalid or expired API key | Check `WATSONX_API_KEY` in `.env`; generate a new key in IBM Cloud IAM |
| `403 Forbidden` from watsonx.ai | Wrong project ID or model not enabled | Check `WATSONX_PROJECT_ID`; ensure Granite is enabled in your watsonx project |
| BLUF shows "template" badge even with API key set | watsonx call failed silently | Check the Flask console for error lines starting with `[BLUF]`; verify the key and project ID |
| CSV upload returns 400 error | Missing required columns | Ensure your CSV has at least `source_ip`, `dest_ip`, `event_type`, and `severity` columns (any recognised alias names accepted) |
| Charts not rendering | Browser JS error | Open DevTools console; ensure Chart.js CDN is reachable or use the sample data button which uses no external assets |
