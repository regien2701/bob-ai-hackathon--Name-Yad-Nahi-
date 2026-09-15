# Threat Intelligence Correlation & Alert Prioritisation Assistant — Implementation Plan

## Top-Level Overview

**Goal:** Build a working student-level prototype for IBM Bob AI Hackathon 2026 (problem D2).

**Scope:** A Flask web application that ingests multi-source threat alerts (CSV/JSON upload),
normalises them into a common schema, scores and classifies each alert, correlates related
alerts into incidents, maps techniques to MITRE ATT&CK, identifies likely false positives,
and generates a BLUF investigation summary (via IBM watsonx.ai or a local fallback template)
for every high-priority incident. Results are shown on an HTML/JS dashboard.

**Approach:** Rule-based scoring engine (explainable, no black box), SQLite for persistence,
pandas for ingestion, Jinja2 templates for server-rendered pages, vanilla JS for interactive
components, ibm-watsonx-ai SDK for BLUF generation. All configuration via environment
variables; `.env.example` already exists in `src/`.

**Non-goals:**
- Live SIEM/threat-feed connectors (stubs only, real connectors can be added later).
- Machine-learning model training.
- User authentication / multi-tenancy.
- Production deployment hardening.

---

## A. System Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        Browser                           │
│  Dashboard (HTML/CSS/Vanilla JS)                         │
│  Pages: Upload · Alerts · Incidents · MITRE · Settings   │
└──────────────────┬───────────────────────────────────────┘
                   │  HTTP (REST + HTML forms)
┌──────────────────▼───────────────────────────────────────┐
│              Flask Application  (src/app/)               │
│                                                          │
│  routes/          – page & API route handlers            │
│  services/        – business logic layer                 │
│    ingest.py      – CSV/JSON normalisation               │
│    scoring.py     – threat scoring & classification      │
│    correlation.py – alert → incident grouping            │
│    mitre.py       – MITRE ATT&CK mapping                 │
│    bluf.py        – BLUF generation (watsonx / fallback) │
│    fp_detector.py – false-positive heuristics            │
│  models/          – SQLAlchemy ORM models                │
│  data/            – static MITRE stubs & sample data     │
└──────────────────┬───────────────────────────────────────┘
                   │  SQLAlchemy
┌──────────────────▼───────────────────────────────────────┐
│          SQLite  (src/instance/threats.db)               │
│  Tables: alerts · incidents · alert_incidents · feeds    │
└──────────────────────────────────────────────────────────┘
                   │  HTTP (optional)
┌──────────────────▼───────────────────────────────────────┐
│          IBM watsonx.ai  (granite / llama model)         │
│          Graceful fallback if API key not set            │
└──────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- Server-rendered Jinja2 pages keep JS minimal and the prototype easy to demo offline.
- A thin REST JSON API layer (`/api/v1/…`) is included so the front-end can refresh data
  dynamically and so a real SIEM connector can POST alerts without a browser.
- The scoring engine is a transparent weighted-sum formula — every score can be explained
  in the UI.
- watsonx.ai is called only for BLUF; the rest of the logic is purely local and explainable.

---

## B. Data Flow

```
[Upload CSV/JSON or API POST]
         │
         ▼
   ingest.py  ──► normalise to CommonAlert schema
         │
         ▼
   fp_detector.py ──► mark suspected false positives
         │
         ▼
   scoring.py ──► compute numeric risk score (0–100)
                  classify HIGH / MEDIUM / LOW
         │
         ▼
   mitre.py ──► assign MITRE ATT&CK technique IDs
         │
         ▼
   correlation.py ──► group alerts into Incidents
         │
         ▼
   SQLite ──► persist alerts + incidents
         │
         ▼
   bluf.py ──► for HIGH incidents: call watsonx (or fallback template)
                store BLUF text in incident record
         │
         ▼
   Flask routes ──► render dashboard pages / return JSON
```

---

## C. Recommended Folder Structure

```
src/
├── app/
│   ├── __init__.py           – app factory (create_app)
│   ├── config.py             – config classes (Dev / Prod)
│   ├── extensions.py         – db, migrate singletons
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py          – Alert ORM model
│   │   ├── incident.py       – Incident ORM model
│   │   └── feed.py           – Feed source registry
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dashboard.py      – HTML page routes
│   │   └── api.py            – /api/v1/* JSON routes
│   ├── services/
│   │   ├── ingest.py
│   │   ├── scoring.py
│   │   ├── correlation.py
│   │   ├── mitre.py
│   │   ├── bluf.py
│   │   └── fp_detector.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard/
│   │   │   ├── index.html       – summary dashboard
│   │   │   ├── alerts.html      – alert list & detail
│   │   │   ├── incidents.html   – incident list
│   │   │   ├── incident_detail.html
│   │   │   └── mitre_map.html   – MITRE technique coverage
│   │   └── upload.html
│   └── static/
│       ├── css/
│       │   └── main.css
│       └── js/
│           ├── dashboard.js
│           └── upload.js
├── data/
│   ├── sample_alerts.csv     – 30+ sample rows
│   ├── sample_alerts.json    – same data in JSON
│   └── mitre_techniques.json – curated subset of ATT&CK techniques
├── tests/
│   ├── test_ingest.py
│   ├── test_scoring.py
│   ├── test_correlation.py
│   ├── test_mitre.py
│   ├── test_bluf.py
│   └── test_api.py
├── run.py                    – entry point (python run.py)
├── requirements.txt
└── .env.example              – already exists; will be updated
```

---

## D. Database Schema

### Table: `alerts`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto-increment |
| `external_id` | TEXT | original alert ID from source |
| `source_feed` | TEXT | e.g. "splunk", "csv_upload", "sample" |
| `timestamp` | DATETIME | normalised UTC |
| `source_ip` | TEXT | attacker/src IP |
| `dest_ip` | TEXT | victim/dst IP |
| `event_type` | TEXT | normalised category |
| `severity_raw` | TEXT | original severity string |
| `description` | TEXT | raw description text |
| `risk_score` | REAL | 0–100 computed score |
| `priority` | TEXT | HIGH / MEDIUM / LOW |
| `is_false_positive` | BOOLEAN | FP flag |
| `fp_reason` | TEXT | human-readable FP reason |
| `mitre_technique_id` | TEXT | e.g. "T1059" |
| `mitre_technique_name` | TEXT | e.g. "Command and Scripting Interpreter" |
| `raw_data` | JSON | original record verbatim |
| `created_at` | DATETIME | insert time |

### Table: `incidents`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto-increment |
| `title` | TEXT | generated title |
| `priority` | TEXT | HIGH / MEDIUM / LOW |
| `risk_score` | REAL | max alert score in group |
| `alert_count` | INTEGER | number of constituent alerts |
| `mitre_techniques` | TEXT | comma-separated IDs |
| `bluf_summary` | TEXT | generated BLUF text |
| `bluf_source` | TEXT | "watsonx" or "template" |
| `status` | TEXT | open / investigating / closed |
| `created_at` | DATETIME | first alert time |
| `updated_at` | DATETIME | last modification |

### Table: `alert_incidents` (join)

| Column | Type |
|---|---|
| `alert_id` | INTEGER FK → alerts |
| `incident_id` | INTEGER FK → incidents |

### Table: `feeds`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | |
| `name` | TEXT | human name |
| `source_type` | TEXT | csv / json / api_stub |
| `last_ingested` | DATETIME | |
| `alert_count` | INTEGER | total ever ingested |

---

## E. Alert Data Format (Common Schema)

The normalised `CommonAlert` dict (produced by `ingest.py` before DB insert):

```python
{
  "external_id":       str,   # source's own ID or generated UUID
  "source_feed":       str,   # feed name
  "timestamp":         str,   # ISO-8601 UTC
  "source_ip":         str,   # "unknown" if missing
  "dest_ip":           str,   # "unknown" if missing
  "event_type":        str,   # normalised category (see below)
  "severity_raw":      str,   # original verbatim severity
  "description":       str,
  "raw_data":          dict   # full original record
}
```

**Accepted source formats (CSV/JSON):**
Fields are mapped to the common schema via configurable column-name aliases in `ingest.py`.
Any unknown field is preserved in `raw_data`.

**Normalised event_type vocabulary:**

| Canonical | Accepted aliases |
|---|---|
| `malware` | malware, virus, trojan, ransomware |
| `intrusion` | intrusion, breach, lateral_movement |
| `phishing` | phishing, spearphishing |
| `recon` | recon, scan, discovery |
| `c2` | c2, command_and_control, beacon |
| `exfiltration` | exfiltration, data_theft |
| `dos` | dos, ddos |
| `credential_access` | credential_access, brute_force, password |
| `other` | anything unrecognised |

---

## F. Threat Scoring Methodology

Risk score = **weighted sum of factor scores**, clamped to [0, 100].

| Factor | Max pts | Logic |
|---|---|---|
| Severity mapping | 30 | critical=30, high=22, medium=14, low=6, info=0 |
| Event type weight | 25 | c2=25, exfiltration=25, malware=20, intrusion=20, credential_access=18, phishing=15, recon=10, dos=8, other=5 |
| Destination sensitivity | 20 | dest in known critical subnet list → 20; dest is internal → 10; external → 0 |
| Recurrence bonus | 15 | same source_ip appeared ≥5 times in last 24 h → +15; ≥2 times → +8 |
| Description keywords | 10 | matches high-signal keyword list (e.g. "admin", "root", "lateral", "domain controller") → up to +10 |

**Classification thresholds (configurable in `config.py`):**

| Range | Label |
|---|---|
| 70–100 | HIGH |
| 40–69 | MEDIUM |
| 0–39 | LOW |

All factor scores and the threshold used are stored alongside the alert so the UI can
show a score breakdown tooltip — fully explainable.

---

## G. False-Positive Detection

`fp_detector.py` applies a sequence of deterministic heuristics. If any rule fires, the
alert is flagged `is_false_positive=True` and a human-readable `fp_reason` is recorded.

| Rule | Condition | Reason label |
|---|---|---|
| FP-1 Whitelisted source | source_ip in configurable IP allowlist | "Source IP is whitelisted" |
| FP-2 Whitelisted dest | dest_ip in configurable IP allowlist | "Destination IP is whitelisted" |
| FP-3 Info-only | severity_raw == "informational" AND event_type == "recon" | "Informational recon — noise" |
| FP-4 Scanner known | source_ip matches known vuln-scanner CIDR block | "Known internal scanner" |
| FP-5 Duplicate within window | identical (source_ip, dest_ip, event_type) within 60 s | "Duplicate within 60 s" |
| FP-6 Very low score | risk_score < 10 | "Risk score below minimum threshold" |

False positives are **not** deleted — they are excluded from incident correlation and
displayed separately in the UI so analysts can review the FP decisions.

---

## H. MITRE ATT&CK Mapping

`mitre.py` performs **keyword + event-type rule matching** against a curated local lookup
table (`data/mitre_techniques.json`).

The lookup table stores a subset of ATT&CK techniques with:
- `technique_id` (e.g. "T1059")
- `technique_name`
- `tactic` (e.g. "Execution")
- `keywords` — list of terms that trigger this technique

**Mapping algorithm:**
1. Concatenate `event_type`, `description` (lower-cased).
2. For each technique in the lookup, count matching keywords.
3. Assign the technique with the highest keyword overlap (ties broken by event_type match).
4. If no technique scores > 0, assign `T0000 / Unknown`.

The lookup table will cover the ~25 most commonly seen student-demo techniques across all
major tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense
Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, C2).

---

## I. BLUF Generation

`bluf.py` generates a 3–5 sentence bottom-line-up-front summary for each HIGH-priority
incident.

**watsonx.ai path (when `WATSONX_API_KEY` is set):**
- Model: `ibm/granite-13b-instruct-v2` (or configurable via `WATSONX_MODEL_ID`).
- A structured prompt is built from incident fields:
  - Alert count, top MITRE techniques, max risk score, source IPs, destination IPs,
    event types, and a selection of alert descriptions (truncated to fit context).
- The prompt instructs the model to write in BLUF military style:
  *"Bottom line: … Supporting facts: … Recommended action: …"*
- The response is stored verbatim in `incidents.bluf_summary` with
  `bluf_source = "watsonx"`.

**Template fallback (when API key is absent or call fails):**
- A deterministic Jinja2 string template fills in incident statistics.
- `bluf_source = "template"` is set so the UI can show a badge.
- Example output: *"HIGH priority incident comprising 7 correlated alerts. Primary
  technique: T1059 Command and Scripting Interpreter. Source IPs: 192.168.5.42.
  Recommended action: isolate affected hosts and escalate to Tier-2 analyst."*

Both paths produce identical fields in the DB — the rest of the app is agnostic to which
path was used.

---

## J. Dashboard Pages & Components

### Page 1 — Summary Dashboard (`/`)
- **KPI cards:** Total alerts ingested | HIGH incidents | Open incidents | FP rate %
- **Priority donut chart** (Chart.js — CDN, no build step)
- **Top 5 incidents table** sorted by risk score
- **Recent alerts feed** (last 10, auto-refreshed every 30 s via fetch)
- **MITRE tactic heatmap bar** — horizontal bar showing alert count per tactic

### Page 2 — Upload (`/upload`)
- Drag-and-drop file zone (CSV or JSON)
- "Load Sample Data" button (loads `data/sample_alerts.csv` without a file)
- Processing status bar and ingestion result summary

### Page 3 — Alerts (`/alerts`)
- Filterable/sortable table: all alerts
- Column filters: source feed, priority, event type, FP flag
- Row click → alert detail slide-over (shows raw data JSON, score breakdown, MITRE tag)

### Page 4 — Incidents (`/incidents`)
- Card grid of all incidents, colour-coded by priority
- Each card: title, risk score badge, alert count, MITRE techniques list, status badge
- Click → Incident Detail

### Page 5 — Incident Detail (`/incidents/<id>`)
- BLUF summary box (with "watsonx" or "template" badge)
- Score breakdown for the highest-scoring constituent alert
- Timeline of constituent alerts (sorted by timestamp)
- Each alert row is expandable to show full raw JSON
- "Re-generate BLUF" button (calls `/api/v1/incidents/<id>/bluf`)

### Page 6 — MITRE Coverage Map (`/mitre`)
- Table grouped by tactic → technique rows
- Each row shows how many alerts mapped to it, colour intensity by count
- Links back to filtered alert list

---

## K. API Endpoints

All JSON endpoints are under `/api/v1/`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/alerts/upload` | Upload CSV or JSON file, returns ingestion summary |
| POST | `/api/v1/alerts/sample` | Load built-in sample data |
| GET | `/api/v1/alerts` | List alerts (query params: priority, feed, fp, page, per_page) |
| GET | `/api/v1/alerts/<id>` | Single alert detail |
| GET | `/api/v1/incidents` | List incidents (query params: priority, status, page, per_page) |
| GET | `/api/v1/incidents/<id>` | Single incident detail with constituent alert IDs |
| POST | `/api/v1/incidents/<id>/bluf` | Re-generate BLUF for an incident |
| GET | `/api/v1/stats` | KPI counts for dashboard cards |
| GET | `/api/v1/mitre/coverage` | Technique hit counts for MITRE map |
| DELETE | `/api/v1/alerts/all` | Clear all data (demo reset) |

---

## L. Testing Strategy

Framework: **pytest** with **Flask test client**.

| Test file | What it covers |
|---|---|
| `test_ingest.py` | CSV normalisation, JSON normalisation, missing-field handling, type coercion |
| `test_scoring.py` | Score formula correctness, classification thresholds, edge cases (score=0, score=100) |
| `test_correlation.py` | Alert grouping logic, incident title generation, single-alert incident |
| `test_mitre.py` | Keyword matching, no-match fallback, top-technique selection |
| `test_bluf.py` | Template fallback produces expected structure; watsonx path is mocked |
| `test_api.py` | All API endpoints return correct HTTP status codes and JSON shapes |

Sample data in `src/data/` serves double duty as test fixtures.
No test should require a live watsonx API key — the watsonx client is mocked in
`test_bluf.py`.

---

## M. Step-by-Step Implementation Plan

### Sub-Task 1 — Project Scaffold & Environment
**Intent:** Create the folder skeleton, `requirements.txt`, Flask app factory, config, and
SQLite wiring so every subsequent sub-task has a runnable application shell.

**Expected outcomes:**
- `python run.py` starts Flask on port 5000 with no errors.
- `flask db init` / `flask db migrate` / `flask db upgrade` create `threats.db`.
- `.env.example` is updated with new variables (`FLASK_SECRET_KEY`, `WATSONX_MODEL_ID`,
  `SCORE_HIGH_THRESHOLD`, `SCORE_MEDIUM_THRESHOLD`).

**Todo list:**
- [ ] Create `src/requirements.txt` (flask, flask-sqlalchemy, flask-migrate, pandas,
      python-dotenv, ibm-watsonx-ai, pytest)
- [ ] Create `src/app/__init__.py` — `create_app()` factory
- [ ] Create `src/app/config.py` — `DevelopmentConfig` reading from env
- [ ] Create `src/app/extensions.py` — db + migrate singletons
- [ ] Create `src/app/models/alert.py`, `incident.py`, `feed.py`
- [ ] Create `src/run.py` entry point
- [ ] Update `src/.env.example` with new keys

**Relevant context:** `src/.env.example` already exists and has `WATSONX_*` keys.

**Status:** [x] done

---

### Sub-Task 2 — Sample Data & MITRE Lookup Table
**Intent:** Create realistic sample threat data and the MITRE technique lookup so every
later service has data to work with and tests have fixtures.

**Expected outcomes:**
- `src/data/sample_alerts.csv` contains ≥30 rows covering all event types and priority levels.
- `src/data/sample_alerts.json` contains the same data.
- `src/data/mitre_techniques.json` contains ≥25 technique entries with keyword lists.

**Todo list:**
- [ ] Create `src/data/sample_alerts.csv` with realistic (synthetic) columns
- [ ] Create `src/data/sample_alerts.json` (same data, JSON array)
- [ ] Create `src/data/mitre_techniques.json` with curated ATT&CK subset
- [ ] Add a `README` note in `src/data/` that data is **synthetic/simulated**

**Status:** [x] done

---

### Sub-Task 3 — Ingestion Service
**Intent:** Implement `ingest.py` to normalise CSV and JSON uploads into `CommonAlert` dicts
and persist them to the `alerts` table via the ORM.

**Expected outcomes:**
- CSV and JSON files with varied column names are mapped to the common schema.
- Unknown columns land in `raw_data`.
- `Feed` record is created/updated.
- `test_ingest.py` passes.

**Todo list:**
- [ ] Implement `IngestService.from_csv(filepath)` using pandas
- [ ] Implement `IngestService.from_json(filepath)`
- [ ] Implement column-alias mapping dict (covers Splunk, QRadar, generic export names)
- [ ] Implement `IngestService.save_alerts(common_alerts)` → Alert ORM objects
- [ ] Write `tests/test_ingest.py` with at least 5 test cases

**Status:** [x] done

---

### Sub-Task 4 — False-Positive Detection & Scoring Engine
**Intent:** Implement `fp_detector.py` and `scoring.py` to classify each alert.

**Expected outcomes:**
- Every ingested alert has a `risk_score`, `priority`, `is_false_positive`, and `fp_reason`.
- Score breakdown dict is stored so the UI can render an explanation.
- `test_scoring.py` passes all edge cases.

**Todo list:**
- [ ] Implement `FPDetector.check(alert)` → (is_fp: bool, reason: str)
- [ ] Implement whitelist loading from env / config
- [ ] Implement `ScoringEngine.score(alert)` → (score: float, breakdown: dict)
- [ ] Integrate both into ingestion pipeline
- [ ] Write `tests/test_scoring.py`

**Status:** [x] done

---

### Sub-Task 5 — MITRE ATT&CK Mapping
**Intent:** Implement `mitre.py` to assign a technique to each alert.

**Expected outcomes:**
- Every non-FP alert has `mitre_technique_id` and `mitre_technique_name`.
- The mapping is deterministic (same input → same output).
- `test_mitre.py` passes.

**Todo list:**
- [ ] Implement `MITREMapper.load_techniques()` from JSON file
- [ ] Implement `MITREMapper.map(alert)` → (technique_id, technique_name)
- [ ] Integrate into ingestion pipeline after scoring
- [ ] Write `tests/test_mitre.py`

**Status:** [x] done

---

### Sub-Task 6 — Alert Correlation Engine
**Intent:** Implement `correlation.py` to group related alerts into incidents.

**Correlation strategy (two-pass):**
1. **IP cluster:** alerts sharing the same `source_ip` within a configurable time window
   (default 2 h) are grouped.
2. **Technique cluster:** alerts sharing the same `mitre_technique_id` with no IP overlap
   and within the same time window are secondarily grouped.

**Expected outcomes:**
- `Incident` records are created/updated in the DB.
- `alert_incidents` join table is populated.
- Incident title is auto-generated (e.g. "Malware campaign from 10.0.1.5").
- Incident `risk_score` = max of constituent alert scores.
- `test_correlation.py` passes.

**Todo list:**
- [ ] Implement `CorrelationEngine.correlate(alerts)` → list of Incident objects
- [ ] Implement IP-cluster pass
- [ ] Implement technique-cluster pass
- [ ] Implement incident title generation
- [ ] Integrate into post-ingestion pipeline
- [ ] Write `tests/test_correlation.py`

**Status:** [x] done

---

### Sub-Task 7 — BLUF Generation Service
**Intent:** Implement `bluf.py` to produce a BLUF summary for each HIGH incident.

**Expected outcomes:**
- HIGH incidents have `bluf_summary` populated immediately after correlation.
- If watsonx API key is set, the watsonx Granite model is called.
- If not set or call fails, a deterministic template is used.
- `bluf_source` correctly reflects which path was taken.
- `test_bluf.py` passes with watsonx mocked.

**Todo list:**
- [ ] Implement `BLUFService.build_prompt(incident)` → str
- [ ] Implement `BLUFService.call_watsonx(prompt)` → str using ibm-watsonx-ai SDK
- [ ] Implement `BLUFService.template_fallback(incident)` → str
- [ ] Implement `BLUFService.generate(incident)` — tries watsonx, falls back to template
- [ ] Write `tests/test_bluf.py` (mock watsonx client)

**Status:** [x] done

---

### Sub-Task 8 — Flask Routes & REST API
**Intent:** Implement all HTML page routes and all `/api/v1/` JSON endpoints.

**Expected outcomes:**
- All 6 dashboard pages render without error.
- All API endpoints in Section K return correct status codes and JSON.
- File upload endpoint triggers the full pipeline (ingest → FP → score → MITRE → correlate → BLUF).
- `test_api.py` passes.

**Todo list:**
- [ ] Implement `routes/dashboard.py` — 6 page routes
- [ ] Implement `routes/api.py` — all `/api/v1/` endpoints
- [ ] Implement upload handling (Flask `request.files`, save to temp, call pipeline)
- [ ] Implement demo-reset endpoint (`DELETE /api/v1/alerts/all`)
- [ ] Write `tests/test_api.py`

**Status:** [x] done

---

### Sub-Task 9 — HTML Templates & CSS
**Intent:** Build the dashboard UI: `base.html`, all 6 page templates, and `main.css`.

**Expected outcomes:**
- All pages render correctly in browser.
- Priority labels use consistent colour coding (red=HIGH, amber=MEDIUM, green=LOW).
- Chart.js donut and bar charts render on the summary dashboard.
- Alert detail slide-over shows raw JSON and score breakdown.
- "Load Sample Data" button works.
- Application is usable on a standard laptop screen.

**Todo list:**
- [ ] Create `base.html` with nav, sidebar, and content slot
- [ ] Create `dashboard/index.html` — KPI cards + charts
- [ ] Create `upload.html` — file zone + sample-data button
- [ ] Create `dashboard/alerts.html` — filterable alert table
- [ ] Create `dashboard/incidents.html` — incident cards
- [ ] Create `dashboard/incident_detail.html` — BLUF + alert timeline
- [ ] Create `dashboard/mitre_map.html` — technique coverage table
- [ ] Create `static/css/main.css`
- [ ] Create `static/js/dashboard.js` (chart init + 30s refresh)
- [ ] Create `static/js/upload.js` (file drag-drop + progress)

**Status:** [x] done

---

### Sub-Task 10 — Documentation & Submission Metadata
**Intent:** Fill in all hackathon template files so the submission is complete.

**Expected outcomes:**
- `submission.yaml` is fully populated.
- `docs/architecture.md`, `docs/problem-statement.md`, `docs/solution-overview.md`,
  `docs/setup-guide.md` are all written.
- `README.md` is updated.

**Todo list:**
- [ ] Fill in `submission.yaml`
- [ ] Write `docs/problem-statement.md`
- [ ] Write `docs/solution-overview.md`
- [ ] Write `docs/architecture.md`
- [ ] Write `docs/setup-guide.md`
- [ ] Update root `README.md`

**Status:** [x] done

---

### Sub-Task 11 — End-to-End Smoke Test & Demo Polish
**Intent:** Run a full end-to-end pass with sample data, fix any integration bugs, and
ensure the demo flow works cleanly.

**Expected outcomes:**
- `pytest src/tests/` passes with no failures.
- Full demo flow: load sample data → view dashboard → open HIGH incident → read BLUF → inspect alerts.
- All known limitations are documented in `submission.yaml`.

**Todo list:**
- [ ] Run `pytest src/tests/` and fix failures
- [ ] Manual demo walkthrough — note and fix any UI/UX issues
- [ ] Verify template BLUF works without any API key
- [ ] Verify watsonx BLUF works when key is present (if available)
- [ ] Add screenshots to `demo/screenshots/`
- [ ] Update `demo/demo-video-link.txt` placeholder

**Status:** [x] done

---

## Configuration Variables (to add to `.env.example`)

```dotenv
# Flask
FLASK_SECRET_KEY=change-me-in-production
FLASK_ENV=development
APP_PORT=5000

# IBM watsonx.ai (optional — template fallback used if absent)
WATSONX_API_KEY=your_api_key_here
WATSONX_PROJECT_ID=your_project_id_here
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL_ID=ibm/granite-13b-instruct-v2

# Scoring thresholds (defaults shown)
SCORE_HIGH_THRESHOLD=70
SCORE_MEDIUM_THRESHOLD=40

# Correlation window in hours
CORRELATION_WINDOW_HOURS=2

# False-positive allowlist (comma-separated CIDRs or IPs)
FP_WHITELIST_IPS=127.0.0.1,10.0.0.1

# Internal scanner CIDR (alerts from these IPs are soft-flagged)
INTERNAL_SCANNER_CIDR=10.0.0.0/8
```
