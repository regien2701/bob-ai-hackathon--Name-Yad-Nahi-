# Solution Overview

## What We Built

**ThreatIntel Correlator** is a lightweight Flask web application that automates the
most time-consuming parts of SOC alert triage. An analyst uploads a CSV or JSON file
exported from any security tool, or uses the built-in sample dataset, and within
seconds receives a prioritised, correlated view of every meaningful threat — with
MITRE ATT&CK technique tags, explainable risk scores, and AI-generated commander
briefings for the highest-priority incidents.

The application is entirely self-contained: it runs on a laptop with no cloud
account required, stores data in an embedded SQLite database, and falls back to a
deterministic template when the optional IBM watsonx.ai integration is not
configured.

## How It Works

Data moves through a six-stage pipeline triggered automatically on every upload:

1. **Ingest** — `ingest.py` reads the uploaded CSV or JSON, maps varied column names
   to a normalised `CommonAlert` schema using a configurable alias dictionary, and
   preserves all unknown fields in a `raw_data` JSON column. Any source format that
   exports `timestamp`, `source_ip`, `dest_ip`, `event_type`, and `severity` in any
   recognised column-name variant is accepted without configuration changes.

2. **False-Positive Detection** — `fp_detector.py` applies six deterministic
   heuristic rules to each alert (IP whitelist check, known scanner CIDR match,
   informational-recon filter, 60-second duplicate suppression, and minimum score
   threshold). Suspected false positives are flagged and excluded from correlation
   but retained in the database so analysts can review and dispute FP decisions.

3. **Risk Scoring** — `scoring.py` computes a weighted-sum risk score from 0 to 100
   across five factors: severity mapping (30 pts), event-type weight (25 pts),
   destination sensitivity (20 pts), source-IP recurrence bonus (15 pts), and
   description keyword match (10 pts). The score is stored alongside a full factor
   breakdown so every number shown in the UI can be explained at a glance.

4. **MITRE ATT&CK Mapping** — `mitre.py` matches each alert against a curated local
   lookup table of ~25 ATT&CK techniques using keyword overlap scoring. The best-
   matching technique ID and name are stored on the alert record and displayed in
   both the alert detail view and the MITRE coverage map page.

5. **Correlation** — `correlation.py` runs a two-pass grouping algorithm. In the
   first pass, alerts sharing the same `source_ip` within a configurable time window
   (default 2 hours) are grouped into an incident. In the second pass, remaining
   alerts sharing the same `mitre_technique_id` within the same window are
   secondarily grouped. Each incident receives an auto-generated title, a risk score
   equal to the maximum of its constituent alerts, and a status of `open`.

6. **BLUF Generation** — `bluf.py` generates a Bottom Line Up Front summary for
   every HIGH-priority incident. When `WATSONX_API_KEY` is set, the IBM Granite
   `ibm/granite-13b-instruct-v2` model is called with a structured prompt that
   includes alert count, top MITRE techniques, max risk score, and source/destination
   IPs. When the key is absent or the call fails, a deterministic Jinja2 string
   template produces a structurally identical summary. A `bluf_source` badge
   ("watsonx" or "template") is displayed next to the summary so analysts know which
   path was taken.

## Key Components

| Component | File | Responsibility |
|---|---|---|
| App factory | `app/__init__.py` | Creates the Flask app, registers blueprints, initialises DB |
| ORM models | `app/models/` | Alert, Incident, Feed SQLAlchemy models |
| Ingestion service | `app/services/ingest.py` | CSV/JSON normalisation via pandas |
| FP detector | `app/services/fp_detector.py` | Six-rule false-positive heuristics |
| Scoring engine | `app/services/scoring.py` | Weighted risk score + breakdown dict |
| MITRE mapper | `app/services/mitre.py` | Keyword-match ATT&CK assignment |
| Correlation engine | `app/services/correlation.py` | IP-cluster and technique-cluster grouping |
| BLUF service | `app/services/bluf.py` | watsonx.ai call + template fallback |
| Page routes | `app/routes/dashboard.py` | Six Jinja2-rendered HTML pages |
| API routes | `app/routes/api.py` | Ten REST JSON endpoints under `/api/v1/` |

## IBM Technologies Used

- **IBM watsonx.ai** — used via the `ibm-watsonx-ai` Python SDK to call the
  `ibm/granite-13b-instruct-v2` foundation model. A structured BLUF prompt is
  constructed from incident statistics and sent to the Granite model's text-
  generation endpoint. The response is stored verbatim as the incident's
  `bluf_summary` field with `bluf_source = "watsonx"`.

- **IBM Bob** — used throughout development as an AI coding assistant to design the
  architecture, write service implementations, generate test fixtures, and author
  this documentation set.

## Architecture Diagram

```
Browser (HTML/CSS/Vanilla JS)
  │  HTTP (REST + HTML forms)
  ▼
Flask Application  (src/app/)
  ├── routes/dashboard.py   ← 6 Jinja2 page routes
  ├── routes/api.py         ← /api/v1/* JSON endpoints
  └── services/
        ingest.py → fp_detector.py → scoring.py
        → mitre.py → correlation.py → bluf.py
  │  SQLAlchemy ORM
  ▼
SQLite  (src/instance/threats.db)
  tables: alerts · incidents · alert_incidents · feeds
  │  HTTP (optional — only when WATSONX_API_KEY is set)
  ▼
IBM watsonx.ai  (Granite model)
  graceful fallback if key absent
```

> For the full diagram with component descriptions and data-flow detail, see
> [`architecture.md`](architecture.md).

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Rule-based scoring engine instead of ML model | Fully explainable — every score component is stored and displayed. No training data needed. Judges can verify correctness by inspection. |
| Deterministic template fallback for BLUF | Ensures the prototype is 100 % demoable without a live API key. Structurally identical output to the watsonx path keeps the rest of the app agnostic. |
| Server-rendered Jinja2 pages | Keeps the frontend simple and the demo easy to run offline. No Node.js build step or bundler required. |
| Thin REST API layer alongside HTML routes | Allows the dashboard to refresh data without page reloads and provides a clean integration point for future SIEM connectors posting alerts via HTTP. |
| Pluggable alias mapping in ingest.py | Accepts exports from Splunk, QRadar, and generic CSV formats without schema changes — a key demo selling point. |
| SQLite for persistence | Zero-config database requires no separate server process. Easily swapped for PostgreSQL by changing `DATABASE_URL` in `.env`. |
