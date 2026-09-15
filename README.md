# ThreatIntel Correlator

> IBM Bob AI Hackathon 2026 — Problem D2: Threat Intelligence Correlation & Alert Prioritisation Assistant
> **Team: Name Yad Nahi**

---

## The Problem

Security Operations Centre analysts are overwhelmed by hundreds of noisy, uncorrelated
alerts every shift. Manual triage is slow and error-prone, genuine threats get buried
in false-positive noise, and security commanders have no fast way to get a plain-language
briefing on what is actually happening.

---

## The Solution

**ThreatIntel Correlator** is a Flask web application that ingests multi-source threat
alerts, scores and classifies each one with a transparent rule-based engine, correlates
related alerts into incidents, maps techniques to MITRE ATT&CK, and generates a BLUF
(Bottom Line Up Front) summary for every high-priority incident using IBM watsonx.ai.

---

## Key Features

- **Explainable risk scoring** — weighted-sum formula (0–100) with per-factor breakdown
  shown in the UI; no black box
- **Automated incident correlation** — groups related alerts by shared source IP and
  MITRE technique within a configurable time window
- **MITRE ATT&CK mapping** — keyword-match against curated technique table with tactic
  heatmap visualisation
- **IBM watsonx.ai BLUF generation** — Granite `ibm/granite-13b-instruct-v2` produces
  military-style commander briefings; deterministic template fallback when offline
- **False-positive detection** — six heuristic rules (IP whitelist, scanner CIDR,
  duplicate suppression, low-score filter) with a separate FP review queue

---

## Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python, HTML, CSS, JavaScript |
| **Frameworks** | Flask, SQLAlchemy, Flask-Migrate, pandas, Jinja2 |
| **IBM Technologies** | watsonx.ai, ibm-watsonx-ai Python SDK, IBM Bob |
| **Database** | SQLite |
| **Other** | Chart.js, pytest, python-dotenv |

---

## Quick Start

```bash
# 1. Clone and enter the repo
git clone https://github.com/ibm-hackathon/bob-ai-hackathon--Name-Yad-Nahi-.git
cd bob-ai-hackathon--Name-Yad-Nahi-/src

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum set FLASK_SECRET_KEY to any random string

# 5. Run the app
python run.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser, then click
**"Load Sample Data"** on the Upload page to populate the dashboard instantly.

> **No watsonx API key needed for the demo** — the app uses a local template fallback.
> See [docs/setup-guide.md](docs/setup-guide.md) for watsonx setup instructions.

---

## Repository Structure

```
├── src/                        # All source code
│   ├── app/
│   │   ├── models/             # SQLAlchemy ORM models
│   │   ├── routes/             # Flask page & API route handlers
│   │   ├── services/           # Business logic (ingest, score, correlate, BLUF)
│   │   ├── templates/          # Jinja2 HTML templates
│   │   └── static/             # CSS and JavaScript
│   ├── data/                   # Synthetic sample alerts + MITRE lookup table
│   ├── tests/                  # pytest test suite
│   ├── run.py                  # Entry point
│   ├── requirements.txt
│   └── .env.example
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/
│   ├── screenshots/
│   └── demo-video-link.txt
├── presentation/
└── submission.yaml
```

---

## Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## What We're Most Proud Of

The combination of the **watsonx.ai BLUF generation** and the **explainable scoring
engine**. Every risk score breaks down into five labelled factors in the UI, and every
HIGH-priority incident gets an IBM Granite-powered commander briefing that tells a
decision-maker exactly what happened, which MITRE techniques were used, and what action
to take — in under five sentences. The graceful template fallback means the demo works
end-to-end with zero cloud configuration.

---

## Known Limitations

- All alert data is synthetic; the app has not been tested against real SIEM exports
- Live SIEM connectors (Splunk, QRadar) are stubbed; only CSV/JSON upload is implemented
- No user authentication or multi-tenancy
- SQLite is not suitable for production-scale alert volumes
- Scoring thresholds and FP heuristics were tuned on the sample dataset only

---

## Running Tests

```bash
cd src
pytest tests/ -v
```

All tests run without a live watsonx API key.

---

## Team

| Field | Value |
|---|---|
| **Team Name** | Name Yad Nahi |
| **Track** | AI |
| **Hackathon** | IBM Bob AI Hackathon 2026 |
| **Problem** | D2 — Threat Intelligence Correlation & Alert Prioritisation |

---

## Full Documentation

- [Problem Statement](docs/problem-statement.md)
- [Solution Overview](docs/solution-overview.md)
- [Architecture](docs/architecture.md)
- [Setup Guide](docs/setup-guide.md)
