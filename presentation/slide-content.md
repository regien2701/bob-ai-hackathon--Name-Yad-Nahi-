# Slide Content — ThreatIntel Correlator

> **Format:** 10–12 slides, 5–8 minutes presentation  
> Convert this to `slides.pdf` or `slides.pptx` and save as `presentation/slides.pdf`

---

## Slide 1 — Title

**ThreatIntel Correlator**

> Automated Threat Alert Correlation & AI-Powered Prioritisation for SOC Analysts

- Team: **Name Yad Nahi**
- Track: **AI**
- Challenge: **D2 — Threat Intelligence Correlation & Alert Prioritisation**
- Hackathon: **IBM Bob AI Innovation Hackathon 2026**

---

## Slide 2 — The Problem

**SOC Analysts Face Alert Overload**

- Hundreds of raw security alerts per shift
- Majority are noise: false positives, duplicates, low-signal events
- Manual triage is slow and error-prone
- Real threats get buried — attackers move faster than analysts

> *"Mean time to detect (MTTD) is measured in hours. Attackers measure dwell time in minutes."*

**Who has this problem:**
SOC analysts, security commanders, and incident responders at any organisation with a SIEM.

---

## Slide 3 — Our Solution

**ThreatIntel Correlator**

A Flask web application that automates the most time-consuming parts of SOC triage:

1. Ingest alerts from any CSV or JSON export
2. Detect and filter false positives automatically
3. Score every alert with a transparent, explainable formula
4. Group related alerts into incidents
5. Map each technique to MITRE ATT&CK
6. Generate a commander-ready BLUF briefing via IBM watsonx.ai

**Result:** From hundreds of raw alerts to a handful of prioritised, explained incidents — in seconds.

---

## Slide 4 — Architecture

```
CSV / JSON Upload
       │
       ▼
   Ingest Service (pandas normalisation)
       │
       ▼
   FP Detector (6 heuristic rules)
       │
       ▼
   Scoring Engine (weighted sum, 0–100)
       │
       ▼
   MITRE Mapper (keyword ATT&CK match)
       │
       ▼
   Correlation Engine (IP cluster + technique cluster)
       │
       ▼
   BLUF Service ──► IBM watsonx.ai (Granite)
       │                  or template fallback
       ▼
   SQLite (SQLAlchemy ORM)
       │
       ▼
   Flask Dashboard (6 pages + REST API)
```

**Single-process Flask app. Zero cloud dependencies for the demo.**

---

## Slide 5 — Alert Correlation

**From 50 alerts → 5 incidents**

Two-pass grouping algorithm:
- **Pass 1:** Group alerts with the same `source_ip` within a configurable time window (default: 2 hours)
- **Pass 2:** Group remaining alerts sharing the same MITRE technique ID within the same window

Each incident automatically receives:
- Auto-generated title
- Risk score = max of its constituent alerts
- Status: `open`
- MITRE technique list (comma-separated)

**Why this matters:** An attacker running lateral movement generates dozens of individual alerts — correlated, they become one HIGH-priority incident.

---

## Slide 6 — Risk Prioritisation

**Transparent weighted-sum scoring (0–100)**

| Factor | Max Points | Description |
|---|---|---|
| Severity | 30 | critical=30, high=22, medium=14, low=6 |
| Event type | 25 | c2/exfil=25, malware=20, phishing=15 |
| Destination sensitivity | 20 | Critical internal subnet = 20 |
| Source recurrence | 15 | Same IP seen 5+ times = 15 |
| Description keywords | 10 | admin, lsass, mimikatz, ransomware… |

**Every score is stored with its full breakdown** and displayed in the UI as an expandable tooltip.

No black box — analysts and judges can verify every number by inspection.

---

## Slide 7 — False Positive Detection

**Six deterministic rules, evaluated in order:**

| Rule | Trigger |
|---|---|
| FP-1 | Source IP on configured whitelist |
| FP-2 | Destination IP on configured whitelist |
| FP-3 | Informational severity + recon event type |
| FP-4 | Source IP inside known internal scanner CIDR |
| FP-5 | Identical alert within 60-second duplicate window |
| FP-6 | Risk score below minimum threshold (< 10) |

False-positive alerts are **flagged but retained** in the database.
Analysts can review and dispute FP decisions in the FP Review Queue.

---

## Slide 8 — MITRE ATT&CK Mapping

**Automatic technique assignment via keyword matching**

- Local lookup table of ~25 ATT&CK techniques
- For each alert: concatenate `event_type` + `description`, score keyword overlap
- Best-matching technique ID and name stored on the alert record
- Unmatched alerts receive `T0000 / Unknown`

**MITRE Map page** shows a tactic heatmap:
- Which tactics are active (Initial Access, C2, Exfiltration, etc.)
- How many alerts per technique
- Instant visual picture of the attack surface

---

## Slide 9 — IBM watsonx.ai BLUF Generation

**Bottom Line Up Front — military-style commander briefing**

Generated for every HIGH-priority incident using **IBM Granite (`ibm/granite-13b-instruct-v2`)** via the `ibm-watsonx-ai` Python SDK.

**Prompt includes:**
- Incident title, priority, risk score
- Alert count and MITRE techniques
- Sample alert descriptions

**Output format:**
```
BOTTOM LINE: [what happened and severity]
SUPPORTING FACTS: [3 bullet points of key evidence]
RECOMMENDED ACTION: [immediate response steps]
```

**Fallback:** If no API key is configured, a deterministic Jinja2 template produces a structurally identical summary. The UI badge shows `watsonx` or `template`.

---

## Slide 10 — Technology Stack

| Category | Technologies |
|---|---|
| Language | Python 3.10+ |
| Web framework | Flask 3.x + Jinja2 |
| ORM / Database | SQLAlchemy + SQLite |
| Data processing | pandas |
| IBM AI | watsonx.ai (ibm-watsonx-ai SDK), Granite model |
| IBM tooling | IBM Bob (AI coding assistant) |
| Frontend | HTML5, CSS3, Vanilla JS, Chart.js |
| Testing | pytest (55 tests) |
| Config | python-dotenv |

**IBM Bob** was used throughout development: architecture design, service implementation, test generation, and documentation authoring.

---

## Slide 11 — Working Prototype — What We Built

**Fully functional web application, running locally today.**

| Feature | Status |
|---|---|
| Multi-format alert ingestion (CSV/JSON) | ✅ Implemented |
| False-positive detection (6 rules) | ✅ Implemented |
| Explainable risk scoring | ✅ Implemented |
| MITRE ATT&CK mapping (~25 techniques) | ✅ Implemented |
| Incident correlation (IP + technique) | ✅ Implemented |
| watsonx.ai BLUF generation | ✅ Implemented (+ template fallback) |
| 6-page SOC dashboard | ✅ Implemented |
| REST API (10 endpoints) | ✅ Implemented |
| Test suite | ✅ 55 tests, all passing |

**Demo is fully runnable offline.** No cloud account required for the demo.

---

## Slide 12 — Conclusion

**ThreatIntel Correlator delivers:**

- **Speed:** From raw alert dump to prioritised incidents in seconds
- **Clarity:** Every score explained, every incident summarised
- **AI-powered:** IBM Granite generates actionable briefings for commanders
- **Transparency:** No black box — rule-based, inspectable, verifiable

**What we're most proud of:**
The combination of an explainable scoring engine and IBM Granite BLUF generation.
A security commander can look at one screen and know exactly what happened, why it matters, and what to do — without reading fifty individual alerts.

---

*Team: Name Yad Nahi | IBM Bob AI Innovation Hackathon 2026 | Track: AI*
