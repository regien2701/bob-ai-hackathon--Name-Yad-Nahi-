# Demo Video Script
## D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant
### IBM BoB AI Innovation Hackathon 2026
### Target duration: 4 min 45 sec (3–5 min range)

---

> **Before you record:** Follow `docs/demo-recording-checklist.md` completely.
> The application must already be running and sample data must already be loaded.
> Record in one continuous take per section; cut between sections if needed.

---

## Section Timestamps & Script

---

### 0:00 – 0:20 — INTRO (20 sec)

**Screen:** Title card / opening slide, OR the dashboard Overview page at `http://localhost:5000/`
**Action:** No clicks. Face camera or show the dashboard.

**Narration:**
> "Security Operations Centres are drowning in alerts — thousands per day, most of them noise.
> This is ThreatIntel Correlator: a full-stack threat intelligence assistant that ingests raw security alerts,
> automatically correlates them into incidents, scores them by risk, filters out false positives,
> and maps every threat to the MITRE ATT&CK framework — giving analysts a clear bottom line
> instead of an endless queue."

**Duration:** ~20 seconds
**⚠ Do NOT show:** Any terminal windows, environment variables, or `.env` file contents.

---

### 0:20 – 0:50 — THE PROBLEM (30 sec)

**Screen:** Dashboard Overview page (`http://localhost:5000/`) — the four KPI cards at the top.
**Action:** Let the KPI cards be visible. No clicks needed.

**Narration:**
> "The problem security teams face is three-fold.
> First, alert volume — hundreds of alerts arrive daily and most are unrelated or duplicated.
> Second, false positives — analysts waste time investigating alerts that are actually benign:
> routine scans, whitelisted IPs, informational events.
> Third, prioritisation — when everything is marked critical, nothing is.
> Analysts need to know which five alerts out of five hundred actually matter right now.
> ThreatIntel Correlator solves all three."

**Duration:** ~30 seconds
**⚠ Do NOT show:** Any numbers you haven't verified by loading sample data first.

---

### 0:50 – 1:20 — THE DASHBOARD (30 sec)

**Screen:** Dashboard Overview page (`http://localhost:5000/`)
**Action:**
1. Point to (hover over) the four KPI cards left to right: Total Alerts → High/Critical → Active Incidents → False Positives.
2. Scroll down briefly to show the Alert Severity donut chart and the Alerts by MITRE Tactic bar chart.
3. Glance at the right column: Threat Level gauge, MITRE ATT&CK Tactics panel, Active Incidents list, BLUF panel.

**What will be visible (after loading sample data):**
- **Total Alerts** card (37 after loading sample data)
- **High / Critical Incidents** card (number of HIGH priority incidents)
- **Active Incidents** card (open incident count)
- **False Positives** card (count + % rate)
- Alert Severity donut chart (HIGH / MEDIUM / LOW breakdown)
- Alerts by MITRE Tactic bar chart (tactics populated from 27-technique library)
- Threat Level gauge (score derived from the top-ranked incident's risk score)
- MITRE ATT&CK Tactics sidebar list
- Active Incidents sidebar list (top 5 by risk score)
- BLUF panel showing the top incident summary

**Narration:**
> "The command dashboard gives a security commander instant situational awareness.
> The four cards at the top show total alert volume, how many are high or critical priority,
> how many active incidents exist, and how many alerts were automatically suppressed as false positives.
> The severity donut and MITRE tactic bar chart show the threat landscape at a glance.
> On the right, the threat level gauge reflects the highest active risk score,
> and the bottom card shows a BLUF — a Bottom Line Up Front summary — for the top incident."

**Duration:** ~30 seconds
**⚠ Do NOT show:** The sparkline trend labels ("↑ 12% vs previous 24h") — those are static display text, not live metrics.

---

### 1:20 – 1:50 — DATA INGESTION (30 sec)

**Screen:** Navigate to Upload page via sidebar or `http://localhost:5000/upload`
**Action:**
1. Show the Upload page with the drag-and-drop zone.
2. Click **"⚡ Load Built-in Sample Data"** button.
3. Watch the progress label and progress bar animate.
4. When complete, the Ingestion Complete card appears showing the summary stats.
5. Click **"View Dashboard →"** to return to the dashboard.

**What will be visible on the result card (actual values from sample data):**
- `alerts_ingested: 37`
- `false_positives: N` (exact count depends on FP rules applied)
- `incidents_created: N` (depends on correlation; multiple clusters from 192.168.5.42 and technique grouping)
- `high_count`, `medium_count`, `low_count` breakdowns

**Narration:**
> "The ingestion pipeline accepts CSV or JSON alert data from any source — Splunk SIEM, QRadar, API feeds, or manual uploads.
> Here I'm loading the built-in sample dataset: 37 synthetic alerts covering every event type and severity level.
> The system normalises field names automatically — 'src_ip' becomes 'source_ip', 'severity' maps to the internal schema —
> so it works with exports from real security tools without manual reformatting.
> The result: every alert is scored, FP-checked, and MITRE-mapped in a single transaction."

**Duration:** ~30 seconds
**⚠ Do NOT claim:** Real-time streaming ingestion. The pipeline is file-upload based (CSV/JSON POST).

---

### 1:50 – 2:25 — ALERT CORRELATION (35 sec)

**Screen:** Navigate to Incidents page via sidebar or `http://localhost:5000/incidents`
**Action:**
1. Show the incidents grid. Point out the incident cards with their priority badges, risk scores, and MITRE technique tags.
2. Click on the **highest-risk HIGH priority incident** card (look for the one titled something like "c2 campaign from 192.168.5.42" or similar — it will have the highest score).
3. On the Incident Detail page, show the **Alert Timeline** section.
4. Click one timeline row to expand it and reveal the Score Breakdown panel.

**What will be visible:**
- Incident cards grouped by colour: HIGH (red border), MEDIUM (orange), LOW (cyan).
- Each card shows: incident title (auto-generated from IP or technique), priority badge, status badge, alert count, risk score, MITRE technique tags, and the first 120 characters of the BLUF.
- On the detail page: Alert Timeline with timestamps, event types, source/dest IPs, risk scores, and FP badges.
- Expanded timeline row: Score Breakdown grid showing `severity`, `event_type`, `dest_sensitivity`, `recurrence`, `keywords`, and `total` with progress bars.

**Narration:**
> "The correlation engine automatically groups related alerts into incidents.
> It runs two passes: first it clusters alerts sharing the same source IP within a configurable time window —
> here that's two hours — then a second pass groups any remaining alerts by shared MITRE technique.
> False positives are excluded from correlation entirely.
> The result is this incident grid: individual noisy alerts collapsed into actionable incident groups,
> each with an auto-generated title, a combined risk score, and a complete alert timeline.
> Clicking into an incident reveals every constituent alert with timestamps, source and destination IPs,
> and an expanded score breakdown showing exactly which factors drove the risk score."

**Duration:** ~35 seconds
**⚠ Do NOT claim:** Machine-learning-based clustering. The engine uses rule-based IP and technique grouping.

---

### 2:25 – 2:55 — RISK PRIORITISATION (30 sec)

**Screen:** Still on Incident Detail page for the top-risk incident, OR navigate to Alerts page (`http://localhost:5000/alerts`)
**Action:**
1. On the Incident Detail page — point to the large risk score number in the top-right of the header card.
2. Click a timeline row to open the score breakdown panel.
3. Point to each factor in the breakdown grid.

**What will be visible (actual scoring factors from `src/app/services/scoring.py`):**
- **Severity** — up to 30 points (critical=30, high=22, medium=14, low=6)
- **Event Type** — up to 25 points (c2=25, exfiltration=25, malware=20, intrusion=20, credential_access=18, phishing=15, recon=10, dos=8)
- **Destination Sensitivity** — up to 20 points (critical subnet prefix like 10.10.0.x = 20, other private ranges = 10)
- **Recurrence** — up to 15 points (5+ alerts from same source IP = 15, 2+ = 8)
- **Keywords** — up to 10 points (high-signal keywords like "lsass", "mimikatz", "cobalt strike", "ransomware" in description: 3+ matches = 10, 1+ = 5)
- **Classification thresholds:** Score ≥ 70 → HIGH, Score ≥ 40 → MEDIUM, Score < 40 → LOW

**Narration:**
> "Every alert receives a risk score from zero to one hundred, computed from five independent factors.
> Severity contributes up to 30 points. Event type adds up to 25 — command-and-control and exfiltration
> score highest because they indicate active attacker activity.
> Destination sensitivity adds up to 20 points when critical internal subnets are targeted.
> Recurrence adds up to 15 points when the same source IP appears repeatedly — a strong indicator of persistence.
> And keyword analysis of the description adds up to 10 points for signals like 'lsass', 'cobalt strike', or 'ransomware'.
> Scores above 70 are HIGH priority. Above 40 are MEDIUM. Below that, LOW.
> This scoring is transparent and auditable — every point is explained."

**Duration:** ~30 seconds

---

### 2:55 – 3:20 — FALSE POSITIVE DETECTION (25 sec)

**Screen:** Scroll down on Dashboard Overview (`http://localhost:5000/`) to the **False Positives** table section, OR navigate to `http://localhost:5000/alerts?fp=true`
**Action:**
1. On the dashboard, scroll down to show the False Positives table card.
2. Point to the FP reason column showing strings like "Informational recon — noise", "Source IP is whitelisted", "Known internal scanner", "Risk score below minimum threshold".
3. Optionally navigate to `/alerts?fp=true` to see all filtered FP alerts.

**What will be visible (actual FP rules from `src/app/services/fp_detector.py`):**
- FP-1: Source IP whitelisted (default: `127.0.0.1`, `10.0.0.1`)
- FP-2: Destination IP whitelisted
- FP-3: Informational severity + recon event type → "Informational recon — noise"
- FP-4: Source IP in known internal scanner CIDR (`10.0.0.0/8` by default)
- FP-5: Duplicate within 60-second window (same source IP, dest IP, event type)
- FP-6: Risk score below 10 (below minimum threshold)

**In the sample data** — alerts that will be flagged:
- ALERT-033: `10.0.0.1` source (whitelisted) — "Source IP is whitelisted"
- ALERT-034: `10.0.0.1` source (whitelisted) — "Source IP is whitelisted"
- ALERT-035, 036, 037: informational + recon — "Informational recon — noise" or internal scanner CIDR

**Narration:**
> "The false positive detector runs six sequential rules against every ingested alert.
> Alerts from whitelisted IPs are suppressed immediately.
> Informational-severity recon events — routine scans, heartbeats, background noise — are classified as noise.
> Alerts from the internal scanner CIDR are flagged as known scanners.
> Duplicate events within a 60-second window are collapsed.
> And alerts that score below 10 on the risk engine are filtered out automatically.
> False positives are excluded from incident correlation entirely,
> so analysts only see events that actually warrant investigation."

**Duration:** ~25 seconds

---

### 3:20 – 3:45 — MITRE ATT&CK MAPPING (25 sec)

**Screen:** Navigate to MITRE ATT&CK Coverage Map via sidebar or `http://localhost:5000/mitre`
**Action:**
1. Show the three summary stat cards: Detected techniques, Unique Tactics, Coverage %.
2. Scroll down to show the tactic sections — each collapses techniques grouped by tactic.
3. Point to a heavily-hit technique row (coloured red/orange in the frequency bar).
4. Point to a zero-count technique row (greyed out) to show what's not yet seen.

**What will be visible (techniques from `src/data/mitre_techniques.json`):**
- 27 known techniques across 12 tactic categories
- Tactics seen: Initial Access, Execution, Impact, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control
- After loading sample data: multiple techniques with non-zero alert counts (T1071 Application Layer Protocol from c2 alerts; T1003 OS Credential Dumping from LSASS alerts; T1486 Data Encrypted for Impact from ransomware alerts; T1110 Brute Force from credential alerts; T1046 Network Service Discovery from recon/scan alerts; T1041 Exfiltration Over C2 Channel; T1566 Phishing; T1190 Exploit Public-Facing Application from SQL injection; T1048 Exfiltration Over Alternative Protocol from DNS tunnelling)
- Frequency bars coloured red (top 70%), orange (top 30%), cyan (lower)

**Narration:**
> "Every alert is automatically mapped to the MITRE ATT&CK framework using keyword matching
> against a curated library of 27 techniques spanning 12 tactic categories.
> This coverage map shows exactly which attack techniques are present in your data.
> Brightly coloured bars indicate high-frequency techniques — here Command and Control and Credential Access
> are the most active.
> Greyed-out rows show techniques in our library that haven't been detected yet —
> useful for identifying gaps in detection coverage.
> Incident titles are automatically named after the dominant technique or source IP,
> giving analysts immediate context without manual triage."

**Duration:** ~25 seconds

---

### 3:45 – 4:20 — BLUF — BOTTOM LINE UP FRONT (35 sec)

**Screen:** Navigate to Incidents page (`http://localhost:5000/incidents`), then click the highest-risk incident.
**Action:**
1. Show the Incident Detail page.
2. Point to the **BLUF — Bottom Line Up Front** box prominently displayed below the header.
3. Read the three-part structure aloud: BOTTOM LINE, SUPPORTING FACTS, RECOMMENDED ACTION.
4. Point to the attribution line at the bottom of the BLUF box ("Source: IBM watsonx (template)" or "Source: AI (watsonx)").
5. Optionally click **"↺ Re-generate"** to trigger a fresh BLUF generation.

**What will be visible (actual BLUF structure from `src/app/services/bluf.py`):**
```
BOTTOM LINE: HIGH priority incident comprising N correlated alerts.
             Primary technique: T1071 Application Layer Protocol.
SUPPORTING FACTS: • Source IP(s): 192.168.5.42.
                  • Event types observed: c2, exfiltration.
                  • Maximum risk score: XX/100.
RECOMMENDED ACTION: Isolate affected hosts, escalate to Tier-2 analyst,
                    and review T1071 Application Layer Protocol indicators.
```

**Attribution line options:**
- If `WATSONX_API_KEY` is set and the API call succeeds → "Source: AI (watsonx)"
- If no API key is set (default demo configuration) → "Source: IBM watsonx (template)"

**⚠ CRITICAL — be accurate about BLUF source:**
- **If the attribution line shows "IBM watsonx (template)":** say *"The system generates a structured BLUF using the incident's scored data — title, priority, risk score, source IPs, event types, and MITRE technique. When a watsonx API key is configured, the IBM Granite model generates the summary instead."*
- **If the attribution line shows "AI (watsonx)":** say *"This BLUF was generated live by IBM watsonx.ai using the IBM Granite model, called via the ibm-watsonx-ai SDK."*
- **Do NOT claim watsonx generated the text if the attribution line says "template".**

**Narration (template path — most likely for demo without credentials):**
> "The final step is the BLUF: Bottom Line Up Front.
> This is a military-style briefing format designed to give a security commander the key facts
> in under 30 seconds.
> The system automatically produces three sections:
> the Bottom Line — what happened and at what severity;
> Supporting Facts — the source IPs, event types observed, and maximum risk score;
> and a Recommended Action — specific to the primary MITRE technique detected.
> This summary is generated from the incident's scored and correlated data.
> When IBM watsonx.ai credentials are configured, the IBM Granite model generates
> a richer natural-language summary instead. The architecture is production-ready
> for both paths."

**Duration:** ~35 seconds

---

### 4:20 – 4:40 — IBM TECHNOLOGY (20 sec)

**Screen:** Dashboard Overview page OR Incident Detail page with BLUF visible.
**Action:** No new clicks. Summarise verbally.

**IBM technologies actually used in this project (verified from code):**

| Technology | Role | Evidence |
|---|---|---|
| IBM watsonx.ai (ibm/granite-13b-instruct-v2) | BLUF generation via `ibm-watsonx-ai` SDK | `src/app/services/bluf.py` — `ModelInference` call |
| IBM watsonx.ai SDK | Python package `ibm-watsonx-ai==1.1.2` | `src/requirements.txt` |
| IBM Bob (AI coding assistant) | Used during development for SDLC | This conversation |

**⚠ Only claim the following if verified at runtime:**
- Claim watsonx.ai is generating live text ONLY if the BLUF attribution says "AI (watsonx)" during your demo.
- Always safe to say: "The system is architected to call IBM watsonx.ai Granite when credentials are present, with a deterministic fallback for offline/demo environments."

**Narration:**
> "The IBM technology stack powering this platform:
> IBM watsonx.ai with the Granite 13B instruct model handles BLUF generation,
> called via the official ibm-watsonx-ai Python SDK.
> The system is designed for resilience — if watsonx is unavailable or credentials aren't configured,
> a deterministic template produces a structured BLUF automatically,
> so analysts always have a summary.
> IBM Bob, IBM's AI coding assistant, was used throughout development for architecture,
> code generation, and testing."

**Duration:** ~20 seconds

---

### 4:40 – 5:00 — CONCLUSION (20 sec)

**Screen:** Dashboard Overview page (`http://localhost:5000/`) — the full populated dashboard.
**Action:** Slow pan / scroll showing the full dashboard: KPI cards → charts → Recent Alerts table → False Positives table → right column with threat gauge and BLUF panel.

**Narration:**
> "From alert overload to actionable intelligence.
> ThreatIntel Correlator delivers a complete, automated pipeline:
> Ingest from any feed → Correlate into incidents → Prioritise by risk score →
> Detect and suppress false positives → Map every threat to MITRE ATT&CK →
> Generate a BLUF investigation summary → Investigate with full alert timeline.
> No more alert fatigue. Every analyst starts their shift with a clear priority queue
> and a bottom line they can act on immediately.
> Thank you."

**Duration:** ~20 seconds

---

## Complete Pipeline Summary (reference card)

```
Raw CSV/JSON Upload
        │
        ▼
  Column Normalisation  ← COLUMN_ALIASES mapping (30+ field name variants)
        │
        ▼
  Event Type Normalisation  ← EVENT_TYPE_MAP (9 canonical types)
        │
        ▼
  Risk Scoring  ← 5 factors: severity + event_type + dest_sensitivity
                             + recurrence + keywords  →  0–100 score
        │
        ▼
  Priority Classification  ← HIGH ≥70, MEDIUM ≥40, LOW <40
        │
        ▼
  FP Detection  ← 6 rules: whitelist / informational-recon / scanner-CIDR
                            / duplicate-60s / score<10
        │
        ▼
  MITRE ATT&CK Mapping  ← keyword scoring against 27-technique JSON library
        │
        ▼
  Alert Correlation  ← Pass 1: same source IP within 2h window
                      Pass 2: same MITRE technique (ungrouped alerts only)
                      FP alerts excluded
        │
        ▼
  BLUF Generation  ← IBM watsonx.ai Granite (if key set)
                     OR deterministic template fallback
        │
        ▼
  Dashboard  ← Real-time KPIs, charts, alert table, incident grid,
                MITRE coverage map, incident detail with timeline
```

---

## Pages to Show — Quick Reference

| Time | URL | Page Name |
|---|---|---|
| 0:00–0:20 | `http://localhost:5000/` | Dashboard Overview |
| 0:20–0:50 | `http://localhost:5000/` | Dashboard Overview (KPI cards) |
| 0:50–1:20 | `http://localhost:5000/` | Dashboard Overview (scroll through) |
| 1:20–1:50 | `http://localhost:5000/upload` | Upload / Ingest page |
| 1:50–2:25 | `http://localhost:5000/incidents` | Incidents grid |
| 1:50–2:25 | `http://localhost:5000/incidents/1` | Incident Detail (top incident) |
| 2:25–2:55 | `http://localhost:5000/incidents/1` | Incident Detail (score breakdown) |
| 2:55–3:20 | `http://localhost:5000/` or `/alerts?fp=true` | Dashboard FP table or FP filter |
| 3:20–3:45 | `http://localhost:5000/mitre` | MITRE ATT&CK Coverage Map |
| 3:45–4:20 | `http://localhost:5000/incidents/1` | Incident Detail (BLUF box) |
| 4:20–4:40 | `http://localhost:5000/incidents/1` | Incident Detail (BLUF attribution) |
| 4:40–5:00 | `http://localhost:5000/` | Dashboard Overview (full scroll) |

---

## Features You Must NOT Claim in the Video

| Claim | Reality |
|---|---|
| "ML-powered clustering" | Correlation is rule-based (IP + technique grouping) |
| "Real-time streaming alerts" | Pipeline is triggered by file upload or button click |
| "watsonx generated this summary" | Only true if attribution line says "AI (watsonx)" |
| "50 sample alerts" | Sample dataset has exactly **37** alerts |
| "Trend percentages are live" | The "↑ 12%" sparkline labels in KPI cards are static display text |
| "Deployed in production" | This is a development Flask application |
| "Processes live threat feeds" | Ingest is file-based; no live feed connectors are implemented |
