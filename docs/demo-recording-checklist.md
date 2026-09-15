# Demo Recording Checklist
## D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant
### IBM BoB AI Innovation Hackathon 2026

---

## PART 1 — Application Startup

### 1.1 Prerequisites

- [ ] Python 3.11+ is installed (`python --version`)
- [ ] You are in the `src/` directory of the repository
- [ ] Dependencies are installed:
  ```powershell
  cd src
  pip install -r requirements.txt
  ```
- [ ] A `.env` file exists at `src/.env` (copy from `src/.env.example`):
  ```powershell
  Copy-Item .env.example .env
  ```
  - The app runs without a watsonx API key. BLUF will use the template fallback.
  - If you have credentials, fill in `WATSONX_API_KEY` and `WATSONX_PROJECT_ID` now.
  - **Do NOT set a visible `.env` file on screen during recording.**

### 1.2 Start the Application

Run from the `src/` directory:

```powershell
python run.py
```

Expected console output (confirm before recording):
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

- [ ] Application starts without errors
- [ ] No red traceback in the terminal

### 1.3 Browser URL

Open:
```
http://localhost:5000/
```

- [ ] Browser loads the Dashboard Overview page
- [ ] If no data is loaded yet, you see the empty state: **"No data yet — Load the built-in sample dataset"**
- [ ] Sidebar shows: Overview · Alerts · Incidents · MITRE ATT&CK · Upload

---

## PART 2 — Pre-Recording Setup

### 2.1 Recommended Browser & Window Size

- [ ] Use **Google Chrome** or **Microsoft Edge** (Chromium-based)
- [ ] Set browser window to **full screen** (F11) or maximised
- [ ] Recommended resolution: **1920×1080** or **1440×900** minimum
- [ ] Zoom level: **100%** (Ctrl+0 to reset)
- [ ] Open DevTools? **No.** Close DevTools if open.
- [ ] Extensions? **Disable all visible extensions** that might show notifications

### 2.2 Reset the Database (Clean Demo State)

Before recording, reset all data so you can load it live:

Option A — Use the API reset endpoint:
```powershell
Invoke-RestMethod -Uri "http://localhost:5000/api/v1/alerts/all" -Method DELETE
```

Option B — Delete and recreate the database file:
```powershell
Remove-Item src/instance/threats.db -ErrorAction SilentlyContinue
# Restart the app — it will recreate the empty DB automatically
python run.py
```

- [ ] After reset, navigate to `http://localhost:5000/` and confirm the **empty state** is shown
- [ ] The empty state message: *"No data yet — Load the built-in sample dataset"*
- [ ] The "⚡ Load Sample Data" button is visible

### 2.3 Tabs to Open Before Recording

Open these browser tabs in order **before** you start recording:

| Tab # | URL | Purpose |
|---|---|---|
| 1 | `http://localhost:5000/` | Dashboard Overview (start here) |
| 2 | `http://localhost:5000/upload` | Upload / Ingest page |
| 3 | `http://localhost:5000/incidents` | Incidents grid |
| 4 | `http://localhost:5000/mitre` | MITRE ATT&CK map |

- [ ] All four tabs are open and loaded
- [ ] Tab 1 (dashboard) is currently showing the **empty state** (no data loaded yet)

### 2.4 Terminal / Console

- [ ] **Minimise or hide the terminal window** — do not show it during recording
- [ ] The Flask development server prints every request to the console — this is fine, but hide the terminal
- [ ] If you need to see the terminal, use a second monitor; do NOT share that screen

---

## PART 3 — Recording Setup

### 3.1 Screen Recording Software

Recommended tools (Windows):
- **OBS Studio** (free) — best quality
- **Xbox Game Bar** (Win+G) — quick screen capture
- **Camtasia** — if available

Settings:
- [ ] Record at **1920×1080** or match your display resolution
- [ ] Frame rate: **30fps** minimum
- [ ] Audio: microphone enabled if you are narrating live

### 3.2 Things to Hide / Remove Before Recording

- [ ] **Terminal window** — minimise or close (app still runs in background)
- [ ] **`.env` file** — never show this in any editor or file browser
- [ ] **API keys** — if you paste into `.env`, do it before recording; never type credentials live
- [ ] **File paths** containing your username (e.g. `C:\Users\YourName\...`) — minimise file explorers
- [ ] **Personal email / notifications** — enable Do Not Disturb (Windows Focus Assist)
- [ ] **Browser bookmarks bar** — hide it (Ctrl+Shift+B)
- [ ] **Other browser tabs** not related to the demo — close them
- [ ] **Desktop icons** — hide desktop or clear visible clutter (right-click desktop → View → Show desktop icons: off)

### 3.3 Credential / API Key Safety Rules

- **Never type or paste** a real API key while screen recording is active.
- The `.env` file should be configured **before** you start recording.
- The application works completely without a watsonx API key — the BLUF uses the template fallback.
- If asked "is watsonx running?" — check the attribution line on the BLUF box:
  - "Source: IBM watsonx (template)" → template mode, no live AI call
  - "Source: AI (watsonx)" → live watsonx call confirmed
- **Do NOT claim watsonx generated the BLUF if it says "template".**

---

## PART 4 — Exact Click Sequence for Live Demo

Follow this sequence during recording. Each step corresponds to a section in the script.

---

### STEP 1 — Dashboard Empty State (0:00–0:20)

1. [ ] Confirm you are on `http://localhost:5000/`
2. [ ] The empty state is visible: "No data yet"
3. [ ] Begin narration

---

### STEP 2 — Problem Setup (0:20–0:50)

1. [ ] Stay on `http://localhost:5000/`
2. [ ] The four KPI cards show zeros (empty state)
3. [ ] Continue narration — no clicks needed

---

### STEP 3 — Load Sample Data (1:20–1:50)

**Option A — Load from Upload page (recommended — shows the ingest UI):**
1. [ ] Click **"Upload"** in the left sidebar (or navigate to `/upload`)
2. [ ] Show the drag-and-drop zone briefly
3. [ ] Click the **"⚡ Load Built-in Sample Data"** button
4. [ ] Watch the progress bar animate (takes ~1–3 seconds)
5. [ ] The Ingestion Complete card appears — read/point to the stats:
   - `alerts_ingested` = 37
   - `false_positives` = count
   - `incidents_created` = count
   - `high_count` / `medium_count` / `low_count` breakdown
6. [ ] Click **"View Dashboard →"**

**Option B — Load from Dashboard empty state:**
1. [ ] Click **"⚡ Load Sample Data"** on the empty state page
2. [ ] Wait for the page to auto-refresh with data

**After loading:**
- [ ] KPI cards show real numbers
- [ ] Recent Alerts table is populated
- [ ] False Positives table is populated

---

### STEP 4 — Show Dashboard (0:50–1:20) ← do this AFTER data is loaded

1. [ ] Point to each KPI card left to right (Total Alerts, High/Critical, Active Incidents, False Positives)
2. [ ] Scroll down to show the Alert Severity donut chart and Alerts by MITRE Tactic bar chart
3. [ ] Scroll to show the Recent Alerts table — click one alert row to expand the score breakdown detail panel
4. [ ] Note the right column: Threat Level gauge (SVG arc) → MITRE ATT&CK Tactics list → Active Incidents list → BLUF panel

---

### STEP 5 — Incident Correlation (1:50–2:25)

1. [ ] Click **"Incidents"** in the left sidebar (or click `http://localhost:5000/incidents`)
2. [ ] Show the incident cards grid — HIGH cards have a red left border
3. [ ] Click the **first / top-ranked card** (highest risk score)
4. [ ] On the Incident Detail page:
   - [ ] Point to the header: incident title, priority badge, risk score (top-right number)
   - [ ] Point to the BLUF box
   - [ ] Scroll to the Alert Timeline
   - [ ] Click one timeline row to expand it and show the Score Breakdown grid
5. [ ] Point to the `recurrence` factor if the incident comes from 192.168.5.42 (3 alerts, scores 8 recurrence points)

---

### STEP 6 — Risk Scoring (2:25–2:55)

1. [ ] Remain on the Incident Detail page
2. [ ] Open or keep open one timeline alert row with the Score Breakdown panel visible
3. [ ] Point to each factor in the grid:
   - `severity` (up to 30)
   - `event_type` (up to 25)
   - `dest_sensitivity` (up to 20)
   - `recurrence` (up to 15)
   - `keywords` (up to 10)
   - `total` (capped at 100)
4. [ ] The progress bars visually represent each factor's contribution

---

### STEP 7 — False Positives (2:55–3:20)

**Option A — On dashboard:**
1. [ ] Click **"Overview"** in the sidebar to return to `http://localhost:5000/`
2. [ ] Scroll down to the **False Positives** card (below Recent Alerts)
3. [ ] Show the table: ID, Source, Event Type, **Reason** column, Detected At, Status (FP badge)

**Option B — Filtered alerts page:**
1. [ ] Navigate to `http://localhost:5000/alerts?fp=true`
2. [ ] All rows shown have `is_false_positive = True`
3. [ ] Point to the FP badge and the reason

**Actual FP reasons you will see in the sample data:**
- "Source IP is whitelisted" (for 10.0.0.1 source)
- "Informational recon — noise" (for informational + recon alerts)
- "Known internal scanner" (for IPs in 10.0.0.0/8 CIDR — if applicable)

---

### STEP 8 — MITRE ATT&CK (3:20–3:45)

1. [ ] Click **"MITRE ATT&CK"** in the left sidebar (or navigate to `http://localhost:5000/mitre`)
2. [ ] Show the three KPI cards at top: Detected, Unique Tactics, Coverage %
3. [ ] Scroll through the tactic sections — each group has a header with tactic name and alert count
4. [ ] Point to a high-count row (coloured red/orange in the frequency bar)
5. [ ] Point to a zero-count row (grey/muted) — these are techniques not yet seen

---

### STEP 9 — BLUF (3:45–4:20)

1. [ ] Navigate to `http://localhost:5000/incidents` (or click Incidents sidebar)
2. [ ] Click the top incident card → Incident Detail page
3. [ ] Point to the **"BLUF — Bottom Line Up Front"** box
4. [ ] Read the three-part structure: BOTTOM LINE / SUPPORTING FACTS / RECOMMENDED ACTION
5. [ ] Point to the attribution line: **"Source: IBM watsonx (template)"** or **"Source: AI (watsonx)"**
6. [ ] Optional: Click **"↺ Re-generate"** to demonstrate live re-generation
   - A spinner appears briefly
   - The BLUF text updates in place

---

### STEP 10 — Conclusion (4:40–5:00)

1. [ ] Navigate back to `http://localhost:5000/` (Dashboard Overview)
2. [ ] Slow scroll: top KPI cards → charts → alerts table → FP table → right column
3. [ ] Final narration

---

## PART 5 — What Should Be Visible on Screen

### Confirmed Visual Elements (after loading sample data)

| Element | Location | What to Show |
|---|---|---|
| KPI cards | `/` top row | Total Alerts (37), High/Critical count, Active Incidents count, False Positives count + rate |
| Alert Severity donut | `/` main column | HIGH / MEDIUM / LOW donut segments |
| MITRE Tactic bar | `/` main column | Tactic names with alert counts |
| Top Attack Sources | `/` left of map | Up to 5 unique source IPs with priority dots |
| Alert Origins map | `/` right of map | SVG world map with coloured dots |
| Threat Level gauge | `/` right column | SVG arc showing score/100 |
| MITRE Tactics list | `/` right column | Tactic names with counts |
| Active Incidents | `/` right column | Top 5 incidents by risk score |
| BLUF panel | `/` right column | First 200 chars of top incident BLUF |
| Recent Alerts table | `/` main | 10 most recent alerts with expandable score breakdown |
| False Positives table | `/` main | FP alerts with reason column |
| Incident grid | `/incidents` | Cards with colour border, score, MITRE tags, BLUF excerpt |
| Alert Timeline | `/incidents/N` | Chronological alerts with expand |
| Score Breakdown | `/incidents/N` expanded row | 5 factor progress bars |
| BLUF box | `/incidents/N` | Full BLUF text + attribution line |
| MITRE Coverage Map | `/mitre` | 27 techniques grouped by 12 tactics with frequency bars |

---

## PART 6 — What Must NOT Appear on Screen

| Item | Why | How to Prevent |
|---|---|---|
| Terminal / console output | Shows internal debug info | Minimise terminal before recording |
| `.env` file contents | Contains secrets | Never open in editor during recording |
| `WATSONX_API_KEY` value | API key exposure | Keep `.env` closed |
| Your Windows username in file paths | Privacy | Close file explorer |
| Personal browser bookmarks | Privacy | Hide bookmarks bar (Ctrl+Shift+B) |
| Email / calendar notifications | Distraction | Enable Do Not Disturb |
| DevTools Network tab | Shows internal API calls | Close DevTools |
| Flask debug reloader messages | Confuses viewers | Minimise terminal |
| `src/instance/threats.db` file path | Reveals project structure | Don't show file browser |

---

## PART 7 — Final Pre-Recording Checklist

Run through this checklist in order immediately before pressing "Record":

### Environment
- [ ] Application is running (`python run.py` from `src/`)
- [ ] `http://localhost:5000/` loads in browser
- [ ] Database was reset — empty state is showing on dashboard
- [ ] Four browser tabs are open (Overview, Upload, Incidents, MITRE)

### Screen
- [ ] Browser is full-screen or maximised
- [ ] Zoom is 100%
- [ ] Bookmarks bar is hidden
- [ ] Do Not Disturb / Focus Assist is ON
- [ ] Terminal window is minimised
- [ ] `.env` file is NOT open in any editor
- [ ] No personal files or folders visible

### Audio
- [ ] Microphone is selected in recording software
- [ ] Test audio level — voice is clearly audible
- [ ] Background noise minimised

### Script
- [ ] `docs/demo-video-script.md` is open on a **second screen** or printed (not visible in recording)
- [ ] You have practised the narration at least once
- [ ] You know which tabs to switch to and in which order

### Content accuracy
- [ ] You will say "37 sample alerts" (not "50")
- [ ] You will say the correlation is rule-based (IP + technique), not ML
- [ ] You have checked the BLUF attribution line and know which narration path to use
- [ ] You will not claim live watsonx generation unless attribution says "AI (watsonx)"
- [ ] You will not claim live streaming ingestion

---

## PART 8 — Post-Recording Steps

- [ ] Watch the full recording before sharing
- [ ] Confirm no credentials, API keys, or personal information are visible
- [ ] Confirm all four demo sections (correlation, scoring, FP, MITRE) are clearly shown
- [ ] Add title card at start (optional): project name, team name, hackathon name
- [ ] Add end card (optional): "Thank you — D2 ThreatIntel Correlator"
- [ ] Export at 1080p minimum
- [ ] File name suggestion: `d2-threatintel-correlator-demo.mp4`

---

## Quick Reference — URL & Startup Commands

```powershell
# 1. Install dependencies (once)
cd src
pip install -r requirements.txt

# 2. Create .env (once)
Copy-Item .env.example .env

# 3. Start app
python run.py

# 4. Open browser
# http://localhost:5000/

# 5. Reset DB for clean demo (optional)
Invoke-RestMethod -Uri "http://localhost:5000/api/v1/alerts/all" -Method DELETE

# 6. Load sample data (during demo)
# Click "⚡ Load Built-in Sample Data" on the Upload page or Dashboard empty state
```

---

## Sample Data Reference (exact values)

These are the **actual values** from `src/data/sample_alerts.csv`:

| Metric | Value |
|---|---|
| Total alerts | 37 |
| Severity: critical | 8 |
| Severity: high | 5 |
| Severity: medium | 12 |
| Severity: low | 7 |
| Severity: informational | 5 |
| Unique source feeds | 4 (splunk_siem, qradar, csv_upload, api_feed) |
| Alerts from 192.168.5.42 | 4 (ALERT-001, 003, 006, 022) — triggers recurrence scoring |
| Whitelisted source (10.0.0.1) | 2 (ALERT-033, 034) — will be FP |
| Informational+recon alerts | 3–5 (ALERT-033 through 037) — likely FP |
| MITRE techniques library | 27 techniques across 12 tactics |
| Scoring HIGH threshold | ≥ 70 |
| Scoring MEDIUM threshold | ≥ 40 |
| Correlation window | 2 hours |

---

*All data in `src/data/` is synthetic and simulated. See `src/data/README.md` for full disclaimer.*
