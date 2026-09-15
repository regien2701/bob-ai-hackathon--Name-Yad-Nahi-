# Submission Checklist

Use this checklist before pushing your final commit and submitting.

---

## 1 — Source Code

- [ ] `src/` contains all application source files
- [ ] `src/run.py` is the correct entry point (`python run.py` starts the app)
- [ ] `src/requirements.txt` lists all dependencies
- [ ] `src/.env.example` contains only placeholder values — no real secrets
- [ ] `src/.env` is **NOT** committed (it is in `.gitignore`)
- [ ] All Python `__pycache__/` and `.pyc` files are excluded by `.gitignore`
- [ ] `src/instance/threats.db` does not contain sensitive data (sample data only)

---

## 2 — Tests

- [ ] `cd src && python -m pytest tests/ --cache-clear` passes with **55 passed, 0 failed**
- [ ] No test is skipped or disabled to hide a real failure

---

## 3 — README.md

- [ ] Project title is present
- [ ] Problem statement is present
- [ ] Solution description is present
- [ ] Key features listed
- [ ] Technology stack listed
- [ ] Quick-start / how-to-run instructions are correct
- [ ] IBM technology integration is described
- [ ] Team name is present
- [ ] No placeholder text (`[Your Project Title Here]`, `[Your Team Name]`) remains

---

## 4 — submission.yaml

- [ ] `team.name` is filled in (not a placeholder)
- [ ] `team.track` is `"AI"`
- [ ] `team.lead.name` is the real team lead name (not `[TEAM_LEAD_NAME]`)
- [ ] `team.lead.email` is the real team lead email (not `[TEAM_LEAD_EMAIL]`)
- [ ] All `team.members` names and emails are filled in
- [ ] `submission.title` is `"ThreatIntel Correlator"`
- [ ] `submission.problem_statement` is filled in
- [ ] `submission.solution_summary` is filled in
- [ ] `submission.key_features` has at least 3 entries

---

## 5 — Documentation

- [ ] `docs/problem-statement.md` exists
- [ ] `docs/solution-overview.md` exists
- [ ] `docs/architecture.md` exists
- [ ] `docs/setup-guide.md` exists (Windows-friendly instructions)

---

## 6 — Demo Video

- [ ] Demo video has been recorded (2–3 minutes)
- [ ] Video is uploaded to YouTube, Loom, IBM Box, or Google Drive
- [ ] `demo/demo-video-link.txt` contains the real URL (not `[ADD_DEMO_VIDEO_URL]`)
- [ ] The URL is publicly accessible (not private/restricted)
- [ ] Video shows the running application, not just slides

---

## 7 — Live Demo

- [ ] `demo/live-demo-url.txt` is updated:
  - Either contains a real public URL, OR
  - Contains `NOT DEPLOYED — run locally using docs/setup-guide.md`

---

## 8 — Screenshots

- [ ] `demo/screenshots/` directory exists
- [ ] At least 2–3 screenshots of the running application are present
- [ ] Screenshots show: dashboard, incident detail with BLUF, MITRE map

---

## 9 — Presentation

- [ ] `presentation/slides.pdf` (or `slides.pptx`) exists, OR
- [ ] `presentation/slide-content.md` exists as a fallback

---

## 10 — Security

- [ ] No real API keys in any committed file
- [ ] No `.env` committed
- [ ] No passwords, tokens, or credentials visible in source
- [ ] `src/.env.example` values are all placeholders (e.g. `your_api_key_here`)

---

## 11 — GitHub Actions

- [ ] `.github/workflows/validate.yml` exists
- [ ] Push to `main` and confirm the Actions workflow passes (green checkmark)
- [ ] All validation checks pass:
  - Required files present
  - `submission.yaml` is valid YAML
  - Required fields are filled
  - `src/` is not empty
  - `demo/demo-video-link.txt` is not the original placeholder
  - `README.md` has no template placeholders

---

## 12 — Final Git State

- [ ] `git status` shows only intended changes
- [ ] No unintended files staged
- [ ] Final commit message is descriptive (e.g. `chore: final submission artifacts`)
- [ ] Pushed to `main` branch
- [ ] **DO NOT PUSH** until all items above are checked

---

## Quick Validation Commands

```powershell
# From repo root — run tests
cd src
python -m pytest tests/ --cache-clear -q

# Verify submission.yaml is valid YAML (requires yq or Python)
python -c "import yaml; yaml.safe_load(open('../submission.yaml'))"

# Check for placeholder text in submission.yaml
Select-String -Pattern "\[TEAM_LEAD|MEMBER_" submission.yaml

# Check demo video link is updated
Select-String -Pattern "ADD_DEMO_VIDEO_URL" demo/demo-video-link.txt
```
