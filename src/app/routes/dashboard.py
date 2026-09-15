"""HTML page routes — rendered Jinja2 templates for the dashboard."""

import json
import os

from flask import Blueprint, render_template, request, abort, current_app
from sqlalchemy import func

from app.extensions import db
from app.models.alert import Alert
from app.models.incident import Incident

dashboard_bp = Blueprint("dashboard", __name__)

# ---------------------------------------------------------------------------
# Helper — load MITRE data
# ---------------------------------------------------------------------------

def _load_mitre() -> list[dict]:
    """Return the full MITRE techniques list from the JSON file."""
    data_dir = os.path.join(current_app.root_path, "..", "data")
    path = os.path.join(data_dir, "mitre_techniques.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Page 1 — Summary Dashboard
# ---------------------------------------------------------------------------

@dashboard_bp.route("/")
def index():
    total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
    open_incidents = (
        db.session.query(func.count(Incident.id))
        .filter(Incident.status == "open")
        .scalar() or 0
    )
    high_incidents = (
        db.session.query(func.count(Incident.id))
        .filter(Incident.priority == "HIGH")
        .scalar() or 0
    )
    fp_count = (
        db.session.query(func.count(Alert.id))
        .filter(Alert.is_false_positive == True)  # noqa: E712
        .scalar() or 0
    )
    fp_rate = round((fp_count / total_alerts * 100), 1) if total_alerts else 0.0

    top_incidents = (
        db.session.query(Incident)
        .order_by(Incident.risk_score.desc())
        .limit(5)
        .all()
    )
    recent_alerts = (
        db.session.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )

    # Priority counts for donut chart
    priority_rows = (
        db.session.query(Alert.priority, func.count(Alert.id))
        .group_by(Alert.priority)
        .all()
    )
    priority_counts = {row[0]: row[1] for row in priority_rows if row[0]}

    # Tactic counts — requires loading MITRE JSON to resolve technique → tactic
    tactic_map: dict[str, str] = {}
    try:
        for tech in _load_mitre():
            tactic_map[tech["technique_id"]] = tech["tactic"]
    except Exception:
        pass

    technique_rows = (
        db.session.query(Alert.mitre_technique_id, func.count(Alert.id))
        .filter(Alert.mitre_technique_id != None)  # noqa: E711
        .group_by(Alert.mitre_technique_id)
        .all()
    )
    tactic_agg: dict[str, int] = {}
    for tech_id, cnt in technique_rows:
        tactic = tactic_map.get(tech_id, "Unknown")
        tactic_agg[tactic] = tactic_agg.get(tactic, 0) + cnt
    tactic_counts = [{"tactic": k, "count": v} for k, v in sorted(tactic_agg.items())]

    return render_template(
        "dashboard/index.html",
        total_alerts=total_alerts,
        high_incidents=high_incidents,
        open_incidents=open_incidents,
        fp_count=fp_count,
        fp_rate=fp_rate,
        top_incidents=top_incidents,
        recent_alerts=recent_alerts,
        priority_counts=priority_counts,
        tactic_counts=tactic_counts,
    )


# ---------------------------------------------------------------------------
# Page 2 — Upload
# ---------------------------------------------------------------------------

@dashboard_bp.route("/upload")
def upload():
    return render_template("upload.html")


# ---------------------------------------------------------------------------
# Page 3 — Alerts (filterable, paginated)
# ---------------------------------------------------------------------------

@dashboard_bp.route("/alerts")
def alerts():
    priority = request.args.get("priority", "")
    feed = request.args.get("feed", "")
    fp_filter = request.args.get("fp", "all")  # "true" / "false" / "all"
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))

    query = db.session.query(Alert)
    if priority:
        query = query.filter(Alert.priority == priority.upper())
    if feed:
        query = query.filter(Alert.source_feed == feed)
    if fp_filter == "true":
        query = query.filter(Alert.is_false_positive == True)  # noqa: E712
    elif fp_filter == "false":
        query = query.filter(Alert.is_false_positive == False)  # noqa: E712

    pagination = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template(
        "dashboard/alerts.html",
        alerts=pagination.items,
        pagination=pagination,
        priority=priority,
        feed=feed,
        fp_filter=fp_filter,
    )


# ---------------------------------------------------------------------------
# Page 4 — Incidents (filterable, paginated)
# ---------------------------------------------------------------------------

@dashboard_bp.route("/incidents")
def incidents():
    priority = request.args.get("priority", "")
    status = request.args.get("status", "")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))

    query = db.session.query(Incident)
    if priority:
        query = query.filter(Incident.priority == priority.upper())
    if status:
        query = query.filter(Incident.status == status.lower())

    pagination = query.order_by(Incident.risk_score.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template(
        "dashboard/incidents.html",
        incidents=pagination.items,
        pagination=pagination,
        priority=priority,
        status=status,
    )


# ---------------------------------------------------------------------------
# Page 5 — Incident Detail
# ---------------------------------------------------------------------------

@dashboard_bp.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        abort(404)
    constituent_alerts = sorted(
        list(incident.alerts), key=lambda a: (a.timestamp or a.created_at or 0)
    )
    return render_template(
        "dashboard/incident_detail.html",
        incident=incident,
        constituent_alerts=constituent_alerts,
    )


# ---------------------------------------------------------------------------
# Page 6 — MITRE Coverage Map
# ---------------------------------------------------------------------------

@dashboard_bp.route("/mitre")
def mitre_map():
    try:
        techniques = _load_mitre()
    except Exception:
        techniques = []

    # Count alerts per technique_id
    rows = (
        db.session.query(Alert.mitre_technique_id, func.count(Alert.id))
        .filter(Alert.mitre_technique_id != None)  # noqa: E711
        .group_by(Alert.mitre_technique_id)
        .all()
    )
    counts: dict[str, int] = {r[0]: r[1] for r in rows}

    # Annotate techniques and group by tactic
    by_tactic: dict[str, list[dict]] = {}
    for tech in techniques:
        tech_copy = dict(tech)
        tech_copy["count"] = counts.get(tech["technique_id"], 0)
        tactic = tech["tactic"]
        by_tactic.setdefault(tactic, []).append(tech_copy)

    return render_template(
        "dashboard/mitre_map.html",
        by_tactic=by_tactic,
        counts=counts,
    )
