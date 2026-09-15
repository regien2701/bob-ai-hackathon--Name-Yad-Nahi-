"""REST API routes — all endpoints under /api/v1/."""

import os
import uuid

from flask import Blueprint, jsonify, request, current_app
from sqlalchemy import func

from app.extensions import db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.alert import Alert as _Alert
from app.models.incident import AlertIncident

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


# ---------------------------------------------------------------------------
# POST /api/v1/alerts/upload
# ---------------------------------------------------------------------------

@api_bp.route("/alerts/upload", methods=["POST"])
def upload_alerts():
    """Accept a multipart file upload (CSV or JSON) and run the full pipeline."""
    from app.services.ingest import run_pipeline  # local import avoids circular dep

    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    if not f or f.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = f.filename or ""
    ext = os.path.splitext(filename)[1].lower()
    content_type = (f.content_type or "").lower()

    if ext == ".csv" or "csv" in content_type:
        file_type = "csv"
    elif ext == ".json" or "json" in content_type:
        file_type = "json"
    else:
        return jsonify({"error": f"Unsupported file type: {ext!r}. Use .csv or .json"}), 400

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    save_path = os.path.join(upload_dir, f"{uuid.uuid4().hex}_{filename}")
    f.save(save_path)

    feed_name = request.form.get("feed_name") or os.path.splitext(filename)[0]

    try:
        summary = run_pipeline(save_path, feed_name, file_type, db.session)
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Pipeline error during upload")
        return jsonify({"error": str(exc)}), 500
    finally:
        try:
            os.remove(save_path)
        except OSError:
            pass

    return jsonify({"status": "ok", **summary}), 200


# ---------------------------------------------------------------------------
# POST /api/v1/alerts/sample
# ---------------------------------------------------------------------------

@api_bp.route("/alerts/sample", methods=["POST"])
def load_sample():
    """Load the built-in sample_alerts.csv through the full pipeline."""
    from app.services.ingest import run_pipeline  # local import

    data_dir = os.path.join(current_app.root_path, "..", "data")
    sample_path = os.path.abspath(os.path.join(data_dir, "sample_alerts.csv"))

    if not os.path.exists(sample_path):
        return jsonify({"error": "Sample data file not found"}), 500

    try:
        summary = run_pipeline(sample_path, "sample", "csv", db.session)
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Pipeline error loading sample data")
        return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "ok", **summary}), 200


# ---------------------------------------------------------------------------
# GET /api/v1/alerts
# ---------------------------------------------------------------------------

@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """Return a paginated list of alerts with optional filters."""
    priority = request.args.get("priority", "")
    feed = request.args.get("feed", "")
    fp = request.args.get("fp", "")          # "true" / "false" / ""
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    query = db.session.query(Alert)
    if priority:
        query = query.filter(Alert.priority == priority.upper())
    if feed:
        query = query.filter(Alert.source_feed == feed)
    if fp == "true":
        query = query.filter(Alert.is_false_positive == True)  # noqa: E712
    elif fp == "false":
        query = query.filter(Alert.is_false_positive == False)  # noqa: E712

    pagination = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "items": [a.to_dict() for a in pagination.items],
        "page": pagination.page,
        "per_page": per_page,
        "total": pagination.total,
        "pages": pagination.pages,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/v1/alerts/<alert_id>
# ---------------------------------------------------------------------------

@api_bp.route("/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    """Return a single alert including score_breakdown and raw_data."""
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert.to_dict()), 200


# ---------------------------------------------------------------------------
# GET /api/v1/incidents
# ---------------------------------------------------------------------------

@api_bp.route("/incidents", methods=["GET"])
def list_incidents():
    """Return a paginated list of incidents with optional filters."""
    priority = request.args.get("priority", "")
    status = request.args.get("status", "")
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)

    query = db.session.query(Incident)
    if priority:
        query = query.filter(Incident.priority == priority.upper())
    if status:
        query = query.filter(Incident.status == status.lower())

    pagination = query.order_by(Incident.risk_score.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "items": [inc.to_dict() for inc in pagination.items],
        "page": pagination.page,
        "per_page": per_page,
        "total": pagination.total,
        "pages": pagination.pages,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/<incident_id>
# ---------------------------------------------------------------------------

@api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
def get_incident(incident_id):
    """Return a single incident including its constituent alert IDs."""
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident.to_dict(include_alert_ids=True)), 200


# ---------------------------------------------------------------------------
# POST /api/v1/incidents/<incident_id>/bluf
# ---------------------------------------------------------------------------

@api_bp.route("/incidents/<int:incident_id>/bluf", methods=["POST"])
def regenerate_bluf(incident_id):
    """Re-generate the BLUF summary for an incident."""
    from app.services.bluf import BLUFService  # local import

    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found"}), 404

    bluf_service = BLUFService()
    bluf_text, bluf_source = bluf_service.generate(incident)
    incident.bluf_summary = bluf_text
    incident.bluf_source = bluf_source
    db.session.commit()

    return jsonify({"bluf_summary": bluf_text, "bluf_source": bluf_source}), 200


# ---------------------------------------------------------------------------
# GET /api/v1/stats
# ---------------------------------------------------------------------------

@api_bp.route("/stats", methods=["GET"])
def get_stats():
    """Return KPI counts for the dashboard summary cards."""
    total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
    fp_count = (
        db.session.query(func.count(Alert.id))
        .filter(Alert.is_false_positive == True)  # noqa: E712
        .scalar() or 0
    )
    high_incidents = (
        db.session.query(func.count(Incident.id))
        .filter(Incident.priority == "HIGH")
        .scalar() or 0
    )
    open_incidents = (
        db.session.query(func.count(Incident.id))
        .filter(Incident.status == "open")
        .scalar() or 0
    )
    fp_rate = round((fp_count / total_alerts * 100), 2) if total_alerts else 0.0

    return jsonify({
        "total_alerts": total_alerts,
        "fp_count": fp_count,
        "fp_rate": fp_rate,
        "high_incidents": high_incidents,
        "open_incidents": open_incidents,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/v1/mitre/coverage
# ---------------------------------------------------------------------------

@api_bp.route("/mitre/coverage", methods=["GET"])
def mitre_coverage():
    """Return per-technique alert counts for the MITRE coverage map."""
    import json

    # Load technique metadata
    data_dir = os.path.join(current_app.root_path, "..", "data")
    mitre_path = os.path.join(data_dir, "mitre_techniques.json")
    try:
        with open(mitre_path, "r", encoding="utf-8") as fh:
            techniques = json.load(fh)
    except Exception:
        techniques = []

    # Build a lookup from technique_id → metadata
    tech_meta: dict[str, dict] = {t["technique_id"]: t for t in techniques}

    # Count alerts per technique_id from the DB
    rows = (
        db.session.query(Alert.mitre_technique_id, func.count(Alert.id))
        .filter(Alert.mitre_technique_id != None)  # noqa: E711
        .group_by(Alert.mitre_technique_id)
        .all()
    )

    coverage = []
    for tech_id, count in rows:
        meta = tech_meta.get(tech_id, {})
        coverage.append({
            "technique_id": tech_id,
            "technique_name": meta.get("technique_name", tech_id),
            "tactic": meta.get("tactic", "Unknown"),
            "count": count,
        })

    # Also include techniques in the JSON with zero hits (for completeness)
    seen = {r["technique_id"] for r in coverage}
    for tech in techniques:
        if tech["technique_id"] not in seen:
            coverage.append({
                "technique_id": tech["technique_id"],
                "technique_name": tech["technique_name"],
                "tactic": tech["tactic"],
                "count": 0,
            })

    coverage.sort(key=lambda x: (-x["count"], x["technique_id"]))
    return jsonify(coverage), 200


# ---------------------------------------------------------------------------
# DELETE /api/v1/alerts/all
# ---------------------------------------------------------------------------

@api_bp.route("/alerts/all", methods=["DELETE"])
def delete_all():
    """Delete all alerts, incidents, join records, and feeds — demo reset."""
    from app.models.feed import Feed  # local import to avoid circularity

    db.session.query(AlertIncident).delete()
    db.session.query(Alert).delete()
    db.session.query(Incident).delete()
    db.session.query(Feed).delete()
    db.session.commit()

    return jsonify({"status": "cleared"}), 200
