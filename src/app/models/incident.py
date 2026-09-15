"""Incident and AlertIncident (join) ORM models."""

from datetime import datetime, timezone
from app.extensions import db


# Join table (explicit model so we can query it directly)
class AlertIncident(db.Model):
    __tablename__ = "alert_incidents"

    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), primary_key=True)


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=True)
    priority = db.Column(db.Text, nullable=True)          # HIGH / MEDIUM / LOW
    risk_score = db.Column(db.Float, nullable=True)
    alert_count = db.Column(db.Integer, default=0)
    mitre_techniques = db.Column(db.Text, nullable=True)  # comma-separated IDs
    bluf_summary = db.Column(db.Text, nullable=True)
    bluf_source = db.Column(db.Text, nullable=True)       # "watsonx" or "template"
    status = db.Column(db.Text, default="open")           # open / investigating / closed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship to alerts via join table
    alerts = db.relationship(
        "Alert",
        secondary="alert_incidents",
        back_populates="incidents",
        lazy="dynamic",
    )

    def to_dict(self, include_alert_ids: bool = False) -> dict:
        """Serialise Incident to a JSON-safe dict."""
        d = {
            "id": self.id,
            "title": self.title,
            "priority": self.priority,
            "risk_score": self.risk_score,
            "alert_count": self.alert_count,
            "mitre_techniques": self.mitre_techniques,
            "bluf_summary": self.bluf_summary,
            "bluf_source": self.bluf_source,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_alert_ids:
            try:
                d["alert_ids"] = [a.id for a in self.alerts]
            except Exception:
                d["alert_ids"] = []
        return d

    def __repr__(self):
        return f"<Incident id={self.id} priority={self.priority} title={self.title!r}>"
