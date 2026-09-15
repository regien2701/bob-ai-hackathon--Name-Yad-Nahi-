"""Alert ORM model — maps to the `alerts` table."""

from datetime import datetime, timezone
from app.extensions import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.Text, nullable=True)
    source_feed = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=True)
    source_ip = db.Column(db.Text, nullable=True)
    dest_ip = db.Column(db.Text, nullable=True)
    event_type = db.Column(db.Text, nullable=True)
    severity_raw = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    priority = db.Column(db.Text, nullable=True)          # HIGH / MEDIUM / LOW
    is_false_positive = db.Column(db.Boolean, default=False)
    fp_reason = db.Column(db.Text, nullable=True)
    mitre_technique_id = db.Column(db.Text, nullable=True)
    mitre_technique_name = db.Column(db.Text, nullable=True)
    raw_data = db.Column(db.JSON, nullable=True)
    score_breakdown = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to incidents via join table
    incidents = db.relationship(
        "Incident",
        secondary="alert_incidents",
        back_populates="alerts",
        lazy="dynamic",
    )

    def to_dict(self) -> dict:
        """Serialise Alert to a JSON-safe dict."""
        return {
            "id": self.id,
            "external_id": self.external_id,
            "source_feed": self.source_feed,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
            "severity_raw": self.severity_raw,
            "description": self.description,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "is_false_positive": self.is_false_positive,
            "fp_reason": self.fp_reason,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "score_breakdown": self.score_breakdown,
            "raw_data": self.raw_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Alert id={self.id} priority={self.priority} score={self.risk_score}>"
