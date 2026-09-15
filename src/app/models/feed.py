"""Feed ORM model — tracks ingestion sources."""

from datetime import datetime, timezone
from app.extensions import db


class Feed(db.Model):
    __tablename__ = "feeds"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    source_type = db.Column(db.Text, nullable=True)   # csv / json / api_stub
    last_ingested = db.Column(db.DateTime, nullable=True)
    alert_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Feed id={self.id} name={self.name!r} count={self.alert_count}>"
