"""Ingestion service — normalises CSV and JSON uploads into CommonAlert dicts
and persists them to the ``alerts`` table via the ORM.
"""

import json
import uuid
from datetime import datetime, timezone

import pandas as pd

from app.models.alert import Alert
from app.models.feed import Feed
from app.services.scoring import ScoringEngine
from app.services.fp_detector import FPDetector
from app.services.mitre import MITREMapper

_scoring_engine = ScoringEngine()
_fp_detector = FPDetector()
_mitre_mapper = MITREMapper()

# ---------------------------------------------------------------------------
# Column alias mapping
# ---------------------------------------------------------------------------

COLUMN_ALIASES: dict[str, str] = {
    # external_id aliases
    "alert_id": "external_id",
    "id": "external_id",
    "event_id": "external_id",
    "alertid": "external_id",
    # source_feed aliases
    "feed": "source_feed",
    "source": "source_feed",
    "sensor": "source_feed",
    # timestamp aliases
    "time": "timestamp",
    "datetime": "timestamp",
    "event_time": "timestamp",
    "occurred": "timestamp",
    # source_ip aliases
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "attacker_ip": "source_ip",
    "origin_ip": "source_ip",
    # dest_ip aliases
    "dst_ip": "dest_ip",
    "dstip": "dest_ip",
    "destination_ip": "dest_ip",
    "target_ip": "dest_ip",
    # event_type aliases
    "type": "event_type",
    "category": "event_type",
    "alert_type": "event_type",
    "event_category": "event_type",
    # severity_raw aliases
    "severity": "severity_raw",
    "level": "severity_raw",
    "risk_level": "severity_raw",
    "priority": "severity_raw",
    # description aliases
    "message": "description",
    "details": "description",
    "alert_description": "description",
    "summary": "description",
}

# ---------------------------------------------------------------------------
# Event-type normalisation map  { canonical: [accepted aliases …] }
# ---------------------------------------------------------------------------

EVENT_TYPE_MAP: dict[str, list[str]] = {
    "malware": ["malware", "virus", "trojan", "ransomware", "worm"],
    "intrusion": ["intrusion", "breach", "lateral_movement", "lateral movement"],
    "phishing": ["phishing", "spearphishing", "spear-phishing", "spear_phishing"],
    "recon": ["recon", "scan", "discovery", "reconnaissance"],
    "c2": ["c2", "command_and_control", "command and control", "beacon", "c&c"],
    "exfiltration": ["exfiltration", "data_theft", "data theft", "data exfil"],
    "dos": ["dos", "ddos", "denial_of_service", "denial of service"],
    "credential_access": [
        "credential_access",
        "credential access",
        "brute_force",
        "brute force",
        "password",
        "credential",
    ],
    "other": [],  # fallback
}

# Build reverse lookup  { alias_lower: canonical }
_EVENT_TYPE_LOOKUP: dict[str, str] = {}
for _canonical, _aliases in EVENT_TYPE_MAP.items():
    for _alias in _aliases:
        _EVENT_TYPE_LOOKUP[_alias.lower()] = _canonical
    _EVENT_TYPE_LOOKUP[_canonical.lower()] = _canonical  # canonical maps to itself

# Common schema fields (used to separate known from unknown keys)
_SCHEMA_FIELDS = frozenset(
    {
        "external_id",
        "source_feed",
        "timestamp",
        "source_ip",
        "dest_ip",
        "event_type",
        "severity_raw",
        "description",
        "raw_data",
    }
)


# ---------------------------------------------------------------------------
# IngestService
# ---------------------------------------------------------------------------


class IngestService:
    """Converts raw CSV/JSON files into CommonAlert dicts and persists them."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def from_csv(self, filepath: str, feed_name: str | None = None) -> list[dict]:
        """Read a CSV file and return a list of CommonAlert dicts."""
        df = pd.read_csv(filepath, dtype=str)
        # Rename columns according to alias map (only columns that exist)
        rename_map = {col: COLUMN_ALIASES[col] for col in df.columns if col in COLUMN_ALIASES}
        df = df.rename(columns=rename_map)
        records = df.where(pd.notna(df), None).to_dict(orient="records")
        _feed = feed_name or "csv_upload"
        return [self.normalise_record(r, _feed) for r in records]

    def from_json(self, filepath: str, feed_name: str | None = None) -> list[dict]:
        """Read a JSON array file and return a list of CommonAlert dicts."""
        with open(filepath, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            # Support {"alerts": [...]} envelope
            raw = raw.get("alerts", raw.get("data", list(raw.values())[0]))
        _feed = feed_name or "json_upload"
        return [self.normalise_record(self._apply_aliases(r), _feed) for r in raw]

    def normalise_record(self, record: dict, feed_name: str) -> dict:
        """Map raw field names to common schema and normalise values.

        Parameters
        ----------
        record:
            A dict whose keys have already been renamed via ``COLUMN_ALIASES``
            (as done by ``from_csv``), or a raw dict whose keys are yet to be
            renamed (as done by ``from_json`` via ``_apply_aliases`` first).
        feed_name:
            The name to assign to ``source_feed`` when not present in the record.
        """
        # Keep the full original record before any mutation
        raw_data: dict = dict(record)

        # Apply alias mapping in case the caller passes a raw record
        record = self._apply_aliases(record)

        common: dict = {
            "external_id": str(record.get("external_id") or uuid.uuid4()),
            "source_feed": str(record.get("source_feed") or feed_name),
            "timestamp": self._parse_timestamp(record.get("timestamp")),
            "source_ip": str(record.get("source_ip") or "unknown"),
            "dest_ip": str(record.get("dest_ip") or "unknown"),
            "event_type": self._normalise_event_type(record.get("event_type")),
            "severity_raw": str(record.get("severity_raw") or ""),
            "description": str(record.get("description") or ""),
            "raw_data": raw_data,
        }

        # Merge any unknown fields into raw_data (they're already there via raw_data = dict(record))
        return common

    def save_alerts(self, common_alerts: list[dict], session) -> list[Alert]:
        """Persist CommonAlert dicts as Alert ORM objects.

        Scoring and FP detection are applied to each alert before persistence.
        Creates or updates the Feed record for each unique ``source_feed``.
        Does NOT commit — the caller is responsible for committing the session.

        Parameters
        ----------
        common_alerts:
            List of dicts produced by ``from_csv`` / ``from_json``.
        session:
            An active SQLAlchemy session.

        Returns
        -------
        list[Alert]
            The newly created Alert ORM objects (not yet committed).
        """
        alert_objects: list[Alert] = []
        feed_counts: dict[str, int] = {}

        for ca in common_alerts:
            # Convert ISO timestamp string back to datetime if needed
            ts = ca.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = None

            # --- Scoring ---
            risk_score, breakdown = _scoring_engine.score(ca)
            priority = _scoring_engine.classify(risk_score)

            # --- FP detection (FP-6 requires the score computed above) ---
            is_fp, fp_reason = _fp_detector.check(
                ca,
                recent_alerts=None,
                risk_score=risk_score,
            )

            # --- MITRE ATT&CK mapping (applied to all alerts, including FPs) ---
            mitre_id, mitre_name = _mitre_mapper.map(ca)

            alert = Alert(
                external_id=ca.get("external_id"),
                source_feed=ca.get("source_feed"),
                timestamp=ts,
                source_ip=ca.get("source_ip"),
                dest_ip=ca.get("dest_ip"),
                event_type=ca.get("event_type"),
                severity_raw=ca.get("severity_raw"),
                description=ca.get("description"),
                raw_data=ca.get("raw_data"),
                risk_score=risk_score,
                priority=priority,
                is_false_positive=is_fp,
                fp_reason=fp_reason or None,
                mitre_technique_id=mitre_id,
                mitre_technique_name=mitre_name,
                score_breakdown=breakdown,
            )
            session.add(alert)
            alert_objects.append(alert)

            feed_name = ca.get("source_feed") or "unknown"
            feed_counts[feed_name] = feed_counts.get(feed_name, 0) + 1

        # Create / update Feed records
        now = datetime.now(timezone.utc)
        for feed_name, count in feed_counts.items():
            feed = session.query(Feed).filter_by(name=feed_name).first()
            if feed is None:
                feed = Feed(name=feed_name, source_type="csv", alert_count=0)
                session.add(feed)
            feed.last_ingested = now
            feed.alert_count = (feed.alert_count or 0) + count

        return alert_objects

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_aliases(record: dict) -> dict:
        """Return a new dict with column names replaced by their canonical aliases."""
        result: dict = {}
        for key, value in record.items():
            canonical = COLUMN_ALIASES.get(key, key)
            # If both the alias and the canonical name exist, canonical wins
            if canonical not in result:
                result[canonical] = value
            else:
                result[key] = value
        return result

    @staticmethod
    def _normalise_event_type(raw: object) -> str:
        """Return the canonical event_type for *raw*, or 'other' if unrecognised."""
        if not raw:
            return "other"
        return _EVENT_TYPE_LOOKUP.get(str(raw).strip().lower(), "other")

    @staticmethod
    def _parse_timestamp(raw: object) -> datetime | None:
        """Parse *raw* into a timezone-aware datetime, or return None."""
        if raw is None:
            return None
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        try:
            dt = pd.to_datetime(str(raw), utc=True).to_pydatetime()
            return dt
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Pipeline entry-point
# ---------------------------------------------------------------------------

_ingest_service = IngestService()


def run_pipeline(filepath: str, feed_name: str, file_type: str, db_session) -> dict:
    """Full ingestion pipeline: parse → score/FP → MITRE → correlate.

    Parameters
    ----------
    filepath:
        Absolute or relative path to the data file.
    feed_name:
        Human-readable feed label (stored on the Feed record).
    file_type:
        ``"csv"`` or ``"json"``.
    db_session:
        Active SQLAlchemy session.  **Committed by this function.**

    Returns
    -------
    dict with keys:
        alerts_ingested, false_positives, incidents_created,
        high_count, medium_count, low_count
    """
    from app.services.correlation import CorrelationEngine  # local import avoids circular dep
    from app.services.bluf import BLUFService  # local import avoids circular dep

    # 1. Parse
    if file_type == "csv":
        common_alerts = _ingest_service.from_csv(filepath, feed_name)
    else:
        common_alerts = _ingest_service.from_json(filepath, feed_name)

    # 2. Score + FP + MITRE → persist Alert rows
    alert_objects = _ingest_service.save_alerts(common_alerts, db_session)
    db_session.flush()  # assign IDs without committing

    # 3. Correlate
    engine = CorrelationEngine()
    incidents = engine.correlate(alert_objects, db_session)

    # 4. BLUF generation — populate bluf_summary / bluf_source on every incident
    bluf_service = BLUFService()
    for incident in incidents:
        bluf_text, bluf_source = bluf_service.generate(incident)
        incident.bluf_summary = bluf_text
        incident.bluf_source = bluf_source

    # 5. Commit everything in one transaction
    db_session.commit()

    # 6. Build summary
    false_positives = sum(1 for a in alert_objects if a.is_false_positive)
    high_count = sum(1 for a in alert_objects if a.priority == "HIGH")
    medium_count = sum(1 for a in alert_objects if a.priority == "MEDIUM")
    low_count = sum(1 for a in alert_objects if a.priority == "LOW")

    return {
        "alerts_ingested": len(alert_objects),
        "false_positives": false_positives,
        "incidents_created": len(incidents),
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
    }
