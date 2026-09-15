"""Unit tests for IngestService.

These tests exercise normalisation logic directly — no real DB session is used.
Fixture files: src/data/sample_alerts.csv and src/data/sample_alerts.json.
"""

import os
import sys
from datetime import datetime

import pytest

# ---------------------------------------------------------------------------
# Ensure the app package is importable when running pytest from the repo root
# or from within src/
# ---------------------------------------------------------------------------
_SRC_DIR = os.path.join(os.path.dirname(__file__), "..")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# We need a minimal Flask app context so the ORM models can be imported
# (Alert uses db = SQLAlchemy(), which requires an app).  We create a
# lightweight in-memory app just for this purpose.
from flask import Flask
from app.extensions import db as _db

_app = Flask(__name__)
_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
_db.init_app(_app)

with _app.app_context():
    _db.create_all()

# Now import the service (models are already registered)
from app.services.ingest import IngestService, COLUMN_ALIASES, EVENT_TYPE_MAP  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
CSV_PATH = os.path.join(DATA_DIR, "sample_alerts.csv")
JSON_PATH = os.path.join(DATA_DIR, "sample_alerts.json")


@pytest.fixture
def svc():
    return IngestService()


# ---------------------------------------------------------------------------
# Test 1 — CSV ingestion: basic load and record count
# ---------------------------------------------------------------------------


def test_csv_ingestion_basic(svc):
    alerts = svc.from_csv(CSV_PATH, feed_name="test_csv")
    assert len(alerts) >= 30, f"Expected ≥30 records, got {len(alerts)}"
    # Spot-check first record has all required common schema keys
    required = {"external_id", "source_feed", "timestamp", "source_ip",
                "dest_ip", "event_type", "severity_raw", "description", "raw_data"}
    assert required.issubset(alerts[0].keys())


# ---------------------------------------------------------------------------
# Test 2 — JSON ingestion: basic load and record count
# ---------------------------------------------------------------------------


def test_json_ingestion_basic(svc):
    alerts = svc.from_json(JSON_PATH, feed_name="test_json")
    assert len(alerts) >= 30, f"Expected ≥30 records, got {len(alerts)}"
    required = {"external_id", "source_feed", "timestamp", "source_ip",
                "dest_ip", "event_type", "severity_raw", "description", "raw_data"}
    assert required.issubset(alerts[0].keys())


# ---------------------------------------------------------------------------
# Test 3 — Column alias mapping: "src_ip" → source_ip
# ---------------------------------------------------------------------------


def test_column_alias_mapping(svc):
    record = {
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "severity": "high",
        "message": "Test alert",
    }
    result = svc.normalise_record(record, feed_name="alias_test")
    assert result["source_ip"] == "1.2.3.4"
    assert result["dest_ip"] == "5.6.7.8"
    assert result["severity_raw"] == "high"
    assert result["description"] == "Test alert"


# ---------------------------------------------------------------------------
# Test 4 — Event type normalisation: "beacon" → "c2"
# ---------------------------------------------------------------------------


def test_event_type_normalisation(svc):
    cases = [
        ("beacon", "c2"),
        ("c&c", "c2"),
        ("command_and_control", "c2"),
        ("ransomware", "malware"),
        ("virus", "malware"),
        ("brute_force", "credential_access"),
        ("password", "credential_access"),
        ("ddos", "dos"),
        ("scan", "recon"),
        ("spearphishing", "phishing"),
        ("data_theft", "exfiltration"),
        ("lateral_movement", "intrusion"),
        ("totally_unknown_thing", "other"),
        ("", "other"),
    ]
    for raw, expected in cases:
        record = {"event_type": raw}
        result = svc.normalise_record(record, feed_name="norm_test")
        assert result["event_type"] == expected, (
            f"Raw '{raw}' should map to '{expected}', got '{result['event_type']}'"
        )


# ---------------------------------------------------------------------------
# Test 5 — Missing IP fields default to "unknown"
# ---------------------------------------------------------------------------


def test_missing_ip_defaults(svc):
    # Record with no IP fields at all
    record = {"external_id": "X-001", "event_type": "malware"}
    result = svc.normalise_record(record, feed_name="missing_ip_test")
    assert result["source_ip"] == "unknown"
    assert result["dest_ip"] == "unknown"

    # Record with explicit None values
    record2 = {"source_ip": None, "dest_ip": None}
    result2 = svc.normalise_record(record2, feed_name="missing_ip_test")
    assert result2["source_ip"] == "unknown"
    assert result2["dest_ip"] == "unknown"


# ---------------------------------------------------------------------------
# Test 6 — Unknown columns land in raw_data
# ---------------------------------------------------------------------------


def test_unknown_columns_in_raw_data(svc):
    record = {
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "my_custom_field": "some_value",
        "another_extra": 42,
    }
    result = svc.normalise_record(record, feed_name="extra_col_test")
    # Unknown keys must be preserved in raw_data
    assert result["raw_data"]["my_custom_field"] == "some_value"
    assert result["raw_data"]["another_extra"] == 42


# ---------------------------------------------------------------------------
# Test 7 — Timestamp parsing produces datetime objects
# ---------------------------------------------------------------------------


def test_timestamp_parsing(svc):
    ts_strings = [
        "2024-01-15 02:14:33",
        "2024-03-10T08:00:00Z",
        "2024-06-01T00:00:00+00:00",
    ]
    for ts in ts_strings:
        record = {"timestamp": ts, "source_ip": "1.1.1.1"}
        result = svc.normalise_record(record, feed_name="ts_test")
        assert isinstance(result["timestamp"], datetime), (
            f"Expected datetime for '{ts}', got {type(result['timestamp'])}"
        )

    # Missing timestamp → None
    record_no_ts = {"source_ip": "1.1.1.1"}
    result_no_ts = svc.normalise_record(record_no_ts, feed_name="ts_test")
    assert result_no_ts["timestamp"] is None
