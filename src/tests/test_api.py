"""API integration tests — exercises every /api/v1/ endpoint via Flask test client."""

import io
import os
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db as _db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def app():
    """Create a fresh application with an in-memory DB for each test."""
    application = create_app(TestConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    """Return a test client bound to the application fixture."""
    with app.test_client() as c:
        yield c


@pytest.fixture(scope="function")
def client_with_data(client):
    """Test client that has already loaded sample data."""
    resp = client.post("/api/v1/alerts/sample")
    assert resp.status_code == 200, resp.get_json()
    yield client


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _json(resp):
    """Return parsed JSON from a response object."""
    return resp.get_json()


# ---------------------------------------------------------------------------
# Test 1 — GET /api/v1/stats returns 200 with expected keys (all zero)
# ---------------------------------------------------------------------------

def test_stats_empty(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = _json(resp)
    for key in ("total_alerts", "fp_count", "fp_rate", "high_incidents", "open_incidents"):
        assert key in data, f"Missing key: {key}"
    assert data["total_alerts"] == 0
    assert data["high_incidents"] == 0
    assert data["open_incidents"] == 0


# ---------------------------------------------------------------------------
# Test 2 — POST /api/v1/alerts/sample loads ≥ 30 alerts
# ---------------------------------------------------------------------------

def test_load_sample_data(client):
    resp = client.post("/api/v1/alerts/sample")
    assert resp.status_code == 200
    data = _json(resp)
    assert data.get("status") == "ok"
    assert data.get("alerts_ingested", 0) >= 30, (
        f"Expected ≥ 30 alerts ingested, got {data.get('alerts_ingested')}"
    )


# ---------------------------------------------------------------------------
# Test 3 — GET /api/v1/alerts returns non-empty list after sample load
# ---------------------------------------------------------------------------

def test_list_alerts_after_sample(client_with_data):
    resp = client_with_data.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = _json(resp)
    assert "items" in data
    assert len(data["items"]) > 0
    assert "total" in data
    assert data["total"] > 0


# ---------------------------------------------------------------------------
# Test 4 — GET /api/v1/alerts/1 returns risk_score and mitre_technique_id
# ---------------------------------------------------------------------------

def test_get_alert_detail(client_with_data):
    resp = client_with_data.get("/api/v1/alerts/1")
    assert resp.status_code == 200
    data = _json(resp)
    assert "risk_score" in data
    assert "mitre_technique_id" in data
    assert data["id"] == 1


# ---------------------------------------------------------------------------
# Test 5 — GET /api/v1/incidents returns non-empty list after sample load
# ---------------------------------------------------------------------------

def test_list_incidents(client_with_data):
    resp = client_with_data.get("/api/v1/incidents")
    assert resp.status_code == 200
    data = _json(resp)
    assert "items" in data
    assert len(data["items"]) > 0


# ---------------------------------------------------------------------------
# Test 6 — GET /api/v1/incidents/1 includes bluf_summary
# ---------------------------------------------------------------------------

def test_get_incident_detail(client_with_data):
    resp = client_with_data.get("/api/v1/incidents/1")
    assert resp.status_code == 200
    data = _json(resp)
    assert "bluf_summary" in data
    assert data["bluf_summary"]  # non-empty string
    assert "alert_ids" in data


# ---------------------------------------------------------------------------
# Test 7 — POST /api/v1/alerts/upload with a CSV file returns 200
# ---------------------------------------------------------------------------

def test_upload_csv_file(client):
    csv_content = (
        "alert_id,source_ip,dest_ip,event_type,severity,description,timestamp\n"
        "TEST-001,192.168.1.10,10.0.0.1,malware,high,Test malware alert,2024-01-01T00:00:00Z\n"
        "TEST-002,192.168.1.11,10.0.0.2,phishing,medium,Test phishing alert,2024-01-01T01:00:00Z\n"
    )
    data = {
        "file": (io.BytesIO(csv_content.encode()), "test_upload.csv"),
    }
    resp = client.post(
        "/api/v1/alerts/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = _json(resp)
    assert result.get("status") == "ok"
    assert result.get("alerts_ingested", 0) >= 1


# ---------------------------------------------------------------------------
# Test 8 — DELETE /api/v1/alerts/all clears all data, then stats are zero
# ---------------------------------------------------------------------------

def test_delete_all(client_with_data):
    # Confirm data is present first
    stats_before = _json(client_with_data.get("/api/v1/stats"))
    assert stats_before["total_alerts"] > 0

    # Delete all
    resp = client_with_data.delete("/api/v1/alerts/all")
    assert resp.status_code == 200
    assert _json(resp).get("status") == "cleared"

    # Stats should now be zero
    stats_after = _json(client_with_data.get("/api/v1/stats"))
    assert stats_after["total_alerts"] == 0
    assert stats_after["high_incidents"] == 0
    assert stats_after["open_incidents"] == 0


# ---------------------------------------------------------------------------
# Test 9 — GET /api/v1/mitre/coverage returns non-empty list
# ---------------------------------------------------------------------------

def test_mitre_coverage(client_with_data):
    resp = client_with_data.get("/api/v1/mitre/coverage")
    assert resp.status_code == 200
    data = _json(resp)
    assert isinstance(data, list)
    assert len(data) > 0
    # Each entry must have required keys
    for entry in data[:5]:
        assert "technique_id" in entry
        assert "technique_name" in entry
        assert "tactic" in entry
        assert "count" in entry


# ---------------------------------------------------------------------------
# Test 10 — GET /api/v1/alerts?priority=HIGH returns only HIGH alerts
# ---------------------------------------------------------------------------

def test_priority_filter(client_with_data):
    resp = client_with_data.get("/api/v1/alerts?priority=HIGH&per_page=200")
    assert resp.status_code == 200
    data = _json(resp)
    items = data.get("items", [])
    # If there are HIGH alerts, every returned item must be HIGH
    for alert in items:
        assert alert["priority"] == "HIGH", (
            f"Expected HIGH, got {alert['priority']} for alert id={alert['id']}"
        )
