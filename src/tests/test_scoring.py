"""Unit tests for ScoringEngine and FPDetector.

Run with:  pytest src/tests/test_scoring.py -v
"""

import os
import sys
from datetime import datetime, timezone

import pytest

# ---------------------------------------------------------------------------
# Make the app package importable from any working directory
# ---------------------------------------------------------------------------
_SRC_DIR = os.path.join(os.path.dirname(__file__), "..")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# Minimal Flask app context so ORM models can be imported
from flask import Flask
from app.extensions import db as _db

_app = Flask(__name__)
_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
_db.init_app(_app)

with _app.app_context():
    _db.create_all()

from app.services.scoring import ScoringEngine  # noqa: E402
from app.services.fp_detector import FPDetector  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(**kwargs) -> dict:
    """Return a minimal CommonAlert dict, overridable via kwargs."""
    base = {
        "external_id": "test-001",
        "source_feed": "test",
        "timestamp": "2024-01-01T00:00:00+00:00",
        "source_ip": "192.0.2.1",
        "dest_ip": "203.0.113.5",
        "event_type": "other",
        "severity_raw": "low",
        "description": "",
        "raw_data": {},
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# ScoringEngine tests
# ---------------------------------------------------------------------------


def test_critical_c2_scores_high():
    """Test 1 — critical severity + c2 event_type + private dest → score ≥ 70, priority HIGH.

    critical(30) + c2(25) + private_dest(10) = 65 with a generic private IP;
    using a critical-dest pattern (10.10.0.x) adds 20 → total 75 ≥ 70.
    """
    engine = ScoringEngine()
    # dest_ip matches CRITICAL_DEST_PATTERNS prefix "10.10.0." → +20 dest sensitivity
    alert = make_alert(
        severity_raw="critical",
        event_type="c2",
        dest_ip="10.10.0.50",
    )
    score, _ = engine.score(alert)
    assert score >= 70, f"Expected score ≥ 70, got {score}"
    assert engine.classify(score) == "HIGH"


def test_info_recon_scores_low():
    """Test 2 — informational severity + recon event_type → score ≤ 30."""
    engine = ScoringEngine()
    alert = make_alert(severity_raw="informational", event_type="recon")
    score, _ = engine.score(alert)
    assert score <= 30, f"Expected score ≤ 30, got {score}"


def test_classification_thresholds():
    """Test 3 — scores exactly at thresholds map to correct priority labels."""
    engine = ScoringEngine(high_threshold=70, medium_threshold=40)
    assert engine.classify(70) == "HIGH"
    assert engine.classify(69.9) == "MEDIUM"
    assert engine.classify(40) == "MEDIUM"
    assert engine.classify(39.9) == "LOW"
    assert engine.classify(0) == "LOW"


def test_score_clamped_to_100():
    """Test 4 — maximising every factor cannot produce a score above 100."""
    engine = ScoringEngine()
    # critical(30) + c2(25) + critical_dest(20) + recurrence≥5(15) + 3 keywords(10) = 100
    alert = make_alert(
        severity_raw="critical",
        event_type="c2",
        dest_ip="10.10.0.5",
        description="mimikatz lsass admin dump privilege escalat",
    )
    score, _ = engine.score(alert, recent_same_src=5)
    assert score <= 100.0, f"Score must be ≤ 100, got {score}"


def test_score_breakdown_has_all_keys():
    """Test 5 — breakdown dict always contains all required keys."""
    engine = ScoringEngine()
    alert = make_alert(severity_raw="medium", event_type="malware")
    score, breakdown = engine.score(alert)
    required_keys = {"severity", "event_type", "dest_sensitivity", "recurrence", "keywords", "total"}
    assert required_keys == set(breakdown.keys()), (
        f"Missing keys: {required_keys - set(breakdown.keys())}"
    )
    assert breakdown["total"] == score


# ---------------------------------------------------------------------------
# FPDetector tests
# ---------------------------------------------------------------------------


def test_fp_whitelisted_source():
    """Test 6 — source_ip in whitelist → is_fp=True, correct reason."""
    detector = FPDetector(whitelist_ips=["10.1.1.1"])
    alert = make_alert(source_ip="10.1.1.1", severity_raw="high", event_type="c2")
    is_fp, reason = detector.check(alert)
    assert is_fp is True
    assert reason == "Source IP is whitelisted"


def test_fp_whitelisted_dest():
    """Extra — dest_ip in whitelist → is_fp=True."""
    detector = FPDetector(whitelist_ips=["10.1.1.2"])
    alert = make_alert(dest_ip="10.1.1.2", severity_raw="high", event_type="c2")
    is_fp, reason = detector.check(alert)
    assert is_fp is True
    assert reason == "Destination IP is whitelisted"


def test_fp_informational_recon():
    """Test 7 — informational severity + recon event_type → is_fp=True (noise rule)."""
    detector = FPDetector(whitelist_ips=[])
    alert = make_alert(severity_raw="informational", event_type="recon")
    is_fp, reason = detector.check(alert)
    assert is_fp is True
    assert reason == "Informational recon — noise"


def test_fp_low_score():
    """Test 8 — risk_score < 10 → is_fp=True, reason mentions threshold."""
    detector = FPDetector(whitelist_ips=[])
    alert = make_alert(severity_raw="low", event_type="other")
    is_fp, reason = detector.check(alert, risk_score=5)
    assert is_fp is True
    assert reason == "Risk score below minimum threshold"


def test_fp_duplicate():
    """Test 9 — same src+dst+event_type within 60 s window → is_fp=True."""
    detector = FPDetector(whitelist_ips=[], scanner_cidr="")
    ts1 = "2024-01-01T12:00:00+00:00"
    ts2 = "2024-01-01T12:00:30+00:00"  # 30 seconds later — within window

    alert = make_alert(
        source_ip="10.0.0.5",
        dest_ip="10.0.0.10",
        event_type="recon",
        severity_raw="medium",
        timestamp=ts2,
    )
    recent = [
        make_alert(
            source_ip="10.0.0.5",
            dest_ip="10.0.0.10",
            event_type="recon",
            severity_raw="medium",
            timestamp=ts1,
        )
    ]
    is_fp, reason = detector.check(alert, recent_alerts=recent, risk_score=50)
    assert is_fp is True
    assert reason == "Duplicate within 60 s"


def test_fp_not_triggered_for_normal_alert():
    """Sanity — a normal high-severity alert with no FP conditions → is_fp=False."""
    detector = FPDetector(whitelist_ips=[], scanner_cidr=None)
    alert = make_alert(
        source_ip="192.0.2.50",
        dest_ip="10.10.0.1",
        severity_raw="high",
        event_type="c2",
    )
    is_fp, reason = detector.check(alert, risk_score=75)
    assert is_fp is False
    assert reason == ""


def test_fp_scanner_cidr():
    """FP-4 — source_ip inside scanner CIDR → is_fp=True."""
    detector = FPDetector(whitelist_ips=[], scanner_cidr="10.99.0.0/24")
    alert = make_alert(source_ip="10.99.0.15", severity_raw="high", event_type="recon")
    is_fp, reason = detector.check(alert, risk_score=80)
    assert is_fp is True
    assert reason == "Known internal scanner"


def test_score_recurrence_factors():
    """Recurrence factor: ≥5 → 15, ≥2 → 8, <2 → 0."""
    engine = ScoringEngine()
    alert = make_alert(severity_raw="low", event_type="other", dest_ip="8.8.8.8")
    _, bd0 = engine.score(alert, recent_same_src=0)
    _, bd2 = engine.score(alert, recent_same_src=2)
    _, bd5 = engine.score(alert, recent_same_src=5)
    assert bd0["recurrence"] == 0.0
    assert bd2["recurrence"] == 8.0
    assert bd5["recurrence"] == 15.0


def test_keyword_scoring():
    """Keywords factor: ≥3 keywords → 10, ≥1 → 5, 0 → 0."""
    engine = ScoringEngine()
    alert_none = make_alert(description="benign traffic observed")
    alert_one = make_alert(description="admin login attempt detected")
    alert_three = make_alert(description="admin lsass dump detected on dc01")

    _, bd_none = engine.score(alert_none)
    _, bd_one = engine.score(alert_one)
    _, bd_three = engine.score(alert_three)

    assert bd_none["keywords"] == 0.0
    assert bd_one["keywords"] == 5.0
    assert bd_three["keywords"] == 10.0
