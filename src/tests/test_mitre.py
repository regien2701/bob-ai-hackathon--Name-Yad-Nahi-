"""Unit tests for MITREMapper.

Run with:  pytest src/tests/test_mitre.py -v
"""

import json
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Make the app package importable from any working directory
# (conftest.py also does this, but guard here for direct pytest invocation)
# ---------------------------------------------------------------------------
_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from app.services.mitre import FALLBACK_TECHNIQUE_ID, FALLBACK_TECHNIQUE_NAME, MITREMapper

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
_TECHNIQUES_FILE = os.path.join(_DATA_DIR, "mitre_techniques.json")
_SAMPLE_ALERTS_FILE = os.path.join(_DATA_DIR, "sample_alerts.json")


@pytest.fixture(scope="module")
def mapper():
    """Shared MITREMapper instance loaded from the real techniques file."""
    return MITREMapper(_TECHNIQUES_FILE)


# ---------------------------------------------------------------------------
# Test 1 — load_techniques
# ---------------------------------------------------------------------------


def test_load_techniques(mapper):
    """load_techniques() returns ≥25 entries each with the required keys."""
    techniques = mapper.techniques
    assert len(techniques) >= 25, f"Expected ≥25 techniques, got {len(techniques)}"
    required_keys = {"technique_id", "technique_name", "tactic", "keywords"}
    for t in techniques:
        missing = required_keys - t.keys()
        assert not missing, f"Technique {t.get('technique_id')} is missing keys: {missing}"
        assert isinstance(t["keywords"], list), "keywords must be a list"
        assert len(t["keywords"]) > 0, f"Technique {t['technique_id']} has no keywords"


# ---------------------------------------------------------------------------
# Test 2 — C2 beacon → T1071
# ---------------------------------------------------------------------------


def test_c2_beacon_maps_to_T1071(mapper):
    """A C2 beacon alert maps to T1071 (Application Layer Protocol)."""
    alert = {
        "event_type": "c2",
        "description": "beacon traffic C2 domain",
    }
    technique_id, technique_name = mapper.map(alert)
    assert technique_id == "T1071", (
        f"Expected T1071 for C2 beacon alert, got {technique_id} ({technique_name})"
    )


# ---------------------------------------------------------------------------
# Test 3 — phishing → T1566
# ---------------------------------------------------------------------------


def test_phishing_maps_correctly(mapper):
    """A phishing alert maps to T1566 (Phishing)."""
    alert = {
        "event_type": "phishing",
        "description": "spear-phishing email with malicious attachment sent to finance team",
    }
    technique_id, technique_name = mapper.map(alert)
    assert technique_id == "T1566", (
        f"Expected T1566 for phishing alert, got {technique_id} ({technique_name})"
    )


# ---------------------------------------------------------------------------
# Test 4 — no match → fallback T0000
# ---------------------------------------------------------------------------


def test_no_match_returns_fallback(mapper):
    """An alert whose text matches no keywords returns the T0000 fallback."""
    alert = {
        "event_type": "other",
        "description": "xyz123 unrecognised gibberish foobar",
    }
    technique_id, technique_name = mapper.map(alert)
    assert technique_id == FALLBACK_TECHNIQUE_ID, (
        f"Expected fallback {FALLBACK_TECHNIQUE_ID}, got {technique_id}"
    )
    assert technique_name == FALLBACK_TECHNIQUE_NAME


# ---------------------------------------------------------------------------
# Test 5 — malware / ransomware → T1486
# ---------------------------------------------------------------------------


def test_malware_maps_to_execution_or_impact(mapper):
    """A ransomware alert maps to T1486 (Data Encrypted for Impact)."""
    alert = {
        "event_type": "malware",
        "description": "ransomware encrypt files on all network shares",
    }
    technique_id, technique_name = mapper.map(alert)
    # T1486 is the most specific match for ransomware + encrypt
    assert technique_id == "T1486", (
        f"Expected T1486 for ransomware/encrypt alert, got {technique_id} ({technique_name})"
    )


# ---------------------------------------------------------------------------
# Test 6 — map() returns a 2-tuple of strings
# ---------------------------------------------------------------------------


def test_map_returns_tuple(mapper):
    """map() always returns a 2-tuple of non-empty strings."""
    alert = {"event_type": "recon", "description": "port scan detected on subnet"}
    result = mapper.map(alert)
    assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
    assert len(result) == 2, f"Expected 2-tuple, got length {len(result)}"
    technique_id, technique_name = result
    assert isinstance(technique_id, str) and technique_id, "technique_id must be a non-empty string"
    assert isinstance(technique_name, str) and technique_name, "technique_name must be a non-empty string"


# ---------------------------------------------------------------------------
# Test 7 — all sample alerts get a non-None technique_id
# ---------------------------------------------------------------------------


def test_all_sample_alerts_get_mapped(mapper):
    """Every alert in sample_alerts.json receives a non-None technique_id."""
    with open(_SAMPLE_ALERTS_FILE, "r", encoding="utf-8") as fh:
        sample_alerts = json.load(fh)

    assert len(sample_alerts) > 0, "sample_alerts.json must not be empty"

    for alert in sample_alerts:
        # Normalise the keys to common schema names used by MITREMapper
        normalised = {
            "event_type": alert.get("event_type") or alert.get("type") or "",
            "description": alert.get("description") or alert.get("details") or "",
        }
        technique_id, technique_name = mapper.map(normalised)
        assert technique_id is not None, (
            f"Alert {alert.get('alert_id', '?')} returned None for technique_id"
        )
        assert isinstance(technique_id, str) and technique_id, (
            f"Alert {alert.get('alert_id', '?')} returned empty technique_id"
        )
