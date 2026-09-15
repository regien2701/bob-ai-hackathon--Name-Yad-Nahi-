"""Tests for BLUFService.

All tests run without a live watsonx API key.  The ``ibm_watsonx_ai`` SDK is
mocked at the ``BLUFService._get_client`` level so that no real HTTP calls are
made.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services.bluf import BLUFService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_alert(source_ip="192.168.1.10", event_type="malware", description="Malware detected"):
    alert = MagicMock()
    alert.source_ip = source_ip
    alert.event_type = event_type
    alert.description = description
    return alert


def make_mock_incident(
    title="Malware campaign from 192.168.1.10",
    priority="HIGH",
    risk_score=87.5,
    alert_count=5,
    mitre_techniques="T1059, T1071",
    alerts=None,
):
    """Return a MagicMock that looks like an Incident ORM object."""
    incident = MagicMock()
    incident.title = title
    incident.priority = priority
    incident.risk_score = risk_score
    incident.alert_count = alert_count
    incident.mitre_techniques = mitre_techniques

    if alerts is None:
        alerts = [
            make_mock_alert("192.168.1.10", "malware", "Malware C2 beacon detected"),
            make_mock_alert("10.0.0.5", "c2", "Suspicious outbound connection"),
        ]
    # incident.alerts must be iterable (like a SQLAlchemy dynamic relationship)
    incident.alerts = alerts

    return incident


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestTemplateFallback:
    def test_template_fallback_structure(self):
        """template_fallback() always contains all three BLUF sections."""
        service = BLUFService()
        incident = make_mock_incident()
        result = service.template_fallback(incident)

        assert "BOTTOM LINE:" in result
        assert "SUPPORTING FACTS:" in result
        assert "RECOMMENDED ACTION:" in result

    def test_template_fallback_high_priority(self):
        """HIGH priority incident — 'HIGH' appears in the output."""
        service = BLUFService()
        incident = make_mock_incident(priority="HIGH")
        result = service.template_fallback(incident)

        assert "HIGH" in result

    def test_template_fallback_medium_priority(self):
        """MEDIUM priority incident — 'MEDIUM' appears in the output."""
        service = BLUFService()
        incident = make_mock_incident(priority="MEDIUM", risk_score=55.0, alert_count=3)
        result = service.template_fallback(incident)

        assert "MEDIUM" in result

    def test_template_fallback_source_ip_included(self):
        """Source IPs from related alerts appear in the SUPPORTING FACTS section."""
        service = BLUFService()
        alerts = [make_mock_alert(source_ip="10.20.30.40", event_type="recon")]
        incident = make_mock_incident(alerts=alerts)
        result = service.template_fallback(incident)

        assert "10.20.30.40" in result


class TestBuildPrompt:
    def test_build_prompt_contains_incident_info(self):
        """build_prompt() embeds title, priority, and risk score."""
        service = BLUFService()
        incident = make_mock_incident(
            title="Suspicious lateral movement",
            priority="HIGH",
            risk_score=92.0,
        )
        prompt = service.build_prompt(incident)

        assert "Suspicious lateral movement" in prompt
        assert "HIGH" in prompt
        assert "92.0" in prompt


class TestGenerate:
    def test_generate_uses_watsonx_when_key_set(self):
        """When WATSONX_API_KEY is set and client succeeds, source == 'watsonx'."""
        service = BLUFService()
        service.api_key = "test_key"

        mock_client = MagicMock()
        mock_client.generate.return_value = {
            "results": [{"generated_text": "BOTTOM LINE: Threat detected."}]
        }

        with patch.object(service, "_get_client", return_value=mock_client):
            text, source = service.generate(make_mock_incident())

        assert source == "watsonx"
        assert "BOTTOM LINE:" in text

    def test_generate_uses_template_when_no_key(self):
        """When WATSONX_API_KEY is empty, source == 'template'."""
        service = BLUFService()
        service.api_key = ""

        text, source = service.generate(make_mock_incident())

        assert source == "template"
        assert "BOTTOM LINE:" in text

    def test_generate_falls_back_on_watsonx_error(self):
        """When API key is set but call_watsonx raises, source == 'template'."""
        service = BLUFService()
        service.api_key = "some_key"

        with patch.object(service, "call_watsonx", side_effect=RuntimeError("API unavailable")):
            text, source = service.generate(make_mock_incident())

        assert source == "template"
        assert "BOTTOM LINE:" in text
