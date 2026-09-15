"""BLUF (Bottom Line Up Front) generation service.

Produces a military-style summary for each incident.  When a valid
``WATSONX_API_KEY`` is present the IBM Granite model is called via the
``ibm-watsonx-ai`` SDK; otherwise a deterministic string template is used as
a fallback.  Both paths populate ``incident.bluf_summary`` and
``incident.bluf_source``.
"""

import logging
import os

logger = logging.getLogger(__name__)


class BLUFService:
    def __init__(self):
        self.api_key = os.getenv("WATSONX_API_KEY", "").strip()
        self.project_id = os.getenv("WATSONX_PROJECT_ID", "").strip()
        self.url = os.getenv(
            "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
        ).strip()
        self.model_id = os.getenv(
            "WATSONX_MODEL_ID", "ibm/granite-13b-instruct-v2"
        ).strip()
        self._client = None  # lazy-initialised

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, incident) -> tuple[str, str]:
        """Return ``(bluf_text, source)`` where *source* is ``"watsonx"`` or
        ``"template"``.

        The watsonx path is attempted when ``WATSONX_API_KEY`` is set.  Any
        exception from the API call causes a transparent fallback to the
        deterministic template.
        """
        if self.api_key:
            try:
                prompt = self.build_prompt(incident)
                text = self.call_watsonx(prompt)
                return text, "watsonx"
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "watsonx BLUF generation failed (%s); using template fallback.", exc
                )

        return self.template_fallback(incident), "template"

    # ------------------------------------------------------------------
    # Prompt builder
    # ------------------------------------------------------------------

    def build_prompt(self, incident) -> str:
        """Build a structured prompt for the Granite model."""
        info = self._extract_alert_info(incident)
        descriptions_text = "; ".join(info["descriptions"][:5]) or "N/A"
        mitre = incident.mitre_techniques or "unknown"

        return (
            "You are a cybersecurity analyst writing a BLUF (Bottom Line Up Front) briefing\n"
            "for a security commander. Write in military style: concise, direct, actionable.\n"
            "Structure your response EXACTLY as:\n"
            "BOTTOM LINE: [1-2 sentences stating what happened and severity]\n"
            "SUPPORTING FACTS: [2-3 bullet points with key evidence]\n"
            "RECOMMENDED ACTION: [1-2 sentences on immediate response]\n\n"
            "Incident details:\n"
            f"- Title: {incident.title}\n"
            f"- Priority: {incident.priority}\n"
            f"- Risk Score: {incident.risk_score}/100\n"
            f"- Alert Count: {incident.alert_count} correlated alerts\n"
            f"- MITRE Techniques: {mitre}\n"
            f"- Sample descriptions: {descriptions_text}\n"
        )

    # ------------------------------------------------------------------
    # watsonx.ai call
    # ------------------------------------------------------------------

    def call_watsonx(self, prompt: str) -> str:
        """Invoke the IBM watsonx.ai Granite model and return generated text."""
        client = self._get_client()
        response = client.generate(prompt=prompt)
        # SDK returns {"results": [{"generated_text": "..."}]}
        return response["results"][0]["generated_text"].strip()

    # ------------------------------------------------------------------
    # Deterministic template fallback
    # ------------------------------------------------------------------

    def template_fallback(self, incident) -> str:
        """Produce a deterministic BLUF string from incident fields."""
        info = self._extract_alert_info(incident)

        priority = (incident.priority or "UNKNOWN").upper()
        alert_count = incident.alert_count or 0
        risk_score = incident.risk_score or 0

        # Primary MITRE technique (first token of comma-separated list)
        mitre_raw = (incident.mitre_techniques or "").strip()
        primary_technique = mitre_raw.split(",")[0].strip() if mitre_raw else "unknown technique"

        # Source IPs — deduplicated, max 3 shown
        source_ips = list(dict.fromkeys(info["source_ips"]))
        ips_text = ", ".join(source_ips[:3]) if source_ips else "unknown"

        # Event types — deduplicated
        event_types = list(dict.fromkeys(info["event_types"]))
        types_text = ", ".join(event_types) if event_types else "unknown"

        return (
            f"BOTTOM LINE: {priority} priority incident comprising {alert_count} correlated alerts. "
            f"Primary technique: {primary_technique}.\n"
            f"SUPPORTING FACTS: "
            f"• Source IP(s): {ips_text}. "
            f"• Event types observed: {types_text}. "
            f"• Maximum risk score: {risk_score}/100.\n"
            f"RECOMMENDED ACTION: Isolate affected hosts, escalate to Tier-2 analyst, "
            f"and review {primary_technique} indicators."
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        """Lazy-initialise the watsonx ModelInference client."""
        if self._client is None:
            from ibm_watsonx_ai import Credentials  # noqa: PLC0415
            from ibm_watsonx_ai.foundation_models import ModelInference  # noqa: PLC0415

            credentials = Credentials(api_key=self.api_key, url=self.url)
            self._client = ModelInference(
                model_id=self.model_id,
                credentials=credentials,
                project_id=self.project_id,
                params={
                    "max_new_tokens": 400,
                    "temperature": 0.3,
                    "repetition_penalty": 1.1,
                },
            )
        return self._client

    def _extract_alert_info(self, incident) -> dict:
        """Return ``{source_ips, event_types, descriptions}`` from incident alerts.

        Works with both ORM-backed dynamic relationships and plain iterables of
        MagicMock objects (used in tests).
        """
        source_ips: list[str] = []
        event_types: list[str] = []
        descriptions: list[str] = []

        try:
            alerts = list(incident.alerts)
        except Exception:  # noqa: BLE001
            alerts = []

        for alert in alerts:
            ip = getattr(alert, "source_ip", None)
            if ip and ip != "unknown":
                source_ips.append(str(ip))

            et = getattr(alert, "event_type", None)
            if et:
                event_types.append(str(et))

            desc = getattr(alert, "description", None)
            if desc:
                descriptions.append(str(desc))

        return {
            "source_ips": source_ips,
            "event_types": event_types,
            "descriptions": descriptions[:5],
        }
