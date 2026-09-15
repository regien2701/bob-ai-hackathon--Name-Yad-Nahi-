"""Threat scoring engine.

Produces a numeric risk score (0–100) and a breakdown dict for each alert,
then classifies the alert into HIGH / MEDIUM / LOW priority bands.
"""

import os

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[str, float] = {
    "critical": 30,
    "high": 22,
    "medium": 14,
    "low": 6,
    "informational": 0,
    "info": 0,
}

EVENT_TYPE_SCORES: dict[str, float] = {
    "c2": 25,
    "exfiltration": 25,
    "malware": 20,
    "intrusion": 20,
    "credential_access": 18,
    "phishing": 15,
    "recon": 10,
    "dos": 8,
    "other": 5,
}

# Destination IP prefixes considered sensitive (configurable via env).
# Each entry is a string prefix; the first match wins the full 20 points.
CRITICAL_DEST_PATTERNS: list[str] = [
    "10.10.0.",
    "172.16.0.",
    "10.0.0.1",
]

# Keywords in the description that indicate high-signal alerts.
HIGH_SIGNAL_KEYWORDS: list[str] = [
    "admin",
    "root",
    "lateral",
    "domain controller",
    "dc01",
    "lsass",
    "mimikatz",
    "cobalt strike",
    "beacon",
    "ransomware",
    "encrypt",
    "shadow copy",
    "dump",
    "privilege",
    "escalat",
]


# ---------------------------------------------------------------------------
# ScoringEngine
# ---------------------------------------------------------------------------


class ScoringEngine:
    """Compute a risk score and priority classification for a CommonAlert dict.

    Parameters
    ----------
    high_threshold:
        Minimum score for HIGH priority.  Defaults to ``SCORE_HIGH_THRESHOLD``
        env var, then 70.
    medium_threshold:
        Minimum score for MEDIUM priority.  Defaults to ``SCORE_MEDIUM_THRESHOLD``
        env var, then 40.
    critical_dest_patterns:
        List of IP prefixes that map to maximum destination-sensitivity score.
        If *None*, the module-level ``CRITICAL_DEST_PATTERNS`` list is used.
    """

    def __init__(
        self,
        high_threshold: float | None = None,
        medium_threshold: float | None = None,
        critical_dest_patterns: list[str] | None = None,
    ) -> None:
        if high_threshold is None:
            high_threshold = float(os.environ.get("SCORE_HIGH_THRESHOLD", 70))
        if medium_threshold is None:
            medium_threshold = float(os.environ.get("SCORE_MEDIUM_THRESHOLD", 40))

        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold
        self._critical_dest_patterns = (
            critical_dest_patterns
            if critical_dest_patterns is not None
            else list(CRITICAL_DEST_PATTERNS)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self, alert: dict, recent_same_src: int = 0
    ) -> tuple[float, dict]:
        """Compute a risk score for *alert*.

        Parameters
        ----------
        alert:
            CommonAlert dict.
        recent_same_src:
            Count of recent alerts sharing the same ``source_ip``.
            Used to compute the recurrence factor.

        Returns
        -------
        tuple[float, dict]
            ``(risk_score, breakdown)`` where *breakdown* is::

                {
                    "severity":        float,
                    "event_type":      float,
                    "dest_sensitivity": float,
                    "recurrence":      float,
                    "keywords":        float,
                    "total":           float,
                }
        """
        sev = self._score_severity(alert)
        etype = self._score_event_type(alert)
        dest = self._score_dest_sensitivity(alert)
        recurrence = self._score_recurrence(recent_same_src)
        keywords = self._score_keywords(alert)

        total = min(sev + etype + dest + recurrence + keywords, 100.0)
        total = max(total, 0.0)

        breakdown = {
            "severity": sev,
            "event_type": etype,
            "dest_sensitivity": dest,
            "recurrence": recurrence,
            "keywords": keywords,
            "total": total,
        }
        return total, breakdown

    def classify(self, risk_score: float) -> str:
        """Map a numeric score to a priority label.

        Returns
        -------
        str
            One of ``"HIGH"``, ``"MEDIUM"``, or ``"LOW"``.
        """
        if risk_score >= self.high_threshold:
            return "HIGH"
        if risk_score >= self.medium_threshold:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Factor methods
    # ------------------------------------------------------------------

    def _score_severity(self, alert: dict) -> float:
        raw = (alert.get("severity_raw") or "").strip().lower()
        return SEVERITY_SCORES.get(raw, 0.0)

    def _score_event_type(self, alert: dict) -> float:
        etype = (alert.get("event_type") or "").strip().lower()
        return EVENT_TYPE_SCORES.get(etype, 0.0)

    def _score_dest_sensitivity(self, alert: dict) -> float:
        dest = (alert.get("dest_ip") or "")
        # Critical patterns → 20
        for pattern in self._critical_dest_patterns:
            if dest.startswith(pattern):
                return 20.0
        # General private ranges → 10
        if dest.startswith(("10.", "172.", "192.168.")):
            return 10.0
        return 0.0

    @staticmethod
    def _score_recurrence(recent_same_src: int) -> float:
        if recent_same_src >= 5:
            return 15.0
        if recent_same_src >= 2:
            return 8.0
        return 0.0

    @staticmethod
    def _score_keywords(alert: dict) -> float:
        description = (alert.get("description") or "").lower()
        matches = sum(
            1 for kw in HIGH_SIGNAL_KEYWORDS if kw.lower() in description
        )
        if matches >= 3:
            return 10.0
        if matches >= 1:
            return 5.0
        return 0.0
