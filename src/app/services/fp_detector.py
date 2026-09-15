"""False-positive detection service.

Rules are evaluated in order; the first matching rule short-circuits
and returns ``(True, reason)``.  If no rule matches, returns ``(False, "")``.
"""

import ipaddress
import os
from datetime import datetime, timezone


class FPDetector:
    """Classify an alert as a false positive using a priority-ordered rule set.

    Parameters
    ----------
    whitelist_ips:
        Explicit list of IP strings to treat as benign sources/destinations.
        Defaults to the ``FP_WHITELIST_IPS`` env var (comma-separated).
    scanner_cidr:
        CIDR block for known internal scanners.
        Defaults to the ``INTERNAL_SCANNER_CIDR`` env var.
    """

    def __init__(
        self,
        whitelist_ips: list[str] | None = None,
        scanner_cidr: str | None = None,
    ) -> None:
        if whitelist_ips is None:
            raw = os.environ.get("FP_WHITELIST_IPS", "")
            whitelist_ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
        self._whitelist: set[str] = set(whitelist_ips)

        if scanner_cidr is None:
            scanner_cidr = os.environ.get("INTERNAL_SCANNER_CIDR", "")
        self._scanner_network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        if scanner_cidr:
            try:
                self._scanner_network = ipaddress.ip_network(scanner_cidr, strict=False)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        alert: dict,
        recent_alerts: list[dict] | None = None,
        risk_score: float | None = None,
    ) -> tuple[bool, str]:
        """Evaluate all FP rules in order and return on the first match.

        Parameters
        ----------
        alert:
            CommonAlert dict.
        recent_alerts:
            List of recent alert dicts used for duplicate detection (FP-5).
        risk_score:
            Pre-computed risk score for the alert (FP-6).

        Returns
        -------
        tuple[bool, str]
            ``(is_false_positive, reason)``
        """
        src = alert.get("source_ip", "") or ""
        dst = alert.get("dest_ip", "") or ""

        # FP-1: source IP whitelisted
        if self._is_whitelisted_source(src):
            return True, "Source IP is whitelisted"

        # FP-2: destination IP whitelisted
        if self._is_whitelisted_dest(dst):
            return True, "Destination IP is whitelisted"

        # FP-3: informational recon noise
        severity = (alert.get("severity_raw") or "").strip().lower()
        event_type = (alert.get("event_type") or "").strip().lower()
        if severity == "informational" and event_type == "recon":
            return True, "Informational recon — noise"

        # FP-4: known internal scanner CIDR
        if self._is_scanner_ip(src):
            return True, "Known internal scanner"

        # FP-5: duplicate within 60-second window
        if recent_alerts and self._is_duplicate(alert, recent_alerts):
            return True, "Duplicate within 60 s"

        # FP-6: risk score below minimum threshold (requires score already computed)
        if risk_score is not None and risk_score < 10:
            return True, "Risk score below minimum threshold"

        return False, ""

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_whitelisted_source(self, ip: str) -> bool:
        return ip in self._whitelist

    def _is_whitelisted_dest(self, ip: str) -> bool:
        return ip in self._whitelist

    def _is_scanner_ip(self, ip: str) -> bool:
        if not self._scanner_network or not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self._scanner_network
        except ValueError:
            return False

    @staticmethod
    def _is_duplicate(alert: dict, recent_alerts: list[dict]) -> bool:
        """Return True if *recent_alerts* contains a duplicate of *alert*.

        A duplicate is defined as an alert with the same source_ip, dest_ip,
        and event_type whose timestamp falls within a 60-second window of the
        current alert's timestamp.
        """
        src = alert.get("source_ip")
        dst = alert.get("dest_ip")
        etype = alert.get("event_type")
        ts = alert.get("timestamp")

        # Parse alert timestamp to a comparable datetime
        alert_dt = _to_datetime(ts)

        for prev in recent_alerts:
            if (
                prev.get("source_ip") == src
                and prev.get("dest_ip") == dst
                and prev.get("event_type") == etype
            ):
                prev_dt = _to_datetime(prev.get("timestamp"))
                if alert_dt is not None and prev_dt is not None:
                    if abs((alert_dt - prev_dt).total_seconds()) <= 60:
                        return True
                else:
                    # If timestamps cannot be parsed, treat as duplicate on field match alone
                    return True
        return False


def _to_datetime(value) -> datetime | None:
    """Coerce *value* to a timezone-aware datetime, or return None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        from datetime import datetime as _dt
        dt = _dt.fromisoformat(str(value))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
