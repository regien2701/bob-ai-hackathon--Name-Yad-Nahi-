"""Alert Correlation Engine — groups related alerts into Incidents.

Two-pass strategy
-----------------
Pass 1 (IP cluster):   alerts sharing the same ``source_ip`` within the time
                       window are grouped.  False-positive alerts are excluded.
Pass 2 (technique cluster): any alert not already assigned to an incident is
                       re-grouped by ``mitre_technique_id`` within the same
                       time window.

The caller is responsible for committing the session after ``correlate()``
returns.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone

from app.models.incident import AlertIncident, Incident

# Priority ordering for "max priority" logic
_PRIORITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class CorrelationEngine:
    def __init__(self, window_hours: int = 2):
        self.window_hours = window_hours

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, alerts: list, session) -> list:
        """Group *alerts* into Incidents and persist them via *session*.

        Parameters
        ----------
        alerts:
            List of ``Alert`` ORM objects (already scored / FP-flagged).
        session:
            Active SQLAlchemy session.  **Not committed here.**

        Returns
        -------
        list[Incident]
            Newly created Incident objects added to the session.
        """
        # Only non-FP alerts participate in correlation
        eligible = [a for a in alerts if not a.is_false_positive]

        incidents: list[Incident] = []
        assigned_ids: set = set()

        # ----- Pass 1: IP clusters ----------------------------------------
        ip_groups = self._group_by_ip(eligible)
        for _ip, group in ip_groups.items():
            # Filter group to alerts within the time window of each other
            cohort = self._filter_to_window(group)
            if not cohort:
                continue
            incident = self._create_incident(cohort, session)
            incidents.append(incident)
            for a in cohort:
                assigned_ids.add(id(a))

        # ----- Pass 2: Technique clusters (ungrouped alerts only) ----------
        ungrouped = [a for a in eligible if id(a) not in assigned_ids]
        tech_groups = self._group_by_technique(ungrouped)
        for _tech, group in tech_groups.items():
            cohort = self._filter_to_window(group)
            if not cohort:
                continue
            incident = self._create_incident(cohort, session)
            incidents.append(incident)

        return incidents

    # ------------------------------------------------------------------
    # Grouping helpers
    # ------------------------------------------------------------------

    def _group_by_ip(self, alerts: list) -> dict:
        """Return ``{source_ip: [alert, ...]}`` for all non-FP alerts.

        Every eligible alert ends up in exactly one bucket (its source_ip).
        Single-alert groups are kept — they still become incidents.
        """
        groups: dict = {}
        for alert in alerts:
            ip = alert.source_ip or "unknown"
            groups.setdefault(ip, []).append(alert)
        return groups

    def _group_by_technique(self, ungrouped: list) -> dict:
        """Return ``{technique_id: [alert, ...]}`` for *ungrouped* alerts.

        Alerts with no technique (``None`` / empty) are each placed in their
        own singleton bucket keyed by Python object id to avoid false merges.
        """
        groups: dict = {}
        for alert in ungrouped:
            tech = alert.mitre_technique_id
            if tech:
                groups.setdefault(tech, []).append(alert)
            else:
                # No technique — treat as its own bucket so it still becomes
                # an incident (singleton).
                groups.setdefault(f"_no_tech_{id(alert)}", []).append(alert)
        return groups

    def _within_window(self, alert_a, alert_b) -> bool:
        """Return True if the two alerts' timestamps are within ``window_hours``.

        ``None`` timestamps are treated as within the window (permissive).
        """
        ts_a = alert_a.timestamp
        ts_b = alert_b.timestamp
        if ts_a is None or ts_b is None:
            return True
        # Make both timezone-aware for safe subtraction
        if ts_a.tzinfo is None:
            ts_a = ts_a.replace(tzinfo=timezone.utc)
        if ts_b.tzinfo is None:
            ts_b = ts_b.replace(tzinfo=timezone.utc)
        return abs(ts_a - ts_b) <= timedelta(hours=self.window_hours)

    def _filter_to_window(self, group: list) -> list:
        """Return the subset of *group* whose timestamps fall within the window.

        Uses the earliest timestamp in the group as the anchor; any alert
        within ``window_hours`` of that anchor is included.
        """
        if not group:
            return []
        # Determine anchor (earliest non-None timestamp, or None if all missing)
        timestamps = [a.timestamp for a in group if a.timestamp is not None]
        if not timestamps:
            return list(group)  # no timestamps → treat all as in-window
        anchor = min(timestamps)
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        cutoff = anchor + timedelta(hours=self.window_hours)
        result = []
        for a in group:
            if a.timestamp is None:
                result.append(a)
            else:
                ts = a.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts <= cutoff:
                    result.append(a)
        return result

    # ------------------------------------------------------------------
    # Incident creation
    # ------------------------------------------------------------------

    def _create_incident(self, alert_group: list, session) -> Incident:
        """Create an ``Incident`` ORM object from *alert_group* and add join rows.

        Does **not** commit the session.
        """
        now = datetime.now(timezone.utc)

        # created_at = min alert timestamp (or now)
        timestamps = [a.timestamp for a in alert_group if a.timestamp is not None]
        created_at = min(timestamps) if timestamps else now

        # Priority = max priority in group
        priority = self._max_priority(alert_group)

        # risk_score = max
        scores = [a.risk_score for a in alert_group if a.risk_score is not None]
        risk_score = max(scores) if scores else 0.0

        # mitre_techniques = comma-separated unique IDs (preserving first-seen order)
        seen: dict = {}
        for a in alert_group:
            if a.mitre_technique_id:
                seen[a.mitre_technique_id] = True
        mitre_techniques = ",".join(seen.keys()) or None

        incident = Incident(
            title=self._generate_title(alert_group),
            priority=priority,
            risk_score=risk_score,
            alert_count=len(alert_group),
            mitre_techniques=mitre_techniques,
            status="open",
            created_at=created_at,
            updated_at=now,
        )
        session.add(incident)

        # Flush to get the incident.id so join rows can reference it
        session.flush()

        for alert in alert_group:
            if alert.id is not None:
                join_row = AlertIncident(alert_id=alert.id, incident_id=incident.id)
                session.add(join_row)

        return incident

    def _generate_title(self, alerts: list) -> str:
        """Generate a human-readable title for the incident.

        - If all alerts share the same ``source_ip`` (and it is not "unknown"),
          the title is ``"<most_common_event_type> campaign from <ip>"``.
        - Otherwise the title uses the most common MITRE technique ID if present,
          or falls back to the most common event_type.
        """
        event_types = [a.event_type for a in alerts if a.event_type]
        most_common_event = Counter(event_types).most_common(1)[0][0] if event_types else "alert"

        ips = {a.source_ip for a in alerts if a.source_ip and a.source_ip != "unknown"}
        if len(ips) == 1:
            ip = next(iter(ips))
            return f"{most_common_event} campaign from {ip}"

        techs = [a.mitre_technique_id for a in alerts if a.mitre_technique_id]
        if techs:
            most_common_tech = Counter(techs).most_common(1)[0][0]
            # Look up a friendly name from any alert in the group
            tech_name = next(
                (a.mitre_technique_name for a in alerts if a.mitre_technique_id == most_common_tech and a.mitre_technique_name),
                None,
            )
            if tech_name:
                return f"{most_common_tech} {tech_name} activity"
            return f"{most_common_tech} {most_common_event} activity"

        return f"{most_common_event} activity"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _max_priority(alerts: list) -> str:
        """Return the highest priority string found across *alerts*."""
        best = "LOW"
        for a in alerts:
            p = (a.priority or "LOW").upper()
            if _PRIORITY_ORDER.get(p, 0) > _PRIORITY_ORDER.get(best, 0):
                best = p
        return best
