"""MITRE ATT&CK mapping service — assigns a technique to each alert via keyword
scoring against a local lookup table (``data/mitre_techniques.json``).
"""

import json
from pathlib import Path

DATA_FILE = Path(__file__).parent.parent.parent / "data" / "mitre_techniques.json"

FALLBACK_TECHNIQUE_ID = "T0000"
FALLBACK_TECHNIQUE_NAME = "Unknown"


class MITREMapper:
    def __init__(self, techniques_file=None):
        self.techniques = self.load_techniques(techniques_file or DATA_FILE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_techniques(self, filepath) -> list:
        """Load techniques from *filepath* and return a list of dicts.

        Each dict must contain: technique_id, technique_name, tactic, keywords.
        """
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def map(self, alert: dict) -> tuple:
        """Return ``(technique_id, technique_name)`` for *alert*.

        Algorithm
        ---------
        1. Build ``search_text`` = (event_type + " " + description), lower-cased.
        2. For each technique count how many of its keywords appear in search_text.
        3. Return the technique with the highest keyword-hit count.
        4. Ties are broken by preferring the technique where event_type **exactly**
           matches one of its keywords.
        5. If no technique scores > 0, return (FALLBACK_TECHNIQUE_ID, FALLBACK_TECHNIQUE_NAME).
        """
        event_type = str(alert.get("event_type") or "").lower().strip()
        description = str(alert.get("description") or "").lower().strip()
        search_text = event_type + " " + description

        best_technique = None
        best_score = 0
        best_has_event_type_match = False

        for technique in self.techniques:
            keywords = [kw.lower() for kw in technique.get("keywords", [])]
            score = sum(1 for kw in keywords if kw in search_text)
            if score == 0:
                continue

            has_event_type_match = event_type in keywords

            # New leader if: higher score, OR equal score and this one has an
            # event_type exact match while the current leader does not.
            if score > best_score or (
                score == best_score and has_event_type_match and not best_has_event_type_match
            ):
                best_score = score
                best_technique = technique
                best_has_event_type_match = has_event_type_match

        if best_technique is None:
            return (FALLBACK_TECHNIQUE_ID, FALLBACK_TECHNIQUE_NAME)

        return (best_technique["technique_id"], best_technique["technique_name"])

    def get_coverage(self) -> list:
        """Return a list of ``{technique_id, technique_name, tactic, count}`` dicts.

        ``count`` is always 0 here; the caller (route) fills it from DB queries.
        """
        return [
            {
                "technique_id": t["technique_id"],
                "technique_name": t["technique_name"],
                "tactic": t["tactic"],
                "count": 0,
            }
            for t in self.techniques
        ]
