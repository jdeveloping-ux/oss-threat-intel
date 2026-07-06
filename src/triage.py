"""
Triage/scoring module.

Takes the relevant, matched KEV entries from filter.py and assigns each
one a priority level: Critical, Watch, or Informational. This is what
turns "here's a list of vulnerabilities relevant to you" into "here's
what actually needs your attention first," which is the whole point
of a plain language digest instead of a raw feed dump.

Scoring logic, adapted from the original design doc:

Every entry reaching this module already came from CISA's KEV catalog,
which by definition only lists vulnerabilities with CONFIRMED active
exploitation. So "confirmed vs not confirmed" isn't a useful signal
here, everything is already confirmed. The two signals that actually
differentiate urgency are:

    1. Match confidence (from filter.py): "exact" match against the
       org's declared products is a stronger signal than "substring"
       match, which could be an adjacent or related product.
    2. Recency (from the KEV entry's dateAdded field): a vulnerability
       CISA just added is more urgent than one added months ago that
       the organization has likely already had time to address.

Priority rules:
    - Critical: exact match AND added within the last RECENT_DAYS days
    - Watch: exact match but older, OR substring match of any age
    - Informational: fallback, anything not meeting the above
"""

from datetime import datetime, timezone, timedelta

RECENT_DAYS = 14


def _days_since_added(date_added_str: str) -> int:
    """
    Calculate how many days ago a KEV entry's dateAdded value was.

    KEV dates are formatted as YYYY-MM-DD. Returns a large number if
    the date can't be parsed, so malformed dates fail safe into lower
    urgency rather than accidentally being treated as Critical.
    """
    try:
        date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        return (datetime.now(timezone.utc) - date_added).days
    except (ValueError, TypeError):
        return 9999


def assign_priority(entry: dict) -> str:
    """
    Assign a priority level to a single filtered KEV entry.

    Expects the entry to already have a "match_type" field (added by
    filter.py). Returns "Critical", "Watch", or "Informational".
    """
    match_type = entry.get("match_type")
    days_old = _days_since_added(entry.get("dateAdded", ""))

    if match_type == "exact" and days_old <= RECENT_DAYS:
        return "Critical"

    if match_type == "exact" or match_type == "substring":
        return "Watch"

    return "Informational"


def triage_entries(relevant_entries: list[dict]) -> list[dict]:
    """
    Assign priority to a list of filtered entries and sort them so
    Critical items appear first, then Watch, then Informational.

    Returns the entries with an added "priority" field, sorted for
    direct use in the digest formatter (next module in the pipeline).
    """
    priority_order = {"Critical": 0, "Watch": 1, "Informational": 2}

    scored = []
    for entry in relevant_entries:
        entry_with_priority = dict(entry)
        entry_with_priority["priority"] = assign_priority(entry)
        scored.append(entry_with_priority)

    scored.sort(key=lambda e: priority_order[e["priority"]])
    return scored


if __name__ == "__main__":
    from ingest_kev import get_new_entries
    from profile import load_org_profile
    from filter import filter_relevant_entries

    org_profile = load_org_profile()
    new_entries = get_new_entries()
    relevant = filter_relevant_entries(new_entries, org_profile)
    triaged = triage_entries(relevant)

    print(f"Triaged {len(triaged)} entries for {org_profile['organization_name']}:")
    for entry in triaged:
        print(
            f"[{entry['priority']}] ({entry['match_type']}) "
            f"{entry['cveID']}: {entry['vulnerabilityName']} "
            f"(added {entry['dateAdded']})"
        )
