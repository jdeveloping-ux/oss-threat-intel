"""
KEV ingestion module.

Fetches CISA's Known Exploited Vulnerabilities (KEV) catalog and returns
new or updated entries since the last run. This module only handles
fetching and parsing, no filtering or scoring happens here, that's the
next stage in the pipeline (see docs/design.md).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
STATE_FILE = Path("data/last_seen_kev.json")


def fetch_kev_catalog() -> dict:
    """
    Fetch the full CISA KEV catalog.

    Returns the parsed JSON response. Raises requests.HTTPError if the
    request fails, so callers should handle that (e.g. skip this run
    and try again later, rather than crash a scheduled job).
    """
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def load_last_seen() -> set:
    """
    Load the set of CVE IDs seen in the previous run.

    Returns an empty set if this is the first run (no state file yet).
    """
    if not STATE_FILE.exists():
        return set()

    with open(STATE_FILE, "r") as f:
        data = json.load(f)
        return set(data.get("seen_cve_ids", []))


def save_seen(cve_ids: set) -> None:
    """
    Persist the current set of seen CVE IDs so the next run can diff
    against it. Creates the data/ directory if it doesn't exist yet.
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(
            {
                "seen_cve_ids": sorted(cve_ids),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            },
            f,
            indent=2,
        )


def get_new_entries() -> list[dict]:
    """
    Fetch the KEV catalog and return only the entries not seen in a
    previous run. Updates the local state file with the full current
    set of CVE IDs afterward.

    Each returned entry is the raw KEV record for that CVE, containing
    fields like cveID, vendorProject, product, vulnerabilityName,
    dateAdded, shortDescription, requiredAction, and dueDate.
    """
    catalog = fetch_kev_catalog()
    all_vulns = catalog.get("vulnerabilities", [])

    previously_seen = load_last_seen()
    current_ids = {v["cveID"] for v in all_vulns}

    new_entries = [v for v in all_vulns if v["cveID"] not in previously_seen]

    save_seen(current_ids)

    return new_entries


if __name__ == "__main__":
    entries = get_new_entries()
    print(f"Found {len(entries)} new KEV entries since last run.")
    for entry in entries[:5]:
        print(f"- {entry['cveID']}: {entry['vulnerabilityName']}")
