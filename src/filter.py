"""
Filtering module.

Takes new KEV entries (from ingest_kev.py) and an org's product profile
(from profile.py) and narrows the entries down to only the ones
relevant to that organization's actual software.

Matching strategy, in order of priority:
    1. Exact match (case insensitive) between a profile product and
       the KEV entry's "product" or "vendorProject" field. This is the
       strongest, most trustworthy signal.
    2. Substring match as a fallback, so variants like "Microsoft 365"
       vs "Microsoft Office" still connect, but only for phrases
       longer than MIN_SUBSTRING_LENGTH, to avoid short generic words
       (like "office" or "cloud") matching against unrelated entries
       and creating noise.

Each match is tagged with which method found it (exact vs substring),
so the next stage in the pipeline (scoring/triage) can weight exact
matches more heavily than substring matches.
"""

MIN_SUBSTRING_LENGTH = 5


def _normalize(text: str) -> str:
    """Lowercase and strip whitespace for consistent comparison."""
    return text.lower().strip()


def _find_match(profile_products: set, kev_entry: dict) -> str | None:
    """
    Check a single KEV entry against the org's product set.

    Returns "exact", "substring", or None (no match found). Checks
    both the "product" and "vendorProject" fields from the KEV entry,
    since a match on either is meaningful (e.g. profile lists
    "Microsoft" and the entry's vendorProject is "Microsoft" even if
    the specific product name differs).
    """
    kev_product = _normalize(kev_entry.get("product", ""))
    kev_vendor = _normalize(kev_entry.get("vendorProject", ""))

    for profile_product in profile_products:
        # Exact match against either field, strongest signal
        if profile_product == kev_product or profile_product == kev_vendor:
            return "exact"

    # Fall back to substring matching only for longer, more specific
    # phrases, to avoid short generic words causing false positives
    for profile_product in profile_products:
        if len(profile_product) < MIN_SUBSTRING_LENGTH:
            continue
        if profile_product in kev_product or profile_product in kev_vendor:
            return "substring"

    return None


def filter_relevant_entries(kev_entries: list[dict], org_profile: dict) -> list[dict]:
    """
    Filter a list of KEV entries down to only those relevant to the
    given org profile.

    Returns a list of dicts, each the original KEV entry with an added
    "match_type" field ("exact" or "substring"), so downstream scoring
    knows how confident to be in the match.
    """
    profile_products = org_profile.get("products", set())
    relevant = []

    for entry in kev_entries:
        match_type = _find_match(profile_products, entry)
        if match_type is not None:
            entry_with_match = dict(entry)
            entry_with_match["match_type"] = match_type
            relevant.append(entry_with_match)

    return relevant


if __name__ == "__main__":
    from ingest_kev import get_new_entries
    from profile import load_org_profile

    org_profile = load_org_profile()
    new_entries = get_new_entries()
    relevant = filter_relevant_entries(new_entries, org_profile)

    print(
        f"{len(relevant)} of {len(new_entries)} new KEV entries are "
        f"relevant to {org_profile['organization_name']}."
    )
    for entry in relevant:
        print(
            f"- [{entry['match_type']}] {entry['cveID']}: "
            f"{entry['vulnerabilityName']}"
        )
