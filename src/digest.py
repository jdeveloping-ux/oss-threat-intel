"""
Digest formatter and email delivery.

Takes the triaged entries from triage.py and turns them into a plain
language email a nontechnical org director can actually read and act
on, then sends it via Resend.

This is the final module in the v1 pipeline described in docs/design.md:
    ingest_kev.py -> profile.py -> filter.py -> triage.py -> digest.py

Requires a RESEND_API_KEY environment variable, loaded from a local
.env file (see .env.example). Get a key from https://resend.com.
"""

import os
from datetime import date

import requests
from dotenv import load_dotenv

load_dotenv()

RESEND_API_URL = "https://api.resend.com/emails"

# Plain language explanations per priority level, so the digest never
# just shows a bare label without context for a nontechnical reader.
PRIORITY_EXPLANATIONS = {
    "Critical": "This affects software you use and was just confirmed as actively exploited. Act on this first.",
    "Watch": "This is related to your software or slightly older, worth reviewing but not necessarily urgent today.",
    "Informational": "Included for awareness, lower urgency.",
}


def _format_entry(entry: dict) -> str:
    """
    Format a single triaged entry into a plain language block.

    Uses the KEV entry's own shortDescription and requiredAction
    fields where available, since CISA already writes these in
    reasonably plain language, no need to reinvent that content.
    """
    priority = entry["priority"]
    explanation = PRIORITY_EXPLANATIONS[priority]

    return f"""
[{priority}] {entry.get('product', 'Unknown product')} ({entry['cveID']})

What happened: {entry.get('shortDescription', 'No description available.')}

Why it matters: {explanation}

What to do: {entry.get('requiredAction', 'Check vendor guidance for a patch or update.')}
Due by: {entry.get('dueDate', 'Not specified')}
""".strip()


def format_digest(triaged_entries: list[dict], org_profile: dict) -> str:
    """
    Build the full plain text digest body from a list of triaged
    entries. Handles the "nothing critical" case explicitly, per the
    open question in design.md, a digest that goes silent when there's
    nothing to report risks the whole tool being forgotten.
    """
    org_name = org_profile.get("organization_name", "your organization")
    today = date.today().isoformat()

    if not triaged_entries:
        return (
            f"Threat Intel Digest for {org_name}, {today}\n\n"
            "Nothing new to report today. No newly confirmed exploited "
            "vulnerabilities matched your software profile. This is a "
            "good sign, not a sign the tool isn't checking."
        )

    critical_count = sum(1 for e in triaged_entries if e["priority"] == "Critical")
    watch_count = sum(1 for e in triaged_entries if e["priority"] == "Watch")

    header = (
        f"Threat Intel Digest for {org_name}, {today}\n\n"
        f"{critical_count} critical, {watch_count} to watch, "
        f"{len(triaged_entries) - critical_count - watch_count} informational.\n"
        + "=" * 50
    )

    body = "\n\n".join(_format_entry(entry) for entry in triaged_entries)

    return f"{header}\n\n{body}"


def send_digest(digest_text: str, recipient_email: str, org_name: str) -> dict:
    """
    Send the formatted digest via Resend.

    Requires RESEND_API_KEY set in a local .env file. Raises
    requests.HTTPError if the send fails, callers should catch this
    and log it rather than let a scheduled job crash silently.
    """
    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "RESEND_API_KEY not found. Add it to a local .env file "
            "(see .env.example) before running this."
        )

    response = requests.post(
        RESEND_API_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "from": "Threat Intel Digest <onboarding@resend.dev>",
            "to": [recipient_email],
            "subject": f"Threat Intel Digest for {org_name}, {date.today().isoformat()}",
            "text": digest_text,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    from ingest_kev import get_new_entries
    from profile import load_org_profile
    from filter import filter_relevant_entries
    from triage import triage_entries

    org_profile = load_org_profile()
    new_entries = get_new_entries()
    relevant = filter_relevant_entries(new_entries, org_profile)
    triaged = triage_entries(relevant)

    digest = format_digest(triaged, org_profile)
    print(digest)  # Print first so you can review before actually sending

    # Uncomment once you've reviewed the printed digest above:
    # send_digest(digest, recipient_email="you@example.com", org_name=org_profile["organization_name"])
