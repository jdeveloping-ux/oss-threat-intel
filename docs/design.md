# Design Document: OSS Threat Intel

Status: Draft, v1 scope. This document will be updated as the project develops, changes should be committed with dated messages so the evolution of the design is visible in history.

## Update, 2026-07-06: Triage logic revised

Original scoring logic assumed a distinction between confirmed and
unconfirmed exploited vulnerabilities. Since all entries reaching the
triage stage already come from CISA's KEV catalog (which only lists
confirmed exploited vulnerabilities), this distinction doesn't apply
to the data actually available. Revised scoring uses match confidence
(exact vs substring) and recency (dateAdded) instead. See src/triage.py
for implementation.

## Goal for v1

Prove the core loop end to end, on the smallest possible scope, before expanding: pull one real feed, score it, produce one plain language email digest. Everything after v1 (more feeds, better scoring, a dashboard) only matters once this loop works and has been tested against at least one real organization's environment or a realistic simulated one.

## Stack

**Language:** Python. Chosen for speed of execution given prior experience building working automation tools (scheduled bots, API polling, email delivery) rather than starting from zero in a new language.

**Scheduling:** A simple scheduled job (cron, or a scheduled cloud function such as a Vercel cron job or AWS Lambda on a schedule) rather than a long running server. This keeps hosting cost near zero, which matters since the entire premise of the tool is low cost accessibility.

**Email delivery:** Reuse the EmailJS pattern from prior work, or Resend if this ends up deployed alongside the existing Next.js/Vercel infrastructure already in use for other projects.

## v1 Architecture

```
[CISA KEV Catalog API]
        |
        v
[Ingestion module] --> fetches new/updated entries since last run
        |
        v
[Filtering module] --> narrows to entries relevant to a configurable
                         organization profile (industry, software stack,
                         vendor products in use)
        |
        v
[Scoring/triage module] --> assigns a priority level based on:
                              - how recently the vulnerability was added
                              - whether it matches the org's declared
                                software/vendor profile
                              - CISA's own "known exploited" flag (already
                                a strong signal since KEV only lists
                                vulnerabilities with confirmed
                                exploitation)
        |
        v
[Digest formatter] --> converts scored entries into plain language:
                         what it is, why it matters to this org
                         specifically, what to do about it
        |
        v
[Email delivery] --> sends digest to configured recipient(s)
```

## Organization profile (the key differentiator)

The reason this isn't just "forward the KEV feed as an email" is the filtering step. A raw feed of every known exploited vulnerability is noise to someone without a security background. The org profile is a small config (initially just a text file or simple form) where a pilot organization lists:

- What software/platforms they run (e.g., WordPress, QuickBooks, a specific POS system, Microsoft 365)
- What vendors/products they depend on
- Optionally, their sector (useful later for CISA Sector Specific Goals alignment)

The filtering module uses this to cut a feed of hundreds of entries down to the handful that are actually relevant to that specific organization. This is the part of the tool that does the real work, the ingestion and email delivery are comparatively simple engineering.

## Triage/scoring logic, v1 version

Keep this simple and explainable for v1, complexity can come later once there's real usage data to justify it:

- **Critical**: Confirmed exploited (KEV listing) + matches org's declared software profile
- **Watch**: Matches org's software profile but not yet confirmed exploited, or confirmed exploited but for adjacent/related software
- **Informational**: Everything else that passed initial filtering but doesn't meet the above

Each level maps to a different tone and urgency in the digest email. Critical items get a short, direct action recommendation. Everything else is lower key.

## Digest format, v1 version

Plain language, no jargon assumed. Rough structure per entry:

```
[CRITICAL] Your WordPress plugin has a known exploited vulnerability

What happened: A vulnerability in [plugin name] is being actively
exploited right now, according to CISA.

Why it matters to you: You're running this plugin based on your
profile. Attackers already know how to exploit it.

What to do: Update to version X.X or later. If you can't update
immediately, [mitigation step].
```

## What's explicitly out of scope for v1

- Multiple feed sources (start with KEV only, add AbuseIPDB/URLhaus/OTX once the core loop is proven)
- A web dashboard (email only for v1)
- Automated remediation (this tool informs, it does not act on the organization's systems)
- Machine learning based scoring (rule based triage is more explainable and auditable for a nontechnical user, and easier to defend as sound methodology)

## Open questions to resolve during build

- How does an organization update their profile as their software stack changes? (Manual edit for v1 is fine, a simple form later)
- How often should the digest run? Daily seems reasonable for KEV given its update cadence, but this should be validated with a pilot org's actual preference.
- What happens when there's nothing critical to report? (Still worth sending a short "nothing critical this week" digest so the tool doesn't go silent and get forgotten)

## Next steps

1. Build the KEV ingestion module (fetch and parse only, no filtering yet)
2. Build the org profile format (start as a simple YAML or JSON config)
3. Build the filtering module against a test profile
4. Build the scoring/triage logic
5. Build the digest formatter and email delivery
6. Test the full loop against a realistic (even if synthetic) org profile
7. Recruit a real pilot organization once the loop works end to end
