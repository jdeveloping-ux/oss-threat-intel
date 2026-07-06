# OSS Threat Intel

Open, low cost OSINT driven threat intelligence tooling for organizations that can't afford enterprise threat intel platforms.

## The problem

Commercial threat intelligence platforms are built for organizations with a security operations center and a six or seven figure budget. Small businesses, nonprofits, and resource constrained public sector offices rarely have either, yet they are increasingly the entry point for the kind of large scale incidents that do make headlines. CISA has said directly that cyber incidents have surged among small organizations that lack the resources to defend against them, and has built entire programs (Cross Sector Cybersecurity Performance Goals, Cybersecurity Resources for High Risk Communities) specifically because this gap is real and unresolved.

Most of the raw signal needed to catch threats early already exists in the open: breach databases, threat feeds, vulnerability catalogs, exposed infrastructure indicators. What's missing isn't the data, it's a way to turn that data into something a nontechnical decision maker can act on without a dedicated analyst standing between them and the noise.

## What this is

A tool that pulls from free and low cost OSINT and threat intel sources and produces a prioritized, plain language alert digest, built for someone running IT alone or wearing five hats at a small organization, not for an analyst who already has a SIEM.

Planned data sources (subject to change as this develops):
- CISA Known Exploited Vulnerabilities (KEV) catalog
- AbuseIPDB
- URLhaus
- AlienVault OTX
- Shodan (free tier, scoped lookups)

## Status

Early stage. This repo starts as a design document and a skeleton, and will grow in public as the project develops. Commit history here reflects the actual build process, not a polished release dropped all at once.

## Why this matters

This project is part of a broader effort to make cyber threat visibility accessible to organizations the current market leaves behind. Background and reasoning are written up here: [link to Article 1 once published].

## Roadmap

- [ ] Define feed ingestion architecture
- [ ] Build triage/scoring logic for prioritizing alerts
- [ ] Design plain language output format
- [ ] Pilot with at least one small organization
- [ ] Publish findings from pilot deployment

## License

TBD (leaning toward a permissive open source license, MIT or Apache 2.0, to keep this genuinely accessible)
