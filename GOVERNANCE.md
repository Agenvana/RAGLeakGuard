# Governance

RAGLeakGuard is an early-stage open-source project maintained by Agenvana. This document describes how public repository decisions are made; it does not create a foundation, certification body, or commercial commitment.

## Roles

### Maintainer

Maintainers triage issues, define supported scope, appoint reviewers, approve public claims, merge pull requests, coordinate disclosures, and authorize releases. Agenvana is the current project steward and final decision maker until additional maintainers are named publicly.

### Contributor

Contributors propose issues, code, tests, research, and documentation through the workflow in [CONTRIBUTING.md](CONTRIBUTING.md). Contribution does not by itself grant merge, release, disclosure, or governance authority.

### Independent security reviewer

An independent reviewer did not author the security-critical change under review. Reviewers assess the acceptance criteria, [threat model](docs/THREAT_MODEL.md), failure semantics, privacy/data egress, compatibility, tests, and public claims. Review is mandatory for the areas identified in [AGENTS.md](AGENTS.md).

## Decision process

1. Open or identify a focused issue/problem statement without publishing sensitive vulnerability details.
2. Record scope, non-goals, compatibility impact, and acceptance evidence.
3. Implement on an issue-scoped branch and open a draft pull request.
4. Run tests and documentation/link checks; attach the evidence and residual risks.
5. Obtain independent review when the change is security-critical.
6. A maintainer deliberately decides whether and when to merge. Authors and automation do not merge by default.

Consensus is preferred. When consensus is not available, the maintainer records the decision and rationale in the issue, pull request, documentation, or an architecture decision record appropriate to its durability. Security embargoes may delay public rationale until coordinated disclosure is safe.

## Changes requiring heightened review

The following require an independent security review and explicit maintainer approval:

- detection, scoring, confidence, or risk-policy behavior;
- connectors or any operation that touches a source store;
- logs, reports, state, fingerprints, webhooks, alerts, telemetry, or other egress;
- persistence, migrations, serialization, retries, idempotency, signing, or cryptography;
- dependencies, supported runtimes, build/release automation, and provenance;
- public security, privacy, compliance, erasure, patent, certification, or production-safety claims;
- changes to the open-source/private product boundary.

## Project and product boundary

**Implemented now:** this repository contains the local open-source Diagnose/Monitor alpha and its public support material.

**Planned:** additional open connectors, locales, hardening, public schemas, and reproducibility/conformance work may be developed here after review.

**Outside the current repository:** a future proprietary RAGLeakGuard Control Plane, including tenancy, RBAC/SSO, billing, fleet operations, production vault/KMS orchestration, and enterprise operations. Cloud would be a deployment option for that future Control Plane, not a synonym for the open-source project. Nothing in this document claims that surface exists.

The open-source project must not be made intentionally unsafe or unverifiable to create a paid feature. Public interfaces needed for interoperability and independent verification should remain inspectable.

## Releases and claims

Only a human maintainer may authorize a PyPI release, public report, advisory, assurance profile, or compliance/product claim. Follow the [release process](docs/RELEASE_PROCESS.md). A passing CI job is necessary evidence, not release approval.

Released reports are immutable historical artifacts. Corrections use separately versioned amendments with their own review and checksums; they do not silently replace the original.

## Conflicts of interest

Reviewers disclose employment, financial, customer, research-credit, or competitive interests that could materially affect a decision. A conflicted reviewer may provide evidence but should not be the sole approver. Security reports protect reporter privacy and embargoed details.

## Amending governance

Governance changes use a public pull request with rationale and a maintainer decision. Material changes to maintainer authority, the product boundary, disclosure policy, or release authority require a dedicated review rather than being bundled with feature work.
