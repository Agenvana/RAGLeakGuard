# Security policy

RAGLeakGuard is an early-development security scanner. Detection is best-effort, and a clean result is not proof that a store is safe, compliant, or free of sensitive data. Read the [threat model](docs/THREAT_MODEL.md) before relying on it in a sensitive environment.

## Supported versions

| Version | Security-fix status | Notes |
|---|---|---|
| `0.1.x` | Supported on a best-effort basis | `0.1.0` is the current PyPI release at this baseline. The package metadata requires Python `>=3.9`; current CI validates only Python 3.9 on Ubuntu. |
| `main` | Pre-release | Receives fixes first; use a commit SHA when reporting behavior. |
| `<0.1.0` | Unsupported | Upgrade before reporting unless the issue also reproduces on a supported version or `main`. |

This is a pre-1.0 project. Compatibility and the supported runtime matrix may narrow as evidence improves. A finite multi-platform test matrix is **planned**, not implemented; see the [release process](docs/RELEASE_PROCESS.md).

## Reporting a vulnerability

Do not include vulnerability details, proof-of-concept data, credentials, personal data, customer names, local paths, or store contents in a public issue, discussion, or pull request.

1. If GitHub shows **Report a vulnerability** on the repository's Security page, use that private advisory form.
2. Private vulnerability reporting is not enabled at this documentation baseline. Until it is enabled, open a minimal [security contact request](https://github.com/Agenvana/RAGLeakGuard/issues/new) containing only a request for a private channel and the affected version. Do not describe the vulnerability publicly.
3. Once a private channel is established, include the affected version/commit, configuration, impact, reproduction steps using synthetic data, and a proposed disclosure timeline.

Enabling GitHub private vulnerability reporting is **planned repository administration work**. This policy does not claim that the setting is currently enabled.

Maintainers should acknowledge a complete private report within three business days and provide a triage update within seven business days. These are response targets, not a guarantee. Please allow coordinated remediation before public disclosure.

## What to report

Examples include:

- false-success paths that can present an incomplete scan or failed alert as successful;
- raw sensitive values, secrets, local paths, record identifiers, collection/tenant names, or other sensitive metadata leaving their intended boundary;
- unintended vector-store mutation;
- unsafe parsing, state corruption, migration, retry, or webhook behavior;
- dependency or supply-chain issues with a demonstrated RAGLeakGuard impact;
- a public claim that materially overstates implemented security behavior.

Ordinary false positives and false negatives are expected limitations of best-effort detection. Report them as bugs unless they create a false-success or data-exposure condition.

## Scope and current limitations

**Implemented now:** local Chroma scanning, Presidio/spaCy-based detection, an opt-in Australian locale pack, aggregate Markdown reports, and scheduled monitor snapshots/webhook alerts.

**Known limitations:** the current connector materializes collection results; monitoring persists store paths plus collection/record keys; webhook payloads contain the store path and record keys; fingerprints cover finding types and counts rather than finding values; webhook delivery has no durable outbox or signing; and the current scan command does not fail closed for every optional-dependency failure. These are not security guarantees.

**Planned:** bounded connector completion evidence, fail-closed dependency/locale handling, versioned risk policy, privacy-safe finding-level fingerprints, minimized/signed payloads, durable alert delivery, and reproducible release provenance.

The Prevent/Fix layer, erasure proof, Control Plane, multi-tenancy, vault/KMS, compliance certification, and assurance profile are not implemented and are outside the current supported surface.

## Coordinated handling

Maintainers will validate reports against the named commit, minimise access to submitted data, and credit reporters when requested and safe. Release timing depends on severity, exploitability, compatibility, and the ability to ship a tested fix. Security advisories and public claims require human maintainer approval.

Good-faith research using synthetic data and avoiding privacy violations, service disruption, credential access, or persistence is welcome. This project does not currently operate a bug bounty and cannot authorize testing against third-party or customer systems.
