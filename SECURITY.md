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

**Implemented now:** local Chroma scanning, Presidio/spaCy-based detection, an opt-in Australian locale pack, fail-closed locale/runtime preflight, versioned aggregate risk reports, and scheduled monitoring with explicit operator keys, finding-level purpose-separated HMAC-SHA-256 fingerprints, authenticated privacy-minimized version-3 state, explicit initialization, fail-closed version-1 rejection, and safe authenticated-v2 transition. Optional alerts use a one-entry authenticated outbox committed before request construction, one stable 128-bit delivery ID, fresh attempt authentication, bounded exponential CSPRNG full-jitter retry metadata, protocol-v2 secret/framing, HTTPS-only no-redirect transport, and a receiver helper with nonce replay checks plus a durable atomic delivery-ID interface. Pending alerts block source access until durably cleared. See the [monitor state contract](docs/MONITOR_STATE.md) and [webhook protocol](docs/WEBHOOK_PROTOCOL.md).

**Known limitations:** connector completion evidence and detector completeness remain unproved; exact path spelling binds monitor scope; key protection/recovery/rotation, state rollback, non-overlapping writers, Windows DACLs, and filesystem/power-loss behavior remain external. One pending alert and one destination are supported, so receiver outage can block scans indefinitely; no dead-letter administration or silent discard exists. Send/response/clear failure can be ambiguous and duplicate delivery. Receiver clock/cache/store retention/loss, multi-node consistency, transaction ordering, TLS/CA/runtime compromise, and downstream behavior remain external risks. The in-memory receiver stores are test references, not durable production implementations. A `2xx` proves only acceptable response headers. There is no exactly-once, unconditional at-least-once, downstream-processing, human-notification, or recovery-of-historical-v1/v2-alert guarantee.

**Planned:** bounded connector completion evidence, outbox administration/multiple destinations, and reproducible release provenance.

The Prevent/Fix layer, erasure proof, Control Plane, multi-tenancy, vault/KMS, compliance certification, and assurance profile are not implemented and are outside the current supported surface.

## Coordinated handling

Maintainers will validate reports against the named commit, minimise access to submitted data, and credit reporters when requested and safe. Release timing depends on severity, exploitability, compatibility, and the ability to ship a tested fix. Security advisories and public claims require human maintainer approval.

Good-faith research using synthetic data and avoiding privacy violations, service disruption, credential access, or persistence is welcome. This project does not currently operate a bug bounty and cannot authorize testing against third-party or customer systems.
