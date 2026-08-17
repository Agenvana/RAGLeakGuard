# Security policy

RAGLeakGuard is an early-development security scanner. Detection is best-effort, and a clean result is not proof that a store is safe, compliant, or free of sensitive data. Read the [threat model](docs/THREAT_MODEL.md) before relying on it in a sensitive environment.

## Supported versions

| Version | Security-fix status | Notes |
|---|---|---|
| `0.1.0` | Unsafe for Chroma scanning | The published package contains the unsafe direct Chroma path addressed by WP7A and must not be used for Chroma scanning. Yank/publication actions require separate human authorization. |
| `0.1.1` | Proposed; not published | Source proposes the corrective version, but it is unavailable from PyPI until exact artifacts receive independent review and explicit human publication approval. |
| Later `0.1.x` | Not published | No later corrective package is currently available. |
| `main` | Pre-release | Receives fixes first; use a commit SHA when reporting behavior. |
| `<0.1.0` | Unsupported | Do not use for Chroma scanning; reports should be checked against a named, reviewed source commit. |

This is a pre-1.0 project. Compatibility may narrow as evidence improves. The proposed `0.1.1`
base/`detect` release matrix is CPython 3.9–3.12 on Ubuntu 24.04/ext4, macOS 15/APFS, and Windows
Server 2025/NTFS, with package metadata `>=3.9,<3.13`. Each of those twelve artifact-install cells
must pass for candidate evidence. This package matrix does not activate Chroma: WP7D remains exact
ChromaDB 1.5.9 only on Linux/ext4 Python 3.10–3.12, macOS 15/APFS Python 3.12, and Windows/NTFS
Python 3.12. See the canonical [0.1.1 notes](docs/releases/0.1.1.md) and [release
process](docs/RELEASE_PROCESS.md).

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

**Implemented now:** WP7B's private, bounded operator-snapshot confinement foundation passed
independent review at exact implementation head
`128decb3e0d78825e884f6dce019898b568c6ba2` and was merged through
[PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955`. It accepts a complete filesystem snapshot created
separately by the operator, copies it under hard bounds into a restrictive owned workspace, checks
observed source/copy stability, and authenticates ownership and lease controls for cleanup and
recovery. WP7D implements one aggregate-only consumer for exact ChromaDB 1.5.9 on the finite
activation matrix. Detection runs inside the isolated WP7C worker; raw source fields never cross
IPC, and completion is returned only after connector/detector equality, termination, revalidation,
cleanup, and atomic aggregate-report finalization.

Every direct/live local Chroma new-scan path remains disabled and fails closed. `read_chroma()` fails synchronously
without inspecting its arguments, importing Chroma, touching the filesystem, initializing
detection, or constructing a client. Legacy CLI `--path` requests exit 2 before source access.
Monitor new scans remain unavailable and cannot create a report, state transition, new alert, or
webhook.
Presidio/spaCy detection, the opt-in Australian locale pack, versioned aggregate risk-policy/report
helpers, explicit monitor keys, authenticated privacy-minimal version-3 state, and the reviewed
protocol-v2 one-entry outbox remain in the repository. An existing pending alert retains precedence
and may perform the established retry transition or approved atomic clear after accepted delivery,
without a new source scan. See the [architecture](docs/ARCHITECTURE.md), [monitor state
contract](docs/MONITOR_STATE.md), and [webhook protocol](docs/WEBHOOK_PROTOCOL.md).

**Known limitations:** the operator—not RAGLeakGuard—must provide a complete, quiescent/full-filesystem
snapshot; the implementation's observations do not prove provenance, completeness, source
quiescence, or transactionally atomic multi-file consistency. Work-copy data remains visible to the
running account and administrators until cleanup, cleanup is not certified erasure, and crashes or
ambiguous ownership can leave residue for manual investigation. ChromaDB 1.5.0 and 1.5.9 showed
durable mutation; other versions have not established an acceptable read-only boundary. Issue #15
was deferred, not completed. Exact path spelling still binds an existing monitor scope. Key
protection/recovery/rotation, state rollback, non-overlapping writers, Windows DACLs, and
filesystem/power-loss behavior remain external. Receiver outage can leave one alert pending
indefinitely. Send/response/clear failures can be ambiguous and duplicate delivery. A `2xx` proves
only acceptable response headers. Detector completeness, exactly-once delivery, unconditional
at-least-once delivery, downstream processing, human notification, and historical v1/v2 alert
recovery are not proved.

**Planned or under review:** outbox administration/multiple destinations and stronger reproducible
build provenance beyond the pinned build inputs, hashes, and candidate manifests implemented for
WP8. General Chroma support, other versions or environments, direct/live scanning, and monitor new
scans are not implemented. No expansion or future-support commitment is made. The dormant manual
publication workflow does not itself configure the required protected GitHub environment or PyPI
Trusted Publisher and does not authorize publication.

The Prevent/Fix layer, erasure proof, Control Plane, multi-tenancy, vault/KMS, compliance certification, and assurance profile are not implemented and are outside the current supported surface.

## Coordinated handling

Maintainers will validate reports against the named commit, minimise access to submitted data, and credit reporters when requested and safe. Release timing depends on severity, exploitability, compatibility, and the ability to ship a tested fix. Security advisories and public claims require human maintainer approval.

Good-faith research using synthetic data and avoiding privacy violations, service disruption, credential access, or persistence is welcome. This project does not currently operate a bug bounty and cannot authorize testing against third-party or customer systems.
