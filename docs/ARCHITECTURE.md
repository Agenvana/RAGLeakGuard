# Architecture

**Baseline:** WP7B's private bounded operator-snapshot confinement foundation passed independent
review at exact implementation head `128decb3e0d78825e884f6dce019898b568c6ba2` and was merged
through [PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955` on 2026-08-13. This post-review documentation
baseline starts from that merge. This is an alpha architecture description, not a stability,
production-readiness, connector-completeness, or compliance guarantee.

## Implemented now

RAGLeakGuard is a local Python package and CLI. No source-scanning connector is currently
available. The exposed Chroma entry points are explicit fail-closed boundaries:

```mermaid
flowchart LR
    A["scan: valid Chroma request"] --> B["Static exit 6"]
    C["monitor: authenticated state"] --> D{"Pending alert?"}
    D -->|"No"| B
    D -->|"Yes"| E["WP6 recovery/delivery"]
    E --> F["Approved atomic outbox clear after accepted delivery"]
    G["read_chroma(object)"] --> H["Synchronous static exception"]
```

Detection, risk-policy, report construction, authenticated monitor-state, and protocol-v2 webhook
modules remain importable. A separately versioned stable Python SDK contract is not defined.

### Disabled Chroma boundary

[connectors.py](../src/ragleakguard/connectors.py) defines the public
`ChromaConnectorUnavailableError`, the one static disabled message, and a non-generator
`read_chroma()` function. Invocation raises synchronously before Chroma import, path coercion or
inspection, filesystem access, detector initialization, or client construction. It returns no
iterator or scan session.

For `scan`, Typer performs ordinary option parsing, and RAGLeakGuard preserves source/path and locale
usage validation. A valid Chroma new-scan request then exits 6 before detection, source access,
report construction or replacement, and success output.

For `monitor`, source/path and locale usage validation is followed by existing webhook configuration,
monitor-key, state, and scope authentication. A valid pending alert retains WP6 precedence and is
recovered without a new scan. When there is no pending alert, execution exits 6 before detection,
Chroma import, source access, scan-derived state changes, pending-alert creation, webhook request
preparation, or success output.

This preserves existing report and state bytes on disabled paths, leaves absent artifacts absent,
and creates no temporary artifact. The Chroma runtime dependency is not present in package metadata.

### Evidence and decision boundary

Executable endpoint evidence established durable mutation with ChromaDB 1.5.0 and 1.5.9: approved
local Rust-client construction could append a durable `acquire_write` row, including on migration
validation failure, and successful reads could change hashes of opaque durable segment files. Other
versions have not established an acceptable read-only boundary.

[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred as `not planned`; it
was not completed. Snapshot-backed public scanning is unavailable and not implemented. Its
feasibility, security, and any activation require work separate from the completed private WP7B
foundation. No supported Chroma range or future activation is implied.

### Private snapshot-confinement foundation

[_snapshot.py](../src/ragleakguard/_snapshot.py) implements the private WP7B filesystem lifecycle.
It accepts a directory that the operator represents as a complete, already-created, quiescent
filesystem snapshot; rejects a symlinked root or work parent; inventories only same-device regular
files and directories without following links or reparse points; copies into a new restrictive
RAGLeakGuard-owned workspace; and re-inventories and re-hashes the source and copy before returning a
private held lease. It does not import or construct Chroma.

The lifecycle rejects hard-linked or sparse files, unsupported objects, Windows alternate data
streams, traversal or source/work overlap, observed mutation, insufficient free space, expired
deadlines, cancellation, unsafe permissions, ownership/lease uncertainty, and these hard maxima:

| Bound | Maximum |
|---|---:|
| Source files | 20,000 |
| Source directories, including the root | 10,000 |
| Relative depth | 16 |
| One source file | 16 GiB |
| Aggregate source bytes | 64 GiB |
| Work-copy files, including control files | 21,000 |
| Work-copy bytes, including control files | 72 GiB |
| Copy chunk | 1 MiB |
| Preparation deadline | 1,800 seconds |
| Cleanup/recovery deadline | 600 seconds |

The workspace contains restrictive local key, authenticated owner, authenticated snapshot-phase,
and authenticated lease control files. Cleanup validates resolved containment, the expected
filesystem objects, authenticated ownership, and the held lease before removing anything. Recovery
examines only correctly prefixed direct children of the selected work parent and removes a workspace
only when its ownership documents authenticate and its exclusive lease can be acquired. Static
errors and redacted representations omit source/work paths, file names, contents, and underlying
exception text.

These primitives have no public export, CLI option, connector hook, package extra, report path,
monitor transition, or webhook behavior. `read_chroma()`, `scan`, and new-scan `monitor` remain at
the WP7A disabled boundary. A separate issue, evidence set, exact-commit independent review, and
human authorization are required before any consumer or source-scanning surface may use WP7B.

### Detection and risk reports

[detect.py](../src/ragleakguard/detect.py) contains the Presidio/spaCy detector. Default library use
requests global/US types; `au` is the only implemented opt-in locale pack. Findings may contain raw
detected text in process, so importing callers are responsible for protecting it. Disabled CLI paths
do not initialize detection.

[risk_policy.py](../src/ragleakguard/risk_policy.py) implements `RLG-ID-RISK@1.0.0`.
[report.py](../src/ragleakguard/report.py) can build deterministic aggregate Markdown reports, but
disabled new-scan CLI paths never invoke or write one. Historical reports remain unversioned when
they lack explicit policy attribution.

### Monitor state and pending-alert recovery

[monitor.py](../src/ragleakguard/monitor.py) retains the authenticated version-3 checkpoint and its
one-entry privacy-minimal pending-alert outbox. Key/scope/state validation still precedes new-scan
disablement. Pending recovery uses the same stable delivery ID with fresh attempt authentication,
bounded retry metadata, HTTPS-only no-redirect transport, and static privacy-safe failure messages.

Only accepted `2xx` response headers permit the approved authenticated atomic transition from an
existing pending alert to `pending_alert: null`. A clear failure remains ambiguous and can cause a
duplicate. Recovery does not access the source or construct any new scan result. See the
[monitor state contract](MONITOR_STATE.md) and [webhook protocol](WEBHOOK_PROTOCOL.md).

### CLI exits

- `0`: credential generation succeeded, or an existing pending alert was accepted and durably
  cleared without a scan.
- `2`: ordinary CLI source/path/locale or option-pair usage failure.
- `4`: monitor key/state, retry-metadata, or accepted-but-not-cleared failure.
- `5`: pending configuration/backoff/retry or webhook configuration/preparation/transport/response
  failure.
- `6`: a valid direct local Chroma new-scan path was reached and disabled.

Exit codes 1 and 3 remain reserved by historical behavior but are not emitted by disabled new-scan
paths because no scan or detector initialization begins.

## Trust boundaries

- A supplied source object/path is sensitive input and must not be inspected on the library disabled
  path or accessed as a filesystem path on CLI disabled new-scan paths.
- Existing report and monitor-state files are sensitive local artifacts and must remain byte-identical
  when a new scan is disabled.
- Monitor keys and webhook secrets remain explicit local secret inputs. Their storage, backup,
  rotation, recovery, and scheduled-job permissions are operator boundaries.
- A pending-alert receiver, TLS endpoint, replay cache, delivery-ID store, logs, and downstream work
  remain separate trust boundaries.
- Package indexes, dependencies, model downloads, source control, and release systems are supply-chain
  boundaries.
- The operator who creates a source snapshot, the local account and administrators that can alter
  it, filesystem semantics, free-space accounting, and process/power-loss behavior are boundaries
  for the private WP7B lifecycle.

## Planned or unavailable

Snapshot-backed public Chroma scanning remains unavailable and requires separate feasibility,
security, activation, and exact-commit review; the private WP7B lifecycle is not a connector.
Direct Chroma access remains disabled. Additional connectors, Prevent/Fix, Prove, Control Plane,
certification, and hosted services are not implemented.
PyPI 0.1.0 contains the unsafe direct path and must not be used for Chroma scanning.
