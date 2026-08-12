# Threat model

**Baseline:** WP7A begins at `e9fdbbe456386b052f35de2c180901275aa6747c`. RAGLeakGuard is an
alpha security project. No source-scanning connector is currently available.

## Scope

In scope:

- synchronous library disablement of direct local Chroma access;
- `scan` and `monitor` CLI validation and precedence;
- preservation of reports, authenticated monitor state, and the WP6 pending-alert outbox;
- detection, risk-policy, report, console, package, documentation, and release claim boundaries;
- protocol-v2 pending-alert recovery and delivery.

Out of scope because it is unavailable or not implemented:

- direct or snapshot-backed Chroma source scanning;
- every other source connector;
- connector pagination, metadata expansion, consistency receipts, and version support;
- Prevent/Fix, erasure proof, Control Plane, certification, or compliance guarantees.

## Evidence and security decision

Executable endpoint tests established durable store mutation for ChromaDB 1.5.0 and 1.5.9 during
client construction or reads. Other Chroma versions have not established an acceptable read-only boundary.
Therefore, direct local Chroma entry points fail closed without importing Chroma or
accessing the source. [Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred,
not completed. Snapshot-backed support remains under separate review and is unavailable.

PyPI 0.1.0 contains the unsafe direct path and must not be used for Chroma scanning.

## Assets and objectives

| Asset | Security objective |
|---|---|
| Supplied source object/path | Do not inspect it in `read_chroma()` and do not access it as a filesystem path on disabled CLI new-scan paths. |
| Source store | Do not import or construct Chroma, execute embeddings, or attempt network access. |
| Existing report/state | Preserve bytes exactly; leave absent artifacts absent; create no temporary artifact. |
| Operator-facing result | Exit 6 with one static message; emit no clean, scan, baseline, report, change, or delivery success signal. |
| Monitor key and authenticated state | Preserve validation precedence, static failures, checkpoint integrity, and scope binding. |
| Existing pending alert | Recover without a new scan; only an accepted delivery may authorize the existing atomic clear transition. |
| Package and public claims | Do not install or advertise a Chroma runtime connector or claim read-only, supported-version, snapshot, completeness, or production safety. |

## Actors and assumptions

- The operator controls command arguments and local artifact locations.
- Supplied objects, source paths, state, and stores may be hostile or privacy-sensitive.
- A local user, logger, dependency, receiver, or CI actor may observe outputs.
- The process is not a sandbox; a compromised dependency inherits process permissions.
- The operator may misread a zero exit or familiar success phrase as evidence of a completed scan.

## Threats, controls, and residual risks

| Threat | Current control | Residual risk / limitation |
|---|---|---|
| Chroma mutates a production source during inspection | Every direct new-scan entry point is disabled before import, client construction, filesystem access, embeddings, or socket activity. | Snapshot feasibility is unresolved and no connector is available. |
| Hostile path leaks through evaluation or errors | `read_chroma()` is a non-generator and raises one static public exception without coercion, formatting, attribute access, comparison, iteration, hashing, `str`, or `repr`. CLI output is also static. | Monitor scope authentication must process the operator-provided path string before pending recovery; this is not filesystem source access. |
| Disabled scan corrupts an artifact or creates false evidence | Exit 6 precedes report work and scan-derived state transitions. Byte-preservation and absent-artifact tests cover reports, state, and temporary files. | Host filesystem compromise remains outside the process contract. |
| Disabled monitor masks key/state or pending-alert failure | Webhook configuration and authenticated key/state validation retain precedence. A pending alert retains WP6 configuration, backoff, retry, transport, ambiguous-clear, and recovery semantics. | A permanently pending alert can block new scans indefinitely; new scans are independently disabled. |
| Pending recovery begins a source scan or creates a new alert | Recovery terminates after one due attempt or one established failure branch. It may only update retry metadata or atomically clear the existing pending entry. | Network-send and clear crashes remain ambiguous and may duplicate delivery. |
| Chroma re-enters through packaging | The Chroma optional dependency is removed; wheel/sdist metadata and clean no-Chroma installation are tested. | PyPI 0.1.0 remains unsafe for Chroma scanning until a separately authorized human action changes public package state. |
| Public prose overstates capability | English, Traditional Chinese, CLI help, architecture, threat model, security, contribution, release, and package claims are regression tested. | Historical artifacts require context and must not be read as current behavior. |
| Detector false negatives mistaken for absence | Disabled CLI paths produce no clean report. Library detection remains explicitly best-effort. | No detector is complete; importing callers remain responsible for raw in-memory findings. |
| Alert replay or duplicate delivery | Existing HMAC framing, freshness, nonce cache, stable delivery ID, and durable atomic receiver interface remain unchanged. | Exactly-once, unconditional at-least-once, downstream processing, and human notification are not proved. |

## Release and review triggers

Connector, state, report, dependency, release, egress, cryptographic, and public security-claim changes
require independent review. A passing test suite is evidence for the named commit and environment only.
It does not establish production safety or authorize merge, tag, package publication, yank, or release.
