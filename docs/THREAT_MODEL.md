# Threat model

**Baseline:** implemented runtime behavior independently inspected at `fda413662dc0583cbee357169bf4b7a7a804ad2f`. RAGLeakGuard is an alpha data-inventory scanner, not a prevention, erasure, or compliance system.

## Scope

In scope:

- local `scan` and `monitor` CLI execution;
- the local Chroma connector;
- Presidio/spaCy detection and post-processing;
- Markdown reports, console messages, JSON monitor state, and webhook payloads;
- benchmark/demo scripts, package dependencies, CI, and release artifacts.

Out of scope because it is not implemented:

- prompt-injection, jailbreak, model-response, or retrieval authorization testing;
- Pinecone or any connector other than local Chroma;
- Prevent/Fix tokenization, vault/KMS, deletion, erasure, or proof;
- a hosted or private Control Plane, multi-tenancy, RBAC/SSO, billing, or fleet operation;
- certification or a guarantee of legal compliance.

## Assets and security objectives

| Asset | Objective |
|---|---|
| Source documents and metadata | Read only what is required; do not create an unintended copy or mutation. |
| Detected values and spans | Keep process-local and out of persistent/external outputs unless an explicitly reviewed interface requires them. |
| Store path, collection/tenant names, record IDs, and exception text | Treat as potentially sensitive metadata; minimise and do not disclose by default. |
| Scan completeness and risk result | Never present incomplete, inconsistent, or failed work as success. |
| Monitor state and alerts | Preserve integrity and detect relevant change without persisting sensitive values. |
| Benchmarks and released reports | Bind claims to exact source, environment, raw evidence, and immutable checksums. |
| Build and release artifacts | Prevent secret inclusion, dependency substitution, version drift, and unauthorized publication. |

## Actors and assumptions

- The operator controls the local command, paths, configuration, state location, and webhook URL.
- The vector store may contain hostile, malformed, very large, or unexpectedly changing content.
- A local user, backup reader, log collector, webhook receiver, compromised dependency, or CI actor may gain access to outputs.
- The operator may reasonably but incorrectly treat a zero exit, clean report, or successful alert message as proof of completion.
- The scanner process is not a sandbox. Anyone who controls its Python environment or dependencies can act with the process's OS permissions.

## Trust boundaries and data flow

1. Chroma documents and metadata cross into the local Python process.
2. Raw text crosses into Presidio/spaCy and is represented in in-memory findings.
3. Aggregate report data plus the source path crosses into a Markdown file.
4. Finding type/count metadata plus store and record identifiers crosses into local monitor state.
5. Similar metadata crosses the network boundary when a webhook is configured.
6. Dependencies, models, source, and packages cross external supply-chain boundaries during setup and release.

## Threats, current controls, and gaps

| Threat | Current control | Known limitation / planned control |
|---|---|---|
| Raw PII copied into monitor state or webhook | Snapshot and webhook builders use finding types/counts rather than finding text. Tests inject a raw-value canary. | State/webhooks still contain paths, collection names, and record IDs. Recursive allowlist/canary tests and metadata minimisation are **planned**. |
| Raw or tenant-revealing data exposed through console/errors | Normal scan output is aggregate; reports do not include detected values. | Paths and record keys are printed, and webhook exceptions are printed verbatim. Sink-by-sink failure-path review is **planned**. |
| Incomplete scan reported as success | Unsupported/malformed locales and unavailable detection runtimes raise typed errors. Both CLI commands preflight before reading the source; locale/usage failures exit 2, while dependencies or a required model that cannot be loaded and prevent runtime initialization cause exit 3 without a report, state update, or webhook. | Connector completion evidence, bounds, cancellation, and concurrent-mutation handling remain **planned**. |
| False negatives mistaken for absence of sensitive data | Reports state that detection is best-effort. The implemented `au` locale pack is opt-in, and unimplemented packs are not registered or advertised. | No detector is complete. Operators must not use a clean scan as proof of safety. |
| Sensitive values exist only in Chroma metadata | Connector output includes metadata. | The current CLI detects document text only; metadata fields are not analyzed. Metadata coverage is **planned** connector hardening. |
| Store availability impact or memory exhaustion | Connector code performs read/list/get calls only. | Collections and CLI items are materialized without pagination/bounds. Streaming, limits, cancellation, and completeness evidence are **planned**. |
| Source store mutation | Application code contains no intended add/update/delete operation in the scan path. | Dependency-side behavior and supported Chroma versions are not independently proven. Validate in staging and back up critical stores. |
| Sensitive value changes without a monitor event | Type/count fingerprints detect many structural changes. | Equal-type/equal-count value changes collide by design. Keyed finding-level fingerprints and migration handling are **planned**. |
| State tampering, corruption, or replay | Temporary-write plus replace reduces partial-file writes. | State has no schema validation, authentication, signing, rollback protection, or corruption recovery. |
| Alert loss, duplication, or spoofing | Webhook exceptions are printed; exposure changes exit 1. | No durable outbox, retry/backoff, idempotency, signature, response policy, or dead-letter state exists. |
| Webhook exfiltration or internal-service access | The URL is explicitly operator supplied. | No scheme/host allowlist or payload signing exists. Treat webhook configuration as privileged. |
| Risk score misclassification | A deterministic static severity map and tests cover basic high/empty cases. | Policy is unversioned and incomplete for some detected types; golden policy coverage is **planned**. |
| Dependency/model compromise or non-reproducible build | CI installs declared extras and a named spaCy model. | Presidio may attempt model acquisition at runtime when the model is absent. RAGLeakGuard does not currently override or disable this Presidio behavior. Runtime acquisition controls and exact model artifact/version pinning are separate residual hardening concerns, alongside unlocked dependency ranges, secret/dependency scans, provenance, and a finite test matrix. |
| Historical report claim cannot be reproduced exactly | Fixed-seed scripts and the PDF are in Git. | Historical environment and raw public outputs are incomplete; see [Benchmark reproducibility](BENCHMARK_REPRODUCIBILITY.md). |

## Security review triggers

Changes to detection/risk policy, connectors, persistence, fingerprints, reports, logs, errors, webhooks, dependencies, releases, migrations, cryptography, or public security/compliance wording require independent review. Tests must use synthetic privacy canaries and cover failure behavior, not only successful output.

## Residual-risk rule

No documentation or successful test run converts these limitations into a guarantee. A release or pull request must state what was tested, on which commit/configuration, what data crossed each boundary, and what remains unproved.
