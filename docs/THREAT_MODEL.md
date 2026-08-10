# Threat model

**Baseline:** implemented runtime behavior independently inspected at `d33dba52e04923d5e4912d4637ce84d19dd8884f` on 2026-08-10. RAGLeakGuard is an alpha data-inventory scanner, not a prevention, erasure, or compliance system.

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
| Operator monitor key | Keep explicit, confidential, purpose-bound, recoverable, and out of every output; never turn key loss or rotation into a clean result. |
| Dedicated webhook signing secret | Keep separate from monitor-state keys, purpose-bound, explicitly provisioned, recoverable/rotatable, and absent from output. |
| Webhook request authenticity and privacy | Emit only the fixed event, authenticate exact request bytes, reject incomplete delivery, and avoid false replay/delivery claims. |
| Benchmarks and released reports | Bind claims to exact source, environment, raw evidence, and immutable checksums. |
| Build and release artifacts | Prevent secret inclusion, dependency substitution, version drift, and unauthorized publication. |

## Actors and assumptions

- The operator controls the local command, paths, configuration, state location, and webhook URL.
- The operator provisions and protects the monitor key, uses the same source/path spelling for an existing scope, prevents overlapping jobs, and deliberately authorizes any re-baseline.
- The operator separately provisions the webhook signing secret at the sender and receiver, protects both copies, maps its random key ID, and controls the HTTPS endpoint.
- The vector store may contain hostile, malformed, very large, or unexpectedly changing content.
- A local user, backup reader, log collector, webhook receiver, compromised dependency, or CI actor may gain access to outputs.
- The operator may reasonably but incorrectly treat a zero exit, clean report, or successful alert message as proof of completion.
- The scanner process is not a sandbox. Anyone who controls its Python environment or dependencies can act with the process's OS permissions.

## Trust boundaries and data flow

1. Chroma documents and metadata cross into the local Python process.
2. Raw text crosses into Presidio/spaCy and is represented in in-memory findings.
3. Aggregate report data plus the source path crosses into a Markdown file.
4. The operator key crosses from a permission-restricted local file into process memory. Purpose-separated derived keys are not persisted.
5. Keyed store/record/finding-derived tokens, counts, construction/key identifiers, and an authenticator cross into local version-2 monitor state. Raw source/store/state paths, collection/record identifiers, finding types/values, document text, spans, and key bytes do not.
6. A dedicated webhook secret crosses from its restricted file into process memory. The exact HTTPS target, fixed 60-byte event, public key ID, timestamp, nonce, and full HMAC cross the network boundary; source/store data, findings, counts, tokens, monitor key, and state path do not.
7. The receiver's TLS endpoint, verifier, trusted clock, key mapping, atomic replay cache, logs, and downstream behavior form a separate trust boundary.
8. Dependencies, models, source, and packages cross external supply-chain boundaries during setup and release.

## Threats, current controls, and gaps

| Threat | Current control | Known limitation / planned control |
|---|---|---|
| Raw PII or tenant metadata copied into monitor state | Version-2 state uses an exact field allowlist containing full-length keyed tokens/fingerprints, counts, public construction/key IDs, and a state authenticator. It omits raw paths, collection/tenant names, record IDs, finding types/values, document text, spans, exceptions, and key material. Recursive serialized-state canaries cover every named class. | Tokens become linkable/forgeable within a compromised or reused key scope. Low-entropy identifiers may be guessed after key compromise. Process memory still contains source data and key material during a run. |
| Raw or tenant-revealing data exposed through console/errors/webhook | Monitor and webhook failures use static messages without exceptions, paths, endpoint details, Host, key IDs, signed bytes, response data, tokens, types, or counts. The webhook body is an exact fixed event; the header allowlist contains only protocol fields. Monitor change output is static. Recursive canaries cover request/body/header/repr/console success and failure paths. | Scan/report console output and reports still print configured paths. Endpoint metadata is visible to DNS/network/TLS infrastructure. Compromised process/runtime/receiver components can access in-memory data or secret material. |
| Incomplete scan reported as success | Unsupported/malformed locales and unavailable detection runtimes raise typed errors. Both CLI commands preflight before reading the source; locale/usage failures exit 2, while dependencies or a required model that cannot be loaded and prevent runtime initialization cause exit 3 without a report, state update, or webhook. | Connector completion evidence, bounds, cancellation, and concurrent-mutation handling remain **planned**. |
| False negatives mistaken for absence of sensitive data | Reports state that detection is best-effort. The implemented `au` locale pack is opt-in, and unimplemented packs are not registered or advertised. | No detector is complete. Operators must not use a clean scan as proof of safety. |
| Sensitive values exist only in Chroma metadata | Connector output includes metadata. | The current CLI detects document text only; metadata fields are not analyzed. Metadata coverage is **planned** connector hardening. |
| Store availability impact or memory exhaustion | Connector code performs read/list/get calls only. | Collections and CLI items are materialized without pagination/bounds. Streaming, limits, cancellation, and completeness evidence are **planned**. |
| Source store mutation | Application code contains no intended add/update/delete operation in the scan path. | Dependency-side behavior and supported Chroma versions are not independently proven. Validate in staging and back up critical stores. |
| Sensitive value changes without a monitor event | Exact type/value identities use typed UTF-8 framing, purpose-separated HMAC-SHA-256 finding tokens, and a full-length keyed aggregate over a sorted multiset. Tests cover equal-type/equal-count replacement, additions/removals, reorder, and duplicate multiplicity. | Score/position-only movement is deliberately ignored. Detector false negatives/instability and non-zero HMAC collision probability remain. Forced cross-run token collisions cannot be distinguished without raw history. |
| State tampering, corruption, incompatible rotation, or false re-baseline | Strict v2 schema/count/digest limits, canonical state authentication with a separate derived key, key/scope binding, explicit no-overwrite initialization, fail-closed v1 rejection, and static remediation precede source access/diff/write/success/webhook. Same-directory temp-file fsync plus atomic replacement is failure-injection tested. | No rollback counter or trusted clock detects replay of an older valid state. Host filesystem durability, local key compromise, insecure backups, and overlapping scheduled writers remain risks. |
| Monitor key exposure, loss, weak provisioning, or unsafe rotation | The helper generates 256 random bits with `secrets`, a random non-secret key ID, strict purpose/construction fields, exclusive creation, and POSIX `0600`; the loader requires exact 256-bit material and rejects broad POSIX permissions. Key IDs/constructions/authentication prevent silent rotation. | Entropy cannot be verified after key creation. Portable Python cannot prove a restrictive Windows DACL. Key backups/recovery/retirement are operator responsibilities; key loss requires restoration or an explicit new-path baseline with lost cross-key history. |
| Alert tampering, forgery, or unsigned compatibility fallback | Exact typed framing and HMAC-SHA-256 authenticate method, authority, request target, allowlisted headers, timestamp, nonce, and the same immutable 60-byte body that is transmitted. The secret is dedicated and purpose-bound; unsigned configuration fails closed. The verifier uses constant-time digest comparison. | Compromise of either shared-secret copy permits forgery. HMAC provides no confidentiality, receiver trust, or downstream-processing proof. Python modules have no separately versioned stable SDK. |
| Replay inside the freshness window | The verifier authenticates first, requires inclusive `±300`-second freshness, then atomically rejects an accepted `(key_id, nonce)` through its cache interface. | HMAC alone does not prevent replay. Receiver clock errors, restarts, process-local cache loss, or multi-node deployments without a shared/durable cache can admit replay. Nonces retain non-zero collision probability. |
| Redirect, downgrade, response-body, client-default, or unbounded transport behavior | URL preflight permits only bounded ASCII HTTPS URLs without credentials/fragments; TLS verification is ordinary and cannot be disabled. A raw HTTP/1.1 client emits the exact header allowlist, follows no redirects, reads only through the response-header terminator, accepts only `2xx`, and uses one monotonic deadline across DNS/connect/TLS/write/headers. | The operator controls the endpoint, so HTTPS URLs can still target internal services. CA-store/runtime compromise is out of scope. A platform DNS call timed out by the caller can remain in a daemon thread until the OS resolver returns. |
| Alert loss, duplication, or ambiguous crash | Signing precedes checkpoint replacement; sending occurs only after checkpoint success. Preparation failure preserves the checkpoint, checkpoint failure sends nothing, transport failure exits 5 without success, and `2xx` is the only delivery-success condition. | The checkpoint advances before transport. A failed send can therefore lose the alert on the next run. A send or response failure cannot prove that the receiver did not accept the request, and crashes around the request are ambiguous. There is no durable outbox, retry/backoff/jitter, idempotency guarantee, dead-letter handling, crash recovery, multi-destination routing, or exactly-once/at-least-once guarantee. |
| Risk score misclassification | The source-controlled [`RLG-ID-RISK@1.0.0`](RISK_POLICY.md) contract explicitly covers every current default and implemented-locale identifier type. It records its version in each new report; uses exact inclusive threshold comparisons; treats unknown/custom types as visible `REVIEW` findings with conservative high-impact overall handling; rejects contradictory aggregates; and has golden matrix, boundary, combination, compatibility, privacy, and determinism tests. | Severity remains context-independent and the 0-3 score is ordinal, not a probability, harm estimate, compliance determination, or completeness proof. Aggregate validation cannot prove connector or detector completeness. Historical reports without attribution remain unversioned and require regeneration for a policy-attributed result. |
| Dependency/model compromise or non-reproducible build | CI installs declared extras and a named spaCy model. | Presidio may attempt model acquisition at runtime when the model is absent. RAGLeakGuard does not currently override or disable this Presidio behavior. Runtime acquisition controls and exact model artifact/version pinning are separate residual hardening concerns, alongside unlocked dependency ranges, secret/dependency scans, provenance, and a finite test matrix. |
| Historical report claim cannot be reproduced exactly | Fixed-seed scripts and the PDF are in Git. | Historical environment and raw public outputs are incomplete; see [Benchmark reproducibility](BENCHMARK_REPRODUCIBILITY.md). |

## Security review triggers

Changes to detection/risk policy, connectors, persistence, fingerprints, reports, logs, errors, webhooks, dependencies, releases, migrations, cryptography, or public security/compliance wording require independent review. Tests must use synthetic privacy canaries and cover failure behavior, not only successful output.

## Residual-risk rule

No documentation or successful test run converts these limitations into a guarantee. A release or pull request must state what was tested, on which commit/configuration, what data crossed each boundary, and what remains unproved. See the complete [webhook protocol](WEBHOOK_PROTOCOL.md) for the language-neutral verifier and key-lifecycle contract.
