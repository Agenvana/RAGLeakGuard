# RAGLeakGuard agent instructions

This file applies to the entire repository. RAGLeakGuard is security software: a change that creates a false success signal or a new data sink is a security change even when the diff is small.

## Read before changing the repository

Read the following before editing code, tests, packaging, workflows, reports, or public claims:

1. [README.md](README.md)
2. [ROADMAP.md](ROADMAP.md)
3. [pyproject.toml](pyproject.toml)
4. Every file under [tests/](tests/)
5. [Architecture](docs/ARCHITECTURE.md)
6. [Threat model](docs/THREAT_MODEL.md)
7. [Security policy](SECURITY.md)
8. [Contributing guide](CONTRIBUTING.md)
9. [Release process](docs/RELEASE_PROCESS.md)

Read any more-specific `AGENTS.md` before changing files below it. A nested file overrides this one only within its directory.

## Status and claim discipline

Public prose must use these meanings consistently:

- **Implemented now:** behavior present in the current code and supported by executable evidence.
- **Known limitation:** behavior present in the current code that narrows a guarantee or requires operator care.
- **Planned:** roadmap or hardening work that is not current behavior.

Never describe planned work in the present tense. Do not claim production safety, complete detection, compliance, certified erasure, breach prevention, enterprise readiness, or support for a connector, locale, platform, or version without evidence tied to the reviewed commit. RAGLeakGuard currently diagnoses data at rest; it does not implement the planned Prevent/Fix, Prove, Control Plane, or assurance surfaces.

## Repository and data boundaries

- This public repository owns the local open-source CLI, detection, monitoring, connectors, public documentation, tests, and reproducibility material.
- A future paid Control Plane is outside this repository and is not implemented here. Do not add private tenancy, billing, KMS/vault operations, customer operations, or proprietary orchestration to this repository without an explicit boundary decision.
- Keep private planning, customer or partner information, pricing, unpublished research findings, unredacted filing material, and post-filing invention details out of this repository.
- Fixtures and examples must be deterministic synthetic data. Never commit real personal data, customer data, credentials, tokens, store snapshots, local reports, state files, or webhook captures.
- Treat store paths, collection or tenant names, record IDs, exception text, and metadata as potentially sensitive even when they are not raw detected values.

## Security invariants for changes

New or changed behavior must satisfy all applicable rules below:

1. A scan, dependency load, locale selection, alert, migration, or evidence operation that did not complete must not report success or emit a success artifact.
2. Do not add raw document text, detected values, spans, secrets, tenant-revealing identifiers, or local paths to logs, persisted state, reports, caches, errors, telemetry, or external payloads.
3. Minimise outputs with explicit allowlists. Tests must recursively inspect serialized data with canary values rather than checking only the top level.
4. Monitoring and persistence changes require corruption, migration, ordering, duplicate, and privacy-leak tests. Cryptographic changes require explicit domain separation and key-lifecycle documentation.
5. Connector changes must remain application-level read-only and prove bounds, pagination/completeness, malformed-input behavior, cancellation, and concurrent-mutation handling. An incomplete or inconsistent scan cannot be reported as complete.
6. Alert-delivery changes must document failure semantics, retry bounds, idempotency, and recovery. A transport exception may not be converted into success.
7. Detection or risk-policy changes require positive, negative, boundary, false-positive, unknown-type, and deterministic golden tests. Locale stubs must stay out of the runtime registry until implemented.
8. Changes to serialization, dependencies, supported runtimes, CLI exits, release workflows, or public security/compliance wording require compatibility and threat-model review.

## Change and review workflow

- Work from an up-to-date `main` in a dedicated issue-scoped branch and worktree. Never push directly to or merge `main` as part of implementation.
- Keep one security objective per pull request. Do not fold unrelated roadmap work into a hardening change.
- Add or update tests with behavior changes. Documentation-only changes must still run link validation and the repository test suite available in the environment.
- Stage only intended paths. Review the complete staged diff and verify that generated output, secrets, stores, state, reports, and virtual environments are absent.
- Record the starting SHA, validation commands, limitations, and residual risks in the pull request.
- The author must not be the sole approver for security-critical work. Independent review is required for detection/risk policy; connectors; state, fingerprints, reports, logs, webhooks, or other egress; dependency and release changes; migrations; and public security or compliance claims.
- Agents may prepare branches and draft pull requests when authorized. A human maintainer owns publication, release, disclosure, and merge decisions.

## Baseline validation

Run the narrowest relevant tests and then, when dependencies are available:

```bash
python -m pytest -q
```

For documentation changes, verify all repository-relative Markdown links and recompute any cited artifact checksum. Follow [Benchmark reproducibility](docs/BENCHMARK_REPRODUCIBILITY.md) when touching report methods or evidence. Do not rewrite a released report artifact to correct its provenance; publish a separately reviewed amendment.
