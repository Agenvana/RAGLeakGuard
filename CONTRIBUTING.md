# Contributing to RAGLeakGuard

RAGLeakGuard welcomes focused, evidence-backed contributions. It is an alpha security tool, so correctness, failure semantics, and data minimisation take priority over feature count.

## Before you start

Read [AGENTS.md](AGENTS.md), the [architecture](docs/ARCHITECTURE.md), the [threat model](docs/THREAT_MODEL.md), and the public [roadmap](ROADMAP.md). For a vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a detailed public issue.

Use an issue-scoped branch and keep a pull request to one objective. Roadmap entries express intent, not implementation approval or current support.

## Development setup

The proposed `0.1.1` package metadata is finite at Python `>=3.9,<3.13`. Its base/`detect` artifact
matrix covers CPython 3.9–3.12 on Ubuntu 24.04/ext4, macOS 15/APFS, and Windows Server 2025/NTFS.
Those twelve cells are distinct from WP7D's exact five-cell ChromaDB 1.5.9 activation matrix. A
passing job is evidence only for its named commit, artifact hashes, resolved inputs, and environment.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[detect,dev]"
python -m spacy download en_core_web_sm
python -m pytest -q
```

Dependency installation and the spaCy model download use the network. Never substitute a customer environment or real data for the synthetic tests.

## Pull request requirements

A pull request should include:

- the problem and explicit non-goals;
- the starting and tested commit SHAs;
- tests covering success, failure, malformed input, and privacy canaries where applicable;
- documentation and migration/compatibility impact;
- commands and results used for validation;
- data-egress and logging impact;
- residual risks and anything not proved.

Run focused tests while developing and the full available suite before requesting review. Independent review is required for the security-critical areas listed in [AGENTS.md](AGENTS.md). Authors must not approve their own security-critical change.

Release-readiness changes must also run the non-publishing build-once candidate workflow, install
both wheel and sdist without editable or repository-relative package imports, inspect both archives,
and record the exact hashes and candidate run. The canonical proposed `0.1.1` wording lives in
[the corrective release notes](docs/releases/0.1.1.md). Do not create a tag, release, publish, yank,
or configure external trust as an incidental part of release preparation.

## Security and privacy rules

- Use only deterministic synthetic identifiers assigned to no real person.
- Never commit `.env` files, credentials, local vector stores, reports generated from non-public data, monitor state, webhook captures, or customer/tenant information.
- Treat metadata, collection names, record IDs, file paths, and exception strings as potentially sensitive.
- A failed or incomplete operation must be visible through a non-success result and must not leave a success report, checkpoint, or alert.
- Tests for serialized output must search recursively for canary secrets and identifiers.
- Do not weaken a security check merely to make a fixture pass. Record and review the intended policy.

## Detection and locale packs

**Implemented now:** global/US Presidio entities are enabled by default and `au` is the only implemented optional locale pack.

A locale contribution must:

- stay out of `LOCALE_PACKS` until all recognizers are implemented;
- be opt-in unless a separately reviewed compatibility decision changes defaults;
- use published validation/checksum rules where they exist;
- include valid, invalid, boundary, overlap, formatting, and false-positive fixtures;
- use synthetic values and cite primary algorithm sources in code or documentation;
- update public capability wording without presenting planned locales as supported.

## Connectors and integrations

**Implemented now:** one aggregate-only operator-snapshot Chroma connector is available for exact
ChromaDB 1.5.9 on Linux/ext4 Python 3.10–3.12, macOS 15/APFS Python 3.12, and Windows/NTFS Python
3.12. Direct/live Chroma entry points remain disabled and fail closed before Chroma import or source access.
[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred as `not planned`, not
completed. Executable endpoint evidence established durable mutation with ChromaDB 1.5.0 and 1.5.9;
1.5.0 remains private evidence only and every other version is rejected publicly.

WP7D consumes a held WP7B work copy through WP7C's bounded two-pass enumeration and runs detection
inside the isolated worker. It exposes bounded connector counters and detector entity-type counts
only after exact equality, teardown, semantic/capability revalidation, proven cleanup, and atomic
aggregate-report finalization. The operator—not RAGLeakGuard—must create a complete,
quiescent/full-filesystem snapshot separately. The implementation does not prove provenance,
quiescence, completeness, or atomic multi-file consistency. Monitor new scans remain unavailable.

Do not widen the version/environment matrix, limits, IPC/report surface, retry policy, or connector
scope without a separate issue, executable evidence, exact-commit independent review, and human authorization.
PyPI 0.1.0 contains the unsafe direct Chroma path and must not be used for Chroma
scanning; no corrective release has been published.

The private foundation passed independent review at exact implementation head
`128decb3e0d78825e884f6dce019898b568c6ba2` and was merged through
[PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955`. That review record does not authorize direct/live
Chroma access, a release, or any expansion beyond the finite WP7D boundary.

Changes to the private snapshot lifecycle must preserve its hard maxima, no-follow regular-object
allowlist, same-device containment, observed-stability checks, restrictive work permissions,
authenticated ownership/lease controls, static privacy-safe failures, and proven-owned cleanup
boundary. Tests must use deterministic synthetic bytes and cover native filesystem behavior rather
than inferring it from the operating-system name.

Changes to the private WP7C layer must preserve exact candidate and native-filesystem gates,
complete migration manifests, local-only settings, application-level read-only calls, two-pass
pagination and canonicalization, keyed bounded manifests, worker termination before cleanup,
static privacy-safe failures, zero child output, OS egress evidence, and explicit classification of
all work-copy effects. Run its isolated candidate matrix as well as the complete no-Chroma suite.

Changes to the public WP7D surface must preserve aggregate-only results, first-pass-only detection,
exact connector/detector count equality, pre-source acknowledgement/locale/source-ID/runtime/host
gates, exact ChromaDB 1.5.9 activation, report atomicity, cleanup-before-result ordering, recursive
privacy canaries, and all five mandatory native-filesystem cells. Keep the ten-cell WP7C private
matrix intact.

Any future connector change requires an independently reviewed read-only boundary and must test application and dependency effects, bounds, completeness, malformed input, cancellation, concurrent mutation, filesystem mutation, and outbound network behavior. An incomplete or inconsistent scan must never report success.

Integrations must not emit raw detected values. Any metadata egress needs a documented allowlist and threat-model update.

## Documentation and claims

Use **Implemented now**, **Known limitation**, and **Planned** consistently. Link present-tense capability statements to code/tests in the pull request. Do not state that RAGLeakGuard prevents breaches, proves erasure, guarantees compliance, or is safe for production without scoped evidence and human approval.

Released research is historical evidence. Follow [Benchmark reproducibility](docs/BENCHMARK_REPRODUCIBILITY.md); never replace a released PDF in place to correct methodology or claims.

## Licensing

By submitting a contribution, you agree that it may be distributed under the repository's [Apache-2.0 license](LICENSE) and that you have the right to contribute it.
