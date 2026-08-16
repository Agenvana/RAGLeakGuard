# Release process

RAGLeakGuard releases require explicit human approval. CI, an agent, or a merged pull request must not publish to PyPI or create a release automatically without a separately reviewed release workflow and maintainer authorization.

## Current baseline

Repository and release-system facts for the unpublished WP8 source state:

- PyPI reports `ragleakguard` version `0.1.0` and Python `>=3.9`.
- Source proposes corrective version `0.1.1`. Hatch reads
  `src/ragleakguard/__init__.py` as the single authoritative version source; executable tests require
  equality with project policy, wheel/sdist metadata, and the canonical release notes.
- GitHub has no repository release or Git tag.
- The proposed base/`detect` artifact matrix is CPython 3.9–3.12 on Ubuntu 24.04/ext4, macOS
  15/APFS, and Windows Server 2025/NTFS. Package metadata is finite at `>=3.9,<3.13`.
- WP7D adds five mandatory exact ChromaDB 1.5.9 cells: Linux/ext4 Python 3.10–3.12, macOS 15/APFS
  Python 3.12, and Windows/NTFS Python 3.12. WP8 does not widen those cells. WP7C retains the
  existing private ten-cell 1.5.0/1.5.9 evidence matrix.
- Build-only wheels and their hashes, GitHub Actions, runner labels, the builder Python, direct test
  inputs, and the spaCy model asset SHA-256 are pinned for the candidate workflow. Transitive runtime
  dependencies are still resolved per environment and recorded with `pip list`; they are not fully
  locked and remain a residual supply-chain risk.
- `release-candidate.yml` builds once and never publishes. It checks metadata/archive contents,
  forbidden material and privacy canaries, tests wheel and sdist outside repository imports, runs
  the base/WP7C/WP7D matrices, and produces artifact SHA-256 hashes plus build and review manifests.
- `publish-pypi.yml` is `workflow_dispatch` only, never rebuilds, and validates a named candidate
  run, annotated tag, commit, version, hashes, evidence, exact workflow identity, and an existing
  protected `pypi` environment. Dispatch must select `refs/tags/v0.1.1`; `github.sha`,
  `github.workflow_sha`, the annotated tag target, and the reviewed commit must be identical.
  Only its final job has `id-token: write`.
- WP8 does not configure the protected environment or the external PyPI Trusted Publisher. It does
  not tag, release, publish, yank, or alter PyPI/TestPyPI state.

WP7A corrective status from approved baseline
`e9fdbbe456386b052f35de2c180901275aa6747c`:

- PyPI `0.1.0` contains the unsafe direct Chroma path and must not be used for Chroma scanning. WP7A removes the Chroma runtime extra and disables direct access in source, but no corrective package has been published.
- Executable endpoint evidence established durable mutation for ChromaDB 1.5.0 and 1.5.9. Other versions have not established an acceptable read-only boundary. Issue #15 was deferred, not completed.

WP7B review and merge record:

- The private bounded operator-snapshot confinement foundation passed independent review at exact
  implementation head `128decb3e0d78825e884f6dce019898b568c6ba2` and was merged through
  [PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
  `5db765689d35eec8ba918f0f616d5fea34e56955`.
- WP7D adds a bounded aggregate-only consumer of that foundation for complete operator-created
  offline snapshots. Direct/live Chroma and monitor new scans remain disabled. The operator must
  create a complete, quiescent/full-filesystem snapshot; RAGLeakGuard does not prove provenance,
  quiescence, completeness, or atomic consistency. No corrective release has been published.

Do not describe candidate evidence as a reproducible-build guarantee, production-safety evidence,
or publication authorization. `ready-for-independent-review` means only that every named gate in one
exact workflow run succeeded.

## Roles and separation

- A release preparer proposes the version, changelog, artifacts, evidence, and rollback plan.
- An independent reviewer checks security-sensitive changes, version consistency, supported-scope claims, test evidence, artifacts, and provenance.
- A human maintainer approves the exact commit and performs or explicitly authorizes publication.
- The author/preparer does not self-approve a security-critical release. Agents do not merge, publish, or create a release without explicit authorization.
- The protected environment must set `prevent_self_review: true`. If only one qualified maintainer
  exists, that maintainer cannot both dispatch and approve the deployment; publication remains
  blocked until a second eligible reviewer is available. Do not weaken the environment to work
  around that limitation.

## Release gates

All applicable gates must pass on the exact release commit.

### 1. Scope and history

- Release from an issue-scoped pull request based on current `main`.
- Confirm the tree is clean and the reviewed commit is reachable from the approved branch.
- Resolve review findings and record known limitations and compatibility changes.
- Confirm no released report, raw evidence, or history was rewritten.

### 2. Claims and security

- Reconcile README, roadmap, architecture, threat model, security policy, CLI help, and package metadata with implemented behavior.
- Re-check every present-tense security/compliance/production claim against evidence.
- Confirm that planned connectors, locales, Prevent/Fix, Prove, Control Plane, certification, and assurance behavior are labeled planned.
- Confirm that only the finite exact-1.5.9 operator-snapshot connector is advertised; direct/live
  Chroma and monitor new scans remain disabled; operator snapshot duties and non-proofs are explicit;
  and no broader Chroma range or guaranteed-future-support claim appears.
- Review logs, errors, reports, state, webhooks, fixtures, and built artifacts for secrets, PII canaries, paths, and tenant/record identifiers.
- Complete coordinated disclosure for any vulnerability that should not be exposed by release notes.

### 3. Version and compatibility

- Use one authoritative version and assert equality across package metadata, runtime `__version__`, built wheel/sdist metadata, CLI output if exposed, tag, and release notes.
- Document schema/state and CLI-exit migrations. Provide an explicit upgrade path or fail closed on incompatible persisted state.
- Keep the finite base package matrix at the twelve cells in
  [the canonical 0.1.1 notes](releases/0.1.1.md). The five WP7D cells prove only exact ChromaDB
  1.5.9 behavior for the immutable source/artifact evidence; they do not widen the base matrix or
  activate other Chroma versions.

### 4. Tests and documentation

- Run focused security/regression tests and `python -m pytest -q` on every supported matrix entry.
- Validate repository-relative documentation links and any changed external links.
- Run privacy-canary and failure-injection tests relevant to outputs and state.
- Re-run benchmark/evidence checks when a release changes detection, scoring, fixtures, dependencies, or claims. Follow [Benchmark reproducibility](BENCHMARK_REPRODUCIBILITY.md).

### 5. Build and install

The non-publishing candidate workflow automates the following checks with exact build inputs:

```bash
python -m build --no-isolation --sdist --wheel --outdir dist
python .github/release/verify_candidate.py ...
```

- Build wheel and sdist once from the reviewed commit in a clean environment.
- Record builder OS/architecture, Python version, build frontend/backend versions, lock/material inputs, source SHA, and timestamp.
- Inspect both archives for unexpected files, secrets, stores, state, reports, credentials, or private material.
- Install each artifact into a fresh environment without Chroma and exercise imports, CLI help,
  synchronous `read_chroma()` failure, legacy direct-path rejection, disabled monitor exit 6, and
  pending-alert recovery without repository-relative imports. Separately install the exact
  `chroma-snapshot` and detection extras on every claimed activation tuple and exercise a synthetic
  complete operator snapshot, cleanup, and aggregate report finalization.
- Generate SHA-256 checksums and provenance for the final artifacts. Do not rebuild after approval; publish the reviewed bytes.

The build manifest is created only after archive and metadata checks pass. The separate review
manifest is created only after both artifact-install jobs and every base, WP7C, and WP7D matrix job
passes. Neither manifest is a success signal for publication.

### 6. Supply chain

WP8 implements full-SHA action pins, hash-pinned build tools, exact direct test constraints, archive
credential/privacy pattern checks, resolved-input logs, verified artifact installation, artifact
hashes, and fail-closed candidate manifests. Full transitive locks, hermetic/reproducible builds,
independent malware/vulnerability scanning, and externally verifiable provenance remain planned.
Findings require human triage; zero pattern matches are not a guarantee.

### 7. Approval and publication

- Present the commit SHA, version, matrix results, artifact hashes, provenance, changelog, limitations, and rollback plan to the maintainer.
- Require an explicit human approval for the exact artifacts.
- After separate authorization, a human maintainer may create the exact annotated `v0.1.1` tag and
  GitHub release for the approved commit. The dormant workflow must be dispatched at that tag, so
  its exact secure workflow ref is
  `Agenvana/RAGLeakGuard/.github/workflows/publish-pypi.yml@refs/tags/v0.1.1`. It can then publish
  only the same reviewed wheel/sdist bytes through the protected `pypi` environment and
  preconfigured PyPI OIDC Trusted Publisher.
- Verify the public hashes, metadata, install, import version, and CLI smoke test after publication.
- Record publisher, approval, time, URLs, and verification result in the release evidence.

## Rollback and incident response

Python package indexes are append-only: never replace files for an existing version.

1. Stop further publication and preserve logs, artifacts, hashes, credentials, and the affected source SHA.
2. If compromise is suspected, revoke/rotate publication credentials and protect the advisory details.
3. Yank the affected PyPI version only after explicit human authorization, with a concise reason that does not expose embargoed details. WP7A implementation and review alone do not authorize a yank.
4. Publish a new patched version from a reviewed commit; do not reuse the old version number or tag.
5. Add an advisory/release note, upgrade guidance, affected-version range, and evidence after coordinated disclosure approval.
6. Review whether reports or public claims relied on the affected behavior. Amend them separately; never rewrite released artifacts.

For any future corrective release, the release note must say that direct/live Chroma and monitor new
scans are disabled; Issue #15 was deferred, not completed; ChromaDB 1.5.0 and 1.5.9 exhibited durable
mutation; only exact 1.5.9 operator snapshots on the five reviewed tuples are activated; the
operator must create a complete quiescent/full-filesystem snapshot; provenance, quiescence,
completeness, and atomic consistency are not proved; detection is best-effort; and PyPI 0.1.0 must
not be used for Chroma scanning. The canonical proposed wording is
[0.1.1 corrective release notes](releases/0.1.1.md). Its `proposed; not published` status must remain
until a human maintainer authorizes and completes publication of the exact reviewed bytes.

## Automation boundary

The candidate workflow has `contents: read` only and no credential or OIDC permission. The manual
publication workflow does not build. Its first step validates every dispatch input from environment
variables before checkout or artifact download and emits only validated outputs. The workflow run
must originate from the exact `v0.1.1` tag and reviewed commit; an arbitrary branch workflow ref is
rejected.

Referencing an environment in YAML is not sufficient protection. Before the OIDC job can start, the
validation job requires all of this existing administrative state:

- environment name exactly `pypi`, with required reviewers and `prevent_self_review: true`;
- Allow administrators to bypass configured protection rules: disabled.
- selected-branches-and-tags deployment policy (`protected_branches: false`,
  `custom_branch_policies: true`);
- exactly one deployment policy, of type `tag`, named exactly `v0.1.1`, with no branch policy.

The tag-only deployment policy is independently enforced by GitHub before the environment job and
prevents a modified publication workflow dispatched from an arbitrary branch from reaching `pypi`.
The exact PyPI Trusted Publisher tuple that a maintainer would configure only after separate
authorization is:

```text
repository: Agenvana/RAGLeakGuard
workflow: publish-pypi.yml
environment: pypi
```

WP8 does not create that environment, those protection rules, the tag, or the external trusted
publisher. Absent any one of them, publication remains blocked. Human maintainers own environment
protection, external trust, tag, release, publication, yank, rollback, and merge decisions.
