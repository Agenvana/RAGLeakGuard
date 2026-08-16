# Release process

RAGLeakGuard releases require explicit human approval. CI, an agent, or a merged pull request must not publish to PyPI or create a release automatically without a separately reviewed release workflow and maintainer authorization.

## Current baseline

Repository and release-system facts carried forward from the WP7B review record and updated for the
unreleased WP7D source implementation:

- PyPI reports `ragleakguard` version `0.1.0` and Python `>=3.9`.
- `pyproject.toml` declares version `0.1.0`, while `ragleakguard.__version__` is `0.0.1`. This mismatch must be resolved before the next release; this documentation-only change does not alter either value.
- GitHub has no repository release or Git tag.
- CI runs the suite for pull requests and pushes to `main` on ext4/Python 3.9, APFS/Python 3.9,
  NTFS/Python 3.9, and NTFS/Python 3.12. This is the finite WP7B evidence matrix, not a documented
  supported release matrix.
- WP7D adds five mandatory exact ChromaDB 1.5.9 cells: Linux/ext4 Python 3.10–3.12, macOS 15/APFS
  Python 3.12, and Windows/NTFS Python 3.12. These are source-commit activation evidence, not a
  published package support claim.
- CI installs ranged dependencies and downloads `en_core_web_sm`; inputs are not fully locked.
- There is no package-build, artifact-install, provenance, checksum, secret/dependency-scan, or PyPI publication workflow in this repository.

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

Do not describe the current workflow as a reproducible release pipeline.

## Roles and separation

- A release preparer proposes the version, changelog, artifacts, evidence, and rollback plan.
- An independent reviewer checks security-sensitive changes, version consistency, supported-scope claims, test evidence, artifacts, and provenance.
- A human maintainer approves the exact commit and performs or explicitly authorizes publication.
- The author/preparer does not self-approve a security-critical release. Agents do not merge, publish, or create a release without explicit authorization.

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
- Define the finite supported Python/platform matrix before release. The current WP7B CI jobs are
  evidence for their exact Python/filesystem environments only. The five WP7D cells likewise prove
  only the immutable source head and are not a published release matrix.

### 4. Tests and documentation

- Run focused security/regression tests and `python -m pytest -q` on every supported matrix entry.
- Validate repository-relative documentation links and any changed external links.
- Run privacy-canary and failure-injection tests relevant to outputs and state.
- Re-run benchmark/evidence checks when a release changes detection, scoring, fixtures, dependencies, or claims. Follow [Benchmark reproducibility](BENCHMARK_REPRODUCIBILITY.md).

### 5. Build and install

The following is a target release check and is **planned** until automation and locked inputs are added:

```bash
python -m build
python -m twine check dist/*
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

### 6. Supply chain

Secret scanning, dependency/vulnerability review, locked release inputs, provenance attestations, and verified artifact installation are **planned release requirements**. A future workflow must pin actions and prevent publication when a required check fails. Findings require human triage; a scanner's zero findings are not a guarantee.

### 7. Approval and publication

- Present the commit SHA, version, matrix results, artifact hashes, provenance, changelog, limitations, and rollback plan to the maintainer.
- Require an explicit human approval for the exact artifacts.
- Create the version tag and GitHub release from the approved commit, then publish those same wheel/sdist bytes to PyPI using the narrowest project-scoped credentials or trusted publishing available.
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
not be used for Chroma scanning. This repository has no unreleased release-note mechanism, so do not
invent a version or changelog file; carry proposed wording in the reviewed pull request until a
human authorizes release preparation.

## Planned automation

A future release workflow should encode the gates above with least-privilege permissions, protected environments, pinned actions, locked inputs, full supported-matrix tests, build-once artifacts, provenance/checksums, dry-run installation, and human approval before publication. Adding that workflow is not part of this documentation baseline.
