# Release process

RAGLeakGuard releases require explicit human approval. CI, an agent, or a merged pull request must not publish to PyPI or create a release automatically without a separately reviewed release workflow and maintainer authorization.

## Current baseline

Release-system facts recorded at commit `75fb62766f7324264a6ed08847018a6cac348e8b`:

- PyPI reports `ragleakguard` version `0.1.0` and Python `>=3.9`.
- `pyproject.toml` declares version `0.1.0`, while `ragleakguard.__version__` is `0.0.1`. This mismatch must be resolved before the next release; this documentation-only change does not alter either value.
- GitHub has no repository release or Git tag.
- CI runs the test suite for pull requests and pushes to `main` on `ubuntu-latest` with Python 3.9.
- CI installs ranged dependencies and downloads `en_core_web_sm`; inputs are not fully locked.
- There is no package-build, artifact-install, provenance, checksum, secret/dependency-scan, or PyPI publication workflow in this repository.

WP7A corrective status from approved baseline
`e9fdbbe456386b052f35de2c180901275aa6747c`:

- PyPI `0.1.0` contains the unsafe direct Chroma path and must not be used for Chroma scanning. WP7A removes the Chroma runtime extra and disables direct access in source, but no corrective package has been published.
- Executable endpoint evidence established durable mutation for ChromaDB 1.5.0 and 1.5.9. Other versions have not established an acceptable read-only boundary. Issue #15 was deferred, not completed.

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
- Confirm that no source-scanning connector is advertised, snapshot-backed support is described as unavailable and under separate review, and no Chroma supported-version or guaranteed-future-support claim appears.
- Review logs, errors, reports, state, webhooks, fixtures, and built artifacts for secrets, PII canaries, paths, and tenant/record identifiers.
- Complete coordinated disclosure for any vulnerability that should not be exposed by release notes.

### 3. Version and compatibility

- Use one authoritative version and assert equality across package metadata, runtime `__version__`, built wheel/sdist metadata, CLI output if exposed, tag, and release notes.
- Document schema/state and CLI-exit migrations. Provide an explicit upgrade path or fail closed on incompatible persisted state.
- Define the finite supported Python/platform matrix before expanding CI. Current Python 3.9/Ubuntu CI is evidence for that job only, not a full matrix.

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
- Install each artifact into a fresh environment without Chroma and exercise imports, CLI help, synchronous `read_chroma()` failure, disabled scan/monitor exit 6, and pending-alert recovery without repository-relative imports.
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

For the WP7A corrective release, the release note must say that direct local Chroma scanning is
disabled; no source-scanning connector is currently available; Issue #15 was deferred, not
completed; ChromaDB 1.5.0 and 1.5.9 exhibited durable mutation; other versions have not established
an acceptable read-only boundary; snapshot-backed support is unavailable and under separate review;
and PyPI 0.1.0 must not be used for Chroma scanning. This repository has no unreleased release-note
mechanism, so do not invent a version or changelog file; carry the exact proposed wording in the
reviewed pull request until a human authorizes release preparation.

## Planned automation

A future release workflow should encode the gates above with least-privilege permissions, protected environments, pinned actions, locked inputs, full supported-matrix tests, build-once artifacts, provenance/checksums, dry-run installation, and human approval before publication. Adding that workflow is not part of this documentation baseline.
