# Contributing to RAGLeakGuard

RAGLeakGuard welcomes focused, evidence-backed contributions. It is an alpha security tool, so correctness, failure semantics, and data minimisation take priority over feature count.

## Before you start

Read [AGENTS.md](AGENTS.md), the [architecture](docs/ARCHITECTURE.md), the [threat model](docs/THREAT_MODEL.md), and the public [roadmap](ROADMAP.md). For a vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a detailed public issue.

Use an issue-scoped branch and keep a pull request to one objective. Roadmap entries express intent, not implementation approval or current support.

## Development setup

The package metadata requires Python 3.9 or newer. The current CI job validates Python 3.9 on Ubuntu; other Python/platform combinations are not yet a documented supported matrix.

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

**Implemented now:** no source-scanning connector is available. Direct local Chroma entry points fail closed before Chroma import or source access. [Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred as `not planned`, not completed. Executable endpoint evidence established durable mutation with ChromaDB 1.5.0 and 1.5.9; other versions have not established an acceptable read-only boundary.

Snapshot-backed support is under separate feasibility and security review and is unavailable. Do not add snapshot code, activate a connector, claim a supported Chroma range, or commit to future support without separate issue scope and evidence. PyPI 0.1.0 contains the unsafe direct Chroma path and must not be used for Chroma scanning.

Any future connector change requires an independently reviewed read-only boundary and must test application and dependency effects, bounds, completeness, malformed input, cancellation, concurrent mutation, filesystem mutation, and outbound network behavior. An incomplete or inconsistent scan must never report success.

Integrations must not emit raw detected values. Any metadata egress needs a documented allowlist and threat-model update.

## Documentation and claims

Use **Implemented now**, **Known limitation**, and **Planned** consistently. Link present-tense capability statements to code/tests in the pull request. Do not state that RAGLeakGuard prevents breaches, proves erasure, guarantees compliance, or is safe for production without scoped evidence and human approval.

Released research is historical evidence. Follow [Benchmark reproducibility](docs/BENCHMARK_REPRODUCIBILITY.md); never replace a released PDF in place to correct methodology or claims.

## Licensing

By submitting a contribution, you agree that it may be distributed under the repository's [Apache-2.0 license](LICENSE) and that you have the right to contribute it.
