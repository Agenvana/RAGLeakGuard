# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**English** | [繁體中文](README.zh-TW.md)

RAGLeakGuard is an early-development security project for diagnosing sensitive data at rest.
Its detection, risk-policy, monitor-state, and authenticated webhook components remain in the
repository. A bounded aggregate-only Chroma connector is implemented for complete operator-created
offline snapshots. Direct/live source-store scanning remains disabled.

## Chroma safety notice

Direct/live local Chroma scanning is disabled. Executable endpoint evidence established that
ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client construction or reads.
Other Chroma versions have not established an acceptable read-only boundary. This is the exact
tested scope; it is not a claim about every Chroma version.

[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred as `not planned`;
it was not completed. WP7B's private, bounded operator-snapshot confinement foundation passed
independent review at exact implementation head
`128decb3e0d78825e884f6dce019898b568c6ba2` and was merged through
[PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955`. WP7D now consumes that private work copy through the
reviewed WP7C two-pass enumerator and performs detection inside the isolated worker. Public
activation is limited to exact ChromaDB 1.5.9 on Linux/ext4 with Python 3.10–3.12, macOS 15/APFS
with Python 3.12, and Windows/NTFS with Python 3.12. ChromaDB 1.5.0 remains private evidence only
and is rejected by the public activation path.

The operator—not RAGLeakGuard—must create a complete, quiescent/full-filesystem snapshot before
invocation. RAGLeakGuard does not prove its provenance, quiescence, completeness, or transactional
atomic consistency. The snapshot is potentially hostile and sensitive. No general Chroma support,
read-only live-source access, connector completeness, or production-safety claim is made.

The PyPI `0.1.0` package contains the unsafe direct Chroma path and **must not be used for Chroma
scanning**. Yanking that package and publishing a corrective release require separate human
maintainer authorization and have not been performed by this repository change.

## Corrective release status

`0.1.1` is the proposed corrective version in source; it is not published, tagged, or released.
Hatch reads `ragleakguard.__version__` as the single version source. The build-once
`release-candidate.yml` workflow has read-only repository permissions, no publication credential,
and no OIDC `id-token` permission. It builds wheel and sdist from one exact commit, inspects and
hashes them, and tests the installed artifacts before it can emit review-only candidate evidence.

The proposed base/`detect` package matrix is CPython 3.9–3.12 on Ubuntu 24.04/ext4, macOS 15/APFS,
and Windows Server 2025/NTFS. Package metadata is finite at `>=3.9,<3.13`. This twelve-cell package
matrix does not widen Chroma support: public snapshot activation remains the exact five ChromaDB
1.5.9 cells stated above. See the canonical [0.1.1 corrective release
notes](docs/releases/0.1.1.md) and [release process](docs/RELEASE_PROCESS.md).

The separate `publish-pypi.yml` workflow is manual and dormant. It never rebuilds artifacts and
requires an exact annotated tag, commit, version, candidate run, artifact hashes, a pre-existing
protected `pypi` environment, and externally configured PyPI OIDC Trusted Publishing. WP8 does not
create any of those publication authorities and publishes nothing.

## Current command behavior

`scan --source chroma` accepts only `--snapshot`, `--work-parent`, a narrow pseudonymous
`--source-id`, the explicit `--acknowledge-offline-complete-snapshot`, optional `--locale`, and
`--report`. Legacy `--path` is rejected before source access. A success line is emitted only after
bounded copy preparation, two-pass enumeration, complete detection, exact aggregate equality,
worker termination, final capability validation, cleanup, and atomic report finalization.
`read_chroma()` still raises `ChromaConnectorUnavailableError` synchronously without inspecting its
arguments.

`monitor` continues to authenticate its key and state first. If authenticated state contains a
pending WP6 alert, the existing configuration, backoff, retry, transport, ambiguous-delivery, and
atomic-clear recovery workflow runs without a new scan. If no alert is pending and a new scan would
otherwise start, `monitor` exits 6 without changing state or creating a report, alert, or webhook.

Ordinary missing-option, unsupported-source, and malformed/unsupported-locale validation still exits
2. Scan/report uncertainty exits 1, detection-runtime failure exits 3, and an unavailable exact
candidate or activation environment exits 6. Monitor key/state failures exit 4; pending-alert and
webhook failures retain exit 5.

Install the exact optional Chroma candidate and the existing detector stack, then point the command
only at a separately created offline snapshot:

```bash
python -m pip install ".[chroma-snapshot,detect]"
python -m spacy download en_core_web_sm
ragleakguard scan --source chroma \
  --snapshot /private/offline-snapshot \
  --work-parent /private/ragleakguard-work \
  --source-id source-1 \
  --acknowledge-offline-complete-snapshot \
  --report /private/reports/source-1.md
```

The paths above are placeholders and are never included in normal console output or the report.
There is intentionally no Chroma monitor quickstart because monitor new scans remain unavailable.

## Development setup

Chroma remains outside base dependencies. The following installs the exact snapshot candidate,
detection stack, and test tools:

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python -m venv .venv
# Activate the environment for your platform.
python -m pip install --upgrade pip
python -m pip install -e ".[chroma-snapshot,detect,dev]"
python -m spacy download en_core_web_sm
python -m pytest -q
```

The deterministic Chroma seed/evaluation scripts are retained only as historical research and
development-fixture material. They are not a supported scanning workflow and must never be run
against real, production, customer, or otherwise sensitive stores.

## Detection

- **Default library configuration:** global and US Presidio recognizers.
- **Locale packs (`--locale`):** `au` is the only implemented opt-in country pack.

Detection is best-effort. A result from the detector library is not proof that data is safe,
compliant, or free of sensitive information. The required spaCy model must already be installed;
the isolated worker denies model acquisition, network egress, and nested processes.

## Monitor recovery

The authenticated version-3 state and protocol-v2 webhook design are documented in the
[monitor state contract](docs/MONITOR_STATE.md) and [webhook protocol](docs/WEBHOOK_PROTOCOL.md).
Pending recovery does not access Chroma and cannot create a new scan-derived alert. A `2xx` response
permits only the approved atomic outbox-clear transition. This does not prove exactly-once delivery,
downstream processing, or human notification.

Credential helpers remain available:

```bash
ragleakguard generate-monitor-key --output rlg-monitor-key.json
ragleakguard generate-webhook-secret --output rlg-webhook-secret.json
```

Recovery requires the original `--key-file`, authenticated `--state`, and—when an alert is
pending—the protocol-v2 `--webhook-secret-file` plus its authenticated HTTPS receiver. New baseline
creation with `--initialize` is disabled because it would require a new scan. Invalid key/state
material exits 4; pending configuration, backoff, retry, preparation, transport, or response failure
uses exit 5. Direct Slack and Discord incoming webhooks are incompatible because recovery requires the
dedicated protocol-v2 verifier and durable delivery-ID deduplication described in the protocol.

## Historical research

The July 2026 [AI Data Security Report](reports/AI-Data-Security-Report-01-2026-07.pdf) and its
source history are frozen historical evidence. They do not establish current connector availability
or safety. See [benchmark reproducibility](docs/BENCHMARK_REPRODUCIBILITY.md).

## Roadmap and non-claims

See [ROADMAP.md](ROADMAP.md). The finite operator-snapshot connector described above is implemented.
Additional connectors, direct/live scanning, monitor new scans, Prevent/Fix, Prove, Control Plane,
erasure, compliance, certification, and assurance surfaces are not implemented.

## License

Apache-2.0
