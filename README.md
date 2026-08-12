# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**English** | [繁體中文](README.zh-TW.md)

RAGLeakGuard is an early-development security project for diagnosing sensitive data at rest.
Its detection, risk-policy, monitor-state, and authenticated webhook components remain in the
repository, but **no source-scanning connector is currently available**.

## Chroma safety notice

Direct local Chroma scanning is disabled. Executable endpoint evidence established that
ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client construction or reads.
Other Chroma versions have not established an acceptable read-only boundary. This is the exact
tested scope; it is not a claim about every Chroma version.

[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred as `not planned`;
it was not completed. Snapshot-backed support is under separate feasibility and security review,
is not implemented, and may never become available. No supported Chroma version range, future
availability, connector completeness, read-only source access, or production-safety claim is made.

The PyPI `0.1.0` package contains the unsafe direct Chroma path and **must not be used for Chroma
scanning**. Yanking that package and publishing a corrective release require separate human
maintainer authorization and have not been performed by this repository change.

## Current command behavior

A syntactically valid `scan --source chroma` request exits with code 6 and the static disabled-path
message before Chroma import, detector initialization, source access, report work, or success output.
`read_chroma()` raises the public `ChromaConnectorUnavailableError` synchronously without inspecting
its argument.

`monitor` continues to authenticate its key and state first. If authenticated state contains a
pending WP6 alert, the existing configuration, backoff, retry, transport, ambiguous-delivery, and
atomic-clear recovery workflow runs without a new scan. If no alert is pending and a new scan would
otherwise start, `monitor` exits 6 without changing state or creating a report, alert, or webhook.

Ordinary missing-option, unsupported-source, and malformed/unsupported-locale validation still exits
2. Monitor key/state failures exit 4; pending-alert and webhook failures retain exit 5.

```text
Local Chroma scanning is disabled because executable endpoint evidence proved that ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client construction or reads, while other versions have not established an acceptable read-only boundary. No report, monitor state, or webhook was created or replaced.
```

There is intentionally no Chroma scan or monitor quickstart while direct access is disabled.

## Development setup

The Chroma runtime extra has been removed. The following installs the package, detection stack, and
test tools; it does not provide a source-scanning connector.

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python -m venv .venv
# Activate the environment for your platform.
python -m pip install --upgrade pip
python -m pip install -e ".[detect,dev]"
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
compliant, or free of sensitive information. When the required model is absent, Presidio may try to
acquire it during initialization; runtime acquisition control and exact model pinning remain residual
hardening work. Disabled CLI new-scan paths do not initialize this runtime.

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

See [ROADMAP.md](ROADMAP.md). Planned connectors, snapshot feasibility work, Prevent/Fix, Prove,
Control Plane, erasure, compliance, certification, and assurance surfaces are not implemented.

## License

Apache-2.0
