# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**English** | [繁體中文](README.zh-TW.md)

> Scan your AI's vector database for exposed sensitive data — before it becomes a breach you can't delete.

**RAGLeakGuard** is a CLI that connects to your vector store (Chroma today; more soon), reads what's stored, detects sensitive data (PII, health, financial), and writes a **risk-scored report**. No changes to your app — point it at the store and scan.

> **What it is:** a *data-inventory & compliance* scanner — it answers the question a
> compliance officer actually asks: *"what regulated data is sitting in our vector store,
> and can we prove we can delete it?"* Read-only; safe to run against production.
>
> **What it isn't:** a red-team tool. It doesn't fire prompt-injection or jailbreak attacks —
> it audits the **data at rest**, not how the model responds under attack.

> 🚧 Early development — building in public. Not production-ready yet.

## Why this matters

RAG systems embed your private data into vector databases. That data **can be reconstructed** from the vectors (embedding inversion), is **hard to delete** (backups, replicas, caches, fine-tuned models), and usually **isn't inventoried**. RAGLeakGuard finds it.

## Install

```bash
pip install "ragleakguard[chroma,detect]"   # scanner + Chroma connector + detection engine
python -m spacy download en_core_web_sm       # one-time: the NLP model (~12 MB)
```

> **Python 3.9 note:** dependencies are pinned (`spaCy<3.8`, `numpy<2`) so prebuilt wheels are used — no source build needed.

<details>
<summary>Or install from source (for development)</summary>

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip          # fresh venvs ship an old pip; the editable install needs a newer one
pip install -e ".[chroma,detect,dev]"
python -m spacy download en_core_web_sm
```
</details>

## Quickstart (≈2 minutes)

```bash
# 1. Create a test vector store full of FAKE sensitive records
python scripts/seed_synthetic.py                          # -> ./sample_store (100 fake clinic records)

# 2. Scan it — global + US recognisers are on by default
ragleakguard scan --source chroma --path ./sample_store --report report.md

# 3. The fixture is Australian, so add the AU locale pack for full coverage
ragleakguard scan --source chroma --path ./sample_store --locale au --report report.md

# 4. Open report.md  (summary, findings by type + severity, risk level, remediation)
```

## Monitor (continuous checks)

One scan tells you where you stand today; `monitor` tells you when it changes:

```bash
# Generate a local 256-bit monitor key; this never overwrites an existing path
ragleakguard generate-monitor-key --output rlg-monitor-key.json

# Generate a separate 256-bit webhook signing secret; share it securely with
# the verifying receiver or gateway, never through the monitor key path
ragleakguard generate-webhook-secret --output rlg-webhook-secret.json

# Explicitly authorize creation of a new authenticated version-2 baseline
ragleakguard monitor --source chroma --path ./sample_store --locale au \
  --key-file rlg-monitor-key.json --state rlg-state.json --initialize

# Later runs diff against the baseline and emit a signed, minimal alert on a
# NEW or CHANGED exposure. The receiver must verify the RAGLeakGuard protocol.
ragleakguard monitor --source chroma --path ./sample_store --locale au \
  --key-file rlg-monitor-key.json --state rlg-state.json \
  --webhook https://receiver.example.com/rlg \
  --webhook-secret-file rlg-webhook-secret.json

# Cron it (hourly): exit 1 = exposure and accepted 2xx delivery; exit 5 =
# webhook configuration, preparation, transport, redirect, or response failure
0 * * * *  ragleakguard monitor --source chroma --path /srv/store --key-file /etc/rlg/monitor-key.json --state /var/lib/rlg/state.json --webhook https://receiver.example.com/rlg --webhook-secret-file /etc/rlg/webhook-secret.json
```

The authenticated state contains full-length keyed scope/record tokens and finding-level fingerprints plus validation counts—no raw path, collection name, record ID, document text, detected value, span, or key material. Version-1 state is rejected without modification because it lacks finding-value history. Missing, invalid, mismatched, or unauthenticated key/state material exits 4 before diffing, success output, or a webhook. Baseline creation requires `--initialize` and never overwrites an existing path.

The authenticated webhook body is always the same 60-byte version-1 exposure-change event. It contains no source/store path, record token, finding type/count, document data, or installation identifier. The exact URL target, body, and allowlisted HTTP/1.1 headers are signed with the dedicated secret; HTTPS certificate and hostname verification is mandatory, redirects are not followed, and one 10-second monotonic deadline covers DNS, connection, TLS, transmission, and response headers. Unsigned `--webhook` usage is intentionally rejected. Direct Slack or Discord incoming webhooks are incompatible; Zapier, n8n, or another downstream service requires a receiver/gateway that first verifies this protocol.

Webhook delivery is still not durable. The checkpoint is advanced before the single network attempt, so a transport failure exits 5 but may lose that alert on the next run. A send or response failure also cannot prove that the receiver did not accept the request. There are no retries, outbox, dead-letter handling, or exactly-once/at-least-once guarantees. A `2xx` proves only that acceptable response headers arrived, not downstream processing. See the [webhook protocol](docs/WEBHOOK_PROTOCOL.md) and [monitor key and state contract](docs/MONITOR_STATE.md) for verification, replay-cache requirements, secret lifecycle, compatibility, and residual risks.

## Detection

- **Default:** global + US recognisers — SSN, bank number, driver license, credit card, email, phone, names, locations, dates, IP, crypto…
- **Locale packs (`--locale`):** `au` (Medicare / phone / TFN / ABN / ACN) — the only implemented opt-in country pack. Other packs are [planned](ROADMAP.md).

Locale codes are case-insensitive and surrounding whitespace is ignored. Unsupported or malformed
locale input exits with code 2. If detection dependencies or the required spaCy model cannot be loaded,
detection-runtime initialization cannot complete and the command exits with code 3. Both checks run
before the source is read, so these failures do not write a report or monitor state and do not send a
webhook.

When the required model is absent, Presidio may attempt to acquire it during initialization.
RAGLeakGuard does not currently override or disable this Presidio behavior. Runtime model acquisition
and exact model pinning remain separate residual hardening concerns.

## 📊 The AI Data Security Report

A monthly, methods-open report measuring where AI pipelines actually leak data — produced with this tool's benchmark scripts, on synthetic data, reproducible on your machine. **Issue #1 (July 2026): [Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.](reports/AI-Data-Security-Report-01-2026-07.pdf)** All issues: [reports/](reports/).

## Roadmap

See **[ROADMAP.md](ROADMAP.md)** — next up includes a custom AU phone recogniser, more connectors (Pinecone, pgvector), and the **Fix** layer (**patent pending**): tokenize sensitive data *before* it's embedded, keep the originals in a secure vault, and erase a person from every copy — replicas, caches, backups included — with a single vault revocation; then **Prove** it with signed, auditor-ready erasure reports.

## License

Apache-2.0
