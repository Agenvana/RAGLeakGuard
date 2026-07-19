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
# First run writes a baseline (fingerprints only — never your data)
ragleakguard monitor --source chroma --path ./sample_store --locale au --state rlg-state.json

# Later runs diff against the baseline and alert on NEW or CHANGED findings
ragleakguard monitor --source chroma --path ./sample_store --locale au --state rlg-state.json \
  --webhook https://hooks.example.com/your-alert   # Slack / Discord / Zapier / n8n

# Cron it (hourly): exit code 1 = new exposure detected
0 * * * *  ragleakguard monitor --source chroma --path /srv/store --state /var/lib/rlg/state.json --webhook $HOOK
```

The state file and webhook payloads contain **record ids, finding types, and counts only** — no document text, no detected values, ever.

## Detection

- **Default:** global + US recognisers — SSN, bank number, driver license, credit card, email, phone, names, locations, dates, IP, crypto…
- **Locale packs (`--locale`):** `au` (Medicare / TFN / ABN), `uk`, `sg`, `in` — opt-in country IDs.

## 📊 The AI Data Security Report

A monthly, methods-open report measuring where AI pipelines actually leak data — produced with this tool's benchmark scripts, on synthetic data, reproducible on your machine. **Issue #1 (July 2026): [Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.](reports/AI-Data-Security-Report-01-2026-07.pdf)** All issues: [reports/](reports/).

## Roadmap

See **[ROADMAP.md](ROADMAP.md)** — next up includes a custom AU phone recogniser, more connectors (Pinecone, pgvector), and the **Fix** layer (**patent pending**): tokenize sensitive data *before* it's embedded, keep the originals in a secure vault, and erase a person from every copy — replicas, caches, backups included — with a single vault revocation; then **Prove** it with signed, auditor-ready erasure reports.

## License

Apache-2.0
