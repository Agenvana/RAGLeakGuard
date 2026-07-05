# The AI Data Security Report

A monthly, methods-open report on where AI pipelines actually leak data. Measured, not guessed: every number is produced by open-source scripts with fixed seeds (in this repository), on synthetic data, and can be reproduced on your machine.

| # | Issue | PDF |
|---|---|---|
| 1 | **Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.** (July 2026) | [Download](AI-Data-Security-Report-01-2026-07.pdf) |

Issue #2 (August 2026): *"The Erasure Illusion"*. We test what "delete" actually deletes in AI memory.

**Reproduce issue #1:** `scripts/benchmark.py` (280 labelled identifiers, 28 US/AU format variants, 4 configurations) and `scripts/clinic_eval.py` (100-record synthetic clinic store, end-to-end through Chroma). Fixed seeds; identical numbers on every run. All data is synthetic; no real person's information is used anywhere.

Author: Wen-Chia "Belle" Chang · Agenvana
