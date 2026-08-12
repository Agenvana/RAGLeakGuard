# The AI Data Security Report

A monthly, methods-open report on where AI pipelines actually leak data. Measured, not guessed: every number is produced by open-source scripts with fixed seeds (in this repository), on synthetic data, and can be reproduced on your machine.

| # | Issue | PDF |
|---|---|---|
| 1 | **Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.** (July 2026) | [Download](AI-Data-Security-Report-01-2026-07.pdf) |

Issue #2 (August 2026): *"The Erasure Illusion"*. We test what "delete" actually deletes in AI memory.

**Historical issue #1 evidence:** `scripts/benchmark.py` used 280 labelled identifiers and 28 US/AU format variants; `scripts/clinic_eval.py` used a 100-record synthetic clinic store and the then-current Chroma connector. The released result is tied to its historical source snapshot and does not establish current connector availability or safety. Direct local Chroma scanning is now disabled. All fixture data is synthetic; see [benchmark reproducibility](../docs/BENCHMARK_REPRODUCIBILITY.md).

Author: Wen-Chia "Belle" Chang · Agenvana
