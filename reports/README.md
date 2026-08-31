# The AI Data Security Report

A monthly, methods-open report on where AI pipelines actually leak data. Measured, not guessed: every number is produced by open-source scripts with fixed seeds (in this repository), on synthetic data, and can be reproduced on your machine.

| # | Issue | PDF |
|---|---|---|
| 1 | **Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.** (July 2026) | [Download](AI-Data-Security-Report-01-2026-07.pdf) |
| 2 | **We Asked an AI Database to Delete 100 Patients. All 100 Were Still There.** (August 2026) | [Download](AI-Data-Security-Report-02-2026-08.pdf) |

**Issue #2 evidence:** `findings/src/chroma_erasure.py` reproduces every figure on chromadb 1.5.9 with a fixed seed and fully synthetic data; the pinned environment is `tools/requirements-chroma.txt`, and the raw results for all three tagged runs are in `findings/`. Rerun, from the repository root:

    python -m venv reports/tools/chromaenv
    reports/tools/chromaenv/Scripts/python.exe -m pip install -r reports/tools/requirements-chroma.txt
    reports/tools/chromaenv/Scripts/python.exe reports/findings/src/chroma_erasure.py

(On macOS, substitute `reports/tools/chromaenv/bin/python`.) Findings were disclosed upstream before publication: [chroma-core/chroma#7662](https://github.com/chroma-core/chroma/issues/7662).

Issue #3 (September 2026): the measurement is chosen by what this issue's readers ask.

**Historical issue #1 evidence:** `scripts/benchmark.py` used 280 labelled identifiers and 28 US/AU format variants; `scripts/clinic_eval.py` used a 100-record synthetic clinic store and the then-current Chroma connector. The released result is tied to its historical source snapshot and does not establish current connector availability or safety. Direct local Chroma scanning is now disabled. All fixture data is synthetic; see [benchmark reproducibility](../docs/BENCHMARK_REPRODUCIBILITY.md).

Author: Wen-Chia "Belle" Chang · Agenvana
