# The AI Data Security Report

A monthly, methods-open report on where AI pipelines actually leak data. Measured, not guessed: every number is produced by open-source scripts with fixed seeds (in this repository), on synthetic data, and can be reproduced on your machine.

| # | Issue | PDF |
|---|---|---|
| 1 | **Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.** (July 2026) | [Download](AI-Data-Security-Report-01-2026-07.pdf) |
| 2 | **We Asked an AI Database to Delete 100 Patients. All 100 Were Still There.** (August 2026) | [Download](AI-Data-Security-Report-02-2026-08.pdf) |
| 3 | **We Audited Five Voice-AI Platforms. Three Document Recording On by Default. Four Quick-Starts Never Mention Retention.** (September 2026) | [Download](AI-Data-Security-Report-03-2026-09.pdf) |
| 4 | **What Redaction Left Behind in 200 Synthetic Patient Calls.** After a simulated redaction, in the spoken-form transcripts, 60 of the 80 scripted calls that held a complete fake-invoice kit still held it under RAGLeakGuard 0.1.1 (tested source installation); 0 of 80 under Presidio default. Counts of what remained, so lower is better. (October 2026) | [Download](AI-Data-Security-Report-04-2026-10.pdf) |

**Issue #2 evidence:** `findings/src/chroma_erasure.py` reproduces every figure on chromadb 1.5.9 with a fixed seed and fully synthetic data; the pinned environment is `tools/requirements-chroma.txt`, and the raw results for all three tagged runs are in `findings/`. Rerun, from the repository root:

    python -m venv reports/tools/chromaenv
    reports/tools/chromaenv/Scripts/python.exe -m pip install -r reports/tools/requirements-chroma.txt
    reports/tools/chromaenv/Scripts/python.exe reports/findings/src/chroma_erasure.py

(On macOS, substitute `reports/tools/chromaenv/bin/python`.) Findings were disclosed upstream before publication: [chroma-core/chroma#7662](https://github.com/chroma-core/chroma/issues/7662).

**Issue #3 evidence:** `findings/src/voice_transcripts.py` reproduces every scan and memory figure with a fixed seed on 200 scripted calls from synthetic patients (roster `findings/src/voice_roster_2026-09.json`, derived from the public Synthea generator); the pinned environment is `tools/requirements-voice.txt`, and the raw results for all three tagged runs are in `findings/`. The retention-defaults audit is `findings/PLATFORM-POSTURE-MATRIX.md`: every cell carries the vendor's page, the verbatim sentence and the date it was read, and rows are appended, never rewritten, when a vendor's documentation changes. The data package and verification log are in `findings/FINDINGS-2026-09.md`. Rerun, from the repository root:

    python -m venv reports/tools/voiceenv
    reports/tools/voiceenv/Scripts/python.exe -m pip install -r reports/tools/requirements-voice.txt
    reports/tools/voiceenv/Scripts/python.exe reports/findings/src/voice_transcripts.py

(On macOS, substitute `reports/tools/voiceenv/bin/python`.) Vendor defaults are dated 14 September 2026 and change; the matrix is re-verified quarterly.

**Issue #4 evidence:** `findings/src/scam_kit.py` re-runs the measurement: the 2,000 synthetic clinic notes of Issue #2 and the 200 scripted calls of Issue #3 (both generators imported unchanged, seeds `20260801` and `20260914`) scanned by four configurations (Microsoft Presidio stock defaults; Presidio with its Australian recognisers on; RAGLeakGuard 0.1.1 default and `--locale au`, from source commit `47dedfe`), every finding at or above 0.4 masked, and what each record still showed counted per record. Two pinned environments are required (`tools/requirements-scamkit.txt` for the script and the Presidio pair; `tools/requirements-rlg.txt` for the RAGLeakGuard worker `findings/src/rlg_scan_worker.py`, built from this package's `detect` extra); the script probes the RAGLeakGuard environment and stops if it is outside the package's pins. Raw results for all three tagged runs are in `findings/` (`scamkit-2026-10-v2-raw*.json`, the measured artifacts; `scamkit-2026-10-raw*.json`, the first version, kept for the record). The six files are metadata-redacted publication copies of the measured artifacts: two environment fields that held machine-local paths (`environment.ragleakguard_mode.python`, `environment.ragleakguard.venv`) read `<LOCAL_VENV>` placeholders; every measurement, synthetic sample, version, measured commit, timestamp and configuration field is as measured, checked by a recursive comparison with the originals (SHA-256 of the published files in the findings package header). Regression checks: `findings/src/test_scam_kit.py` (23 checks). The data package and verification log are in `findings/FINDINGS-2026-10.md`. Rerun, from the repository root, Python 3.12:

    py -3.12 -m venv reports/tools/scamenv
    reports/tools/scamenv/Scripts/python.exe -m pip install -r reports/tools/requirements-scamkit.txt
    git worktree add ../RAGLeakGuard-measured 47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0
    py -3.12 -m venv reports/tools/rlgenv
    reports/tools/rlgenv/Scripts/python.exe -m pip install -e "../RAGLeakGuard-measured[detect]"
    reports/tools/rlgenv/Scripts/python.exe -m pip install -r reports/tools/requirements-rlg.txt
    reports/tools/scamenv/Scripts/python.exe reports/findings/src/scam_kit.py run4
    reports/tools/scamenv/Scripts/python.exe -m unittest reports/findings/src/test_scam_kit.py

(On macOS substitute `python3.12 -m venv` and `.../bin/python`.) The worktree holds the product at the measured commit `47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0`; that commit predates these scripts, so the product is installed from a worktree rather than checked out in place. The script records the commit it scanned with. All counts are synthetic exposure measurements on scripted fixtures with a simulated redaction; the comparison is between configured pipelines, not a product ranking, and the report names this tool's own gaps (the Medicare pattern, spoken-form numbers).

**Historical issue #1 evidence:** `scripts/benchmark.py` used 280 labelled identifiers and 28 US/AU format variants; `scripts/clinic_eval.py` used a 100-record synthetic clinic store and the then-current Chroma connector. The released result is tied to its historical source snapshot and does not establish current connector availability or safety. Direct local Chroma scanning is now disabled. All fixture data is synthetic; see [benchmark reproducibility](../docs/BENCHMARK_REPRODUCIBILITY.md).

Author: Wen-Chia "Belle" Chang · Agenvana
