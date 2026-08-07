# Benchmark reproducibility and evidence freeze

This document separates the historical July 2026 report from current product behavior. The released PDF is evidence from a specific snapshot; it is not regenerated or silently replaced when the scanner changes.

## July report identity

| Item | Frozen value |
|---|---|
| Report | `reports/AI-Data-Security-Report-01-2026-07.pdf` |
| Title | *Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.* |
| Size | 274,321 bytes |
| PDF SHA-256 | `92a67d878e373cdb97b33576c52778a202541366923bbb5cc4b3bf3a0e4db5a1` |
| Benchmark/evaluation source commit | `be8cf616da62c1037b8f4ef7960378c73b866600` |
| Immutable publication snapshot | `8dea47e351fe24efc61eb72c31c9bf9d61d13aa3` |
| Publication date in Git | 2026-07-05 (AEST) |

The publication snapshot is the canonical source SHA because it is the first commit containing the released PDF and it also contains the benchmark/evaluation source. At baseline, the report and both scripts are byte-unchanged between that snapshot and `75fb62766f7324264a6ed08847018a6cac348e8b`.

Additional SHA-256 values at the publication/current baseline:

| File | SHA-256 |
|---|---|
| `scripts/benchmark.py` | `3249c010dee0868306e1b347dbffda83a94a0ff42227a6232fd2de1c071456f8` |
| `scripts/clinic_eval.py` | `3a208c80cbbec6aaf96afaa9aa1ea00e376131f504588820eccdbfc6a06ef92b` |

## Evidence status

**Implemented now:** the repository contains the released 10-page PDF, deterministic fixed-seed benchmark/evaluation scripts, synthetic-data generation, and source history binding them to the SHAs above. The public and private published PDF copies checked at this baseline have the same SHA-256.

**Known limitations:**

- The PDF states that raw per-item results were published alongside it, but no raw July result file is present in the current public tree.
- Historical transitive dependencies, spaCy model artifact, Python patch version, OS details, command transcripts, and raw outputs are not locked in this repository.
- No report-specific Git tag exists at this baseline.
- The existing PDF renders all 10 pages, but Poppler/pypdf emit structural parsing warnings. The frozen checksum covers those existing bytes; do not repair/re-export the PDF in place.

Because of these gaps, the fixed seed supports repeatability in a recreated environment but does not by itself prove bit-for-bit historical reproducibility.

## Verify the frozen files

From a clean checkout:

```bash
git cat-file -e 8dea47e351fe24efc61eb72c31c9bf9d61d13aa3^{commit}
git diff --exit-code 8dea47e351fe24efc61eb72c31c9bf9d61d13aa3 -- reports/AI-Data-Security-Report-01-2026-07.pdf scripts/benchmark.py scripts/clinic_eval.py
sha256sum reports/AI-Data-Security-Report-01-2026-07.pdf scripts/benchmark.py scripts/clinic_eval.py
```

PowerShell checksum equivalent:

```powershell
Get-FileHash -Algorithm SHA256 reports/AI-Data-Security-Report-01-2026-07.pdf, scripts/benchmark.py, scripts/clinic_eval.py
```

The command output must match the table above. A mismatch is an evidence incident: stop, preserve both artifacts, and investigate history before publishing a claim.

## Re-run the historical source

Use a disposable checkout of the publication snapshot so current code cannot silently change the result:

```bash
git worktree add --detach ../ragleakguard-report-01 8dea47e351fe24efc61eb72c31c9bf9d61d13aa3
cd ../ragleakguard-report-01
python -m venv .venv
# activate the virtual environment for your platform
python -m pip install --upgrade pip
python -m pip install -e ".[chroma,detect,dev]"
python -m spacy download en_core_web_sm
python scripts/benchmark.py --json benchmark-2026-07-rerun.json
python scripts/clinic_eval.py
```

This reconstructs from ranged dependencies and therefore is a **comparison run**, not proof of the original environment. Record every installed version and do not overwrite an earlier raw output.

## Evidence-freeze process

The following work is **planned** for a complete report evidence package:

1. Start from the immutable publication snapshot and verify the checksums above.
2. Recover the original raw output if available. Before public addition, verify that every value is synthetic and that no path, username, token, or private planning metadata is present.
3. Record OS/architecture, Python executable and patch version, `pip freeze`, spaCy model name/version/checksum, locale/timezone, environment variables that affect results, and exact commands.
4. Run each script in a clean environment, save stdout/stderr and machine-readable results without editing them, and calculate SHA-256 for every evidence file.
5. Compare rerun numbers with every number in the PDF. Record matches, differences, likely causes, and reviewer sign-off in a manifest tied to the source SHA.
6. Have someone other than the runner review synthetic-data status, hashes, environment capture, calculations, and claim wording.
7. After human approval, create an annotated report-specific tag pointing to the publication snapshot and record the tag object ID in the manifest. This documentation change does not create that tag.
8. Store future amendments as new, checksummed files that cite the original PDF and manifest. Never replace the released PDF or rewrite its Git history.

## Current benchmark versus released evidence

Changes after the publication snapshot may be evaluated as a new benchmark, but must use a new evidence directory, manifest, source SHA, environment, date, and claim review. Current test success cannot retroactively validate the July report, and a July result cannot be presented as current detector performance without a new run.
