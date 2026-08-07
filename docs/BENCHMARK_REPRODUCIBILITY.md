# Benchmark reproducibility and evidence freeze

This document separates the historical July 2026 report from current product behavior. The released PDF is evidence from a specific snapshot; it is not regenerated or silently replaced when the scanner changes. The Git blobs at the publication snapshot are the canonical artifacts. A platform checkout is evidence only after its bytes have been verified against those blobs.

## July report identity

| Item | Frozen value |
|---|---|
| Report | `reports/AI-Data-Security-Report-01-2026-07.pdf` |
| Title | *Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.* |
| Size | 273,998 bytes |
| PDF SHA-256 | `1d1391e4e70d17880ca8baab0f52e430684c018ee50569170be785131779d3d6` |
| Benchmark/evaluation source commit | `be8cf616da62c1037b8f4ef7960378c73b866600` |
| Immutable publication snapshot | `8dea47e351fe24efc61eb72c31c9bf9d61d13aa3` |
| Publication date in Git | 2026-07-05 (AEST) |

The publication snapshot is the canonical source SHA because it is the first commit containing the released PDF and it also contains the benchmark/evaluation source. Its Git blob objects, not line-ending-converted working-tree copies, define the canonical bytes. Git confirms that the three paths are content-unchanged between that snapshot and `75fb62766f7324264a6ed08847018a6cac348e8b`.

Additional SHA-256 values at the publication/current baseline:

| File | SHA-256 |
|---|---|
| `scripts/benchmark.py` | `3147358063fcc7884053f09be75a79a8df76b472fb46ed89453b403fe057492c` |
| `scripts/clinic_eval.py` | `bf511ddbf31204b5bd2d6dbc774e2c25dacda8cba84ae62e8cb69654f767ae3f` |

## Evidence status

**Implemented now:** the repository contains the released 10-page PDF, deterministic fixed-seed benchmark/evaluation scripts, synthetic-data generation, and source history binding them to the SHAs above. Repository attributes mark report PDFs as binary and force LF checkouts for the two source scripts. The canonical publication-snapshot PDF blob renders all 10 pages without Poppler PDF parsing warnings.

A prior Windows checkout applied CRLF conversion to these files before the repository attributes existed. Hashing that converted checkout produced different sizes/checksums and PDF parser warnings. Those checkout bytes were not canonical and are not evidence of the published artifact.

**Known limitations:**

- The PDF states that raw per-item results were published alongside it, but no raw July result file is present in the current public tree.
- Historical transitive dependencies, spaCy model artifact, Python patch version, OS details, command transcripts, and raw outputs are not locked in this repository.
- No report-specific Git tag exists at this baseline.

Because of these gaps, the fixed seed supports repeatability in a recreated environment but does not by itself prove bit-for-bit historical reproducibility.

## Verify the frozen files

Use Git's publication-snapshot blobs as the platform-stable source of bytes. From a clean checkout:

```bash
git cat-file -e 8dea47e351fe24efc61eb72c31c9bf9d61d13aa3^{commit}
git diff --exit-code 8dea47e351fe24efc61eb72c31c9bf9d61d13aa3 -- reports/AI-Data-Security-Report-01-2026-07.pdf scripts/benchmark.py scripts/clinic_eval.py
git check-attr --all -- reports/AI-Data-Security-Report-01-2026-07.pdf scripts/benchmark.py scripts/clinic_eval.py
python -c "import hashlib, subprocess; ref='8dea47e351fe24efc61eb72c31c9bf9d61d13aa3'; paths=('reports/AI-Data-Security-Report-01-2026-07.pdf','scripts/benchmark.py','scripts/clinic_eval.py'); [(lambda b: print(len(b), hashlib.sha256(b).hexdigest(), p))(subprocess.check_output(['git','cat-file','blob',f'{ref}:{p}'])) for p in paths]"
```

Expected canonical blob output:

```text
273998 1d1391e4e70d17880ca8baab0f52e430684c018ee50569170be785131779d3d6 reports/AI-Data-Security-Report-01-2026-07.pdf
17161 3147358063fcc7884053f09be75a79a8df76b472fb46ed89453b403fe057492c scripts/benchmark.py
4618 bf511ddbf31204b5bd2d6dbc774e2c25dacda8cba84ae62e8cb69654f767ae3f scripts/clinic_eval.py
```

The blob output must match exactly. After checkout, a working-tree hash may be used as a secondary check, but it does not replace the blob calculation. A mismatch is an evidence incident: stop, preserve both versions, check attributes and filters, and investigate before publishing a claim. Do not regenerate, normalize, or recommit the protected artifacts to make a checksum match.

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

1. Start from the immutable publication snapshot and verify the canonical Git blob sizes/checksums above before inspecting working-tree copies.
2. Recover the original raw output if available. Before public addition, verify that every value is synthetic and that no path, username, token, or private planning metadata is present.
3. Record OS/architecture, Python executable and patch version, `pip freeze`, spaCy model name/version/checksum, locale/timezone, environment variables that affect results, and exact commands.
4. Run each script in a clean environment, save stdout/stderr and machine-readable results without editing them, and calculate SHA-256 for every evidence file.
5. Compare rerun numbers with every number in the PDF. Record matches, differences, likely causes, and reviewer sign-off in a manifest tied to the source SHA.
6. Have someone other than the runner review synthetic-data status, hashes, environment capture, calculations, and claim wording.
7. After human approval, create an annotated report-specific tag pointing to the publication snapshot and record the tag object ID in the manifest. This documentation change does not create that tag.
8. Store future amendments as new, checksummed files that cite the original PDF and manifest. Never replace the released PDF or rewrite its Git history.

## Current benchmark versus released evidence

Changes after the publication snapshot may be evaluated as a new benchmark, but must use a new evidence directory, manifest, source SHA, environment, date, and claim review. Current test success cannot retroactively validate the July report, and a July result cannot be presented as current detector performance without a new run.
