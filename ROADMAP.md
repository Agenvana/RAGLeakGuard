# RAGLeakGuard — Roadmap

Early development (the **Diagnose** stage). Checkboxes are intent, not commitments; dates are targets.

## Detection accuracy
- [x] **Custom AU phone recogniser** — `AU_PHONE` regex recogniser covering `+61…`, `04xx` mobiles, `(0X)…`/`0X…` landlines, and `1300/1800` numbers. Closes Presidio's recall gap on AU formats (measured 20% miss → 0% on the labelled fixture in `tests/test_au_phone.py`).
- [ ] **Locale packs** (opt-in `--locale`) — build in priority order; English-majority markets first (US sensitive IDs are already ON by default). Each pack = regex + checksum where one exists (like the AU TFN/ABN/ACN gate). Stubs stay OUT of `LOCALE_PACKS` until implemented, so `--locale` never silently no-ops.
  1. **UK** — `UK_NHS`, `UK_NINO`
  2. **New Zealand** — IRD number, NHI
  3. **Canada** — SIN (Luhn checksum)
  4. **Singapore** — `SG_NRIC_FIN`
  5. **Taiwan** — national ID (身分證) + NHI card *(first-hand knowledge of the real data here)*
  6. **India** — `IN_PAN`, `IN_AADHAAR` *(lowest priority)*
- [ ] ~~Larger spaCy model for better `PERSON`/`LOCATION`~~ — **parked (someday/maybe).** If ever pulled: ship as opt-in `--accuracy high`, and only in the **paid/Cloud tier** where we control the hardware — *never* in the free "install & scan in 2 minutes" path (it drives OSS adoption). `en_core_web_lg` is only a marginal gain over `sm`; the real jump is `en_core_web_trf`, which pulls in PyTorch and breaks the lightweight Python-3.9 pinned install — a client-pays decision, not a cost we carry.
- [x] Recall/precision **benchmark** against a labelled fixture (so accuracy is measured, not guessed) — `scripts/benchmark.py` (2026-07-04): 280 labelled items, 28 US/AU format variants, 4 configs (Presidio default / Presidio+AU recognisers / RLG default / RLG `--locale au`), two confidence tiers + false-positive counts. Deterministic seed; feeds Report #1.
- [ ] **Locale auto-hint** (from Report #1 benchmark, 2026-07-04): when a scan run *without* `--locale` keeps seeing locale-shaped patterns (04xx/+61 phones, digit groups near "TFN"/"ABN"/"Medicare"), print a hint to rerun with the matching pack. Rationale: default-config scans missed ~46% of AU identifiers at actionable confidence — the user's biggest risk is not knowing the pack exists.
- [ ] **AU phone format residue** (from the clinic-scan eval, 2026-07-04): the AU pack still misses dot-separated numbers (`8433.5705`) and local 8-digit numbers without an area code (`3242 2984`). Dots are a regex tweak; area-code-less locals need context gating ("call", "ph", "contact") to stay precise.
- [ ] **MRN / record-identifier recogniser** (from Report #1 benchmark, 2026-07-04): `MRN-482913`-style chart numbers are invisible to every engine tested (0–40% recall, and then only via mislabels). Context-gated pattern (`MRN-`, "chart", "record"). Directly feeds the Sep clinic/voice-agent report.

## Connectors
A bounded aggregate-only operator-snapshot Chroma connector is implemented in source. Direct/live
source-store access remains disabled.

- [x] **WP7B private bounded operator-snapshot confinement foundation** — the private filesystem lifecycle passed independent review at exact implementation head `128decb3e0d78825e884f6dce019898b568c6ba2` and was merged through [PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit `5db765689d35eec8ba918f0f616d5fea34e56955`. It confines a complete snapshot created separately by the operator. It does not import or construct Chroma, expose a public scanning surface, or prove source quiescence, provenance, completeness, or atomic multi-file consistency.
- [x] **WP7D bounded operator-snapshot Chroma activation** — exact ChromaDB 1.5.9 only, with five native-filesystem/Python cells: Linux/ext4 3.10–3.12, macOS 15/APFS 3.12, and Windows/NTFS 3.12. It runs detection inside the isolated WP7C worker and returns bounded counters and entity-type counts only after two-pass equality, termination, revalidation, cleanup, and atomic aggregate-report finalization. The operator must create a complete quiescent/full-filesystem snapshot separately; RAGLeakGuard does not prove provenance, quiescence, completeness, or atomic consistency. Direct/live access and monitor new scans remain disabled. ChromaDB 1.5.0 remains private evidence only. [Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred, not completed.
- [ ] Pinecone
- [ ] pgvector (Postgres)
- [ ] Qdrant, Weaviate
- [ ] **Files/folder connector (`--source files --path ./docs`)** — scan source documents & transcripts BEFORE they're uploaded to platform-bundled knowledge bases (Vapi, ElevenLabs, agent-builder platforms whose vector stores users can't reach). The pre-upload gate for closed platforms; pairs with `monitor` watching an "outbox" folder. (From Belle's voice-agent question, 2026-07-05.)

## Erasure verification (from Report #2 "The Erasure Illusion", 2026-08)
- [ ] **`ragleakguard erasure-audit <store>`** — point it at a Chroma directory; report vectors present on disk vs records the API admits to. The 2,000-vs-1,900 gap from Report #2 in one command, and its natural demo.
- [ ] **Ghost-slot detector** — parse `data_level0.bin` + `index_metadata.pickle` and list orphaned labels. The parsing code exists in the Report #2 cycle script (`au-pr-niv-plan`); lift it, don't rewrite it.
- [ ] **Post-erasure re-scan** — verify an erasure actually erased. Inside the disclosed patent scope (see **Prove** below), so safe to build in public.
- [x] **Upstream docs note to chroma-core** — filed after Report #2 published: [chroma#7662](https://github.com/chroma-core/chroma/issues/7662).

## Voice-agent transcripts (from Report #3, 2026-09)
- [ ] **Spoken-form number normaliser** (`--source transcript` pre-pass) — before scanning, rewrite spoken digit runs ("oh four one two …", "nine nine nine eight …") into digits and recase lowercase transcripts, so the existing recognisers can see them. Report #3 (200 synthetic scripted calls, no audio transcribed): in the spoken rendering, inspired by Deepgram's default (`smart_format` and `numerals` both off), stock Presidio recognised 0 of 280 phone, Medicare, SSN and insurance numbers as what they were; every spoken-form "catch" was a `DATE_TIME` label (`reports/findings/FINDINGS-2026-09.md` §2).
- [ ] **Health-information recogniser pack** (conditions, medications, allergies) — word lists from public vocabularies (SNOMED/RxNorm display names; the Synthea condition and medication tables are a free seed) plus context words ("I'm on", "allergic to", "diagnosed with"). Report #3: the default and AU-extended Presidio configurations flagged 0 of 440 spoken health items at actionable confidence; neither enables a medical recogniser, and Presidio's optional `MedicalNERRecognizer` was not evaluated, so benchmark it on the same fixture first (§3). Health information is "sensitive information" under the AU Privacy Act and PHI under HIPAA, and clinic voice agents routinely hear it.
- [ ] **Call-memory lookup audit** — given a Chroma collection of transcripts, test whether identifier-shaped queries (phone number, name, name + DOB) return the right caller's record, and report the bleed rate. Report #3: in a synthetic 200-transcript memory, an unfiltered semantic query built from a phone number returned another synthetic caller's transcript first in 199 of 200 cases, one hub transcript dominating 197 of them; an embedding search is not an exact identifier lookup (one model, one corpus, one query template; §4). In production the failure is silent: the agent greets the caller with someone else's history.
- [ ] **`ragleakguard posture <platform>`** (reference, not a scanner) — print the dated posture-matrix row for a named voice platform: default recording, retention, compliance-mode default, BAA path. Source: `reports/findings/PLATFORM-POSTURE-MATRIX.md` (cells dated 2026-09-14; the matrix keeps history). Shipping it in the CLI keeps the matrix alive between reports.

## Integrations (make the scanner usable inside any agent stack)
**Repo layout rule:** all open adapters live in THIS repo (MCP under the package as an optional extra, e.g. `pip install ragleakguard[mcp]`; platform agents under `integrations/<platform>/`). One repo concentrates stars, issues, and credibility instead of fragmenting them. A separate public repo only if a marketplace's listing process forces one. The Cloud stays in its own private repo (it's the paid product).
- [ ] **MCP server wrapper** — expose `scan_store` / `scan_files` as Model Context Protocol tools so any MCP-compatible agent or platform can call the scanner with one config line. Hard rule: tools return **findings metadata only** (counts, types, risk scores, masked samples) — never raw detected values, since chat transcripts are themselves a data store.
- [ ] Agent-platform tool wrappers (Agency Swarm / LangChain Tool, etc.) — thin adapters over the same detection core, built per marketplace demand.

## Compliance & reporting
- [ ] HTML report (alongside Markdown)
- [ ] Map findings to **OWASP LLM Top 10 / GDPR / ISO 27001 / SOC 2** (pluggable per jurisdiction)

## Corrective release readiness
- [x] **WP8 non-publishing candidate preparation** — source proposes `0.1.1` from one Hatch version
  source; canonical corrective notes, a finite base package matrix, build-once artifact checks,
  artifact-only installs, unchanged WP7C/WP7D evidence matrices, hashes, and review manifests are
  encoded in CI. The separate publication workflow is manual, never rebuilds, and remains dormant
  without an exact tag, protected `pypi` environment, human approval, and externally configured PyPI
  OIDC Trusted Publishing. WP8 does not publish, tag, release, yank, or configure external trust.

## Docs & website
- [x] **README.zh-TW.md** — Traditional Chinese README, linked from the top of the English one (done 2026-07-06).
- **Standing rule:** this ROADMAP stays in the repo permanently, website or no website. The repo is the builder-facing source of truth; ragleakguard.com is the buyer-facing story. The site may *summarize* the roadmap; it never replaces it.

## Product stages
- [ ] **Fix** (🔒 **patent pending** — US provisional filed July 2026) — tokenise sensitive data *before* embedding, so vectors and every derived copy (replicas, caches, logs, backups, exports) are created without raw sensitive data; originals live only in a secure vault under per-person keys. Erasing a person = one vault revocation, effective across **all** copies at once — no per-store deletion, no re-embedding. Deletion-safe RAG.
- [ ] **Prove** — signed, auditor-ready erasure & compliance reports with a post-erasure verification re-scan (GDPR Art. 17 / HIPAA / AU Privacy Act mappings); hosted control plane (*RAGLeakGuard Cloud*).
- [ ] Embedding-inversion demo — reconstruct text from a "safe" vector.
