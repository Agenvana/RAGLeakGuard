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
- [ ] Recall/precision **benchmark** against a labelled fixture (so accuracy is measured, not guessed).

## Connectors
- [ ] Pinecone
- [ ] pgvector (Postgres)
- [ ] Qdrant, Weaviate

## Compliance & reporting
- [ ] HTML report (alongside Markdown)
- [ ] Map findings to **OWASP LLM Top 10 / GDPR / ISO 27001 / SOC 2** (pluggable per jurisdiction)

## Product stages
- [ ] **Fix** — tokenise/redact sensitive data *before* embedding; deletion-safe RAG.
- [ ] **Prove** — compliance & erasure reports; hosted control plane (*RAGLeakGuard Cloud*).
- [ ] Embedding-inversion demo — reconstruct text from a "safe" vector.
