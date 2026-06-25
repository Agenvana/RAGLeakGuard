# RAGLeakGuard — Roadmap

Early development (the **Diagnose** stage). Checkboxes are intent, not commitments; dates are targets.

## Detection accuracy
- [x] **Custom AU phone recogniser** — `AU_PHONE` regex recogniser covering `+61…`, `04xx` mobiles, `(0X)…`/`0X…` landlines, and `1300/1800` numbers. Closes Presidio's recall gap on AU formats (measured 20% miss → 0% on the labelled fixture in `tests/test_au_phone.py`).
- [ ] More **locale packs** — EU, Canada, NZ, Japan, Brazil.
- [ ] Optional larger spaCy model (`en_core_web_lg`) for better `PERSON` / `LOCATION` accuracy.
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
