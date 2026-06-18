# vectorscan — Roadmap

Early development (the **Diagnose** stage). Checkboxes are intent, not commitments; dates are targets.

## Detection accuracy
- [ ] **Custom AU phone recogniser** — Presidio's built-in phone recogniser misses ~30% of Australian formats (`+61…`, `0X…`, `(0X)…`); add a regex recogniser, like `AU_MEDICARE`. *(High priority — a recall gap, and missed data is the dangerous error.)*
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
- [ ] **Prove** — compliance & erasure reports; hosted control plane (*vectorscan Cloud*).
- [ ] Embedding-inversion demo — reconstruct text from a "safe" vector.
