# vectorscan

> Scan your AI's vector database for exposed sensitive data — before it becomes a breach you can't delete.

**vectorscan** is an open-source CLI that connects to your vector store (Chroma, Pinecone, …), reads what's stored, detects sensitive data (PII, health, financial), and produces a risk report. **No changes to your app** — point it at the store and scan.

> 🚧 Early development — building in public. Not yet ready for production.

## Why this matters

RAG systems embed your private data into vector databases. That data:

- **is reversible** — embeddings can be turned back into text (inversion);
- **is hard to delete** — "right to erasure" against a vector index is brutal (soft-deletes, backups, replicas);
- **often isn't inventoried** — you can't protect what you can't see.

vectorscan finds it, scores the risk, and tells you what you're exposed to.

## Quickstart (coming soon)

```bash
pip install vectorscan
vectorscan scan --source chroma --path ./chroma_db
```

## Roadmap

- **Diagnose** (this repo) — scan + risk report. ← now
- **Fix** — prevent sensitive data from becoming un-deletable embeddings.
- **Prove** — regulator-grade erasure & compliance reports (vectorscan Cloud).

## License

Apache-2.0
