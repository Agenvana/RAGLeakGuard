"""Connectors — read stored items (text + metadata) from a vector store.

Each connector yields dicts: {"id", "text", "metadata", "collection"}.
Read-only — never modifies the store.
"""
from typing import Iterator, Dict, Any, Optional, List


def read_chroma(path: str, collection: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """Yield stored items from a local (persistent) Chroma store.

    Args:
        path: filesystem path to the Chroma PersistentClient store.
        collection: a specific collection name; if None, scan every collection.
    """
    import chromadb

    client = chromadb.PersistentClient(path=path)
    if collection:
        names: List[str] = [collection]
    else:
        names = [getattr(c, "name", c) for c in client.list_collections()]

    for name in names:
        col = client.get_collection(name)
        batch = col.get(include=["documents", "metadatas"])
        ids = batch.get("ids") or []
        docs = batch.get("documents") or []
        metas = batch.get("metadatas") or []
        for i, item_id in enumerate(ids):
            text = docs[i] if i < len(docs) and docs[i] is not None else ""
            meta = metas[i] if i < len(metas) and metas[i] is not None else {}
            yield {"id": item_id, "text": text, "metadata": meta, "collection": name}


def read_pinecone(index: str) -> Iterator[Dict[str, Any]]:
    """Read items from a Pinecone index. TODO (Week 2)."""
    raise NotImplementedError("Pinecone connector — Week 2")
