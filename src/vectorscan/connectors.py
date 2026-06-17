"""Connectors — read stored items (text + metadata) from a vector store.

Each connector yields dicts: {"id": str, "text": str, "metadata": dict}.
The scanner is read-only and never modifies the store.
"""
from typing import Iterator, Dict, Any


def read_chroma(path: str) -> Iterator[Dict[str, Any]]:
    """Read items from a local Chroma store. TODO (Day 3): implement with chromadb."""
    raise NotImplementedError("Chroma connector — Day 3")


def read_pinecone(index: str) -> Iterator[Dict[str, Any]]:
    """Read items from a Pinecone index. TODO (Week 2)."""
    raise NotImplementedError("Pinecone connector — Week 2")
