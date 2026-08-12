"""Connector entry points.

No source-scanning connector is currently available. Direct local Chroma access is
disabled because reviewed endpoint evidence showed durable source-store mutation.
"""
from typing import Any, Dict, Iterator


CHROMA_DISABLED_MESSAGE = (
    "Local Chroma scanning is disabled because executable endpoint evidence proved "
    "that ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client "
    "construction or reads, while other versions have not established an acceptable "
    "read-only boundary. No report, monitor state, or webhook was created or replaced."
)


class ChromaConnectorUnavailableError(RuntimeError):
    """Static public failure for the unavailable direct local Chroma connector."""

    def __init__(self) -> None:
        super().__init__(CHROMA_DISABLED_MESSAGE)


def read_chroma(path: object, collection: object = None) -> None:
    """Fail synchronously without evaluating either supplied object."""
    raise ChromaConnectorUnavailableError() from None


def read_pinecone(index: str) -> Iterator[Dict[str, Any]]:
    """Read items from a Pinecone index. TODO (Week 2)."""
    raise NotImplementedError("Pinecone connector — Week 2")
