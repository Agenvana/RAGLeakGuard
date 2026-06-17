import pytest

chromadb = pytest.importorskip("chromadb")


def test_read_chroma_roundtrip(tmp_path):
    from vectorscan.connectors import read_chroma

    store = str(tmp_path / "store")
    client = chromadb.PersistentClient(path=store)
    col = client.create_collection("t")
    col.add(
        ids=["a", "b"],
        documents=["Patient Alice, phone 0400 000 000", "Bob lives at 1 Main St"],
        metadatas=[{"k": 1}, {"k": 2}],
    )

    items = list(read_chroma(store))
    assert len(items) == 2
    texts = {it["text"] for it in items}
    assert any("Alice" in t for t in texts)
    assert all(it["collection"] == "t" for it in items)
