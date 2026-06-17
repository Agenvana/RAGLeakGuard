import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("spacy")


def test_detect_finds_pii():
    from vectorscan.detect import detect

    text = "Contact Jane Smith at jane@example.com or call 0400 123 456. Medicare 54909989 1 1."
    found = detect(text)
    types = {f["type"] for f in found}

    assert "EMAIL_ADDRESS" in types       # built-in recogniser
    assert "AU_MEDICARE" in types         # our custom recogniser fired
    assert len(found) >= 2
