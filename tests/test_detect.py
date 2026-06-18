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


def test_phone_validator_drops_medicare_as_phone():
    from vectorscan.detect import detect

    found = detect("Patient on Medicare 54909989 1 1 only.")
    types = {f["type"] for f in found}
    assert "AU_MEDICARE" in types
    assert "PHONE_NUMBER" not in types     # a Medicare number is not a phone


def test_date_validator_keeps_real_dates_drops_bare_numbers():
    from vectorscan.detect import detect

    dated = {f["type"] for f in detect("DOB 06/06/1949.")}
    assert "DATE_TIME" in dated             # real date survives

    bare = {f["type"] for f in detect("Postcode 2949.")}
    assert "DATE_TIME" not in bare          # bare 4-digit number is not a date
