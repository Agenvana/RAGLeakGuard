import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("spacy")


def test_default_detects_us_and_global_pii():
    from vectorscan.detect import detect

    found = detect("Email jane@example.com, card 4111 1111 1111 1111.")
    types = {f["type"] for f in found}
    assert "EMAIL_ADDRESS" in types
    assert "CREDIT_CARD" in types     # global/US recogniser is ON by default


def test_au_locale_pack_toggles_medicare():
    from vectorscan.detect import detect

    text = "Patient on Medicare 54909989 1 1."
    assert "AU_MEDICARE" not in {f["type"] for f in detect(text)}             # off by default
    assert "AU_MEDICARE" in {f["type"] for f in detect(text, locale="au")}    # on with --locale au


def test_date_validator():
    from vectorscan.detect import detect

    assert "DATE_TIME" in {f["type"] for f in detect("DOB 06/06/1949.")}
    assert "DATE_TIME" not in {f["type"] for f in detect("Postcode 2949.")}   # bare number isn't a date
