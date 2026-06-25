"""AU tax/business IDs (TFN / ABN / ACN) — checksum-validated recognisers.

Each ID type has a published check-digit algorithm (TFN/ABN: ATO; ACN: ASIC). The recogniser's
job is precision: surface real IDs, reject look-alike digit strings. These tests use documented
valid numbers and their deliberately-broken twins to prove both directions, and confirm the pack
is opt-in (off unless --locale au).
"""
import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("spacy")

# Valid examples (pass their published checksum):
VALID_TFN = "123 456 782"
VALID_ABN = "51 824 753 556"   # ATO's documented sample ABN
VALID_ACN = "004 085 616"      # ASIC's documented sample ACN

# Same numbers with the last digit bumped — break the checksum:
BAD_TFN = "123 456 781"
BAD_ABN = "51 824 753 557"
BAD_ACN = "004 085 617"


def _types(text):
    from ragleakguard.detect import detect
    return {f["type"] for f in detect(text, locale="au")}


def test_valid_au_ids_detected():
    assert "AU_TFN" in _types(f"Tax file number {VALID_TFN} on file.")
    assert "AU_ABN" in _types(f"Supplier ABN {VALID_ABN}.")
    assert "AU_ACN" in _types(f"Company ACN {VALID_ACN}.")


def test_bad_checksum_rejected():
    # Precision: a number of the right shape but wrong check digit must NOT be reported.
    assert "AU_TFN" not in _types(f"Reference {BAD_TFN}.")
    assert "AU_ABN" not in _types(f"ABN {BAD_ABN}.")
    assert "AU_ACN" not in _types(f"ACN {BAD_ACN}.")


def test_au_ids_off_by_default():
    from ragleakguard.detect import detect
    types = {f["type"] for f in detect(f"Tax file number {VALID_TFN}, ABN {VALID_ABN}.")}
    assert "AU_TFN" not in types and "AU_ABN" not in types
