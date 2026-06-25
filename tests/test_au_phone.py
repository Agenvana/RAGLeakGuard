"""Benchmark: AU phone-number recall — Presidio default vs the AU locale pack.

Presidio's built-in PHONE_NUMBER recogniser (Google libphonenumber, default region) misses
most Australian formats when the +61 country code is absent. This test measures that gap on a
labelled fixture and asserts the AU locale pack closes it. It doubles as a regression guard:
any future detection change that drops AU phone recall fails here.
"""
import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("spacy")

# Labelled AU phone numbers, each in realistic sentence context (one number per line).
AU_PHONES = [
    "Call the clinic on 02 9412 5678 to confirm.",      # landline, spaced
    "Reception is (03) 9012 3456, ask for Dana.",        # landline, parenthesised
    "Brisbane rooms on (07) 3210 9876.",                 # landline, parenthesised
    "Perth office 08 6210 0099.",                        # landline, spaced
    "My mobile is 0412 345 678, text anytime.",          # mobile, spaced
    "Reach me on 0498765432 after five.",                # mobile, no separators
    "International patients call +61 2 1234 5678.",       # +61 landline
    "Or +61 412 345 678 for the on-call nurse.",         # +61 mobile
    "Bookings line 1300 975 707.",                       # 1300 service number
    "Freecall 1800 123 456 for results.",                # 1800 service number
]


def _has_phone(findings):
    return any(f["type"] in {"PHONE_NUMBER", "AU_PHONE"} for f in findings)


def _missed(locale):
    from ragleakguard.detect import detect
    return [t for t in AU_PHONES if not _has_phone(detect(t, locale=locale))]


def test_au_pack_catches_all_au_phone_formats():
    missed = _missed("au")
    assert not missed, f"AU pack missed {len(missed)}/{len(AU_PHONES)}: {missed}"


def test_au_pack_beats_presidio_default():
    # The whole point of the pack: it must strictly improve AU phone recall over the default,
    # which is the build-in-public claim ("the standard tool misses ~30% of AU numbers").
    default_missed = len(_missed(None))
    au_missed = len(_missed("au"))
    assert au_missed < default_missed, (
        f"AU pack did not improve recall (default missed {default_missed}, au missed {au_missed})"
    )
