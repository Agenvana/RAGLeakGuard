"""Detection — find sensitive data in text.

Engine: Microsoft Presidio (small spaCy model, for speed). Global + US recognisers are
ON by default (the primary market); country-specific recognisers are opt-in "locale packs"
(--locale). The differentiation lives in (a) the packs/custom recognisers and (b) the
POST-PROCESSING below — domain judgment that turns a noisy entity dump into trustworthy findings.
"""
import re
from functools import lru_cache
from typing import List, Dict, Optional

# Australian Medicare-style number (matches our synthetic fixture; tune for production).
_MEDICARE_PATTERN = r"\b[2-6]\d{7}\s?\d\s?\d\b"

# Default: global + US sensitive entities (primary market). Excludes URL/ORGANIZATION noise.
DEFAULT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_TIME", "LOCATION",
    "CREDIT_CARD", "IBAN_CODE", "CRYPTO", "IP_ADDRESS", "MEDICAL_LICENSE", "NRP",
    "US_SSN", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_PASSPORT", "US_ITIN",
]

# Opt-in country recognisers — add with --locale. Extend per market.
LOCALE_PACKS = {
    "au": ["AU_MEDICARE", "AU_TFN", "AU_ABN", "AU_ACN"],
    "uk": ["UK_NHS", "UK_NINO"],
    "sg": ["SG_NRIC_FIN"],
    "in": ["IN_PAN", "IN_AADHAAR"],
}

_DATE_LIKE = re.compile(r"\d\s?[/\-.]\s?\d|\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)", re.I)


def _looks_like_date(s: str) -> bool:
    return bool(_DATE_LIKE.search(s))


def _looks_like_phone(s: str) -> bool:
    # Recall-first: keep anything phone-length (>=8 digits). Overlapping country IDs
    # (e.g. AU_MEDICARE) win via NMS, so this can stay permissive.
    return sum(c.isdigit() for c in s) >= 8


def _postprocess(raw: List[Dict]) -> List[Dict]:
    # 1. Entity-specific validation (precision).
    kept = []
    for f in raw:
        if f["type"] == "DATE_TIME" and not _looks_like_date(f["text"]):
            continue
        if f["type"] == "PHONE_NUMBER" and not _looks_like_phone(f["text"]):
            continue
        kept.append(f)
    # 2. Non-max suppression: on overlap, keep highest-score (then longest) span.
    kept.sort(key=lambda f: (-f["score"], -(f["end"] - f["start"])))
    result: List[Dict] = []
    for f in kept:
        if any(f["start"] < o["end"] and o["start"] < f["end"] for o in result):
            continue
        result.append(f)
    result.sort(key=lambda f: f["start"])
    return result


@lru_cache(maxsize=1)
def _analyzer():
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    # Custom AU Medicare recogniser (reliable on our fixture; high score so it wins overlaps).
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="AU_MEDICARE",
        patterns=[Pattern("medicare", _MEDICARE_PATTERN, 0.9)],
        context=["medicare"],
    ))
    return analyzer


def detect(text: str, locale: Optional[str] = None) -> List[Dict]:
    """Return findings [{type, start, end, score, text}].

    locale: optional country pack (e.g. "au") that adds country-specific recognisers
            on top of the global/US defaults.
    """
    if not text or not text.strip():
        return []
    entities = list(DEFAULT_ENTITIES)
    if locale:
        entities += LOCALE_PACKS.get(locale.lower(), [])
    results = _analyzer().analyze(text=text, language="en", entities=entities)
    raw = [
        {"type": r.entity_type, "start": r.start, "end": r.end,
         "score": round(r.score, 2), "text": text[r.start:r.end]}
        for r in results
    ]
    return _postprocess(raw)
