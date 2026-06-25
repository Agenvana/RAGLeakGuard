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

# Australian phone numbers. Presidio's PHONE_NUMBER (Google libphonenumber, default region)
# misses most AU formats when the country code is absent — a recall gap, and a missed number is
# the dangerous error. This regex covers: +61 international, 04xx mobiles, (0x)/0x landlines,
# and 1300/1800 service numbers. Separators are optional (space / hyphen / none).
_AU_PHONE_PATTERN = (
    r"(?<![\w+])(?:"
    r"\+61[\s-]?(?:\(0\)[\s-]?)?\d(?:[\s-]?\d){8}"   # +61 2 1234 5678 / +61 412 345 678
    r"|04\d{2}[\s-]?\d{3}[\s-]?\d{3}"                # 04xx xxx xxx  (mobile)
    r"|\(0[2-8]\)[\s-]?\d{4}[\s-]?\d{4}"             # (02) 1234 5678  (landline)
    r"|0[2-8][\s-]?\d{4}[\s-]?\d{4}"                 # 02 1234 5678    (landline)
    r"|1[38]00[\s-]?\d{3}[\s-]?\d{3}"               # 1300 / 1800 123 456
    r")(?!\d)"
)

# Australian business / tax identifiers. The regex finds the *shape*; the checksum gate in
# _postprocess confirms the check digit — which rejects ~90%+ of look-alike numbers, so we
# surface real IDs without flooding the report with random digit strings. Off by default
# (--locale au). Algorithms: TFN/ABN per the ATO, ACN per ASIC.
_TFN_PATTERN = r"\b\d{3}\s?\d{3}\s?\d{3}\b"          # 9 digits, e.g. 123 456 782
_ABN_PATTERN = r"\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b"  # 11 digits, e.g. 51 824 753 556
_ACN_PATTERN = r"\b\d{3}\s?\d{3}\s?\d{3}\b"          # 9 digits, e.g. 004 085 616

# Default: global + US sensitive entities (primary market). Excludes URL/ORGANIZATION noise.
DEFAULT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_TIME", "LOCATION",
    "CREDIT_CARD", "IBAN_CODE", "CRYPTO", "IP_ADDRESS", "MEDICAL_LICENSE", "NRP",
    "US_SSN", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_PASSPORT", "US_ITIN",
]

# Opt-in country recognisers — add with --locale. Extend per market.
LOCALE_PACKS = {
    "au": ["AU_MEDICARE", "AU_PHONE", "AU_TFN", "AU_ABN", "AU_ACN"],
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


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _valid_tfn(s: str) -> bool:
    """ATO Tax File Number checksum: weighted sum of 9 digits divisible by 11."""
    d = _digits(s)
    if len(d) != 9:
        return False
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    return sum(int(c) * w for c, w in zip(d, weights)) % 11 == 0


def _valid_abn(s: str) -> bool:
    """ATO ABN checksum: subtract 1 from the first digit, weighted sum divisible by 89."""
    d = _digits(s)
    if len(d) != 11:
        return False
    weights = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    nums = [int(c) for c in d]
    nums[0] -= 1
    return sum(n * w for n, w in zip(nums, weights)) % 89 == 0


def _valid_acn(s: str) -> bool:
    """ASIC ACN checksum: complement (mod 10) of the weighted first 8 digits == check digit."""
    d = _digits(s)
    if len(d) != 9:
        return False
    weights = (8, 7, 6, 5, 4, 3, 2, 1)
    total = sum(int(c) * w for c, w in zip(d[:8], weights))
    return (10 - total % 10) % 10 == int(d[8])


# Checksum gate for AU structured IDs — a candidate is kept only if its check digit verifies.
_AU_ID_VALIDATORS = {"AU_TFN": _valid_tfn, "AU_ABN": _valid_abn, "AU_ACN": _valid_acn}


def _postprocess(raw: List[Dict]) -> List[Dict]:
    # 1. Entity-specific validation (precision).
    kept = []
    for f in raw:
        if f["type"] == "DATE_TIME" and not _looks_like_date(f["text"]):
            continue
        if f["type"] == "PHONE_NUMBER" and not _looks_like_phone(f["text"]):
            continue
        if f["type"] in _AU_ID_VALIDATORS and not _AU_ID_VALIDATORS[f["type"]](f["text"]):
            continue  # AU tax/business ID failed its checksum — drop the look-alike
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
    # Custom AU phone recogniser — closes the recall gap Presidio's libphonenumber leaves on
    # AU formats. Score sits above Presidio's PHONE_NUMBER so it wins the label on overlap (NMS).
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="AU_PHONE",
        patterns=[Pattern("au_phone", _AU_PHONE_PATTERN, 0.75)],
        context=["phone", "mobile", "mob", "tel", "ph", "call", "contact"],
    ))
    # Custom AU tax/business IDs — regex finds the shape; the checksum gate in _postprocess
    # confirms the check digit. Score above generic phone so the specific AU label wins NMS.
    for entity, pattern, name, ctx in (
        ("AU_TFN", _TFN_PATTERN, "tfn", ["tfn", "tax file"]),
        ("AU_ABN", _ABN_PATTERN, "abn", ["abn", "business number"]),
        ("AU_ACN", _ACN_PATTERN, "acn", ["acn", "company number"]),
    ):
        analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity=entity,
            patterns=[Pattern(name, pattern, 0.85)],
            context=ctx,
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
