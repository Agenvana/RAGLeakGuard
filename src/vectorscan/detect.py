"""Detection — find sensitive data in text.

Engine: Microsoft Presidio (configured for the small spaCy model, for speed).
The differentiation lives in (a) the CUSTOM recognisers and (b) the ALLOW-LIST —
domain/security judgment that turns a noisy entity dump into trustworthy findings.
"""
from functools import lru_cache
from typing import List, Dict

# Australian Medicare-style number (matches our synthetic fixture; tune for production).
_MEDICARE_PATTERN = r"\b[2-6]\d{7}\s?\d\s?\d\b"

# Security judgment: report only entities that matter in our (AU) context.
# Excludes US-specific recognisers (US_BANK_NUMBER, US_DRIVER_LICENSE, US_SSN…) and
# URL/ORGANIZATION — which otherwise fire as false positives on AU data + email domains.
RELEVANT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_TIME", "LOCATION",
    "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "MEDICAL_LICENSE",
    "AU_MEDICARE", "AU_TFN", "AU_ABN",
]


@lru_cache(maxsize=1)
def _analyzer():
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="AU_MEDICARE",
        patterns=[Pattern("medicare", _MEDICARE_PATTERN, 0.6)],
        context=["medicare"],
    ))
    return analyzer


def detect(text: str) -> List[Dict]:
    """Return findings: [{type, start, end, score, text}] for one piece of text."""
    if not text or not text.strip():
        return []
    results = _analyzer().analyze(text=text, language="en", entities=RELEVANT_ENTITIES)
    return [
        {
            "type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 2),
            "text": text[r.start:r.end],
        }
        for r in results
    ]
