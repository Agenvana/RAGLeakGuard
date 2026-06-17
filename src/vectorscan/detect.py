"""Detection — find sensitive data in text.

Engine: Microsoft Presidio (configured for the small spaCy model, for speed).
The differentiation lives in the CUSTOM recognizers — domain/security judgment
tuned for real verticals. AU_MEDICARE is the first; TFN / health-record IDs next.
"""
from functools import lru_cache
from typing import List, Dict

# Australian Medicare-style number (matches our synthetic fixture; tune for production).
_MEDICARE_PATTERN = r"\b[2-6]\d{7}\s?\d\s?\d\b"


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
    results = _analyzer().analyze(text=text, language="en")
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
