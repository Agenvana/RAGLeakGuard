"""Detection — find sensitive data in text.

Base engine: Microsoft Presidio. Differentiation lives HERE — custom recognizers
tuned for real verticals (AU Medicare/TFN/IHI, health record IDs, legal matter IDs)
to raise recall on what matters and cut false positives.
"""
from typing import List, Dict


def detect(text: str) -> List[Dict]:
    """Return findings: [{"type": str, "start": int, "end": int, "score": float}].

    TODO (Day 4): wire Presidio AnalyzerEngine + custom vertical recognizers.
    """
    raise NotImplementedError("Detection — Day 4")
