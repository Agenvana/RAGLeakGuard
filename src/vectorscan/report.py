"""Reporting — turn findings into a risk report (CLI summary + HTML/Markdown).

Risk score (your security judgment): severity by data sensitivity x re-identifiability
x exposure (raw text stored? reversible? access controls?) x regulatory trigger.
Map findings to OWASP LLM Top 10 first; compliance profiles (GDPR, SOC 2, …) are plugins.
"""
from typing import List, Dict


def build_report(findings: List[Dict]) -> str:
    """Build a human-readable risk report from findings. TODO (Week 2)."""
    raise NotImplementedError("Report — Week 2")
