"""Recall benchmark: PII detection vs real-world identifier formats (ROADMAP item).

Measures, on a labelled synthetic fixture, how much sensitive data slips past:

  1. presidio_default — Microsoft Presidio out of the box (default registry: US + UK_NHS
     recognisers; same small spaCy model as RAGLeakGuard so the comparison isolates
     recogniser coverage, not NLP-model size). "Standard PII detection" as pipelines run it.
  2. presidio_au_on  — Presidio with its own optional AU recognisers (AU_TFN/ABN/ACN/
     MEDICARE) explicitly added — i.e. a team that knew to configure it. Note Presidio
     ships these but does NOT load them by default, and PhoneRecognizer still defaults
     to US regions.
  3. rlg_default     — RAGLeakGuard defaults (global + US entities, post-processing).
  4. rlg_au          — RAGLeakGuard with --locale au (AU phone/Medicare/TFN/ABN/ACN).

Every fixture item is one sentence containing exactly one ground-truth identifier at a
known span, tagged with category + format variant. An identifier counts as CAUGHT if any
finding overlaps its span, regardless of the label the engine chose — a mislabelled hit
still flags the record. Recall is reported at two tiers:

  any-confidence — any overlapping finding, even score 0.01 weak-pattern noise.
    Maximally generous to the engine; a pipeline acting at this threshold would
    redact virtually every number in every document.
  actionable (score >= 0.4) — the confidence range real deployments act on
    (Presidio's own sample configs use 0.35-0.5 thresholds). The honest tier.

False positives = findings at actionable confidence that overlap no ground truth.

Deterministic (seeded): same numbers every run, so results are reproducible/citable.

    python scripts/benchmark.py                # table to stdout
    python scripts/benchmark.py --json out.json --misses

⚠️  FAKE DATA ONLY — all identifiers are synthetic (checksum-valid where a checksum
exists, so they exercise the same code paths as real ones, but assigned to no one).
"""
import argparse
import json
import random
import sys
from collections import defaultdict

random.seed(20260704)  # reproducible fixture

# ---------------------------------------------------------------------------
# Synthetic identifier generators (checksum-valid where the real ID has one)
# ---------------------------------------------------------------------------

def gen_tfn():
    """Random 9-digit TFN with a valid ATO checksum (weighted sum % 11 == 0)."""
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    while True:
        d = [random.randint(1, 9)] + [random.randint(0, 9) for _ in range(7)]
        partial = sum(x * w for x, w in zip(d, weights[:8]))
        # weight of digit 9 is 10 ≡ -1 (mod 11) → d9 must equal partial mod 11
        d9 = partial % 11
        if d9 <= 9:
            return "".join(map(str, d + [d9]))


def gen_abn():
    """Random 11-digit ABN with a valid ATO checksum (mod 89)."""
    weights = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    while True:
        d = [random.randint(1, 9)] + [random.randint(0, 9) for _ in range(10)]
        nums = list(d)
        nums[0] -= 1
        if sum(n * w for n, w in zip(nums, weights)) % 89 == 0:
            return "".join(map(str, d))


def gen_medicare():
    """Medicare-card-shaped number (matches the AU_MEDICARE pattern; fake)."""
    return f"{random.randint(2, 6)}{random.randint(0, 9_999_999):07d}{random.randint(1, 9)}{random.randint(1, 9)}"


def gen_ssn():
    """SSN-shaped, avoiding invalid areas (000, 666, 900+) and 00/0000 groups."""
    area = random.choice([x for x in range(100, 899) if x != 666])
    return f"{area:03d}{random.randint(1, 99):02d}{random.randint(1, 9999):04d}"


def gen_us_phone():
    """NANP number using the reserved fictional 555-01xx block."""
    npa = random.choice([212, 305, 415, 512, 617, 702, 808, 917])
    return f"{npa}555{random.randint(100, 199):04d}"  # 555-0100..0199


def gen_itin():
    """ITIN: 9xx-(70..88)-xxxx (fake)."""
    return f"9{random.randint(0, 99):02d}{random.randint(70, 88):02d}{random.randint(1, 9999):04d}"


def gen_cc():
    """Luhn-valid 16-digit Visa-shaped test number."""
    d = [4] + [random.randint(0, 9) for _ in range(14)]
    total = 0
    for i, x in enumerate(d):  # Luhn over 15 digits + check digit position
        x2 = x * 2 if (len(d) - i) % 2 == 1 else x  # double alternating from the right (check digit will be appended)
        total += x2 - 9 if x2 > 9 else x2
    d.append((10 - total % 10) % 10)
    return "".join(map(str, d))


FIRST = ["Sarah", "Liam", "Mei-Ling", "Priya", "Jack", "Olivia", "Nguyen", "Charlotte", "Ethan", "Aisha"]
LAST = ["Chen", "O'Brien", "Patel", "Nguyen", "Taylor", "Kaur", "Santos", "Walker", "Ivanov", "Reyes"]


def gen_name():
    return f"{random.choice(FIRST)} {random.choice(LAST)}"


def gen_email():
    return f"{random.choice(FIRST).lower().replace('-','.')}{random.randint(1,99)}@example{random.choice(['','mail'])}.com"


def gen_mrn():
    """Medical-record-number shape commonly seen in clinic exports (no std recogniser)."""
    return f"MRN-{random.randint(100000, 999999)}"


# ---------------------------------------------------------------------------
# Format variants: (category, region, variant name, formatter)
# ---------------------------------------------------------------------------

def _space3(s):  # 123 456 789
    return " ".join(s[i:i + 3] for i in range(0, len(s), 3))


VARIANTS = [
    # --- US ---
    ("US_SSN", "US", "dashed",  lambda: (lambda s: f"{s[:3]}-{s[3:5]}-{s[5:]}")(gen_ssn())),
    ("US_SSN", "US", "spaced",  lambda: (lambda s: f"{s[:3]} {s[3:5]} {s[5:]}")(gen_ssn())),
    ("US_SSN", "US", "bare9",   lambda: gen_ssn()),
    ("US_ITIN", "US", "dashed", lambda: (lambda s: f"{s[:3]}-{s[3:5]}-{s[5:]}")(gen_itin())),
    ("US_ITIN", "US", "bare9",  lambda: gen_itin()),
    ("US_PHONE", "US", "paren", lambda: (lambda s: f"({s[:3]}) {s[3:6]}-{s[6:]}")(gen_us_phone())),
    ("US_PHONE", "US", "dashed", lambda: (lambda s: f"{s[:3]}-{s[3:6]}-{s[6:]}")(gen_us_phone())),
    ("US_PHONE", "US", "dotted", lambda: (lambda s: f"{s[:3]}.{s[3:6]}.{s[6:]}")(gen_us_phone())),
    ("US_PHONE", "US", "bare10", lambda: gen_us_phone()),
    ("US_PHONE", "US", "+1 intl", lambda: (lambda s: f"+1 {s[:3]} {s[3:6]} {s[6:]}")(gen_us_phone())),
    ("CREDIT_CARD", "global", "spaced4", lambda: (lambda s: " ".join(s[i:i+4] for i in range(0, 16, 4)))(gen_cc())),
    ("CREDIT_CARD", "global", "dashed4", lambda: (lambda s: "-".join(s[i:i+4] for i in range(0, 16, 4)))(gen_cc())),
    ("CREDIT_CARD", "global", "bare16",  lambda: gen_cc()),
    ("EMAIL", "global", "plain", gen_email),
    ("PERSON", "global", "name", gen_name),
    # --- AU ---
    ("AU_PHONE", "AU", "landline 0X", lambda: f"0{random.choice([2,3,7,8])} {random.randint(6000,9999)} {random.randint(1000,9999)}"),
    ("AU_PHONE", "AU", "landline (0X)", lambda: f"(0{random.choice([2,3,7,8])}) {random.randint(6000,9999)} {random.randint(1000,9999)}"),
    ("AU_PHONE", "AU", "mobile 04xx spaced", lambda: f"04{random.randint(10,99)} {random.randint(100,999)} {random.randint(100,999)}"),
    ("AU_PHONE", "AU", "mobile bare", lambda: f"04{random.randint(10_000_000, 99_999_999)}"),
    ("AU_PHONE", "AU", "+61 intl", lambda: f"+61 4{random.randint(10,99)} {random.randint(100,999)} {random.randint(100,999)}"),
    ("AU_PHONE", "AU", "1300/1800", lambda: f"1{random.choice([3,8])}00 {random.randint(100,999)} {random.randint(100,999)}"),
    ("AU_MEDICARE", "AU", "spaced", lambda: (lambda s: f"{s[:8]} {s[8]} {s[9]}")(gen_medicare())),
    ("AU_MEDICARE", "AU", "bare10", lambda: gen_medicare()[:9] + gen_medicare()[9]),
    ("AU_TFN", "AU", "spaced3", lambda: _space3(gen_tfn())),
    ("AU_TFN", "AU", "bare9",  gen_tfn),
    ("AU_ABN", "AU", "spaced", lambda: (lambda s: f"{s[:2]} {s[2:5]} {s[5:8]} {s[8:]}")(gen_abn())),
    ("AU_ABN", "AU", "bare11", gen_abn),
    # --- no standard recogniser exists at all ---
    ("MRN", "US", "MRN-xxxxxx", gen_mrn),
]

# Sentence templates per category — realistic free-text context, the {id} span is the
# ground truth. Context words are deliberately natural, not keyword-stuffed.
TEMPLATES = {
    "US_SSN":      ["Patient SSN is {id}, per intake form.",
                    "Verified identity; social security number {id} on file.",
                    "Applicant provided {id} as their SSN during onboarding."],
    "US_ITIN":     ["Tax ID (ITIN) {id} recorded for billing.",
                    "Filed under ITIN {id} last quarter."],
    "US_PHONE":    ["Best callback number is {id}, afternoons only.",
                    "Left a voicemail at {id} re: the follow-up.",
                    "Contact the guarantor on {id}."],
    "CREDIT_CARD": ["Card on file {id}, exp 09/27.",
                    "Charged the deposit to {id} as authorised.",
                    "Payment method: {id} (primary)."],
    "EMAIL":       ["Send the results to {id} when ready.",
                    "Follow-up booked; confirmation to {id}."],
    "PERSON":      ["{id} attended the 3pm consult with her partner.",
                    "Referral letter prepared for {id}, cc GP.",
                    "Spoke with {id} about the outstanding balance."],
    "AU_PHONE":    ["Call the patient on {id} to confirm.",
                    "Emergency contact reachable at {id}.",
                    "Rescheduled; left message on {id}."],
    "AU_MEDICARE": ["Medicare {id} verified at check-in.",
                    "Claim lodged against Medicare number {id}.",
                    "Card sighted: {id}, expiry next year."],
    "AU_TFN":      ["Employee TFN {id} added to payroll.",
                    "Super form lists tax file number {id}."],
    "AU_ABN":      ["Invoice issued to ABN {id}.",
                    "Supplier ABN {id} validated against the register."],
    "MRN":         ["Chart {id} updated after the procedure.",
                    "Results filed to record {id}."],
}

N_PER_VARIANT = 10


def build_fixture():
    """[{text, start, end, category, region, variant}] — one identifier per item."""
    items = []
    for category, region, variant, gen in VARIANTS:
        for _ in range(N_PER_VARIANT):
            ident = gen()
            template = random.choice(TEMPLATES[category])
            prefix = template.split("{id}")[0]
            text = template.format(id=ident)
            start = len(prefix)
            items.append({"text": text, "start": start, "end": start + len(ident),
                          "category": category, "region": region, "variant": variant})
    return items


# ---------------------------------------------------------------------------
# The three configurations under test
# ---------------------------------------------------------------------------

def _presidio_default_analyzer():
    """Presidio as shipped — full default registry, no custom recognisers.

    Same en_core_web_sm model as RAGLeakGuard so the comparison isolates
    recogniser coverage (the thing this benchmark is about), not model size.
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


def make_configs():
    from ragleakguard.detect import detect
    from presidio_analyzer.predefined_recognizers import (
        AuAbnRecognizer, AuAcnRecognizer, AuMedicareRecognizer, AuTfnRecognizer)

    presidio = _presidio_default_analyzer()
    presidio_au = _presidio_default_analyzer()
    for rec in (AuTfnRecognizer(), AuAbnRecognizer(), AuAcnRecognizer(), AuMedicareRecognizer()):
        presidio_au.registry.add_recognizer(rec)

    def analyze_with(engine):
        def fn(text):
            results = engine.analyze(text=text, language="en")  # all supported entities
            return [{"type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
                    for r in results]
        return fn

    return {
        "presidio_default": analyze_with(presidio),
        "presidio_au_on": analyze_with(presidio_au),
        "rlg_default": lambda t: detect(t),
        "rlg_au": lambda t: detect(t, locale="au"),
    }


ACTIONABLE = 0.4  # the confidence tier real pipelines act on (see module docstring)


def overlapping(findings, start, end):
    return [f for f in findings if f["start"] < end and start < f["end"]]


def run(json_path=None, show_misses=False):
    fixture = build_fixture()
    configs = make_configs()
    # tally[config][(category, variant)] = [any_caught, actionable_caught, total]
    tally = {c: defaultdict(lambda: [0, 0, 0]) for c in configs}
    region_tally = {c: defaultdict(lambda: [0, 0, 0]) for c in configs}
    misses = {c: [] for c in configs}          # missed at the actionable tier
    fp = {c: defaultdict(int) for c in configs}  # off-target findings >= ACTIONABLE, by label

    for i, item in enumerate(fixture):
        for cname, fn in configs.items():
            findings = fn(item["text"])
            hits = overlapping(findings, item["start"], item["end"])
            any_hit = bool(hits)
            act_hit = any(f["score"] >= ACTIONABLE for f in hits)
            key = (item["category"], item["variant"])
            for t in (tally[cname][key], region_tally[cname][item["region"]]):
                t[2] += 1
                t[0] += any_hit
                t[1] += act_hit
            if not act_hit:
                misses[cname].append({**item, "weak_hits": [
                    f"{f['type']}@{f['score']:.2f}" for f in hits]})
            for f in findings:
                if f["score"] >= ACTIONABLE and f not in hits:
                    fp[cname][f["type"]] += 1
        if (i + 1) % 50 == 0:
            print(f"  … {i + 1}/{len(fixture)} items", file=sys.stderr)

    # ---- report ----
    names = list(configs)
    print(f"\n# PII recall benchmark — {len(fixture)} labelled items, "
          f"{len(VARIANTS)} format variants, {N_PER_VARIANT} per variant")
    print(f"Cells: actionable-tier recall (score >= {ACTIONABLE}); any-confidence in [brackets] when different.\n")
    header = f"| {'Category':<12} | {'Variant':<18} | " + " | ".join(f"{n:>22}" for n in names) + " |"
    print(header)
    print("|" + "-" * 14 + "|" + "-" * 20 + "|" + ("-" * 24 + "|") * len(names))
    for category, region, variant, _ in VARIANTS:
        key = (category, variant)
        cells = []
        for n in names:
            a, act, t = tally[n][key]
            cell = f"{act:>3}/{t:<3} ({100*act/t:>5.1f}%)"
            cell += f" [{a}]" if a != act else "    "
            cells.append(f"{cell:>22}")
        print(f"| {category:<12} | {variant:<18} | " + " | ".join(cells) + " |")

    print("\n## Recall by region (actionable tier / any-confidence tier)\n")
    for n in names:
        parts = []
        for region in ("US", "AU", "global"):
            a, act, t = region_tally[n][region]
            if t:
                parts.append(f"{region} {act}/{t} ({100*act/t:.1f}% / {100*a/t:.1f}%)")
        ta = sum(v[0] for v in region_tally[n].values())
        tact = sum(v[1] for v in region_tally[n].values())
        tt = sum(v[2] for v in region_tally[n].values())
        print(f"- **{n}**: " + " · ".join(parts)
              + f" · OVERALL {tact}/{tt} ({100*tact/tt:.1f}% / {100*ta/tt:.1f}%)")

    print("\n## Off-target findings at actionable confidence (false-positive pressure)\n")
    for n in names:
        total_fp = sum(fp[n].values())
        top = ", ".join(f"{k}×{v}" for k, v in sorted(fp[n].items(), key=lambda kv: -kv[1])[:6])
        print(f"- **{n}**: {total_fp} across {len(fixture)} sentences ({top or 'none'})")

    if show_misses:
        print("\n## Missed at actionable tier (per config)\n")
        for n in names:
            print(f"### {n} — {len(misses[n])} misses")
            for m in misses[n][:60]:
                weak = f"  (weak-only: {', '.join(m['weak_hits'])})" if m["weak_hits"] else ""
                print(f"  - [{m['category']}/{m['variant']}] {m['text']}{weak}")

    if json_path:
        out = {
            "fixture_size": len(fixture),
            "actionable_threshold": ACTIONABLE,
            "per_variant": {n: {f"{k[0]}/{k[1]}": v for k, v in tally[n].items()} for n in names},
            "per_region": {n: dict(region_tally[n]) for n in names},
            "false_positives": {n: dict(fp[n]) for n in names},
            "misses": misses,
        }
        with open(json_path, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nJSON written to {json_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", help="also write full results to this JSON path")
    ap.add_argument("--misses", action="store_true", help="list missed items")
    args = ap.parse_args()
    run(json_path=args.json, show_misses=args.misses)
