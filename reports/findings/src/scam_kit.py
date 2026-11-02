"""The Fraud Supply Chain - how many records in our synthetic stores hold a "scam kit",
and how much of that kit survives a standard PII redaction.

Report #4 (October 2026) data run. Deterministic: the two stores are the
ones Reports #2 and #3 built (same generators, same seeds, imported unchanged);
the scans are re-executed every run so run-to-run stability is measured, not
assumed. These are SYNTHETIC EXPOSURE MEASUREMENTS: they count what a redacted
record still shows, never whether a scam would succeed.

Method (Belle, 2026-10-25, correcting the first draft):
  * three tiers, the STRICT tier is the main measure:
      deliverable  : name intact AND at least one contact channel intact
      core_strict  : deliverable AND provider AND (a particular appointment or
                     date cue OR an amount). "Tuesday 10:15" or "next Tuesday"
                     qualify; a service interval such as "six-month scale and
                     clean" or "a review in three months" does NOT
      core_broad   : deliverable AND provider AND any credibility detail
                     (appointment cue, service interval, billing cue, the service
                     rendered, or a billing identifier: Medicare / SSN / insurance)
    Disclosed: no synthetic record carries an amount, so the strict tier turns on
    the appointment cue; in the clinic store the provider is assumed from the
    database context (one clinic's knowledge base) and is never a text span.
  * an element SURVIVES only when a COMPLETE occurrence of its value is still
    visible after redaction. Redaction is a character mask: the union of every
    finding at or above the actionable score (0.4), whatever its label, so
    overlapping and nested detections are handled once and the same way for the
    counts and for the redacted texture. Each occurrence is visible (no character
    covered), partial (some covered) or removed (all covered); an element is
    intact if any occurrence is visible, partial if none is visible but one is
    partially visible, removed otherwise. Partial remnants are reported
    separately from complete removal.
  * four scanner configurations: Microsoft Presidio stock defaults; Presidio plus
    its optional AU recognisers (both exactly as Report #3 built them, large spaCy
    model); RAGLeakGuard as shipped; RAGLeakGuard with --locale au. The
    RAGLeakGuard pair runs in its own supported environment (rlgenv, the
    package's `detect` pins) through rlg_scan_worker.py; if that venv is missing
    the tool runs in-process in scamenv and the artifact labels the configuration
    EXPERIMENTAL (spaCy / numpy outside the package's pins).
  * regression checks for the counting rules live in test_scam_kit.py.

Artifact version v2 (2026-10-26), after independent review round 1 (its record is
kept in the author's private working archive): every occurrence of the voice
billing cue is annotated (v1 kept only the first, B2); the RAGLeakGuard worker
environment is probed and gated before any scan, compared across batches and (from
2026-10-26) saved per batch (B5; the three stored v2 runs hold the batch count, the
identical flag and the final snapshot only); the
in-process fallback runs only with --allow-experimental and is labelled
EXPERIMENTAL; clinic service-span states are also counted per complaint template
(E3). The v1 artifacts (scamkit-2026-10-raw*.json) are kept beside the v2 ones and
were not re-measured.

Stores: 2,000 synthetic AU dental-clinic notes (chroma_erasure.build_patients,
Report #2, seed 20260801) and 200 synthetic receptionist calls in three text
renderings (voice_transcripts, Report #3, seed 20260914, committed roster). No
real data anywhere.

Rerun from the root of the RAGLeakGuard repository (Python 3.12; paths are
repo-relative; Windows shown, on macOS use python3.12 -m venv and .../bin/python):
  py -3.12 -m venv reports/tools/scamenv
  reports/tools/scamenv/Scripts/python.exe -m pip install -r reports/tools/requirements-scamkit.txt
  git worktree add ../RAGLeakGuard-measured 47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0
  py -3.12 -m venv reports/tools/rlgenv
  reports/tools/rlgenv/Scripts/python.exe -m pip install -e "../RAGLeakGuard-measured[detect]"
  reports/tools/rlgenv/Scripts/python.exe -m pip install -r reports/tools/requirements-rlg.txt
  reports/tools/scamenv/Scripts/python.exe reports/findings/src/scam_kit.py run4 [--rlg-python <path>]
The worktree holds the product at the measured commit, which predates this file:
checking that commit out in the working checkout would remove these scripts. Pass
--rlg-python if the RAGLeakGuard venv lives somewhere else. The commit actually
scanned is recorded in each artifact under environment.ragleakguard. Keep both
venvs out of version control.

Output: reports/findings/scamkit-2026-10-v2-raw[-<tag>].json

The RAGLeakGuard pair needs reports/tools/rlgenv (see requirements-rlg.txt).
Without it the script stops; pass --allow-experimental to run the tool in-process
anyway, which labels those two configurations EXPERIMENTAL in the artifact.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

# ---- our own command line, stripped before the generators read sys.argv -------
_args = sys.argv[1:]
RLG_PYTHON = None
ALLOW_EXPERIMENTAL = False
if "--allow-experimental" in _args:
    ALLOW_EXPERIMENTAL = True
    _args.remove("--allow-experimental")
if "--rlg-python" in _args:
    i = _args.index("--rlg-python")
    RLG_PYTHON = _args[i + 1]
    del _args[i:i + 2]
_TAG = _args[0] if _args and not _args[0].startswith("-") else ""
sys.argv = [sys.argv[0]] + ([_TAG] if _TAG else [])

ARTIFACT_VERSION = "v2"
OUT_JSON = os.path.join(os.path.dirname(HERE),
                        f"scamkit-2026-10-{ARTIFACT_VERSION}-raw{'-' + _TAG if _TAG else ''}.json")
ACTIONABLE = 0.4

# the two generators, imported unchanged (neither main() is called)
import chroma_erasure as ce          # noqa: E402  Report #2 clinic store
import voice_transcripts as vt       # noqa: E402  Report #3 voice store

R: dict = {"issue": "2026-10", "artifact_version": ARTIFACT_VERSION,
           "artifact_version_note": "v2 (2026-10-26): all voice billing-cue occurrences annotated; RAGLeakGuard "
                                    "environment probed, gated and compared across batches (per-batch records saved from 2026-10-26); clinic service states per "
                                    "complaint template. v1 artifacts preserved unchanged",
           "run_tag": _TAG or "run1",
           "seeds": {"clinic": ce.SEED, "voice": vt.SEED}, "actionable": ACTIONABLE,
           "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

# --------------------------------------------------------------------------
# kit definition
# --------------------------------------------------------------------------

CONTACT = ("phone", "email", "address")
IDENTIFIER_ELEMENTS = ("name", "phone", "email", "address", "dob", "medicare", "ssn", "insurance")
CREDIBILITY_ELEMENTS = ("provider", "service", "appointment", "interval", "billing_cue", "amount")
ALL_ELEMENTS = IDENTIFIER_ELEMENTS + CREDIBILITY_ELEMENTS
BILLING_IDS = ("medicare", "ssn", "insurance")

# clinic note cues. The lists are exhaustive over the generator's templates
# (ce.COMPLAINTS and ce.PLANS), checked at import. Classification per Belle's
# rule of 2026-10-25: a particular appointment or date cue is STRICT; a service
# interval is BROAD only.
CLINIC_APPOINTMENT_CUES = ["next Tuesday"]                       # "Booked for a composite restoration next Tuesday."
CLINIC_INTERVAL_CUES = ["six-month", "in three months"]          # "six-month scale and clean"; "a review in three months"
CLINIC_BILLING_CUES = ["payment plan", "health care card", "cost grounds"]

R["definitions"] = {
    "measurement_kind": "synthetic exposure measurement: what a redacted record still shows; not evidence that any scam succeeds",
    "deliverable": "name intact AND at least one of phone / email / address intact",
    "core_strict": "MAIN MEASURE. deliverable AND provider AND (a particular appointment or date cue intact OR an amount intact). "
                   "Appointment cues: the voice slot ('Tuesday 10:15' and the four others) and the clinic plan line 'next Tuesday'. "
                   "No synthetic record carries an amount, so the tier turns on the appointment cue",
    "core_broad": "deliverable AND provider AND any credibility detail intact (appointment cue, service interval, billing cue, "
                  "the service rendered, or a billing identifier: Medicare, SSN, insurance ID)",
    "interval_is_broad_only": "service intervals ('six-month scale and clean', 'a review in three months') count only in the broad tier",
    "survival": "an element survives (is INTACT) only when a complete occurrence of its value has no character covered by any "
                "actionable finding; PARTIAL = no complete occurrence visible but some characters of one still visible; "
                "REMOVED = every occurrence fully covered",
    "redaction": "character mask = union of every finding with score >= 0.4, any label; counts and redacted texture derive "
                 "from the same mask, so overlapping and nested detections are handled once",
    "billing_cue_voice": "every whole-word occurrence of 'bill' in the billing scenario (v1 annotated only the first)",
    "rlg_supported": "the RAGLeakGuard worker environment counts as supported only if it holds the ragleakguard package, "
                     "spaCy >=3.7,<3.8, numpy <2 and en_core_web_sm 3.7.x (the package's own `detect` pins); otherwise "
                     "the two RAGLeakGuard configurations are labelled EXPERIMENTAL",
    "clinic_appointment_cues": CLINIC_APPOINTMENT_CUES,
    "clinic_interval_cues": CLINIC_INTERVAL_CUES,
    "clinic_billing_cues": CLINIC_BILLING_CUES,
    "provider_in_clinic_store": "assumed from database context (one clinic's knowledge base); not a text span; never redactable",
    "dob": "counted as an identifier (a verification cue), not as the kit's date cue",
}


def _find_all(text: str, needle: str):
    out, i = [], 0
    while True:
        j = text.find(needle, i)
        if j < 0:
            return out
        out.append((j, j + len(needle)))
        i = j + 1


def clinic_records():
    """2,000 notes with kit spans. Spans: {element: [(start, end), ...]} = complete occurrences."""
    pts = ce.build_patients()
    assert len(pts) == ce.N_PATIENTS
    for cue in CLINIC_APPOINTMENT_CUES + CLINIC_INTERVAL_CUES + CLINIC_BILLING_CUES:
        assert sum(cue in t for t in ce.COMPLAINTS + ce.PLANS) == 1, cue
    recs = []
    for p in pts:
        note = p["note"]
        spans = defaultdict(list)
        for el in ("name", "dob", "medicare", "phone", "email", "address"):
            hits = _find_all(note, p[el])
            assert hits, (p["pid"], el)
            spans[el] = hits
        complaint = next(c for c in ce.COMPLAINTS if c in note)
        spans["service"] = _find_all(note, complaint)[:1]
        for cue in CLINIC_APPOINTMENT_CUES:
            spans["appointment"] += _find_all(note, cue)
        for cue in CLINIC_INTERVAL_CUES:
            spans["interval"] += _find_all(note, cue)
        for cue in CLINIC_BILLING_CUES:
            spans["billing_cue"] += _find_all(note, cue)
        recs.append({"id": p["pid"], "text": note, "spans": dict(spans),
                     "provider_by_context": True, "group": "clinic", "template": complaint})
    return recs


def voice_records():
    """200 calls x 3 renderings with kit spans, rebuilt exactly as Report #3's main()."""
    roster = vt.load_roster()
    scenarios = list(vt.SCENARIOS)
    out = {m: [] for m in ("formatted", "digits", "spoken")}
    for i, rec in enumerate(roster):
        scenario = scenarios[i % len(scenarios)]
        for mode in out:
            text, spans, _billing_kind, _needs = vt.build_transcript(
                rec, scenario, mode, random.Random(vt.SEED + 100 + i))
            sp = defaultdict(list)
            for kind, s, e, _surface in spans:
                sp[kind].append((s, e))
            clinic = vt.CLINICS[rec["region"]]
            if mode != "formatted":
                clinic = re.sub(r"[^\w\s]", "", clinic.lower())
            hits = _find_all(text, clinic)
            assert hits, (rec["pid"], mode, "clinic")
            sp["provider"] = hits
            for slot in vt.SLOTS:   # the appointment slot: a particular appointment cue (STRICT)
                needle = slot if mode == "formatted" else re.sub(r"[^\w\s]", "", slot.lower())
                if needle in text:
                    sp["appointment"] += _find_all(text, needle)
            if "condition" in sp:   # the service rendered = the condition the visit is about
                sp["service"] = list(sp["condition"])
            if scenario == "billing":
                sp["billing_cue"] = [(m.start(), m.end()) for m in re.finditer(r"\bbill\b", text)]
            out[mode].append({"id": rec["pid"], "text": text, "spans": dict(sp),
                              "provider_by_context": False, "group": f"voice_{mode}",
                              "scenario": scenario, "region": rec["region"]})
    return out


# --------------------------------------------------------------------------
# scanners
# --------------------------------------------------------------------------

def default_rlg_python():
    for cand in (os.path.join(REPO, "reports", "tools", "rlgenv", "Scripts", "python.exe"),
                 os.path.join(REPO, "reports", "tools", "rlgenv", "bin", "python")):
        if os.path.exists(cand):
            return cand
    return None


def classify_rlg_env(env: dict):
    """Does a worker environment satisfy RAGLeakGuard's own `detect` pins? Returns (mode, reasons)."""
    reasons = []
    if not env or not env.get("ragleakguard"):
        reasons.append("ragleakguard package not importable in the worker")
    def ver(key):
        v = (env or {}).get(key)
        if not v:
            return None
        parts = v.split(".")
        try:
            return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            return None
    sp = ver("spacy")
    if sp is None or not ((3, 7) <= sp < (3, 8)):
        reasons.append(f"spaCy {env.get('spacy') if env else None} outside >=3.7,<3.8")
    np_ = ver("numpy")
    if np_ is None or np_[0] >= 2:
        reasons.append(f"numpy {env.get('numpy') if env else None} not <2")
    sm = ver("en-core-web-sm")
    if sm is None or sm[:2] != (3, 7):
        reasons.append(f"en_core_web_sm {env.get('en-core-web-sm') if env else None} not 3.7.x")
    return ("supported" if not reasons else "EXPERIMENTAL"), reasons


class RlgWorker:
    """Batch scanner: runs rlg_scan_worker.py in its own venv, one call per batch; records every batch's environment."""

    def __init__(self, python: str, locale):
        self.python, self.locale, self.environment, self.environments = python, locale, None, []

    def probe(self):
        self.scan_batch([])
        return self.environment

    def scan_batch(self, texts):
        with tempfile.TemporaryDirectory() as td:
            req, resp = os.path.join(td, "req.json"), os.path.join(td, "resp.json")
            with open(req, "w", encoding="utf-8") as fh:
                json.dump({"texts": texts, "locale": self.locale}, fh)
            subprocess.run([self.python, "-I", os.path.join(HERE, "rlg_scan_worker.py"), req, resp],
                           check=True, cwd=HERE)
            with open(resp, encoding="utf-8") as fh:
                data = json.load(fh)
        self.environment = data["environment"]
        self.environments.append(data["environment"])
        return [[tuple(f) for f in per_text] for per_text in data["findings"]]


class InProcess:
    """Batch scanner over a per-text callable."""

    def __init__(self, fn):
        self.fn = fn

    def scan_batch(self, texts):
        return [self.fn(t) for t in texts]


def build_scanners(rlg_python=None):
    engines, nlp_model = vt.build_engines()          # Report #3's two Presidio configurations

    def presidio(engine):
        return lambda text: [(r.entity_type, r.score, r.start, r.end)
                             for r in engine.analyze(text=text, language="en")]

    scanners = {
        "presidio_default": InProcess(presidio(engines["presidio_default"])),
        "presidio_au_on": InProcess(presidio(engines["presidio_au_on"])),
    }
    rlg_python = rlg_python or default_rlg_python()
    if rlg_python:
        probe = RlgWorker(rlg_python, None)
        env = probe.probe()
        mode, reasons = classify_rlg_env(env)
        if mode != "supported" and not ALLOW_EXPERIMENTAL:
            raise SystemExit("RAGLeakGuard worker environment does not satisfy the package's detect pins: "
                             + "; ".join(reasons) + ". Rebuild reports/tools/rlgenv per requirements-rlg.txt, "
                             "or pass --allow-experimental to label the configurations EXPERIMENTAL.")
        rlg_mode = {"mode": mode, "gate_reasons": reasons, "python": rlg_python,
                    "note": "RAGLeakGuard detect() from the recorded source commit, run in its own venv through "
                            "rlg_scan_worker.py; 'supported' means the probed environment satisfies the package's "
                            "`detect` pins (spaCy >=3.7,<3.8, numpy <2, en_core_web_sm 3.7.x)"}
        rlg_mode["probe_environment"] = env
        scanners["rlg_default"] = RlgWorker(rlg_python, None)
        scanners["rlg_au"] = RlgWorker(rlg_python, "au")
    else:
        if not ALLOW_EXPERIMENTAL:
            raise SystemExit("reports/tools/rlgenv not found. Build it per reports/tools/requirements-rlg.txt (the "
                             "measured tables need the supported worker), or pass --allow-experimental to run "
                             "RAGLeakGuard in-process and label those configurations EXPERIMENTAL.")
        from ragleakguard.detect import detect
        import spacy as _sp, numpy as _np
        rlg_mode = {"mode": "EXPERIMENTAL", "gate_reasons": [f"in-process in scamenv: spaCy {_sp.__version__}, numpy {_np.__version__}"],
                    "note": "RAGLeakGuard imported in scamenv, outside the package's `detect` pins; not a supported configuration"}
        scanners["rlg_default"] = InProcess(lambda t: [(f["type"], f["score"], f["start"], f["end"]) for f in detect(t)])
        scanners["rlg_au"] = InProcess(lambda t: [(f["type"], f["score"], f["start"], f["end"]) for f in detect(t, locale="au")])
    return scanners, nlp_model, rlg_mode


# --------------------------------------------------------------------------
# redaction mask, occurrence states, redacted texture (one source of truth)
# --------------------------------------------------------------------------

def coverage_mask(text_len: int, findings, threshold=ACTIONABLE) -> bytearray:
    mask = bytearray(text_len)
    for _label, score, s, e in findings:
        if score >= threshold:
            s, e = max(0, s), min(text_len, e)
            for k in range(s, e):
                mask[k] = 1
    return mask


def occurrence_state(mask: bytearray, s: int, e: int) -> str:
    covered = sum(mask[s:e])
    if covered == 0:
        return "visible"
    if covered == e - s:
        return "removed"
    return "partial"


def element_state(rec, el, mask: bytearray) -> str:
    """intact / partial / removed / absent, from complete occurrences of the element."""
    if el == "provider" and rec.get("provider_by_context"):
        return "intact"                      # database context, not a span
    if el == "amount":
        return "absent"                      # no synthetic record carries an amount
    spans = rec["spans"].get(el)
    if not spans:
        return "absent"
    states = [occurrence_state(mask, s, e) for s, e in spans]
    if "visible" in states:
        return "intact"
    if "partial" in states:
        return "partial"
    return "removed"


def redact(text: str, findings, threshold=ACTIONABLE) -> str:
    """Replace every covered run with <LABEL|LABEL...> built from the same mask the counts use."""
    mask = coverage_mask(len(text), findings, threshold)
    actionable = [f for f in findings if f[1] >= threshold]
    out, i, n = [], 0, len(text)
    while i < n:
        if not mask[i]:
            out.append(text[i])
            i += 1
            continue
        j = i
        while j < n and mask[j]:
            j += 1
        labels = []
        for label, _score, s, e in sorted(actionable, key=lambda f: (f[2], f[3])):
            if s < j and i < e and label not in labels:
                labels.append(label)
        out.append("<" + "|".join(labels) + ">")
        i = j
    return "".join(out)


def kit_flags(states: dict) -> dict:
    ok = lambda el: states.get(el) == "intact"  # noqa: E731
    deliverable = ok("name") and any(ok(c) for c in CONTACT)
    strict_cue = ok("appointment") or ok("amount")
    broad_cue = strict_cue or ok("interval") or ok("billing_cue") or ok("service") or any(ok(b) for b in BILLING_IDS)
    return {"deliverable": deliverable,
            "core_strict": deliverable and ok("provider") and strict_cue,
            "core_broad": deliverable and ok("provider") and broad_cue}


# --------------------------------------------------------------------------
# measurement
# --------------------------------------------------------------------------

def by_construction(recs):
    """What each record holds before any redaction (descriptive, scripted)."""
    present = Counter()
    tiers = Counter()
    contact_channels = Counter()
    per_scenario = defaultdict(Counter)
    for r in recs:
        mask = bytearray(len(r["text"]))
        states = {el: element_state(r, el, mask) for el in ALL_ELEMENTS}
        for el in ALL_ELEMENTS:
            present[el] += states[el] == "intact"
        contact_channels[sum(states[c] == "intact" for c in CONTACT)] += 1
        flags = kit_flags(states)
        for k, v in flags.items():
            tiers[k] += v
            if "scenario" in r:
                per_scenario[r["scenario"]][k] += v
        if "scenario" in r:
            per_scenario[r["scenario"]]["records"] += 1
    out = {"records": len(recs), "elements_present": {el: present[el] for el in ALL_ELEMENTS},
           "contact_channels_per_record": {str(k): v for k, v in sorted(contact_channels.items())},
           "kits_present": dict(tiers)}
    if per_scenario:
        out["per_scenario"] = {s: dict(c) for s, c in sorted(per_scenario.items())}
    return out


def measure(recs, scanner, texture_ids=()):
    """One scan per record; returns (aggregates, texture records)."""
    texts = [r["text"] for r in recs]
    all_findings = scanner.scan_batch(texts)
    state_counts = {el: Counter() for el in ALL_ELEMENTS}
    tiers = Counter()
    labels_on = defaultdict(Counter)
    ident_intact_hist = Counter()
    cred_all_intact = 0
    contact_any = 0
    per_scenario = defaultdict(Counter)
    by_template = defaultdict(lambda: defaultdict(Counter))   # element -> template -> state -> n
    textures = []
    consistency_checks = 0
    for r, findings in zip(recs, all_findings):
        text = r["text"]
        mask = coverage_mask(len(text), findings)
        actionable = [f for f in findings if f[1] >= ACTIONABLE]
        states = {el: element_state(r, el, mask) for el in ALL_ELEMENTS}
        for el in ALL_ELEMENTS:
            state_counts[el][states[el]] += 1
            for s, e in r["spans"].get(el, []):
                for label, _sc, fs, fe in actionable:
                    if fs < e and s < fe:
                        labels_on[el][label] += 1
        contact_any += any(states[c] == "intact" for c in CONTACT)
        flags = kit_flags(states)
        for k, v in flags.items():
            tiers[k] += v
            if "scenario" in r:
                per_scenario[r["scenario"]][k] += v
        if "scenario" in r:
            per_scenario[r["scenario"]]["records"] += 1
        if "template" in r:
            for el in ("service", "interval", "appointment", "billing_cue"):
                by_template[el][r["template"]][states[el]] += 1
        n_ident_present = sum(states[el] != "absent" for el in IDENTIFIER_ELEMENTS)
        n_ident_intact = sum(states[el] == "intact" for el in IDENTIFIER_ELEMENTS)
        ident_intact_hist[f"{n_ident_intact}/{n_ident_present}"] += 1
        cred_present = [el for el in CREDIBILITY_ELEMENTS if states[el] != "absent"]
        if cred_present and all(states[el] == "intact" for el in cred_present):
            cred_all_intact += 1
        # consistency: the redacted texture must agree with the mask-derived states
        redacted = redact(text, findings)
        for el in ALL_ELEMENTS:
            if states[el] == "intact" and r["spans"].get(el):
                vis = [text[s:e] for s, e in r["spans"][el] if occurrence_state(mask, s, e) == "visible"]
                assert any(v in redacted for v in vis), (r["id"], el)
                consistency_checks += 1
        if r["id"] in texture_ids:
            textures.append({"id": r["id"], "group": r["group"], "redacted_text": redacted,
                             "states": states, "kit": flags,
                             "findings_actionable": [(f[0], round(f[1], 2), text[f[2]:f[3]]) for f in actionable]})
    out = {"records": len(recs),
           "elements": {el: {"intact": state_counts[el]["intact"], "partial": state_counts[el]["partial"],
                             "removed": state_counts[el]["removed"], "absent": state_counts[el]["absent"]}
                        for el in ALL_ELEMENTS},
           "contact_any_intact": contact_any,
           "kits_intact": dict(tiers),
           "credibility_elements_all_intact": cred_all_intact,
           "identifier_elements_intact_hist": dict(sorted(ident_intact_hist.items())),
           "labels_on_elements": {el: dict(c.most_common()) for el, c in labels_on.items()},
           "consistency_checks_passed": consistency_checks}
    if per_scenario:
        out["per_scenario"] = {s: dict(c) for s, c in sorted(per_scenario.items())}
    if by_template:
        out["states_by_template"] = {el: {t: dict(c) for t, c in sorted(d.items())} for el, d in by_template.items()}
    return out, textures


def main():
    print("building stores ...", flush=True)
    clinic = clinic_records()
    voice = voice_records()
    R["stores"] = {"clinic": by_construction(clinic), **{f"voice_{m}": by_construction(voice[m]) for m in voice}}
    R["stores"]["clinic"]["source"] = "chroma_erasure.build_patients (Report #2), 2,000 synthetic AU dental-clinic notes"
    R["stores"]["voice_formatted"]["source"] = "voice_transcripts (Report #3), 200 synthetic receptionist calls, three renderings"

    print("building scanners ...", flush=True)
    scanners, nlp_model, rlg_mode = build_scanners(RLG_PYTHON)
    import presidio_analyzer, spacy, chromadb  # noqa: E401
    R["environment"] = {"presidio_default_nlp_model": nlp_model,
                        "presidio_analyzer": getattr(presidio_analyzer, "__version__", "2.2.364"),
                        "spacy": spacy.__version__, "chromadb": chromadb.__version__,
                        "python": sys.version.split()[0], "platform": sys.platform,
                        "ragleakguard_mode": rlg_mode}

    clinic_tex = {"PT-00049"}
    voice_tex = {next(r["id"] for r in voice["formatted"] if r["scenario"] == "booking"),
                 next(r["id"] for r in voice["formatted"] if r["scenario"] == "billing")}

    R["scan"], R["texture"] = {}, {}
    for cfg, scanner in scanners.items():
        print(f"scanning {cfg}: clinic ...", flush=True)
        res, tex = measure(clinic, scanner, clinic_tex)
        R["scan"].setdefault("clinic", {})[cfg] = res
        R["texture"].setdefault(cfg, []).extend(tex)
        for mode in voice:
            print(f"scanning {cfg}: voice_{mode} ...", flush=True)
            res, tex = measure(voice[mode], scanner, voice_tex)
            R["scan"].setdefault(f"voice_{mode}", {})[cfg] = res
            R["texture"][cfg].extend(tex)
        if isinstance(scanner, RlgWorker) and scanner.environments:
            envs = scanner.environments
            R["environment"]["ragleakguard"] = envs[-1]
            R["environment"].setdefault("ragleakguard_batches", {})[cfg] = {
                "batches": len(envs),
                "identical_across_batches": all(json.dumps(e, sort_keys=True) == json.dumps(envs[0], sort_keys=True) for e in envs),
                # every batch's record, saved since 2026-10-26 (independent review, targeted verification);
                # the three stored v2 runs predate this field and hold the count, the flag and the final snapshot
                "environments": envs}
    if "ragleakguard_batches" in R["environment"]:
        probe = R["environment"]["ragleakguard_mode"].get("probe_environment")
        all_envs = [e for cfg in R["environment"]["ragleakguard_batches"].values() for e in cfg["environments"]]
        R["environment"]["ragleakguard_batches"]["all_batches_match_probe"] = bool(probe) and all(
            json.dumps(e, sort_keys=True) == json.dumps(probe, sort_keys=True) for e in all_envs)
    if "ragleakguard" not in R["environment"]:
        try:
            import ragleakguard
            R["environment"]["ragleakguard"] = {"version": ragleakguard.__version__, "in_process": True}
        except ImportError:
            R["environment"]["ragleakguard"] = None

    R["headline"] = {}
    for store, per_cfg in R["scan"].items():
        R["headline"][store] = {cfg: {"records": v["records"],
                                      "deliverable_after_redaction": v["kits_intact"]["deliverable"],
                                      "core_strict_after_redaction": v["kits_intact"]["core_strict"],
                                      "core_broad_after_redaction": v["kits_intact"]["core_broad"]}
                                for cfg, v in per_cfg.items()}

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(R, fh, indent=1, default=str)
    print("wrote", OUT_JSON)
    for store, per_cfg in R["headline"].items():
        for cfg, v in per_cfg.items():
            print(f"{store:16s} {cfg:17s} deliverable {v['deliverable_after_redaction']:5d} / {v['records']}"
                  f"   strict {v['core_strict_after_redaction']:5d}   broad {v['core_broad_after_redaction']:5d}")


if __name__ == "__main__":
    main()
