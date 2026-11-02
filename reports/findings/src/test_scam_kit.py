"""Regression checks for the scam-kit counting rules (Report #4, Belle 2026-10-25).

Independent review found two inconsistencies in the first draft: an element with repeated
occurrences counted as redacted when any one occurrence was touched, and the
redacted texture skipped chained overlapping detections that the counts treated
as redacting. Both are now derived from one character mask. These checks pin
that behaviour.

Run from the repo root:
  reports/tools/scamenv/Scripts/python.exe -m unittest reports/findings/src/test_scam_kit.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.argv = [sys.argv[0]]        # scam_kit and the generators read argv at import

# The research environment (reports/tools/requirements-scamkit.txt) is not the
# product's test environment. Skip only when one of these named optional research
# dependencies is absent; any other import failure (a broken installed dependency,
# an error inside scam_kit or the generators) must fail, not skip.
_RESEARCH_DEPENDENCIES = ("chromadb", "presidio_analyzer", "spacy")
_missing = [name for name in _RESEARCH_DEPENDENCIES if importlib.util.find_spec(name) is None]
if _missing:
    raise unittest.SkipTest("research dependencies not installed: " + ", ".join(_missing)
                            + " (see reports/tools/requirements-scamkit.txt)")

import scam_kit as sk  # noqa: E402


def rec(text, spans, by_context=False):
    return {"id": "T", "text": text, "spans": spans, "provider_by_context": by_context, "group": "test"}


class RepeatedOccurrences(unittest.TestCase):
    text = "Patient Mia Chen, 0412 345 678. Mia Chen again."
    spans = {"name": sk._find_all(text, "Mia Chen"), "phone": sk._find_all(text, "0412 345 678")}

    def test_one_of_two_occurrences_covered_is_intact(self):
        f = [("PERSON", 0.85, 8, 16)]                       # first "Mia Chen" only
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "name", mask), "intact")
        self.assertIn("Mia Chen", sk.redact(self.text, f))

    def test_both_occurrences_covered_is_removed(self):
        f = [("PERSON", 0.85, 8, 16), ("PERSON", 0.85, 32, 40)]
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "name", mask), "removed")
        self.assertNotIn("Mia Chen", sk.redact(self.text, f))

    def test_below_threshold_finding_does_not_redact(self):
        f = [("PERSON", 0.3, 8, 16)]
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "name", mask), "intact")
        self.assertEqual(sk.redact(self.text, f), self.text)


class PartialRemnants(unittest.TestCase):
    text = "Contact 0412 345 678 today."
    spans = {"phone": sk._find_all(text, "0412 345 678")}

    def test_half_covered_is_partial_not_intact(self):
        f = [("DATE_TIME", 0.85, 8, 12)]                    # covers "0412" only
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "phone", mask), "partial")
        red = sk.redact(self.text, f)
        self.assertIn("345 678", red)                       # the remnant is visible
        self.assertNotIn("0412 345 678", red)               # but no complete occurrence is

    def test_partial_counts_as_not_surviving_in_tiers(self):
        states = {"name": "intact", "phone": "partial", "email": "absent", "address": "absent",
                  "provider": "intact", "appointment": "intact"}
        self.assertFalse(sk.kit_flags(states)["deliverable"])


class OverlappingDetections(unittest.TestCase):
    text = "Medicare 4655 04518 5 on file."
    spans = {"medicare": sk._find_all(text, "4655 04518 5")}

    def test_chained_overlaps_remove_completely_and_texture_agrees(self):
        f = [("PHONE_NUMBER", 0.5, 9, 15), ("AU_MEDICARE", 0.9, 12, 21)]   # 9-15 and 12-21 cover 9-21
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "medicare", mask), "removed")
        red = sk.redact(self.text, f)
        self.assertEqual(red, "Medicare <PHONE_NUMBER|AU_MEDICARE> on file.")

    def test_nested_overlap_is_one_token(self):
        f = [("AU_MEDICARE", 0.9, 9, 21), ("DATE_TIME", 0.6, 14, 19)]
        red = sk.redact(self.text, f)
        self.assertEqual(red, "Medicare <AU_MEDICARE|DATE_TIME> on file.")
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "medicare", mask), "removed")

    def test_overlap_touching_only_part_leaves_partial(self):
        f = [("DATE_TIME", 0.6, 14, 19)]
        mask = sk.coverage_mask(len(self.text), f)
        self.assertEqual(sk.element_state(rec(self.text, self.spans), "medicare", mask), "partial")


class TierRules(unittest.TestCase):
    base = {el: "absent" for el in sk.ALL_ELEMENTS}

    def flags(self, **kw):
        s = dict(self.base)
        s.update(kw)
        return sk.kit_flags(s)

    def test_deliverable_needs_name_and_a_contact(self):
        self.assertFalse(self.flags(name="intact")["deliverable"])
        self.assertFalse(self.flags(phone="intact")["deliverable"])
        self.assertTrue(self.flags(name="intact", address="intact")["deliverable"])

    def test_strict_needs_appointment_cue_interval_is_broad_only(self):
        f = self.flags(name="intact", email="intact", provider="intact", interval="intact")
        self.assertFalse(f["core_strict"])
        self.assertTrue(f["core_broad"])
        f = self.flags(name="intact", email="intact", provider="intact", appointment="intact")
        self.assertTrue(f["core_strict"])
        self.assertTrue(f["core_broad"])

    def test_strict_needs_provider(self):
        f = self.flags(name="intact", email="intact", appointment="intact")
        self.assertFalse(f["core_strict"])

    def test_billing_identifier_is_broad_only(self):
        f = self.flags(name="intact", phone="intact", provider="intact", medicare="intact")
        self.assertFalse(f["core_strict"])
        self.assertTrue(f["core_broad"])

    def test_amount_is_never_present(self):
        r = rec("Invoice $120.00 due", {"amount": [(8, 15)]})
        self.assertEqual(sk.element_state(r, "amount", bytearray(len(r["text"]))), "absent")


class ClinicCueClassification(unittest.TestCase):
    def test_interval_cues_are_not_appointment_cues(self):
        self.assertIn("six-month", sk.CLINIC_INTERVAL_CUES)
        self.assertIn("in three months", sk.CLINIC_INTERVAL_CUES)
        self.assertEqual(sk.CLINIC_APPOINTMENT_CUES, ["next Tuesday"])
        for cue in sk.CLINIC_INTERVAL_CUES:
            self.assertNotIn(cue, sk.CLINIC_APPOINTMENT_CUES)

    def test_clinic_provider_is_by_context(self):
        r = rec("note", {}, by_context=True)
        self.assertEqual(sk.element_state(r, "provider", bytearray(4)), "intact")
        r = rec("note", {}, by_context=False)
        self.assertEqual(sk.element_state(r, "provider", bytearray(4)), "absent")


class StoreSpans(unittest.TestCase):
    """The real stores: every span is a complete occurrence and the cue lists are exhaustive."""

    def test_clinic_spans_are_complete_occurrences(self):
        recs = sk.clinic_records()
        self.assertEqual(len(recs), 2000)
        r = next(x for x in recs if x["id"] == "PT-00049")
        for el, spans in r["spans"].items():
            for s, e in spans:
                self.assertTrue(r["text"][s:e])
        self.assertEqual(r["text"][r["spans"]["name"][0][0]:r["spans"]["name"][0][1]], "Marguerite Kaur")

    def test_voice_slot_is_appointment_in_every_rendering(self):
        v = sk.voice_records()
        for mode in ("formatted", "digits", "spoken"):
            booking = [r for r in v[mode] if r["scenario"] == "booking"]
            self.assertEqual(len(booking), 40)
            self.assertTrue(all(r["spans"].get("appointment") for r in booking))
            results = [r for r in v[mode] if r["scenario"] == "results"]
            self.assertTrue(all(not r["spans"].get("appointment") for r in results))


class AnnotationCompleteness(unittest.TestCase):
    """Review round 1, B2: every relevant occurrence must be annotated, not only the first."""

    def test_every_bill_occurrence_is_annotated_in_every_rendering(self):
        import re
        v = sk.voice_records()
        for mode in ("formatted", "digits", "spoken"):
            for r in v[mode]:
                if r["scenario"] != "billing":
                    self.assertFalse(r["spans"].get("billing_cue"))
                    continue
                found = [(m.start(), m.end()) for m in re.finditer(r"\bbill\b", r["text"])]
                self.assertEqual(sorted(r["spans"]["billing_cue"]), found, (r["id"], mode))
                self.assertGreaterEqual(len(found), 2, (r["id"], mode))

    def test_masking_first_bill_only_leaves_cue_intact(self):
        v = sk.voice_records()
        r = next(x for x in v["formatted"] if x["scenario"] == "billing")
        s, e = r["spans"]["billing_cue"][0]
        mask = sk.coverage_mask(len(r["text"]), [("X", 0.9, s, e)])
        self.assertEqual(sk.element_state(r, "billing_cue", mask), "intact")   # v1 returned "removed"
        full = [("X", 0.9, a, b) for a, b in r["spans"]["billing_cue"]]
        mask = sk.coverage_mask(len(r["text"]), full)
        self.assertEqual(sk.element_state(r, "billing_cue", mask), "removed")
        self.assertNotRegex(sk.redact(r["text"], full), r"\bbill\b")

    def test_clinic_spans_cover_every_occurrence_of_each_value(self):
        recs = sk.clinic_records()
        for r in recs[:200]:
            for el in ("name", "phone", "email", "dob", "medicare", "address"):
                surface = r["text"][r["spans"][el][0][0]:r["spans"][el][0][1]]
                self.assertEqual(len(r["spans"][el]), r["text"].count(surface), (r["id"], el))


class EnvironmentGate(unittest.TestCase):
    """Review round 1, B5: 'supported' must be checked against the package's detect pins, not assumed."""

    good = {"ragleakguard": "0.1.1", "spacy": "3.7.5", "numpy": "1.26.4", "en-core-web-sm": "3.7.1"}

    def test_measured_environment_is_supported(self):
        self.assertEqual(sk.classify_rlg_env(self.good), ("supported", []))

    def test_scamenv_like_environment_is_experimental(self):
        env = dict(self.good, spacy="3.8.16", numpy="2.4.6", **{"en-core-web-sm": "3.8.0"})
        mode, reasons = sk.classify_rlg_env(env)
        self.assertEqual(mode, "EXPERIMENTAL")
        self.assertEqual(len(reasons), 3)

    def test_missing_package_is_experimental(self):
        mode, reasons = sk.classify_rlg_env(dict(self.good, ragleakguard=None))
        self.assertEqual(mode, "EXPERIMENTAL")
        self.assertTrue(any("not importable" in r for r in reasons))
        self.assertEqual(sk.classify_rlg_env(None)[0], "EXPERIMENTAL")


if __name__ == "__main__":
    unittest.main()
