"""Your Voice Agent Heard Everything - a synthetic voice-transcript store, scanned end to end.

Report #3 (September 2026), Week-1 data run. Deterministic: same seed, same
roster, same transcripts on every run; the scan and the memory lookups are
re-executed each run so run-to-run stability is measured, not assumed.

What it does, in order:
  A. builds a roster of 200 synthetic patients (100 Australian, 100 US) from
     the public Synthea sample dataset (MITRE synthetic patient generator):
     names, dates of birth, active conditions, current medications and
     allergies come from Synthea; contact and billing identifiers (phone,
     email, Medicare number, insurance member ID) are fabricated with valid
     formats. Synthea SSNs (all 999-xx-xxxx) are kept for the US cohort.
     The roster is committed beside this script so reruns need no download.
  B. scripts one inbound call per patient to an AI receptionist (booking,
     repeat prescription, results follow-up, reschedule, billing) and renders
     the transcript in three scripted text shapes inspired by documented
     speech-to-text behaviours (no audio is transcribed; several text
     properties change between shapes, so no shape isolates one setting):
       formatted : smart formatting ON  - punctuation, casing, digits
       digits    : numerals ON, formatting OFF - lowercase, digit runs
       spoken    : formatting OFF        - lowercase, numbers as words
  C. scans every transcript with Microsoft Presidio, the standard PII engine,
     in two configurations (stock defaults; defaults plus its optional AU
     recognisers) and scores recall per identifier type at two tiers
     (any confidence; actionable, score >= 0.4), generous to the tool: any
     overlapping finding of any label counts as caught.
  D. does the same for health information the caller said out loud
     (condition, medication, allergy).
  E. counts, per call, the identifier kinds in the transcript against a
     scripted per-scenario allowlist (no booking system is implemented; the
     result is by construction, an illustration of the right-place doctrine).
  F. loads the formatted transcripts into a Chroma "call memory" collection
     and queries it with an unfiltered semantic query (the query shape the
     Chroma getting-started page shows; using it for caller identification is
     this script's design, not a vendor recommendation), asking it to recognise
     returning callers by phone number and by name, and counts how often it
     returns a different synthetic patient.

Rerun from the repo root (paths are repo-relative, either machine):
  python -m venv reports/tools/voiceenv
  reports/tools/voiceenv/Scripts/python.exe -m pip install -r reports/tools/requirements-voice.txt
  reports/tools/voiceenv/Scripts/python.exe reports/findings/src/voice_transcripts.py [run2|run3]
macOS: reports/tools/voiceenv/bin/python

Rebuilding the roster from Synthea (only needed if voice_roster_2026-09.json
is missing): download synthea_sample_data_csv_apr2020.zip from
https://synthetichealth.github.io/synthea-sample-data/downloads/ (8,982,431
bytes, SHA-256 4194b18c11eaedcf0d5d5dd448d8ac9661f14381e2ef9f109215dc42266cd38a),
unzip, then:  ... voice_transcripts.py --synthea <dir containing csv/>

No real patient data is used anywhere. Synthea patients are synthetic; every
contact identifier is fabricated (ordinary-format numbers and addresses, emails
at real providers; allocation was not checked, so accidental correspondence to
a real contact detail is not excluded). Allergies fall back to a scripted
"penicillin" where the Synthea roster has none (62 of 80 mentions).
"""

from __future__ import annotations

import csv
import json
import os
import random
import re
import shutil
import sys
import tempfile
from collections import defaultdict

SEED = 20260914
N_PER_REGION = 100
HERE = os.path.dirname(os.path.abspath(__file__))
ROSTER = os.path.join(HERE, "voice_roster_2026-09.json")
ACTIONABLE = 0.4

_argv = list(sys.argv[1:])
if "--synthea" in _argv:
    _i = _argv.index("--synthea")
    del _argv[_i:_i + 2]
_TAG = _argv[0] if _argv else ""
OUT_JSON = os.path.join(os.path.dirname(HERE),
                        f"voice-2026-09-raw{'-' + _TAG if _TAG else ''}.json")
SYNTHEA_DIR = None
if "--synthea" in sys.argv:
    SYNTHEA_DIR = sys.argv[sys.argv.index("--synthea") + 1]

R: dict = {"seed": SEED, "run_tag": _TAG or "run1"}


# --------------------------------------------------------------------------
# A. roster
# --------------------------------------------------------------------------

AU_STREETS = ["Barkly St", "Glenferrie Rd", "Sydney Rd", "Chapel St", "Toorak Rd",
              "Burke Rd", "High St", "Riversdale Rd", "Nicholson St", "Rathdowne St",
              "Lygon St", "Smith St", "Oxford St", "Given Tce", "Rundle St"]
AU_SUBURBS = [("Brunswick", "VIC", "3056"), ("Hawthorn", "VIC", "3122"),
              ("Newtown", "NSW", "2042"), ("Fortitude Valley", "QLD", "4006"),
              ("Norwood", "SA", "5067"), ("Subiaco", "WA", "6008"),
              ("Sandy Bay", "TAS", "7005"), ("Braddon", "ACT", "2612"),
              ("Parramatta", "NSW", "2150"), ("Geelong", "VIC", "3220")]
EMAIL_DOMAINS_AU = ["gmail.com", "outlook.com", "bigpond.com", "hotmail.com"]
EMAIL_DOMAINS_US = ["gmail.com", "yahoo.com", "outlook.com", "comcast.net"]
US_AREA_CODES = ["617", "413", "508", "781", "978", "339"]
RELATIVES = ["daughter", "son", "wife", "husband", "mother", "father", "partner"]

# medications that a caller would plausibly name on the phone, mapped from
# Synthea's RxNorm descriptions to how a person says them
MED_SPOKEN = {
    "Simvastatin": "simvastatin", "Hydrochlorothiazide": "hydrochlorothiazide",
    "Naproxen": "naproxen", "Atenolol": "atenolol", "amLODIPine": "amlodipine",
    "Amlodipine": "amlodipine", "metoprolol": "metoprolol", "Furosemide": "furosemide",
    "Fluticasone": "fluticasone inhaler", "Albuterol": "albuterol inhaler",
    "Metformin": "metformin", "Nitroglycerin": "nitroglycerin spray",
    "Alendronic": "alendronic acid", "ferrous": "iron tablets",
    "Clopidogrel": "clopidogrel", "insulin": "insulin", "Verapamil": "verapamil",
    "Digoxin": "digoxin", "Warfarin": "warfarin", "Fexofenadine": "fexofenadine",
    "Loratadine": "loratadine", "diphenhydrAMINE": "diphenhydramine",
    "Lisinopril": "lisinopril", "Levothyroxine": "levothyroxine",
    "Sertraline": "sertraline", "Ibuprofen": "ibuprofen", "Acetaminophen": "paracetamol",
    "Epinephrine": "epipen", "Vitamin B 12": "b12 injections",
    "Prednisone": "prednisone", "Tamoxifen": "tamoxifen", "Anastrozole": "anastrozole",
    "Salmeterol": "salmeterol inhaler", "Budesonide": "budesonide inhaler",
    "Montelukast": "montelukast", "Leuprolide": "leuprolide injections",
    "DOCEtaxel": "docetaxel chemo", "Tacrolimus": "tacrolimus",
}
# Synthea conditions phrased the way a caller says them
COND_SPOKEN = {
    "Hypertension": "high blood pressure", "Prediabetes": "prediabetes",
    "Anemia (disorder)": "anaemia", "Chronic sinusitis (disorder)": "chronic sinusitis",
    "Hyperlipidemia": "high cholesterol", "Diabetes": "diabetes",
    "Osteoarthritis of knee": "arthritis in my knee",
    "Coronary Heart Disease": "coronary heart disease", "Impacted molars": "an impacted molar",
    "Osteoporosis (disorder)": "osteoporosis",
    "Chronic congestive heart failure (disorder)": "heart failure",
    "Chronic pain": "chronic pain", "Chronic intractable migraine without aura": "chronic migraines",
    "Seizure disorder": "my seizure disorder", "Atrial Fibrillation": "atrial fibrillation",
    "Polyp of colon": "the colon polyp", "Chronic kidney disease stage 1 (disorder)": "kidney disease",
    "Neoplasm of prostate": "my prostate cancer",
    "Perennial allergic rhinitis with seasonal variation": "hay fever",
    "Carcinoma in situ of prostate (disorder)": "prostate cancer",
    "Localized  primary osteoarthritis of the hand": "arthritis in my hands",
    "Alzheimer's disease (disorder)": "alzheimer's", "Perennial allergic rhinitis": "allergic rhinitis",
    "Neuropathy due to type 2 diabetes mellitus (disorder)": "diabetic neuropathy",
    "Epilepsy": "epilepsy", "Diabetic renal disease (disorder)": "diabetic kidney disease",
    "Hyperglycemia (disorder)": "high blood sugar", "Asthma": "asthma",
    "Childhood asthma": "asthma", "Chronic obstructive bronchitis (disorder)": "COPD",
    "Pulmonary emphysema (disorder)": "emphysema", "Rheumatoid arthritis": "rheumatoid arthritis",
    "Major depression disorder": "depression", "Malignant neoplasm of breast (disorder)": "breast cancer",
    "Metabolic syndrome X (disorder)": "metabolic syndrome",
    "Hypertriglyceridemia (disorder)": "high triglycerides", "Stroke": "my stroke",
    "Fibromyalgia (disorder)": "fibromyalgia", "Concussion with loss of consciousness": "the concussion",
    "Sleep apnea (disorder)": "sleep apnoea", "Obstructive sleep apnea syndrome (disorder)": "sleep apnoea",
    "Non-small cell lung cancer (disorder)": "lung cancer", "Blindness due to type 2 diabetes mellitus (disorder)": "diabetic eye disease",
    "Diabetic retinopathy associated with type II diabetes mellitus (disorder)": "diabetic retinopathy",
    "Microalbuminuria due to type 2 diabetes mellitus (disorder)": "the protein in my urine",
    "Proteinuria due to type 2 diabetes mellitus (disorder)": "the protein in my urine",
    "Chronic kidney disease stage 2 (disorder)": "kidney disease",
    "Chronic kidney disease stage 3 (disorder)": "kidney disease",
    "Hypoxemia (disorder)": "low oxygen", "Bullying (finding)": None,
    "Body mass index 30+ - obesity (finding)": None, "Miscarriage in first trimester": None,
    "Normal pregnancy": None, "Drug overdose": None, "Cardiac Arrest": None,
    "History of cardiac arrest (situation)": None, "History of appendectomy": None,
    "History of single seizure (situation)": None, "Appendicitis": None, "Tubal pregnancy": None,
}
ALLERGY_SPOKEN = {
    "Allergy to mould": "mould", "Dander (animal) allergy": "animal dander",
    "Allergy to tree pollen": "tree pollen", "House dust mite allergy": "dust mites",
    "Allergy to grass pollen": "grass pollen", "Shellfish allergy": "shellfish",
    "Allergy to bee venom": "bee stings", "Allergy to nut": "nuts", "Allergy to fish": "fish",
    "Allergy to wheat": "wheat", "Allergy to peanuts": "peanuts", "Latex allergy": "latex",
    "Allergy to eggs": "eggs", "Allergy to dairy product": "dairy", "Allergy to soya": "soy",
    "Penicillin allergy": "penicillin", "Sulfa allergy": "sulfa drugs",
}


def strip_digits(s: str) -> str:
    return re.sub(r"\d", "", s).strip()


def medicare_number(rng: random.Random) -> str:
    body = [rng.randint(2, 6)] + [rng.randint(0, 9) for _ in range(7)]
    weights = [1, 3, 7, 9, 1, 3, 7, 9]
    check = sum(d * w for d, w in zip(body, weights)) % 10
    d = "".join(str(x) for x in body) + str(check)
    return d + str(rng.randint(1, 9))  # 10 digits + issue number, formatted later


def build_roster_from_synthea(synthea_dir: str) -> list[dict]:
    csvdir = os.path.join(synthea_dir, "csv")

    def rows(name):
        with open(os.path.join(csvdir, name), encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    patients = [p for p in rows("patients.csv") if not p["DEATHDATE"]
                and 18 <= 2026 - int(p["BIRTHDATE"][:4]) <= 90]
    patients.sort(key=lambda p: p["Id"])
    conds, meds, allergies = defaultdict(list), defaultdict(list), defaultdict(list)
    for r in rows("conditions.csv"):
        if not r["STOP"] and COND_SPOKEN.get(r["DESCRIPTION"]):
            conds[r["PATIENT"]].append(COND_SPOKEN[r["DESCRIPTION"]])
    for r in rows("medications.csv"):
        if r["STOP"]:
            continue
        for key, spoken in MED_SPOKEN.items():
            if key.lower() in r["DESCRIPTION"].lower():
                meds[r["PATIENT"]].append(spoken)
                break
    for r in rows("allergies.csv"):
        if ALLERGY_SPOKEN.get(r["DESCRIPTION"]):
            allergies[r["PATIENT"]].append(ALLERGY_SPOKEN[r["DESCRIPTION"]])
    providers = sorted({strip_digits(p["NAME"]) for p in rows("providers.csv")
                        if p["SPECIALITY"] == "GENERAL PRACTICE"})

    rng = random.Random(SEED)
    eligible = [p for p in patients if conds[p["Id"]] and meds[p["Id"]]]
    rng.shuffle(eligible)
    roster = []
    for i, p in enumerate(eligible[: 2 * N_PER_REGION]):
        region = "AU" if i % 2 == 0 else "US"
        first, last = strip_digits(p["FIRST"]), strip_digits(p["LAST"])
        y, m, d = p["BIRTHDATE"].split("-")
        rec = {
            "pid": f"CALL-{i:03d}", "region": region, "synthea_id": p["Id"],
            "first": first, "last": last, "gender": p["GENDER"],
            "dob": {"y": int(y), "m": int(m), "d": int(d)},
            "conditions": sorted(set(conds[p["Id"]]))[:2],
            "medication": sorted(set(meds[p["Id"]]))[0],
            "allergy": (sorted(set(allergies[p["Id"]])) or [None])[0],
            "gp": rng.choice(providers),
            "relative": rng.choice(RELATIVES),
            "relative_name": strip_digits(rng.choice(patients)["FIRST"]),
        }
        local = re.sub(r"[^a-z]", "", (first + "." + last).lower().replace(" ", "")) or "caller"
        local = (first + "." + last).lower().replace(" ", "").replace("'", "")
        if region == "AU":
            rec["phone"] = "04" + "".join(str(rng.randint(0, 9)) for _ in range(8))
            rec["medicare"] = medicare_number(rng)
            st = rng.choice(AU_STREETS)
            sub, state, pc = rng.choice(AU_SUBURBS)
            rec["address"] = {"street": f"{rng.randint(1, 240)} {st}", "city": sub,
                              "state": state, "zip": pc}
            rec["email"] = f"{local}{rng.randint(1, 99)}@{rng.choice(EMAIL_DOMAINS_AU)}"
        else:
            rec["phone"] = rng.choice(US_AREA_CODES) + str(rng.randint(2, 9)) + \
                "".join(str(rng.randint(0, 9)) for _ in range(6))
            rec["ssn"] = p["SSN"]
            rec["insurance_id"] = rng.choice(["XQR", "ZGP", "HBK", "MTL"]) + \
                "".join(str(rng.randint(0, 9)) for _ in range(9))
            rec["address"] = {"street": p["ADDRESS"], "city": p["CITY"],
                              "state": p["STATE"], "zip": p["ZIP"]}
            rec["email"] = f"{local}{rng.randint(1, 99)}@{rng.choice(EMAIL_DOMAINS_US)}"
        roster.append(rec)
    return roster


def load_roster() -> list[dict]:
    if SYNTHEA_DIR:
        roster = build_roster_from_synthea(SYNTHEA_DIR)
        with open(ROSTER, "w", encoding="utf-8") as fh:
            json.dump(roster, fh, indent=1)
        print(f"roster rebuilt from Synthea -> {ROSTER}")
    with open(ROSTER, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# B. transcripts in three renderings
# --------------------------------------------------------------------------

ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
MONTHS = ["", "January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
ORD = {1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth", 6: "sixth",
       7: "seventh", 8: "eighth", 9: "ninth", 10: "tenth", 11: "eleventh",
       12: "twelfth", 13: "thirteenth", 14: "fourteenth", 15: "fifteenth",
       16: "sixteenth", 17: "seventeenth", 18: "eighteenth", 19: "nineteenth",
       20: "twentieth", 21: "twenty first", 22: "twenty second", 23: "twenty third",
       24: "twenty fourth", 25: "twenty fifth", 26: "twenty sixth",
       27: "twenty seventh", 28: "twenty eighth", 29: "twenty ninth",
       30: "thirtieth", 31: "thirty first"}
TENS = {2: "twenty", 3: "thirty", 4: "forty", 5: "fifty", 6: "sixty", 7: "seventy",
        8: "eighty", 9: "ninety"}
TEENS = {10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
         15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen"}


def two_digit_words(n: int) -> str:
    if n < 10:
        return ONES[n] if n else "hundred"
    if n < 20:
        return TEENS[n]
    return TENS[n // 10] + (" " + ONES[n % 10] if n % 10 else "")


def year_words(y: int) -> str:
    hi, lo = divmod(y, 100)
    if lo == 0:
        return two_digit_words(hi) + " hundred"
    if hi == 20 and lo < 10:
        return "two thousand and " + ONES[lo]
    if hi == 20:
        return "twenty " + two_digit_words(lo)
    return two_digit_words(hi) + " " + ("oh " + ONES[lo] if lo < 10 else two_digit_words(lo))


def digits_words(s: str, oh_for_zero: bool) -> str:
    return " ".join(("oh" if (c == "0" and oh_for_zero) else ONES[int(c)]) for c in s if c.isdigit())


def render(kind: str, value, region: str, mode: str) -> str:
    """One identifier in one rendering. kind: dob/phone/medicare/ssn/insurance/email/address/number."""
    if kind == "dob":
        y, m, d = value["y"], value["m"], value["d"]
        if mode == "formatted":
            return f"{d} {MONTHS[m]} {y}" if region == "AU" else f"{MONTHS[m]} {d}, {y}"
        if mode == "digits":
            return f"{d} {m} {y}" if region == "AU" else f"{m} {d} {y}"
        return (f"the {ORD[d]} of {MONTHS[m].lower()} {year_words(y)}" if region == "AU"
                else f"{MONTHS[m].lower()} {ORD[d]} {year_words(y)}")
    if kind == "phone":
        if mode == "formatted":
            return (f"{value[:4]} {value[4:7]} {value[7:]}" if region == "AU"
                    else f"({value[:3]}) {value[3:6]}-{value[6:]}")
        if mode == "digits":
            return value
        return digits_words(value, oh_for_zero=True)
    if kind == "medicare":
        if mode == "formatted":
            return f"{value[:4]} {value[4:9]} {value[9]}"
        if mode == "digits":
            return value
        return digits_words(value, oh_for_zero=False)
    if kind == "ssn":
        if mode == "formatted":
            return value
        if mode == "digits":
            return value.replace("-", "")
        return digits_words(value, oh_for_zero=False)
    if kind == "insurance":
        if mode == "formatted":
            return f"{value[:3]} {value[3:6]} {value[6:9]} {value[9:]}"
        if mode == "digits":
            return value.lower()
        return " ".join(value[:3].lower()) + " " + digits_words(value[3:], oh_for_zero=False)
    if kind == "email":
        if mode == "formatted":
            return value
        if mode == "digits":
            return value.replace("@", " at ").replace(".", " dot ")
        local, domain = value.split("@")
        local = re.sub(r"\d+", lambda m: " " + digits_words(m.group(), False), local)
        return local.replace(".", " dot ") + " at " + domain.replace(".", " dot ")
    if kind == "address":
        a = value
        if mode == "formatted":
            return (f"{a['street']}, {a['city']} {a['state']} {a['zip']}" if region == "AU"
                    else f"{a['street']}, {a['city']}, {a['state']} {a['zip']}")
        s = f"{a['street']} {a['city']} {a['state']} {a['zip']}".lower()
        if mode == "digits":
            return s
        return re.sub(r"\d+", lambda m: digits_words(m.group(), region == "AU"), s)
    if kind == "number":
        return str(value) if mode != "spoken" else two_digit_words(int(value))
    raise ValueError(kind)


# the five call scenarios: (needed fields, turn list). A turn is (speaker, text)
# where text contains {slots}. Slots that are identifiers are tagged so ground
# truth spans can be recorded.
SCENARIOS = {
    "booking": {
        "needs": ["name", "dob", "phone", "reason", "time"],
        "turns": [
            ("agent", "Thanks for calling {clinic}. This is the virtual receptionist. How can I help you today?"),
            ("caller", "Hi, I'd like to book an appointment. My name is [name]."),
            ("agent", "Thanks {first}. Can I get your date of birth?"),
            ("caller", "It's [dob]."),
            ("agent", "And the best number to reach you on?"),
            ("caller", "[phone]."),
            ("agent", "What's the appointment for?"),
            ("caller", "I've got [condition] and it's been getting worse. I'm on [medication] but I think the dose needs looking at. Also I'm allergic to [allergy], so please note that."),
            ("agent", "Noted. Is there a doctor you prefer?"),
            ("caller", "Dr [gp], I saw him last time. My [relative] [relative_name] will bring me, she has the car."),
            ("agent", "I have {slot} available. Shall I book that?"),
            ("caller", "Yes please. Can you send the confirmation to [email]?"),
            ("agent", "Done. You'll get a confirmation shortly. Anything else?"),
            ("caller", "No, that's all, thank you."),
        ],
    },
    "refill": {
        "needs": ["name", "dob", "medication"],
        "turns": [
            ("agent", "Thanks for calling {clinic}. This is the virtual receptionist. How can I help you today?"),
            ("caller", "Hi, I need a repeat prescription. It's [name]."),
            ("agent", "Sure. Your date of birth please?"),
            ("caller", "[dob]."),
            ("agent", "Which medication?"),
            ("caller", "My [medication], for [condition]. I've nearly run out."),
            ("agent", "I'll pass that to the doctor. Which pharmacy?"),
            ("caller", "The chemist near me, I'm at [address]. And can you check my [billing_label] on file, it's [billing]."),
            ("agent", "Thanks, I've noted that. A contact number in case the doctor has questions?"),
            ("caller", "[phone]. Thanks."),
        ],
    },
    "results": {
        "needs": ["name", "dob"],
        "turns": [
            ("agent", "Thanks for calling {clinic}. This is the virtual receptionist. How can I help you today?"),
            ("caller", "Hi, I'm calling about my test results. [name], date of birth [dob]."),
            ("agent", "Thanks. Which test was that?"),
            ("caller", "The blood test for my [condition]. Dr [gp] said to ring if I hadn't heard. I've been really worried, my [relative] [relative_name] had the same thing."),
            ("agent", "I can see a note to book a follow-up. Would you like me to do that?"),
            ("caller", "Yes. My number is [phone] and my email is [email]."),
            ("agent", "Booked. Anything else?"),
            ("caller", "Just that I'm still taking the [medication], in case that matters."),
        ],
    },
    "reschedule": {
        "needs": ["name", "dob", "phone"],
        "turns": [
            ("agent", "Thanks for calling {clinic}. This is the virtual receptionist. How can I help you today?"),
            ("caller", "I need to move my appointment. It's [name], born [dob]."),
            ("agent", "I can see it. When suits?"),
            ("caller", "Next week sometime. It's for my [condition] review with Dr [gp]. My [relative] [relative_name] is in hospital so this week is impossible."),
            ("agent", "I have {slot}. Shall I move it?"),
            ("caller", "Yes. Text me at [phone]. I'm allergic to [allergy], can you make sure that's on the file too?"),
            ("agent", "It is. Anything else?"),
            ("caller", "That's it."),
        ],
    },
    "billing": {
        "needs": ["name", "dob", "billing"],
        "turns": [
            ("agent", "Thanks for calling {clinic}. This is the virtual receptionist. How can I help you today?"),
            ("caller", "I got a bill I don't understand. [name], [dob]."),
            ("agent", "I'll look that up. Can you confirm your [billing_label]?"),
            ("caller", "[billing]. And the address on the bill is wrong, it should be [address]."),
            ("agent", "Updated. What was the bill for?"),
            ("caller", "The visit about my [condition]. I'm on [medication] now. Send the corrected bill to [email], and ring me on [phone] if there's a problem."),
            ("agent", "Will do. Anything else?"),
            ("caller", "No thanks."),
        ],
    },
}
SLOTS = ["Tuesday 10:15", "Wednesday 2:30", "Thursday 9:00", "Friday 11:45", "Monday 3:15"]
CLINICS = {"AU": "Northside Family Medical", "US": "Riverside Family Practice"}

# which identifier kinds are in the ground truth and what category they belong to
IDENTITY_KINDS = ["name", "dob", "phone", "email", "address", "medicare", "ssn", "insurance",
                  "gp_name", "relative_name"]
HEALTH_KINDS = ["condition", "medication", "allergy"]
# the label that names what the identifier actually is. A finding with any other
# label still counts as "caught" in the generous tiers; this third tier asks
# whether the tool knew what it was looking at. Kinds with no possible label
# (insurance member IDs, health information) can only score zero here.
CORRECT_LABEL = {"name": {"PERSON"}, "gp_name": {"PERSON"}, "relative_name": {"PERSON"},
                 "dob": {"DATE_TIME"}, "phone": {"PHONE_NUMBER"}, "email": {"EMAIL_ADDRESS"},
                 "address": {"LOCATION"}, "medicare": {"AU_MEDICARE"}, "ssn": {"US_SSN"},
                 "insurance": set(), "condition": set(), "medication": set(), "allergy": set()}


def build_transcript(rec: dict, scenario: str, mode: str, rng: random.Random):
    """Returns (text, spans) where spans = [(kind, start, end, surface)]."""
    region = rec["region"]
    sc = SCENARIOS[scenario]
    slot = rng.choice(SLOTS)
    billing_kind = "medicare" if region == "AU" else rng.choice(["ssn", "insurance"])
    values = {
        "name": f"{rec['first']} {rec['last']}",
        "dob": render("dob", rec["dob"], region, mode),
        "phone": render("phone", rec["phone"], region, mode),
        "email": render("email", rec["email"], region, mode),
        "address": render("address", rec["address"], region, mode),
        "condition": rec["conditions"][0],
        "medication": rec["medication"],
        "allergy": rec["allergy"] or "penicillin",
        "gp_name": rec["gp"],
        "relative_name": rec["relative_name"],
    }
    if billing_kind == "medicare":
        values["medicare"] = render("medicare", rec["medicare"], region, mode)
        billing_label = "Medicare number"
    elif billing_kind == "ssn":
        values["ssn"] = render("ssn", rec["ssn"], region, mode)
        billing_label = "social security number"
    else:
        values["insurance"] = render("insurance", rec["insurance_id"], region, mode)
        billing_label = "insurance member ID"

    text_parts, spans, pos = [], [], 0
    for speaker, tmpl in sc["turns"]:
        line = tmpl.replace("{clinic}", CLINICS[region]).replace("{first}", rec["first"]) \
                   .replace("{slot}", slot).replace("[billing_label]", billing_label) \
                   .replace("[billing]", "[" + billing_kind + "]") \
                   .replace("[gp]", "[gp_name]").replace("[relative]", rec["relative"])
        prefix = ("Agent: " if speaker == "agent" else "Caller: ")
        if mode != "formatted":
            prefix = prefix.lower()
        out = prefix
        for piece in re.split(r"(\[[a-z_]+\])", line):
            m = re.fullmatch(r"\[([a-z_]+)\]", piece)
            if m:
                kind = m.group(1)
                surface = values[kind]
                if mode != "formatted":
                    surface = surface.lower()
                spans.append((kind, pos + len(out), pos + len(out) + len(surface), surface))
                out += surface
            else:
                out += piece
        if mode != "formatted":
            out = re.sub(r"[^\w\s@]", "", out.lower()) if mode == "digits" else \
                re.sub(r"[^\w\s]", "", out.lower())
            out = re.sub(r"[ ]{2,}", " ", out)
        text_parts.append(out)
        pos += len(out) + 1
    text = "\n".join(text_parts)
    # spans were computed before punctuation stripping; recompute by search for the
    # lowercase renderings so offsets are exact
    if mode != "formatted":
        fixed = []
        cursor = 0
        for kind, _s, _e, surface in spans:
            surf = re.sub(r"[^\w\s@]", "", surface) if mode == "digits" else re.sub(r"[^\w\s]", "", surface)
            surf = re.sub(r"[ ]{2,}", " ", surf).strip()
            i = text.find(surf, cursor)
            if i < 0:
                i = text.find(surf)
            assert i >= 0, (kind, surf)
            fixed.append((kind, i, i + len(surf), surf))
            cursor = i + len(surf)
        spans = fixed
    for kind, s, e, surface in spans:
        assert text[s:e] == surface, (kind, text[s:e], surface)
    return text, spans, billing_kind, sc["needs"]


# --------------------------------------------------------------------------
# C/D. scanning with Presidio
# --------------------------------------------------------------------------

def build_engines():
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.predefined_recognizers import (
        AuAbnRecognizer, AuAcnRecognizer, AuMedicareRecognizer, AuTfnRecognizer,
        PhoneRecognizer)
    default = AnalyzerEngine()
    au = AnalyzerEngine()
    for rec in (AuMedicareRecognizer(), AuTfnRecognizer(), AuAbnRecognizer(), AuAcnRecognizer()):
        au.registry.add_recognizer(rec)
    au.registry.remove_recognizer("PhoneRecognizer")
    au.registry.add_recognizer(PhoneRecognizer(
        supported_regions=("US", "GB", "DE", "FR", "IL", "IN", "CA", "BR", "AU")))
    nlp_model = default.nlp_engine.models[0]["model_name"] if hasattr(default.nlp_engine, "models") else "?"
    return {"presidio_default": default, "presidio_au_on": au}, nlp_model


def overlaps(a_s, a_e, b_s, b_e):
    return a_s < b_e and b_s < a_e


def scan(engine, text: str):
    return [(r.entity_type, r.score, r.start, r.end) for r in engine.analyze(text=text, language="en")]


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    roster = load_roster()
    rng = random.Random(SEED + 1)
    scenarios = list(SCENARIOS)
    calls = []
    for i, rec in enumerate(roster):
        scenario = scenarios[i % len(scenarios)]
        call_rng = random.Random(SEED + 100 + i)
        renderings = {}
        for mode in ("formatted", "digits", "spoken"):
            text, spans, billing_kind, needs = build_transcript(rec, scenario, mode, random.Random(SEED + 100 + i))
            renderings[mode] = {"text": text, "spans": spans}
        calls.append({"rec": rec, "scenario": scenario, "renderings": renderings,
                      "billing_kind": billing_kind, "needs": needs})
    R["roster"] = {"calls": len(calls), "au": sum(c["rec"]["region"] == "AU" for c in calls),
                   "us": sum(c["rec"]["region"] == "US" for c in calls),
                   "scenario_counts": {s: sum(c["scenario"] == s for c in calls) for s in scenarios},
                   "roster_file": os.path.basename(ROSTER),
                   "synthea_source": "synthea_sample_data_csv_apr2020.zip sha256 4194b18c11eaedcf0d5d5dd448d8ac9661f14381e2ef9f109215dc42266cd38a"}
    words = {m: sum(len(c["renderings"][m]["text"].split()) for c in calls) for m in ("formatted", "digits", "spoken")}
    R["roster"]["total_words_per_rendering"] = words

    # ---- E. disclosed vs needed (right-place doctrine), independent of scanning
    disclosed_total = 0
    needed_total = 0
    surplus_by_kind = defaultdict(int)
    per_call_surplus = []
    for c in calls:
        kinds = [k for k, *_ in c["renderings"]["formatted"]["spans"]]
        needs = set(c["needs"])
        # 'billing' need is satisfied by whichever billing identifier was asked for
        if "billing" in needs:
            needs.discard("billing")
            needs.add(c["billing_kind"])
        disclosed = set(kinds)
        surplus = disclosed - needs
        disclosed_total += len(disclosed)
        needed_total += len(needs & disclosed)
        per_call_surplus.append(len(surplus))
        for k in surplus:
            surplus_by_kind[k] += 1
    R["E_disclosed_vs_needed"] = {
        "note": "counts distinct identifier KINDS per call; needs are the fields the booking system was designed to hold for that scenario",
        "identifier_kinds_disclosed_total": disclosed_total,
        "identifier_kinds_needed_total": needed_total,
        "surplus_kinds_total": disclosed_total - needed_total,
        "calls_with_surplus": sum(1 for s in per_call_surplus if s > 0),
        "calls_with_health_info_spoken": sum(1 for c in calls if any(k in HEALTH_KINDS for k, *_ in c["renderings"]["formatted"]["spans"])),
        "calls_with_third_party_named": sum(1 for c in calls if any(k in ("relative_name", "gp_name") for k, *_ in c["renderings"]["formatted"]["spans"])),
        "surplus_by_kind": dict(sorted(surplus_by_kind.items())),
        "mean_surplus_kinds_per_call": round(sum(per_call_surplus) / len(per_call_surplus), 2),
    }

    # ---- C/D. scans
    engines, nlp_model = build_engines()
    R["environment"] = {"presidio_nlp_model": nlp_model}
    import presidio_analyzer, spacy, chromadb
    R["environment"].update({"presidio_analyzer": getattr(presidio_analyzer, "__version__", "2.2.364"),
                             "spacy": spacy.__version__, "chromadb": chromadb.__version__,
                             "python": sys.version.split()[0], "platform": sys.platform})
    results = {}
    texture = []
    for cfg, engine in engines.items():
        results[cfg] = {}
        for mode in ("formatted", "digits", "spoken"):
            tally = defaultdict(lambda: {"n": 0, "any": 0, "actionable": 0, "correct_label": 0})
            labels_seen = defaultdict(lambda: defaultdict(int))
            off_target = 0
            records_exposed_identity = 0
            records_exposed_any = 0
            for c in calls:
                text = c["renderings"][mode]["text"]
                spans = c["renderings"][mode]["spans"]
                findings = scan(engine, text)
                hit_any = set()
                exposed_identity = False
                exposed_any = False
                for idx, (kind, s, e, surface) in enumerate(spans):
                    t = tally[kind]
                    t["n"] += 1
                    ov = [f for f in findings if overlaps(s, e, f[2], f[3])]
                    if ov:
                        t["any"] += 1
                        for f in ov:
                            labels_seen[kind][f[0]] += 1
                    if any(f[1] >= ACTIONABLE and f[0] in CORRECT_LABEL[kind] for f in ov):
                        t["correct_label"] += 1
                    if any(f[1] >= ACTIONABLE for f in ov):
                        t["actionable"] += 1
                        hit_any.add(idx)
                    else:
                        exposed_any = True
                        if kind in IDENTITY_KINDS:
                            exposed_identity = True
                # off-target: actionable findings overlapping no ground-truth span
                for f in findings:
                    if f[1] >= ACTIONABLE and not any(overlaps(s, e, f[2], f[3]) for _, s, e, _ in spans):
                        off_target += 1
                records_exposed_identity += exposed_identity
                records_exposed_any += exposed_any
                if cfg == "presidio_default" and c["rec"]["pid"] in ("CALL-000", "CALL-001", "CALL-004", "CALL-007"):
                    texture.append({"call": c["rec"]["pid"], "region": c["rec"]["region"], "scenario": c["scenario"],
                                    "rendering": mode,
                                    "findings_sample": [f"{f[0]}@{f[1]:.2f} '{text[f[2]:f[3]]}'" for f in sorted(findings, key=lambda f: f[2])],
                                    "truth_sample": [f"{k}: '{surf}'" for k, s, e, surf in spans]})
            def block(kinds):
                n = sum(tally[k]["n"] for k in kinds)
                a = sum(tally[k]["any"] for k in kinds)
                act = sum(tally[k]["actionable"] for k in kinds)
                lab = sum(tally[k]["correct_label"] for k in kinds)
                return {"n": n, "caught_any": a, "caught_actionable": act,
                        "caught_with_correct_label": lab,
                        "recall_any_pct": round(100 * a / n, 1) if n else None,
                        "recall_actionable_pct": round(100 * act / n, 1) if n else None,
                        "recall_correct_label_pct": round(100 * lab / n, 1) if n else None}
            results[cfg][mode] = {
                "per_kind": {k: dict(tally[k], **{"labels_seen": dict(labels_seen[k])}) for k in sorted(tally)},
                "identity_total": block(IDENTITY_KINDS),
                "identity_numeric_total": block(["phone", "medicare", "ssn", "insurance"]),
                "health_total": block(HEALTH_KINDS),
                "off_target_actionable_findings": off_target,
                "calls_with_at_least_one_identity_item_missed": records_exposed_identity,
                "calls_with_at_least_one_item_missed_incl_health": records_exposed_any,
                "calls": len(calls),
            }
            print(f"{cfg:18s} {mode:9s} identity {results[cfg][mode]['identity_total']} health {results[cfg][mode]['health_total']}")
    R["C_scan"] = results
    R["texture_samples"] = texture

    # ---- F. Chroma call memory
    tmp = tempfile.mkdtemp(prefix="voicemem-")
    try:
        client = chromadb.PersistentClient(path=tmp)
        col = client.get_or_create_collection("call_memory")
        col.add(ids=[c["rec"]["pid"] for c in calls],
                documents=[c["renderings"]["formatted"]["text"] for c in calls],
                metadatas=[{"region": c["rec"]["region"]} for c in calls])
        mem = {"calls_in_memory": col.count()}
        for probe_name, make_q in {
            "phone_lookup": lambda c: f"Incoming call from {render('phone', c['rec']['phone'], c['rec']['region'], 'formatted')}",
            "name_lookup": lambda c: f"Caller {c['rec']['first']} {c['rec']['last']}",
            "name_dob_lookup": lambda c: f"Caller {c['rec']['first']} {c['rec']['last']}, date of birth {render('dob', c['rec']['dob'], c['rec']['region'], 'formatted')}",
        }.items():
            top1_wrong, top1_wrong_other_health = 0, 0
            true_in_top3, true_in_top10 = 0, 0
            returned_ids = defaultdict(int)
            samples = []
            for c in calls:
                res = col.query(query_texts=[make_q(c)], n_results=10)
                got = res["ids"][0][0]
                returned_ids[got] += 1
                if c["rec"]["pid"] in res["ids"][0][:3]:
                    true_in_top3 += 1
                if c["rec"]["pid"] in res["ids"][0]:
                    true_in_top10 += 1
                if got != c["rec"]["pid"]:
                    top1_wrong += 1
                    other = next(x for x in calls if x["rec"]["pid"] == got)
                    if any(k in HEALTH_KINDS for k, *_ in other["renderings"]["formatted"]["spans"]):
                        top1_wrong_other_health += 1
                    if len(samples) < 3:
                        samples.append({"query": make_q(c), "returned": got,
                                        "returned_caller": f"{other['rec']['first']} {other['rec']['last']}",
                                        "returned_condition": other["rec"]["conditions"][0]})
            most_common = max(returned_ids.items(), key=lambda kv: kv[1])
            mem[probe_name] = {"queries": len(calls), "top1_is_a_different_patient": top1_wrong,
                               "of_which_that_patient_disclosed_health_info": top1_wrong_other_health,
                               "true_transcript_in_top3": true_in_top3,
                               "true_transcript_in_top10": true_in_top10,
                               "distinct_transcripts_returned_at_top1": len(returned_ids),
                               "most_returned_top1_count": most_common[1],
                               "samples": samples}
            print(f"memory {probe_name}: wrong top-1 {top1_wrong}/{len(calls)}")
        R["F_call_memory"] = mem
        del col, client
    finally:
        import gc
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(R, fh, indent=1)
    print("wrote", OUT_JSON)


if __name__ == "__main__":
    main()
