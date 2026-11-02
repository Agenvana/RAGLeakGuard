# Findings package, October 2026 · The AI Data Security Report, Issue #4

**Public copy.** This is the data package behind Issue #4, published beside the report so every figure can be checked. It is a cleaned copy of the working findings file: the method, the measurements, the public statistics, the Report #2 follow-up, the literature sweep, the verification log and the method caveats are carried over. Three working sections are left out because they are editorial planning, not evidence (the candidate headlines, the backlog hand-off and the drafting pointers); section numbers are kept as in the working file, so sections 5, 11 and 12 are absent on purpose. Pointers to the private planning repository are replaced with a plain description, drafting instructions are rewritten as statements of what the report does, and one unresolved item of source reading (table cells whose column alignment the text extraction could not confirm) stays in the working file and is not reproduced here. The three independent review rounds reviewed the working file and the report; this derived copy was not separately reviewed. Everything below is either measured here or quoted from a named source with its access date and a strength label; most sources are primary records, one row is labelled [SECONDARY] (reporting about a primary record, not the record itself), and rows labelled agent-read were read by the drafting agent and not re-read by a person; the limits of each source are noted beside it. All patient data is synthetic.

**Published evidence files.** The six raw artifacts beside this file are metadata-redacted publication copies of the measured artifacts: two environment fields that held machine-local paths (`environment.ragleakguard_mode.python`, `environment.ragleakguard.venv`) read `<LOCAL_VENV>` placeholders and line endings are LF; every measurement, synthetic sample, version, measured commit, timestamp and configuration field is as measured, checked by a recursive comparison of every leaf value with the originals (2026-11-02). SHA-256 of the published files:

- `scamkit-2026-10-raw-run2.json`: `74e4a315e07f21ce6c6fa5ddc291a430ae268b819f5eaebf7c29cc89e7266fd5`
- `scamkit-2026-10-raw-run3.json`: `479aa799e210f6dcf89572dc28f3108f8c7198572929085dd04f22a3237dc453`
- `scamkit-2026-10-raw.json`: `7be940f8a851a72a2c22987957e899edb81077f54cc4a68a471db4b186d30b3d`
- `scamkit-2026-10-v2-raw-run2.json`: `5b3f8e036fbdf97e95f8c649c268158ac3b79ce453525c151a9b0a9492e83f39`
- `scamkit-2026-10-v2-raw-run3.json`: `8afa515009689763c34ec5cb1cb146a411bd6ae0453109cd4abbdca315a692e8`
- `scamkit-2026-10-v2-raw.json`: `c39f72bd860c1037f589e67e1ca1b55075585a5ce93efe99e701c044be6f21d7`

**Measurement history.** The data package was opened 2026-10-25 and the measurement completed the same day after the author corrected the method (strict tier as the main measure, appointment-versus-interval rule, mask-based redaction with intact / partial / removed states, regression checks, RAGLeakGuard in its own supported environment). Three independent review rounds by a different model (2026-10-25 and 2026-10-26) are folded: the one defect that touched the measurement (first-occurrence billing-cue annotation) was fixed and the affected measurements rerun as **artifact version v2**; the v1 artifacts are kept beside them, not re-measured. The review records and disposition tables stay in the private working archive. Every number in sections 2 to 4 is read from the v2 artifacts, not recalled; the principal figures were additionally traced claim-by-claim to their JSON fields by the independent review, which is what verifies them; a passing figure check is a figure check, not claim-to-field verification. **These are synthetic exposure measurements on scripted fixtures with a simulated redaction: they count what a redacted record still shows. They are not evidence that any scam succeeds, and a record that fails a tier is not thereby safe.**

**Reproducibility.** The stores are deterministic (clinic seed `20260801`, voice seed `20260914`; both generators imported unchanged from Reports #2 and #3). The scans are re-executed each run so stability is measured, not assumed. **Two environments are required**, because the Presidio configurations were measured on the Report #3 pins (spaCy 3.8.16, numpy 2.4.6) while RAGLeakGuard's own `detect` extra pins spaCy below 3.8 and numpy below 2; the script probes the RAGLeakGuard environment before scanning and **stops** if it does not satisfy those pins (pass `--allow-experimental` to run anyway, which labels the two RAGLeakGuard configurations EXPERIMENTAL in the artifact). Rerun **from the root of the RAGLeakGuard repository** (repo-relative paths; keep both venvs out of version control; Python 3.12 is required because the RAGLeakGuard package does not install on 3.13):

```bash
py -3.12 -m venv reports/tools/scamenv
reports/tools/scamenv/Scripts/python.exe -m pip install -r reports/tools/requirements-scamkit.txt
git worktree add ../RAGLeakGuard-measured 47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0
py -3.12 -m venv reports/tools/rlgenv
reports/tools/rlgenv/Scripts/python.exe -m pip install -e "../RAGLeakGuard-measured[detect]"
reports/tools/rlgenv/Scripts/python.exe -m pip install -r reports/tools/requirements-rlg.txt
reports/tools/scamenv/Scripts/python.exe reports/findings/src/scam_kit.py run4
```

The `run4` tag keeps a validation rerun from overwriting the three measured v2 artifacts (the bare command writes `scamkit-2026-10-v2-raw.json`). The worktree holds RAGLeakGuard at commit `47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0`, the commit the tables were measured at; that commit predates the research scripts, so the product is installed from the worktree rather than checked out in the working checkout. The script records the commit and dirty state it actually scanned with. On macOS substitute `python3.12 -m venv` and `.../bin/python`. Optional run tag for side-by-side runs: `... scam_kit.py run2`. A rerun writes `scamkit-2026-10-v2-raw[-<tag>].json`; the product's dependency ranges are not an exact lock, so a fresh resolver may pick other compatible versions: a rerun reproduces a supported setup, not necessarily the exact resolved versions recorded in the artifacts.

- Script: `reports/findings/src/scam_kit.py`
- Raw results, **artifact version v2, three runs kept as evidence of stability**: `reports/findings/scamkit-2026-10-v2-raw.json`, `…-run2.json`, `…-run3.json` (2026-10-26). Of 2,240 recorded paths (dictionary leaves, lists atomic), 5 vary between the three runs: the run tag and four label tallies on the US SSN element in the digits rendering (`labels_on_elements.ssn`, RAGLeakGuard configurations, `US_SSN` versus `US_BANK_NUMBER`); every kit count, element state count, per-scenario count and texture is identical in all three. Three repeats of the same deterministic fixtures show repeatability of the scan, not three independent samples
- **v1 artifacts, kept beside v2 and not re-measured**: `reports/findings/scamkit-2026-10-raw.json`, `…-run2.json`, `…-run3.json` (2026-10-25). v1 to v2 differences, checked path by path: every kit count, element state count, per-scenario count, label tally (other than the varying SSN pair) and texture is identical; the differences are the new fields only (`artifact_version`, `states_by_template`, `environment.ragleakguard_mode.gate_reasons`, `environment.ragleakguard_batches`, the extended `definitions`) plus timestamps. The billing-cue annotation fix (B2) changed no count because no configuration touched the word "bill" in any rendering (`elements.billing_cue`: 40 intact, 0 partial, 0 removed in all twelve voice store and configuration combinations, v1 and v2 alike)
- Regression checks: `reports/findings/src/test_scam_kit.py` (23 checks: repeated occurrences, partial remnants, chained and nested overlaps, tier rules, cue classification, store spans, and, added after review round 1, annotation completeness for every billing-cue occurrence (B2) and the RAGLeakGuard environment gate (B5)); run with `reports/tools/scamenv/Scripts/python.exe -m unittest reports/findings/src/test_scam_kit.py`
- RAGLeakGuard worker and its environment: `reports/findings/src/rlg_scan_worker.py`, `reports/tools/requirements-rlg.txt` (venv `reports/tools/rlgenv`, built from the package's `detect` extra). What was measured is **RAGLeakGuard 0.1.1 `detect()` from source commit `47dedfe5c6adb1134372f0f810e9a7dca4b9d8d0`** (an editable install of the local checkout, clean working tree; equivalence to the PyPI distribution was not established), with spaCy 3.7.5, numpy 1.26.4, presidio-analyzer 2.2.364 and en_core_web_sm 3.7.1, at the study threshold 0.4. The stored v2 artifacts retain a batch count and a within-configuration equality flag for each RAGLeakGuard configuration, plus one shared final environment snapshot from the last AU batch (`environment.ragleakguard_batches`, `environment.ragleakguard`). Individual batch environments and the initial gate probe were not retained. The measured code compared batches within each configuration in memory; it did not compare configurations with one another or compare their batches with the initial probe. The amended script saves the individual batch records and probe and computes whether all batches match that probe for future runs only. The existing v2 artifacts remain unchanged. The gate (`environment.ragleakguard_mode`) reads `supported` only when the probed environment satisfies the package's pins. This is the tested configuration, not a claim about every installation or about the production CLI's own redaction behaviour
- Environment: `reports/tools/requirements-scamkit.txt` (venv at `reports/tools/scamenv`); the RAGLeakGuard commit measured is recorded in each artifact under `environment.ragleakguard`
- Number discipline: every figure in this file was matched to the artifact fields by the series' figure checker (`check_numbers.py --issue 2026-10`, kept in the private planning repository) before publication

---

## 1. What we measure (method corrected and authorised by Belle, 2026-10-25)

**The question.** A convincing fake invoice needs the victim's name, a contact channel to deliver it, the provider it pretends to come from, and a credibility detail, a date or an amount. How many records in an AI knowledge base hold that whole kit? And, the part that is not by construction: if the operator runs the standard PII scan and redacts what it flags, how much of the kit is still there afterwards?

**The stores.** The 2,000-record synthetic Australian dental-clinic knowledge base of Report #2 (free-text clinical notes, each with name, DOB, phone, email, Medicare number, address, the complaint and a plan line) and the 200 synthetic receptionist calls of Report #3 (a mixed cohort: 100 Australian and 100 US synthetic patients from the Synthea roster) in their three scripted text renderings (formatted, digits, spoken). No real data anywhere. "Service" below means the clinical or service **context** span (the complaint or condition the visit is about; in the clinic notes sometimes a proposed treatment rather than a delivered service), not an established billable service.

**The kit, three tiers, counted per record:**

| Tier | Definition | Why this tier |
|---|---|---|
| **Deliverable** | name intact AND at least one contact channel (phone, email or postal address) intact | a letter can be addressed and sent |
| **Core, strict (the main measure)** | deliverable AND provider AND (a particular appointment or date cue OR an amount) | Belle's definition. Appointment cues that qualify: the voice slot ("Tuesday 10:15" and the four others) and the clinic plan line "next Tuesday". A service interval ("six-month scale and clean", "a review in three months") does **not** qualify. **No synthetic record carries an amount**, so the tier turns on the appointment cue |
| **Core, broad** | deliverable AND provider AND any credibility detail (appointment cue, service interval, billing cue such as "payment plan", the clinical/service context, or a billing identifier: Medicare, SSN, insurance ID) | what a scammer could cite |

**Disclosed:** in the clinic store the provider is **assumed from the database context** (one clinic's knowledge base); it is not a text span and can never be redacted, so every clinic kit count in this file is **record-plus-context exposure**, not a kit literally contained in the note. In the voice store the clinic name is spoken by the agent in every call and is a text span. The date of birth is counted as an identifier (a verification cue), not as the kit's date cue.

**The redaction.** Four scanner configurations: Microsoft Presidio stock defaults; Presidio with its optional AU recognisers switched on (both exactly as Report #3 built them, large spaCy model); RAGLeakGuard default; RAGLeakGuard with `--locale au` (small spaCy model, as the tool installs). The RAGLeakGuard pair is `detect()` from source commit `47dedfe` run inside its own environment built from the package's `detect` extra (the gate in the reproducibility section); the tables describe that tested configuration, not every installation. Redaction is a **character mask**: the union of every finding at or above the actionable score (0.4), whatever its label, so overlapping and nested detections are handled once and the same way for the counts and for the redacted texture. Each **complete occurrence** of an element is *visible* (no character covered), *partial* (some covered) or *removed* (all covered). An element is **intact** if any occurrence is visible, **partial** if none is visible but one is partly visible, **removed** otherwise. Only *intact* counts as surviving in the tiers; partial remnants are reported separately. Generous to the tool: a Medicare number flagged as a phone number counts as redacted; a first name repeated elsewhere, or a name visible inside an email local-part, is not counted as a surviving name. Codex's review of the first draft found that repeated occurrences and chained overlapping detections were counted inconsistently; the mask fixes both and `test_scam_kit.py` pins the behaviour.

**What gets reported.** Per store and per configuration: records still deliverable after redaction, records still holding each kit tier, which elements survived (name, phone, email, address, DOB, Medicare, appointment and interval cues, service context, billing cue), what label the tool put on each element it did touch, and verbatim redacted texts as texture. The by-construction counts (how many records hold a kit before any redaction) are reported as descriptive only, as Report #3 did.

## 2. Raw results, by construction (descriptive, scripted)

What each record holds before any redaction. These counts are decided by the generators' templates and by our cue lists, so they are **descriptive only** and no headline may be built on them.

| Store | Records | Deliverable | Core, strict | Core, broad | Appointment cue present | Interval cue present | Billing cue present |
|---|---|---|---|---|---|---|---|
| Clinic notes | 2,000 | 2,000 | **357** | 2,000 | 357 ("next Tuesday") | 478 | 648 |
| Voice calls, each rendering | 200 | 200 | **80** | 200 | 80 (the slot, in the booking and reschedule scenarios: 40 + 40) | 0 | 40 (the billing scenario) |

Every clinic note carries name, phone, email, address, DOB and Medicare number (2,000 each). Every call carries name, phone and DOB (200 each); 120 carry an email, 80 an address, 40 a Medicare number, 19 an SSN, 21 an insurance ID. The provider is present in all records (clinic: by database context). Amounts: none, anywhere. In v2 every whole-word occurrence of "bill" in the 40 billing calls is annotated (four per call; v1 annotated only the first, review B2).

## 3. Raw results, the clinic store after redaction (2,000 synthetic notes)

**Kits still complete after redaction.** The strict tier can only survive in the 357 records that hold an appointment cue.

| Configuration | Deliverable (name + a contact) | Core, strict (of 357 possible) | Core, broad |
|---|---|---|---|
| Presidio stock defaults | **1** / 2,000 | **0** / 357 | 1 |
| Presidio, AU recognisers on | 1 / 2,000 | 0 / 357 | 1 |
| RAGLeakGuard default (source commit `47dedfe`) | **80** / 2,000 | **13** / 357 | 80 |
| RAGLeakGuard `--locale au` | 80 / 2,000 | 13 / 357 | 80 |

Clinic counts assume the provider is known from database context (§1); a complete kit here means a complete kit *given* that context. Simulated redaction at threshold 0.4 on the generated note text.

**Element by element (intact / partial / removed, of 2,000 unless stated).**

| Element | Presidio default | Presidio AU on | RAGLeakGuard (both configurations) |
|---|---|---|---|
| Name | 12 / 27 / 1,961 | 12 / 27 / 1,961 | **359 / 30 / 1,611** |
| Phone (04xx) | 0 / 0 / 2,000 | 0 / 0 / 2,000 | 0 / 0 / 2,000 |
| Email | 0 / 0 / 2,000 | 0 / 0 / 2,000 | 0 / 0 / 2,000 |
| Address | 327 / 1,673 / 0 | 327 / 1,673 / 0 | 462 / 1,538 / 0 |
| Date of birth | 0 / 0 / 2,000 | 0 / 0 / 2,000 | 0 / 0 / 2,000 |
| **Medicare number** | **221 / 155 / 1,624** | **0 / 0 / 2,000** | **390 / 0 / 1,610** |
| Any contact channel intact | 327 | 327 | 462 |
| Provider (database context) | 2,000 intact | 2,000 intact | 2,000 intact |
| Clinical/service context | 1,601 / 399 / 0 | 1,601 / 399 / 0 | 2,000 / 0 / 0 |
| Appointment cue "next Tuesday" (of 357) | 0 / 0 / 357 | 0 / 0 / 357 | **357 / 0 / 0** |
| Interval cue (of 478) | 0 / 307 / 171 | 0 / 307 / 171 | 478 / 0 / 0 |
| Billing cue (of 648) | 648 / 0 / 0 | 648 / 0 / 0 | 648 / 0 / 0 |
| Records in which every **present, annotated** credibility element is intact | 1,071 | 1,071 | **2,000** |

**What the tools called things** (labels of actionable findings overlapping each element; artifact field `labels_on_elements`): Presidio default caught every 04xx phone as `PHONE_NUMBER` (2,000) and every email as `EMAIL_ADDRESS` (2,000, with `URL` also firing on the domain); its actionable findings overlapping the annotated Medicare spans carried the labels `PHONE_NUMBER` (1,610 overlaps), `DATE_TIME` (902) and `PERSON` (3); these are overlap counts, not disjoint records, and they are why 221 numbers stayed intact and 155 were only partly covered. With the AU recognisers on, `AU_MEDICARE` fired on all 2,000. RAGLeakGuard's only label on the Medicare spans was `PHONE_NUMBER` (1,610 overlaps); its own `AU_MEDICARE` pattern did not fire on this fixture's spaced format ("4655 04518 5"). RAGLeakGuard's `--locale au` changed the phone label from `PHONE_NUMBER` to `AU_PHONE` (2,000 each) and changed no count; on this fixture the AU pack altered labels, not coverage.

**Why the credibility elements survive, per configuration:** RAGLeakGuard's precision filter drops `DATE_TIME` findings that do not look like a numeric date, so "next Tuesday" (357 of 357) and the interval cues (478 of 478) are never redacted and no service span is touched (2,000 of 2,000). Presidio's date recogniser removes "next Tuesday" in all 357 notes, touches the interval cue in all 478, and partly covers the service span in 399 notes: those 399 are exactly the two complaint templates that contain a time word, "attended for a six-month scale and clean" (207 notes, all partial) and "reported grinding at night, discussed a splint" (192 notes, all partial), both flagged as `DATE_TIME`; the other eight templates are intact in every note (v2 artifacts, field `states_by_template.service`; the independent review's own spot check found the same two). None of the four tested configurations carries a recogniser for a provider name, a complaint or a billing cue. That is a statement about these four configurations on this fixture, not about PII scanners in general, and clinical context tied to a named person is personal information whether or not a recogniser targets it.

**Identifier elements still intact per record (of the 6 present):** Presidio default: 0 of 6 in 1,476 records, 1 in 488, 2 in 36. RAGLeakGuard: 0 in 1,020, 1 in 761, 2 in 207, 3 in 12.

**Texture (`PT-00049`, the Report #2 synthetic patient; the full stored record, rewrapped for display; from `texture.presidio_default` and `texture.rlg_au`).** Presidio default:

```
Patient <PERSON> (DOB <DATE_TIME>, Medicare <PHONE_NUMBER>) reported pain on biting, suspected
cracked cusp. Contact <PHONE_NUMBER> or <EMAIL_ADDRESS|URL>. Address on file: 157 High St,
Norwood SA 5067. Declined treatment on cost grounds; note for follow-up call.
```

The Medicare number went because the tool thought it was a phone number (score 0.4, the actionable floor). The address, the complaint and the billing cue stayed. RAGLeakGuard `--locale au` on the same note: identical shape, `<AU_PHONE>` for the mobile, the Medicare number again removed as `<PHONE_NUMBER>` at 0.4, the address again intact.

## 4. Raw results, the voice store after redaction (200 synthetic calls, three renderings)

**Kits still complete after redaction.** The strict tier can only survive in the 80 calls that carry an appointment slot.

| Rendering | Configuration | Deliverable | Core, strict (of 80) | Core, broad |
|---|---|---|---|---|
| formatted | Presidio default / AU on | **0** / 200 | 0 / 80 | 0 |
| formatted | RAGLeakGuard (both) | 1 / 200 | 0 / 80 | 1 |
| digits | Presidio default / AU on | **24** / 200 | 0 / 80 | 24 |
| digits | RAGLeakGuard (both) | **82** / 200 | **12** / 80 | 82 |
| spoken | Presidio default / AU on | **42** / 200 | **0** / 80 | 42 |
| spoken | RAGLeakGuard (both) | **156** / 200 | **60** / 80 | 156 |

Per scenario, strict kits after redaction (RAGLeakGuard, spoken rendering): booking 24 of 40, reschedule 36 of 40; Presidio: 0 in every scenario and rendering, because its date recogniser removed or partly covered every slot ("tuesday 1015" as `DATE_TIME`: 45 removed, 35 partial, 0 intact in the spoken rendering).

**Element by element, spoken rendering (intact / partial / removed).**

| Element (present) | Presidio default and AU on (identical) | RAGLeakGuard (both configurations) |
|---|---|---|
| Name (200) | 50 / 20 / 130 | **156 / 10 / 34** |
| Phone (200) | **134 / 66 / 0** | **200 / 0 / 0** |
| Email (120) | 44 / 76 / 0 | 106 / 14 / 0 |
| Address (80) | 20 / 60 / 0 | 51 / 29 / 0 |
| Date of birth (200) | 12 / 60 / 128 | 25 / 39 / 136 |
| Medicare (40) | 20 / 20 / 0 | **40 / 0 / 0** |
| SSN (19) | 0 / 19 / 0 | **19 / 0 / 0** |
| Insurance ID (21) | 14 / 7 / 0 | **21 / 0 / 0** |
| Appointment slot (80) | 0 / 35 / 45 | **80 / 0 / 0** |
| Any contact channel intact | 150 | 200 |
| Provider (spoken clinic name, 200) | 200 intact | 200 intact |

The spoken phone numbers were never recognised as phone numbers by any configuration: Presidio's only labels on them were `DATE_TIME` (66 overlaps, the Report #3 result again); RAGLeakGuard put no label on them at all. Neither configuration touched a spoken Medicare number, SSN or insurance ID except Presidio's `DATE_TIME` guesses: 20 overlaps on Medicare spans (20 partial elements), 19 on SSN spans (19 partial) and 8 on insurance IDs (7 partial elements). Overlaps and elements are different counts.

**Formatted rendering** (the shape a transcript has with smart formatting on): Presidio removed 186 of 200 names, every phone (200) and every email (120), 187 of 200 dates of birth; it left the 17 insurance IDs intact and only 6 of 80 addresses fully intact. RAGLeakGuard removed 182 names, 183 phones (17 partial), every email, 193 dates of birth, and left all 80 appointment slots intact (its date filter again). **Digits rendering:** Presidio left 59 of 120 emails intact and 51 names intact; RAGLeakGuard left 159 names and 199 of 200 dates of birth intact. The email survives because the generator verbalises it ("kirk dot reinger34 at bigpond dot com" in the digits rendering, "kirk dot reinger three four at bigpond dot com" in the spoken one), a shape the email recogniser does not match. Note also that the appointment slot stays a digit string in both lowercase renderings ("monday 315"); the generator does not spell times out. The three renderings are scripted text shapes that change several properties at once (casing, punctuation, number words), not a controlled experiment on one speech-to-text setting.

**Texture (`CALL-004`, the billing call, spoken rendering; an excerpt of the stored record, rewrapped, opening and closing turns omitted; `texture.presidio_default`).** Presidio default:

```
caller i got a bill i dont understand noella <LOCATION> <DATE_TIME>
agent ill look that up can you confirm your medicare number
caller six five four two six four two nine zero two and the address on the bill is wrong it
should be <DATE_TIME> given tce newtown nsw two oh four two
agent updated what was the bill for
caller the visit about my high blood pressure im on atenolol now send the corrected bill to
noella dot <LOCATION> <DATE_TIME> at hotmail dot com and ring me on oh four six three one five
nine eight five four if theres a problem
```

The surname was flagged as a `LOCATION`, the house number and the digits in the email as `DATE_TIME`; the Medicare number, the callback number, the suburb, the condition, the medication and the bill itself stayed. The name is *partial* here (first name visible, surname covered), so this call does **not** count as deliverable; it counts in the 20 partial names. RAGLeakGuard `--locale au` on the same call (`texture.rlg_au`) removed `noella hermiston` as `<PERSON>`, partly covered the spoken date of birth (`DATE_TIME` over "january nineteen ninety five") and the surname inside the spoken email address (`LOCATION`), and left the Medicare number, the callback number, the address, the condition, the medication and the bill as spoken (states: name removed; date of birth and email partial; phone, address, Medicare, provider, service context and billing cue intact).

## 6. Public statistics, the context (primary-source verified, access date 2026-10-25)

Research pass by a sweep agent on 2026-10-25; the load-bearing figures below were **re-read by this session in the downloaded primary documents the same day** (the IC3 PDF text, the OAIC spreadsheet cells, the Targeting Scams PDF text, the ASD fact sheet). `[STRONG]` means read at the primary source. Every figure is quoted as printed; percentages marked "computed" are ours.

### 6.1 Australia: National Anti-Scam Centre, *Targeting scams: report of the National Anti-Scam Centre on scams data and activity 2025* (March 2026)

PDF: https://www.scamwatch.gov.au/system/files/targeting-scams-report-2025.pdf (landing page states "Published 30 March 2026"). Combined data = Scamwatch + ReportCyber + AFCX + IDCARE + ASIC, de-duplicated; calendar year 2025.

| Figure | As printed | Where | Strength |
|---|---|---|---|
| Combined reports 2025 | "a combined total of 481,523 reports" | PDF p.7 | [STRONG] |
| Reports with a loss | "Of these 274,577 reported financial losses" | PDF p.7 | [STRONG] |
| Combined losses 2025 | "over $2.18 billion (a slight increase of 7.8%)" | PDF p.7 | [STRONG] |
| Peak comparison | "a reduction in reported scam losses of 29.7 per cent since the peak of $3.1 billion in 2022" | ACCC media release, 30 March 2026, https://www.accc.gov.au/media-release/continued-action-critical-to-combat-fraud-as-annual-scam-losses-exceed-2-billion | [STRONG, agent read] |
| Phishing, combined loss | $97.6m in 2025, up 15.5% from $84.5m | Table 3, PDF p.8 | [STRONG] |
| Payment redirection (business email compromise, the fake-invoice redirection), combined loss | $166.8m in 2025, up 9.3% from $152.6m | Table 3, PDF p.8 | [STRONG] |
| Phishing, Scamwatch reports | "Scamwatch received 65,361 reports about phishing scams, a decrease of 33.2% compared to 2024. Despite being the most reported scam only 2.3% of people reporting phishing scams reported a financial loss." | PDF p.36 | [STRONG] |
| Identity theft reports | "Identity theft reports increased by 13.1%." | PDF p.33 | [STRONG] |
| False billing (Scamwatch) | In the top five categories both by reports with a loss (Figure 3) and by overall loss (Figure 4); **the totals are printed only inside chart images, not as text**, so the report quotes no false-billing total for 2025 | PDF p.37 | [STRONG for position; total NOT FOUND in text] |
| Small business | "Small businesses lodged 2,228 reports to Scamwatch in 2025, with 287 reporting financial loss amounting to $9.5 million, 27.9% lower than 2024." · "False billing was the most reported scam type both with and without financial loss. False billing reports from business generally relate to 'payment redirections' also known as 'business email compromise' scams." | PDF pp.43 to 44 | [STRONG] |
| Government impersonation | "Throughout 2025, Services Australia detected and responded to over 14,000 unique agency impersonation scams and supported over 9,000 customers affected by agency impersonation scams" | PDF p.25 (content supplied by Services Australia) | [STRONG] |

**Taxonomy change (flag):** the live Scamwatch dashboard (https://www.scamwatch.gov.au/research-and-resources/scam-statistics, read in the browser pane 2026-10-25) has retired "False billing" as a category for 2025 onwards (new categories include "Payment redirection", "Takeover", "Buying and selling"); it showed 2026 year-to-date all-types "Reported losses $250,441,924.20" and "Reported scams 138,392" with **no "as at" date visible**. Any 2026 figure is not like-for-like with the 2025 report's "false billing". The report quotes the dashboard only as "read 2026-10-25, no as-at date shown".

### 6.2 United States: FBI IC3, *2025 Internet Crime Report*

PDF: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf (printed page = PDF page).

| Figure | As printed | Where | Strength |
|---|---|---|---|
| Complaints 2025 | "1,008,597 complaints" | p.6 | [STRONG] |
| Losses 2025 | "$20.877 billion in losses; 26% increase in losses from 2024" | p.6 | [STRONG] |
| Business Email Compromise | 24,768 complaints; "$3,046,598,558" | pp.7 to 8 | [STRONG] |
| Phishing/Spoofing | 191,561 complaints (the most reported type); "$215,843,126" | pp.7 to 8 | [STRONG] |
| **Personal Data Breach** | 67,456 complaints; "$1,314,923,988" (fourth by count and by loss). IC3's definition, Appendix B p.60: "A leak/spill of personal data which is released from a secure location to an untrusted environment…" | pp.7 to 8, p.60 | [STRONG] |
| Government Impersonation | 32,424 complaints; "$797,943,193" (2024: $405,624,084) | pp.7 to 8, p.26 | [STRONG] |
| AI-related descriptor | "In 2025, IC3 received more than 22,000 complaints reporting AI-related information. Adjusted losses of these complaints exceed $893 million." (displayed totals 22,364 and $893,346,472; descriptor-linked complaints, not losses attributable to any store) | p.39 (also pp.7 to 8) | [STRONG] |
| Government and law-enforcement impersonation, 2025 to mid-2026 | nearly 61,000 complaints, "more than $1.6 billion" (January 2025 to July 2026) | IC3 PSA I-091726-PSA, 17 Sep 2026, https://www.ic3.gov/PSA/2026/PSA260917 | [STRONG, agent read] |

### 6.3 United States: FTC, 2025 consumer fraud data

| Figure | As printed | Source | Strength |
|---|---|---|---|
| Fraud reports and losses 2025 | "In 2025, consumers submitted 3 million fraud reports to CSN and reported $15.9 billion in losses." | FTC prepared statement to the Joint Economic Committee, 25 March 2026, PDF p.3 (printed p.2), https://www.ftc.gov/system/files/ftc_gov/pdf/ftc-testimony-jec-hearing-on-the-rising-scam-economy.pdf | [STRONG, agent read] |
| Imposter scams 2025 | "over 1 million reports about imposter frauds, with consumers reporting over $3.5 billion in losses"; business impersonators "nearly $1 billion" (from $866 million in 2024); government impersonators "about $920 million" (from $789 million) | same, pp.3 to 4; FTC press release 15 June 2026, https://www.ftc.gov/news-events/news/press-releases/2026/06/ftc-data-show-people-reported-losing-3-point-5-billion-imposter-scams-2025 | [STRONG, agent read] |
| Consumer Sentinel Data Book 2025 | **Not found on ftc.gov as of 2026-10-25**; the latest Data Book listed there is 2024 (https://www.ftc.gov/system/files/ftc_gov/pdf/csn-annual-data-book-2024.pdf) | ftc.gov, searched 2026-10-25 | NOT FOUND in the sources searched |

### 6.4 Australia: OAIC Notifiable Data Breaches, the latest periods

The January to June 2026 statistics were **not found as of 2026-10-25** on the OAIC dashboard page (dated 2025-11-04, which still says updates are "forthcoming"), the OAIC publications page or data.gov.au; this is a bounded search result, not proof of non-publication. Latest data: the OAIC spreadsheet *NDB Data 1 July 2025 to 31 Dec 2025* on data.gov.au (https://data.gov.au/data/dataset/notifiable-data-breaches-ndb-scheme; resource last modified 2026-06-29). The spreadsheet prints counts only; percentages are **computed by us** from n = 670.

Resource: https://data.gov.au/data/dataset/5781dc17-2ad0-4dd1-bced-01c544943ce3/resource/e14c521b-0966-42cf-849b-0ef1214e8903/download/ndb-data-1-july-2025-to-31-dec-2025.xlsx (sheet names and cell addresses below are from that workbook).

| Figure | As printed (sheet!cell) | Computed | Strength |
|---|---|---|---|
| Notifications Jul to Dec 2025 | "Grand Total 670" (`Individuals affected!B20`; also `NDB by month` total) | | [STRONG, cell re-read] |
| Malicious or criminal attack | 405 (`Source of breach!B13`; of which cyber incident 253, social engineering / impersonation 88, rogue employee / insider 34, theft 30, `B14:B17`) | 60.4% | [STRONG, cell re-read] |
| Human error / system fault | 194 (`Source of breach!B3`) / 35 (`B18`) | 29.0% / 5.2% | [STRONG] |
| Top sector | "Health service providers 128" (`Top 5 sectors by source!B4`; rank 1; human error 51, malicious or criminal 64, system fault 5, `B6:B9`); Finance 83 (`B10`); Business/Professional Associations 72 (`B16`); Australian Government 51 (`B21`); Personal services 47 (`B27`) | health 19.1% | [STRONG, cell re-read] |
| **Kinds of personal information involved** | "Contact information 537" · "Identity information 386" · "Financial details 253" · "Health information 228" · "Other sensitive information 161" · "Tax File Numbers 151" (`Personal information!B4:B9`) | 80.1% · 57.6% · 37.8% · 34.0% · 24.0% · 22.5% | [STRONG, cells re-read] |
| Calendar 2025 | "1,205" notifications, "an 8% increase over 2024 (1,112 notifications)"; malicious or criminal 716; health "225 notifications (19% of the total)", ranked first | | OAIC media release, 6 July 2026, https://www.oaic.gov.au/news/media-centre/data-breach-notifications-increase-to-all-time-high-in-2025,-new-ndb-stats-show [STRONG, agent read] |
| Jan to Jun 2025 | "532 data breach notifications"; malicious or criminal "59%, at 308 notifications"; health "18%" | | OAIC blog, 4 Nov 2025 [STRONG, agent read] |

**Not exhaustive decompositions:** the three source categories 405 + 194 + 35 = 634 leave 36 notifications in the workbook's "currently unknown" and "other" categories; the health sector's 51 + 64 + 5 leaves 8 in those categories. Quote the subsets as subsets.

**Contradiction flag:** 532 + 670 = 1,202, not 1,205 (and 308 + 405 = 713, not 716). A likely explanation is revision after publication, which we have not confirmed from any OAIC revision log; quote each period from its own release and never add them.

The line that matters for this issue: **contact information was involved in 537 of 670 breaches (80.1%, computed)**, the single most common kind. Contact information is the delivery channel of the kit.

### 6.5 The supply-chain link: official statements that breached data feeds scams

The link from a leak to a scam is an argument in this report, not a measurement. These are the official statements that carry it; **no post-breach scam-report spike figure was found in the sources searched as of 2026-10-25** (Optus, Medibank, Latitude); absence in our search is not proof that none exists.

| Statement | As printed | Source | Strength |
|---|---|---|---|
| Scamwatch, Optus breach alert (2022, still live) | "Scammers will use the data breach and target people in any way that they can. This means you will likely notice an increased number of phishing emails, phone calls, and SMS or social media messages." Data listed: name, date of birth, phone numbers, email addresses, residential addresses, identity document numbers | https://www.scamwatch.gov.au/about-us/news-and-alerts/browse-news-and-alerts/optus-data-breach-scams | [STRONG, agent read] |
| Scamwatch, Medibank breach alert (2022) | same wording; data: "Names and addresses, date so [sic] birth, Medicare numbers, policy numbers, phone numbers and some claims data" | https://www.scamwatch.gov.au/about-us/news-and-alerts/browse-news-and-alerts/medibank-private-data-breach | [STRONG, agent read] |
| IDCARE, end-2024 review | Most common sources of compromise, ranked: 1. unknown to the client; **2. data breaches**; 3. online shopping scams; 4. telephone phishing; 5. SMS phishing. "Scammers often leverage credentials from data breaches or phishing scams…" No count for the data-breach source is printed | https://www.idcare.org/latest-news/the-year-that-was-a-record-year-for-financial-losses-to-cybercrime | [STRONG, agent read; no figure] |
| ASD, Annual Cyber Threat Report 2024–25 fact sheet for individuals | "Individuals are commonly targeted by cybercriminals for financial gain. This can be through scams or through the on-selling of personally identifiable information…" · "over 84,700 cybercrime reports" · average self-reported cost for individuals "$33,000 (up 8%)" · top type "Identity fraud (30%)" | https://www.cyber.gov.au/sites/default/files/2025-10/Annual%20Cyber%20Threat%20Report%202024-25%20factsheet%20for%20individuals.pdf | [STRONG, re-read in the fact-sheet text] |
| FBI IC3 PSA, 15 May 2026 | "The compromise of sensitive customer or enterprise data could allow threat actors to craft highly sophisticated spearphishing campaigns using real-world context" | https://www.ic3.gov/PSA/2026/PSA260515 | [STRONG, agent read] |
| Scamwatch, fake business invoice alert (4 Apr 2024) | "Scammers pose as a real business you've recently dealt with. They send fake invoices with changed payment details…" · "Scammers make these invoices look real by copying business logos and ABNs" | https://www.scamwatch.gov.au/about-us/news-and-alerts/scam-alert-fake-business-invoice-scams | [STRONG, agent read] |

**Not found in the sources searched as of 2026-10-25 (the report says so; absence in our search is not proof of absence):** a 2025 or 2026 false-billing total for Australia; an as-at date on the Scamwatch dashboard; the OAIC January to June 2026 statistics; any official post-breach scam spike count; IDCARE breach-related contact counts; an Australian energy-ombudsman or toll fake-bill figure for 2025–26 (the February 2026 "Energy Ombudsman" fake-bill warning is the UK ombudsman); HHS-OIG fake-medical-bill statistics; a sourced dark-web price per health record (the often-repeated "$250 a record" and "50 times a credit card" figures are not quoted). IBM's 2026 healthcare breach-cost figure ($6.64 million) is `[SECONDARY]`, seen only in trade press; IBM's own release gives the global $4.99 million (vendor methodology).

## 7. Follow-up to Report #2 (dated note; re-checked at drafting 2026-10-26 and at publication 2026-11-02)

**Status 2026-10-25 (verified by this session through the GitHub CLI and the live docs):** Belle reported on 2026-08-31 that, in her local reproduction on ChromaDB 1.5.9, deleting 100 records left all 100 tested vectors in the HNSW index file and that `chroma vacuum` did not remove them (`chroma-core/chroma#7662`, reproducible script attached). An outside contributor, SiluPanda, reproduced the result independently within eight days and wrote documentation PR #7693. After the maintainer asked on 2026-10-12 where the "vacuum equals secure delete" expectation came from, the contributor narrowed the PR to Chroma's Delete Data page (head `f143c43`, 2026-10-13) and Belle confirmed the same day that the revised wording addresses her concern, pointing to the page's own sentence "The embeddings, documents, and metadata associated with each item will be deleted". **As of 2026-10-25 the PR is open and unmerged, there is no formal maintainer review or approval object (the only review object is the automated bot notice of 2026-09-08; the maintainer's substantive comment of 2026-10-12 is the only maintainer engagement), the contributor pinged the maintainer again on 2026-10-21, issue #7662 is open, and both `main` and the live Delete Data page still carry the original sentence.** The evidence dossier (private archive) stays labelled *proposed, unmerged*; the next capture is owed on merge or close. **Re-checked 2026-11-02 at publication through the GitHub CLI: PR #7693 still open and unmerged, last activity 2026-10-21; nothing in this section changed.**

What this does and does not establish: a documentation change, if merged, implements no erasure mechanism and validates no report claim beyond the wording it corrects; the behaviour was measured on local Chroma 1.5.9 and says nothing about newer releases, managed services or backups; there has been no Chroma release since 1.5.9 (2026-05-05). Related literature, not a rerun: Culatana and Li (arXiv:2609.19456, 2026-09-16) describe hnswlib's `mark_deleted` path, the library Chroma uses, scoring deleted vectors during traversal in general; a separate Chroma PR (#7921, 2026-10-16, closed unmerged) describes persisted HNSW data surviving *collection* deletion when the segment was evicted. Neither reproduces the Report #2 experiment, neither was audited in this cycle, and neither changes Report #2; both belong in the "what it means" guidance of this and later issues as research context, not as verification of every Report #2 claim or as findings about every platform. The full narrative is kept in the private incident tracker.

## 8. Literature and market sweep (2026-10-25), summary

Full rows with sources and strength markers are kept in the private incident tracker. Highlights for this issue:

- **CVEs:** no new advisory for Chroma, Milvus, Qdrant, Weaviate, Pinecone, LlamaIndex or LangChain was found in the window in the sources searched (GitHub Advisory DB `affects=` queries and the NVD JSON API, 2026-10-25); new pgvector High (CVE-2026-103484, 8.8, fixed 0.8.7); three LangGraph advisories including a cross-user read/update/delete (CVE-2026-104873, 7.6); the four unpatched ChromaDB 1.5.9 advisories (one rated 10.0) remain unpatched and a user issue asking for a fix (#7909) has no maintainer reply.
- **Literature:** arXiv:2609.19456 (deleted vectors still scored in HNSW traversal in general; related to Report #2's mechanism, not a rerun of it); arXiv:2610.04195 MemLeak (pooled agent memory leaks other users' memories 70 to 100% of the time); arXiv:2610.30193 (a verbatim-copy guard that cuts copying to 0.0% still lets an adaptive attacker recover 48.3% of hidden facts, the "redaction is not privacy" point this issue makes with data).
- **Regulators:** OAIC's APP 1 automated-decision transparency duty commences 2026-12-10 (resources published 2026-09-30); the Latitude investigation explicitly probes destruction and de-identification; **fourth consecutive sweep in which no FTC enforcement action involving AI systems and personal data was found in the sources searched** (not proof that none exists).
- **Incidents:** 302.ai's exposed storage bucket, as reported by Cybernews through two press reports of 2026-10-21 and 10-23 (more than 144,000 chat logs with user-typed PII, as reported; the researcher write-up itself was not opened); no exposed vector-database report found in the window.
- **Presidio mechanism, now exact:** the AU recognisers ship `enabled: false` by default since v2.2.359. This issue's Presidio-default configuration therefore has no AU Medicare, TFN, ABN or ACN recogniser loaded; the AU-on configuration adds them and an AU-aware phone recogniser.

## 9. Verification log (adversarial pass, the §3 quality gate; continues as the measurement lands)

1. *Claim (agent):* "Targeting Scams 2025: 481,523 reports, 274,577 with a loss, over $2.18 billion, up 7.8%." *Check:* grep of the PDF text extracted from the downloaded report. *Result:* CONFIRMED (each string present; title page reads "Targeting scams, Report of the National Anti-Scam Centre on scams data and activity 2025, March 2026").
2. *Claim (agent):* "Phishing $97.6m up 15.5%; payment redirection $166.8m; 65,361 phishing reports, 2.3% with loss; small business 2,228 / 287 / $9.5 million; Services Australia 14,000 / 9,000; identity theft up 13.1%." *Result:* CONFIRMED, all strings present in the PDF text.
3. *Claim (agent):* Table 6 false-billing-by-age cells. *Result:* UNCONFIRMED; the text extraction misaligns the columns. The cells stay in the working file, are not reproduced in this public copy, and the report quotes none of them.
4. *Claim (agent):* IC3 2025 figures (1,008,597; $20.877 billion; BEC $3,046,598,558; Personal Data Breach 67,456 / $1,314,923,988; Phishing $215,843,126; Government Impersonation $797,943,193; "more than 22,000 complaints reporting AI"). *Result:* CONFIRMED in the extracted PDF text.
5. *Claim (agent):* OAIC Jul to Dec 2025 counts. *Check:* the spreadsheet's cells read directly (sheets "NDB by month", "Personal information", "Source of breach", "Top 5 sectors by source"). *Result:* CONFIRMED: Grand Total 670; contact 537, identity 386, financial 253, health 228, other sensitive 161, TFN 151; malicious or criminal 405 (cyber incident 253, social engineering 88, insider 34, theft 30); health service providers 128, rank 1. Percentages computed by us.
6. *Claim (agent):* ASD fact sheet figures (84,700; $33,000; identity fraud 30%; "on-selling of personally identifiable information"). *Result:* CONFIRMED in the fact-sheet text.
7. *Claim (agent):* "Scamwatch retired False billing in its 2026 dashboard taxonomy; no as-at date shown." *Result:* NOT RE-CHECKED by this session (browser read by the agent; the Power BI embed cannot be fetched). Carry as agent-read; the page was re-opened by the drafting session on 2026-10-26.
8. *Claim (agent):* "PR #7693 open, unmerged; last activity 2026-10-21." *Result:* CONFIRMED independently by this session through `gh` before the agent reported (§7).
9. *Claim (agent):* "Vapi states 14 days raw data retention on its pricing page; the docs page no longer carries a figure." *Result:* ACCEPTED as agent-read, with the matrix's 2026-09-14 row showing the docs page did carry the figure then; recorded as a page change, not a correction (`PLATFORM-POSTURE-MATRIX.md` §3.1; the private incident tracker).
10. *Claim (first draft of this file's method):* "an element counts as redacted if any finding overlaps any part of any span." *Refute attempt (Codex, 2026-10-25, executed the functions):* repeated occurrences and chained overlapping detections were counted inconsistently with the redacted texture. *Result:* CONFIRMED, method replaced by the character mask with complete-occurrence survival and intact / partial / removed states; 17 regression checks passed on the v1 package (2026-10-25; 23 in v2); the in-run consistency assertion (every intact element's visible occurrence must appear in the redacted text) passed on every record of every configuration (artifact field `consistency_checks_passed`).
11. *Claim:* "RAGLeakGuard as shipped." *Refute attempt:* the first smoke test imported the package into scamenv, whose spaCy 3.8 and numpy 2.4 sit outside the package's `detect` pins. *Result:* NARROWED, then fixed: the three runs used a separate venv built from `pip install -e <checkout>[detect]` (spaCy 3.7.5, numpy 1.26.4, recorded in the artifact); the artifact field `environment.ragleakguard_mode.mode` reads `supported`. Had it read `EXPERIMENTAL`, the configuration would have to be labelled so.
12. *Claim:* "the three runs agree." *Check:* every path of the three artifacts compared. *Result (v1 artifacts, 2026-10-25):* 1,953 paths, 5 vary: the run tag and four label tallies on the SSN element in the digits rendering under the RAGLeakGuard configurations (`US_BANK_NUMBER` versus `US_SSN`). No kit count, element state or texture varies. Presidio's scoring did not vary at all, as in Report #3. (v2, 2026-10-26: 2,240 paths, the same 5 vary; see the reproducibility bullet.)
13. *Claim (candidate B):* "376 of 2,000 Medicare numbers at least partly visible." *Check:* 221 intact + 155 partial from `scan.clinic.presidio_default.elements.medicare`. *Result:* CONFIRMED as a sum of two artifact fields; quote both components beside the sum.
14. *Claim (candidate A):* "156 of 200 spoken calls still deliverable under the OSS tool." *Refute attempt:* is "deliverable" inflated by first names or email local-parts? *Result:* NO; only complete full-name occurrences count, and a call whose surname was covered counts as partial (20 such under Presidio, 10 under RAGLeakGuard in the spoken rendering, excluded from deliverable).
15. **Independent review round 1 (Codex, 2026-10-25) folded 2026-10-26.** 4 blockers (B4 reproduction recipe, E1 candidate A tool switch, E3 candidate C overreach, F1 causal drafting sentence) and 13 should-fix items; every correction and its validation is recorded in the disposition table in the private working archive. The one finding that touched the measurement, B2 (first-occurrence billing-cue annotation), was fixed in `scam_kit.py`, pinned by two new regression checks, and the measurement rerun as v2; the v1 to v2 comparison above shows no kit, state, scenario or texture count changed. The review's §A ledger traced every principal figure in §2 to §4 to its JSON field; those fields are unchanged in v2. Round 2 (2026-10-26) closed 13 of 17 and listed eight remaining items, folded the same day; round 3 (2026-10-26) confirmed six closed and supplied verbatim wording for the last two (candidate C's title and one body sentence; the environment-recording description), applied as written.
16. **Whole-file numbers audit:** `check_numbers.py --issue 2026-10` passes on this file (v2 artifacts; result in the commit message). What that proves is bounded: the checker matches numeric values against compatible artifact fields and skips several token classes; it does not bind a sentence to the right store, tool, state or denominator, and `--trace` lists unmatched figures (citations, versions, derived sums) without failing. The claim-to-field verification of the principal figures is the independent review's §A ledger (round 1), not the checker.
17. **Publication export (2026-11-02).** The six raw artifacts were published as metadata-redacted copies: two environment fields that held machine-local paths (`environment.ragleakguard_mode.python`, `environment.ragleakguard.venv`) were replaced by `<LOCAL_VENV>` placeholders, line endings normalised to LF, nothing else changed; a recursive comparison of every leaf value between each original and its copy found no other difference, and the originals were not modified. SHA-256 of originals and exports are in the private publication record; the exported checksums are listed in the header of this copy. This copy is derived from the working file after the three review rounds; the rounds reviewed the working file and the report, not this derived copy.

## 10. Method caveats (draft; write these into "How we measured")

1. **Synthetic and scripted.** Both stores are templated; which kit elements a record holds is decided by the generators (and by our cue lists), so the by-construction counts in §2 are descriptive only. The redaction results depend on the *shape* of the identifiers and of the surrounding text, and the shapes are real-world formats.
2. **The kit definition is ours.** No regulator or vendor defines a "scam kit"; the three tiers are stated in §1 so a reader can disagree with the definition and still use the numbers. The strict tier turns on a date cue because no synthetic record carries an amount.
3. **Generous to the tool, on a literal-span endpoint.** Any actionable finding, whatever its label, counts as redaction; an element survives only when a complete annotated occurrence is untouched, and a partly covered occurrence is reported as *partial*, never as surviving; a first name repeated elsewhere, or a name visible inside an email local-part, is not counted as a surviving name. The other direction follows: partial strings, complementary fragments across occurrences and a reconstructable email name could still help a reader, so a zero strict-kit result means "no intact annotated strict combination remained under this definition", not anonymity, not that the person cannot be contacted, and not that no useful scam material remains.
4. **Model sizes and versions differ by design.** Presidio's default configuration loads `en_core_web_lg` on spaCy 3.8.16; RAGLeakGuard ships on `en_core_web_sm` and ran in its own environment (spaCy 3.7.5, numpy 1.26.4, the package's `detect` pins), as `detect()` from source commit `47dedfe`, an editable local install rather than a PyPI download. The comparison is "what each tool does in its tested configuration", not a model-size experiment: model and version differences may contribute to the name and address columns, the experiment does not isolate their contribution, and the Medicare and date columns reflect recogniser and post-processing differences that the stored labels do show.
5. **One threshold.** 0.4 is the actionable tier the series has used since Report #1. The raw artifacts keep the labels but not every sub-threshold score.
6. **No retrieval, no deletion, no audio in this cycle.** The stores are scanned as text. Nothing here measures how an attacker obtains the store; that is the premise of Reports #1 to #3 and the CVE table, not a result.
7. **The leak-to-scam link is an argument** supported by the official statements in §6.5, not a measurement; no post-breach scam-spike figure was found in the sources searched as of 2026-10-25. The report says this plainly.
8. **Public statistics are dated** (access 2026-10-25) and taxonomies move: Scamwatch has retired "false billing" for 2025 onwards; the OAIC half-year and full-year totals differ (revision is a likely but unconfirmed explanation); FTC 2025 figures were found only in testimony and a press release, no 2025 Data Book was found on ftc.gov.
9. **Contact identifiers in both stores are fabricated, not reserved** (Report #3 caveat 11 applies); the voice roster is Synthea-derived (100 AU and 100 US synthetic patients). The code and committed roster support "synthetic fixtures, no live dataset"; they cannot prove that no fabricated email, address or phone number happens to belong to a real person, so the fixtures are never to be contacted or distributed without this caveat.
10. **Scripted renderings, not speech-to-text settings.** The digits and spoken renderings verbalise emails ("kirk dot reinger34 at bigpond dot com"), keep appointment times as digit strings ("monday 315") and change casing and punctuation at the same time; no audio was transcribed. Results per rendering are comparisons of text shapes, not of one vendor setting.
11. **Appointment cue, not a verified appointment date.** "Next Tuesday" and "Tuesday 10:15" are relative or partial cues inside scripted text, and no record carries an amount; `element_state` treats amounts as absent by construction, so the script is not a general invoice-amount detector.
12. **Clinic kits are record-plus-context.** The provider is assumed from database context in every clinic count (§1); the clinic strict and broad tiers therefore state what a reader with access to one clinic's knowledge base could assemble, not what one note contains on its own.
