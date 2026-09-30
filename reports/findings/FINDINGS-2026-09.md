# Findings package, September 2026 · The AI Data Security Report, Issue #3

**Public copy.** This is the data package behind Issue #3, published beside the report so every figure can be checked. It is a cleaned copy of the working findings file: the measurements, the audit summary, the literature sweep, the verification log and the method caveats are unchanged. Three working sections are left out because they are editorial planning, not evidence (candidate headlines, the backlog hand-off and the drafting pointers), and so is the market-context block that the report does not use. Section numbers are kept as in the working file, so sections 7, 11 and 12 are absent on purpose. Everything below is measured or primary-sourced. All patient data is synthetic.

**Reproducibility.** Deterministic seed `20260914`: the roster and every transcript are byte-identical on every run; the scan and the memory lookups are re-executed each run so stability is measured, not assumed (section 10, caveat 9). Rerun from the repository root:

```bash
python -m venv reports/tools/voiceenv
reports/tools/voiceenv/Scripts/python.exe -m pip install -r reports/tools/requirements-voice.txt
reports/tools/voiceenv/Scripts/python.exe reports/findings/src/voice_transcripts.py
```

On macOS substitute `reports/tools/voiceenv/bin/python`. Published with this file: the script, the Synthea-derived roster, the pinned environment file, the raw results of three runs and the Platform Posture Matrix. Measured on presidio-analyzer 2.2.364 with its default model en_core_web_lg, spaCy 3.8.16, chromadb 1.5.9, Python 3.13.5, Windows.

**Update, 1 October 2026.** Vapi's call-recording page no longer states the pay-as-you-go retention periods recorded in section 6 on 14 September. The section 6 row is kept as the dated reading; the matrix carries both rows; the report uses no Vapi retention period outside its platform table.

---

## 1. What we measured

Three legs, per REPORT-ENGINE §2 row 3 and the spine note.

**Leg 1, the transcript store (own scan).** 200 synthetic patients, 100 Australian and 100 US, built from the **Synthea** synthetic-patient dataset (MITRE): names, dates of birth, active conditions and current medications come from Synthea's tables; allergies come from Synthea where the patient has one recorded, and a scripted penicillin allergy is substituted where the roster has none (62 of the 80 allergy mentions are that substitute); phone numbers, emails, addresses (AU cohort), Medicare numbers (valid check digit) and insurance member IDs are fabricated; Synthea's own 999-prefixed SSNs are kept for the US cohort. Each patient makes **one inbound call to an AI receptionist**: booking, repeat prescription, results follow-up, reschedule or billing (40 of each). The caller gives what real callers give: name, date of birth, a number to call back, and then the reason, which means a condition, a medication, sometimes an allergy, a relative's name, the GP's name, an email, an address, a Medicare or insurance number.

Each call is rendered in **three scripted text shapes, inspired by documented speech-to-text behaviours** (no audio was transcribed; the posture matrix, §6, shows number formatting is a vendor setting the builder rarely sees). The renderings change several text properties at once (casing, punctuation, names, dates, email surfaces and numbers), so a difference between two renderings is a difference between two text shapes, not the isolated effect of one vendor switch:

| Rendering | What it models | Example of a phone number | Words in the 200 transcripts |
|---|---|---|---|
| **formatted** | smart formatting ON: casing, punctuation, digits (AssemblyAI default, Azure always) | `0454 955 980` | 23,448 |
| **digits** | numerals ON, formatting OFF: lowercase, concatenated digit runs (inspired by Deepgram `numerals=true`; the vendor's own example keeps spaces between digits, `5 5 5 2 1 2 4 3 9 4`, so our concatenated run is more favourable to number-pattern recognisers) | `0454955980` | 23,702 |
| **spoken** | formatting OFF: lowercase, no punctuation, numbers as words (inspired by Deepgram's default, `smart_format` and `numerals` both `false`; our rendering also lowercases sentence-initial capitals, which the vendor's numerals example keeps, so it is less favourable to case-sensitive name recognition; a few numerals survive as text, such as `b12` and the appointment time `315`) | `oh four five four nine five five nine eight oh` | 27,469 |

Every transcript is then scanned with **Microsoft Presidio**, the standard PII engine, in two configurations carried over from Report #1: stock defaults, and defaults plus Presidio's own optional AU recognisers. Ground truth is 1,120 identity items (200 names, 200 dates of birth, 200 phones, 120 emails, 80 addresses, 40 Medicare, 19 SSN, 21 insurance IDs, 120 GP names, 120 relatives' names) and **440 health items** (200 conditions, 160 medications, 80 allergies).

**Scoring, three tiers, generous to the tool.** An item is *caught* if any finding of any label overlaps its span (a Medicare number flagged as a phone counts). Reported at **any confidence**, **actionable** (score ≥ 0.4, the two-tier rule from cycle #1), and a third tier new this cycle, **correct label** (at least one actionable finding whose label is on the accepted list for that kind overlaps the annotated item), because in the spoken rendering the first two tiers count date-guesses as catches. Partial overlap counts at every tier, so a city inside an address earns full address credit: the tiers measure whether the tool touched and labelled the item, not whether the whole span would be redacted. Insurance member IDs and the three health kinds have no accepted label, so they can only score zero at the correct-label tier. Published numbers use the actionable tier unless the sentence says otherwise.

**Leg 2, the call memory (own scan).** The 200 formatted transcripts loaded into a persistent Chroma collection with the default embedding function and queried with an unfiltered semantic query, the query shape Chroma's own getting-started page demonstrates (it does not recommend identifying callers this way; the design is ours). The collection stores only `region` as metadata, so no phone or name filter was possible in this design. Then the memory is asked who is calling, by phone number, by name, and by name plus date of birth.

**Leg 3, the retention-defaults audit (documentation, primary source).** Five voice-agent platforms (Vapi, Retell AI, Bland AI, ElevenLabs Agents, Synthflow), the telephony layer (Twilio), an STT vendor (Deepgram) and two LLM providers (OpenAI, Anthropic), read from their own docs on 2026-09-14, load-bearing cells re-fetched independently the same day. Full matrix in `PLATFORM-POSTURE-MATRIX.md`; summary in §6.

## 2. Raw results, the scan (Presidio stock defaults)

**Identity items, 1,120 per rendering.**

| Rendering | Caught, any confidence | Caught, actionable | Caught with the correct label | Calls with at least one identity item missed (actionable) |
|---|---|---|---|---|
| formatted | 1,065 / 1,120 (95.1%) | 1,065 (95.1%) | 1,010 (90.2%) | **49 / 200** |
| digits | 920 (82.1%) | 917 (81.9%) | 789 (70.4%) | **132 / 200** |
| spoken | 784 (70.0%) | 784 (70.0%) | 568 (50.7%) | **172 / 200** |

**The numeric identifiers are where the transcript shape decides everything** (phone, Medicare, SSN, insurance; 280 items):

| Rendering | Caught, actionable | Recognised as what they are |
|---|---|---|
| formatted | 260 / 280 | 219 / 280 |
| digits | 259 / 280 | 219 / 280 |
| spoken | 112 / 280 | **0 / 280** |

Per kind, stock defaults, written as any / actionable / correct-label:

| Item | n | formatted | digits | spoken | What the spoken-form "catches" were |
|---|---|---|---|---|---|
| Phone number | 200 | 200 / 200 / 200 | 200 / 200 / 200 | **66 / 66 / 0** | all 66 labelled `DATE_TIME` |
| Medicare number | 40 | 37 / 37 / 0 | 40 / 37 / 0 | 20 / 20 / 0 | 20 × `DATE_TIME`; formatted ones were caught as `PHONE_NUMBER` (31) or `DATE_TIME` (30), never as Medicare |
| SSN | 19 | 19 / 19 / 19 | 19 / 19 / 19 | 19 / 19 / 0 | 19 × `DATE_TIME` |
| Insurance member ID | 21 | 4 / 4 / 0 | 3 / 3 / 0 | 7 / 7 / 0 | no recogniser exists; stray `DATE_TIME` overlaps |
| Email | 120 | 120 / 120 / 120 | 61 / 61 / 0 | 76 / 76 / 0 | "kirk dot reinger" flagged as a `PERSON` |
| Date of birth | 200 | 200 / 200 / 200 | 191 / 191 / 190 | 188 / 188 / 186 | spaCy reads "the twenty sixth of november nineteen forty seven" as a date; this one survives |
| Caller's name | 200 | 187 / 187 / 183 | 149 / 149 / 142 | 150 / 150 / 143 | both lowercase renderings sit near 150 against 187 formatted; the renderings differ in more than casing, so no single cause is isolated |
| Relative's name | 120 | 112 / 112 / 110 | 82 / 82 / 79 | 82 / 82 / 79 | same pattern, same limit |
| GP's name | 120 | 112 / 112 / 112 | 116 / 116 / 116 | 116 / 116 / 116 | "dr lucio" is a PERSON either way |
| Address | 80 | 74 / 74 / 66 | 59 / 59 / 43 | 60 / 60 / 44 | |

**Presidio's optional AU pack (the Report #1 switch) improves correct-label recall for one kind here:** formatted and digit-run Medicare numbers go from 0 to 40 of 40 correctly labelled (and from 37 to 40 caught). Spoken-form Medicare stays 20 / 20 / 0. The pack is not otherwise neutral: it adds two mislabelled catches on formatted insurance IDs (4 → 6 caught, the new overlaps labelled `AU_TFN` and `AU_ACN`, still 0 correct) and changes several label-overlap counts in the digits rendering without moving a tally (nine phone numbers also overlapped by `AU_MEDICARE`, one SSN by `AU_TFN` and `AU_ACN`, one more DOB by `PHONE_NUMBER`). Spoken rows are identical. The AU engine also widens the phone recogniser's region list to include AU, so "AU on" is five recognisers changed, not four. Identity totals with AU on: 1,070 / 920 / 784 caught at actionable confidence; calls with a miss 46 / 132 / 172. The switch that saved Report #1 does not save a transcript.

**Off-target findings, for the credibility section.** Actionable findings that fall outside our annotated spans: 450 (formatted), 388 (digits), 388 (spoken). This is not a measured false-positive count: the agent repeats the caller's first name, unannotated, in 40 calls, so a legitimate `PERSON` hit there counts as off-target, and no per-label histogram of the off-target set was saved. The texture samples show `DATE_TIME` on "today" and "Monday", `URL` on email fragments and `PERSON` on the repeated first name; a histogram is a Week-2 rerun item if the draft needs one.

**Texture (verbatim from the run).** Call `CALL-001`, a US repeat-prescription call, formatted rendering, ground truth includes SSN `999-87-7767` and phone `(617) 782-1563`; both caught at 0.85 and 0.75. The same call in spoken rendering:

```
truth : ssn 'nine nine nine eight seven seven seven six seven'
        phone 'six one seven seven eight two one five six three'
found : DATE_TIME@0.85 'nine nine nine eight'
        (nothing on the phone number at all)
```

And `CALL-004`, an AU billing call, spoken: Medicare `six five four two six four two nine zero two` and mobile `oh four six three one five nine eight five four`, findings: `LOCATION@0.85 'hermiston'` (the caller's surname), `DATE_TIME@0.85 'four eight'`, `DATE_TIME@0.85 'five two'`. Neither number is touched.

## 3. Raw results, health information (all three renderings, both configurations)

| | Conditions | Medications | Allergies | Total |
|---|---|---|---|---|
| Items spoken by callers | 200 | 160 | 80 | 440 |
| Caught at actionable confidence | 0 | 0 | 0 | **0 / 440** |
| Touched at any confidence | 0 | 9 | 0 | 9 / 440 |

The 9 are medication spans overlapped by a `US_DRIVER_LICENSE` finding below the actionable threshold; the artifacts do not retain those individual scores. Re-applying the installed recogniser's patterns to the reconstructed transcripts puts all nine on `b12` inside "b12 injections" in every rendering, matched by the alphanumeric pattern whose base score is 0.3 (the recogniser's 0.01 pattern is the long-digit-run one and does not fire here). **Every one of the 200 scripted calls carried at least one health item**, so "calls with at least one item missed, health included" is 200 / 200 in every rendering and configuration. **Scope, stated fairly:** neither tested configuration (stock defaults, and defaults plus the AU pack) enables a medical recogniser. Presidio does ship an optional `MedicalNERRecognizer` (entities such as `MEDICAL_DISEASE_DISORDER` and `MEDICAL_MEDICATION`, documented under supported entities, extra dependency, not enabled by default); it was not evaluated here, so its performance is unknown. The 0 / 440 is a fact about the default and AU-extended configurations a builder gets out of the box, not about the tool's ceiling (caveat 4).

## 4. Raw results, the call memory

200 transcripts in one Chroma collection, default embeddings, no metadata filter. The agent asks its memory who is calling.

| Lookup query | Top result is a different (synthetic) patient | True transcript in top 3 | True transcript in top 10 | Distinct transcripts returned at rank 1 |
|---|---|---|---|---|
| "Incoming call from {phone number}" | **199 / 200** | 3 / 200 | 18 / 200 | **2** (one transcript came back first 197 times) |
| "Caller {first} {last}" | 72 to 73 / 200 (runs 1, 2, 3: 72, 72, 73) | 157 to 159 / 200 (159, 159, 157) | 176 to 179 / 200 (179, 179, 176) | 130 to 131 (131, 131, 130) |
| "Caller {name}, date of birth {DOB}" | 61 to 62 / 200 (61, 61, 62) | 167 to 168 / 200 (168, 168, 167) | 185 to 186 / 200 (186, 185, 185) | 140 to 141 (141, 141, 140) |

In every wrong case the returned patient's transcript contained their health information (all of them, in every run), because every transcript does.

**Say this carefully.** The phone-number result is not "the memory picked the wrong patient 199 times" in the sense of a near miss. An embedding search is not a lookup: a query that is mostly a number string has no semantic content, and the search collapsed onto one hub transcript (returned first for 197 of the 200 queries; the true transcript was in the top 10 only 18 times). The honest claim is narrower and still useful: **in this synthetic corpus, an unfiltered Chroma semantic query built from a phone number returned another synthetic caller's transcript first in 199 of 200 cases, and one hub transcript dominated 197 of them; this was never an exact identifier lookup.** In this experiment, that is a stranger's call history returned on nearly every phone-number query; it is one embedding model, one corpus and one query template, not a general statement about semantic search. The number must travel with that qualifier (it is registered as fragile in `check_numbers.py`). The name lookups are ordinary retrieval and fail for ordinary reasons (Synthea shares surnames: "Caller Micheal Lang" returned Jermaine Lang's call). The name-lookup counts move by one between runs because Chroma's nearest-neighbour search is approximate; quote them as ranges, never as a fixed count.

## 5. Disclosed versus needed (descriptive, by construction)

For each scenario the booking system was designed to hold a fixed set of fields (booking: name, DOB, phone, reason, time; repeat script: name, DOB, medication; results: name, DOB; reschedule: name, DOB, phone; billing: name, DOB, billing number). Across the 200 scripted calls the transcripts contain **1,560** per-call identifier-kind entries; **560** of them intersect the scenario's allowlist and **1,000** do not (mean 5.0 per call). This is an intersection of two lists we wrote (the `needs` list per scenario and the annotated kinds per call), not an inspection of any booking system: no booking record is implemented, and two allowlisted fields (`reason`, `time`) are never annotated, so the 40 booking calls each carry two allowlist entries the intersection cannot count. Whether those 1,000 entries live nowhere but the transcript is not measured; what is scripted is that they fall outside the allowlist. 200 / 200 calls disclosed health information; 120 / 200 named a third party (a relative or a doctor).

**These numbers are what we scripted, not what we discovered.** They are useful only as the worked illustration of the right-place doctrine (the booking record is the right place; the transcript copy is the leak) and must be presented as such, never as a measurement of real calls. Caveat 1.

## 6. The retention-defaults audit (summary of `PLATFORM-POSTURE-MATRIX.md`)

| Platform | Records audio by default | Stores transcript by default | Compliance mode ships | Default retention | BAA |
|---|---|---|---|---|---|
| Vapi | **yes** (`recordingEnabled` default true) | yes | off (paid org add-ons: HIPAA mode, Zero Data Retention; mutually exclusive; not enableable by API) | up to 14 days calls, 30 days chats (pay-as-you-go); Enterprise configurable | Enterprise or paid add-on |
| Retell AI | **yes** | yes | off (`data_storage_setting` defaults to "everything") | **indefinite** ("no automatic deletion") | self-serve, free |
| Bland AI | no (`record` default false) | yes (transcript and summary in call details) | not documented | not documented | trust page only |
| ElevenLabs Agents | **yes** ("audio recordings are enabled") | yes | off ("history preservation enabled" by default) | **2 years** | Enterprise only |
| Synthflow | toggle, default not documented (framed as opt-out) | toggle, default not documented | 30-day auto-delete toggle exists; its default not documented | "depends on your plan" | not documented |

- **Recording by default: 3 of 5 document it on** (Vapi, Retell, ElevenLabs), **1 documents it off** (Bland), **1 does not document the default** (Synthflow: a Save Recordings toggle exists and the docs are framed as opt-out, but no page states its initial state). **Transcript by default: 4 of 5 documented on** (Bland keeps the transcript even though it does not record), Synthflow undocumented. These must not be rounded up; an undocumented default is unknown, not "on".
- **Every compliance mode whose default is documented ships off** (Vapi, Retell, ElevenLabs), and two of them are paid add-ons; Bland's and Synthflow's default states are not documented.
- **4 of 5 quick-start pages do not mention retention, HIPAA or deletion; ElevenLabs' quick-start mentions and links "conversation retention"** (one line, as a feature; no default, no deletion). No quick-start states a retention default, but whether guides *explain* defaults was not a separately defined check.
- Default retention runs from up to 14 days for calls (Vapi, pay-as-you-go; Enterprise configurable) to 2 years (ElevenLabs) to indefinite (Retell).
- The telephony layer does not record unless asked (Twilio `Record` default false), and then keeps recordings until deleted, billed monthly. Deepgram stores no transcripts. OpenAI and Anthropic retain API content for up to 30 days by default and offer zero-retention and BAAs on request; ElevenLabs' non-Enterprise tier trains on data unless a toggle is switched off.
- **The STT setting behind §2:** Deepgram's `smart_format` and `numerals` both default to `false`, so its default transcript renders a phone number as words; AssemblyAI formats by default; Azure always formats. Which shape a builder's transcripts take depends on which vendor the platform chose for them.

All rows dated 2026-09-14 with verbatim quotes and URLs in the matrix file; every cell in the table above except the two "not documented" Bland/Synthflow cells was read directly from the vendor's docs.

## 8. Literature and market sweep (2026-09-14), primary-source verified unless marked

**The transcript shape problem (anchors B):**
- **VoiceCodeBench: Evaluating Exact Structured-Token Recovery in Automatic Speech Recognition**, Baumgartner et al., [arXiv:2608.28916](https://arxiv.org/abs/2608.28916), 28 Aug 2026. 12 ASR systems, 1,482 audited entities across 26 types: "The strongest baseline by TSR reached only 68.7%, leaving nearly one third of recordings with at least one unrecovered workflow-critical value." Low word-error rate does not mean identifiers survive transcription. Our renderings assume perfect recognition; real transcripts add recognition errors, which can move spans, labels and denominators in either direction. [STRONG, re-fetched]
- **Meddies-PII**, Le et al., [arXiv:2609.12544](https://arxiv.org/abs/2609.12544), 11 Sep 2026: the newest clinical de-identification baseline, "a mean F1 of 0.827 across fifteen external benchmarks, compared with 0.658 for the strongest baseline." Even the best purpose-built clinical de-identifier is well short of 1.0. [STRONG, re-fetched]
- No ASR-noise-aware spoken-PII benchmark was found; REDACT (arXiv:2606.19881, Report #1) remains the only controlled multilingual PII benchmark. The gap is itself a finding: nobody has published the number B measures.

**What a voice carries (anchors the five-stop map, stop 1):**
- **Do Speech Tokens Leak Voiceprints? Speaker Inversion Attacks Against End-to-End Speech Language Models**, Lu et al., [arXiv:2607.16870](https://arxiv.org/abs/2607.16870), 18 Jul 2026: "with only three seconds of frontend output, SpInv achieves cosine similarities above 0.70 in the attacker-specified speaker-encoder space." The intermediate representations of a voice LLM carry a recoverable voiceprint. [STRONG, re-fetched]
- **HearSay Benchmark: Do Audio LLMs Leak What They Hear?**, Wang et al., [arXiv:2601.03783](https://arxiv.org/abs/2601.03783), 7 Jan 2026: "ALLMs inherently extract private attributes from voiceprints, reaching 92.89% accuracy on gender." The audio is sensitive even when the transcript is redacted. [STRONG, re-fetched]
- **Evaluating privacy leakages in LLM-driven ambient clinical documentation**, Chim, Pearson, Schofield, Liakata, Frontiers in Digital Health, [10.3389/fdgth.2026.1761624](https://www.frontiersin.org/journals/digital-health/articles/10.3389/fdgth.2026.1761624/full), 31 Mar 2026: "All examined models leaked third-party information, and privacy instructions helped reduce leakage but proved neither complete nor robust as a solution." Relatives and other patients end up in the note. Our scripted 120 / 200 third-party mentions (a rate we wrote, not measured) are the same shape. [STRONG, re-fetched]
- Research-pass items not re-fetched, cite only after a second read: VoxPrivacy (arXiv:2601.19956), membership inference on audio LLMs (arXiv:2603.28378), the Interlocutor Effect (arXiv:2606.09844, people disclose up to 23 points more PII to an AI agent), AI-scribe safety signals (arXiv:2512.04118), voice-clone trust (arXiv:2605.16578).

**Embeddings (the standing "a vector is not anonymous" leg):**
- **Denoising-Aware Inversion**, Wang et al., [arXiv:2608.18610](https://arxiv.org/abs/2608.18610), 19 Aug 2026: "approximately 154% relative improvement in BLEU over the existing generative inversion baseline", against the add-Gaussian-noise defence. Vec2Text's line continues. [STRONG, re-fetched]
- Research pass, not re-fetched: Embedding Inference Attack (arXiv:2607.01276, fingerprints the embedding model behind a live RAG), Zero2Text (arXiv:2602.01757), the KDD 2026 RAG extraction benchmark (arXiv:2602.09319), EMBER (arXiv:2606.03695). No new vector-database deletion paper since Ghost Vectors (arXiv:2606.18497, Report #2).

**Incidents, regulators, CVEs:** in `INCIDENT-TRACKER.md` §6 to §9. The ones the draft will want: the **Sears Home Services** exposure (three open databases of AI voice-agent call audio and transcripts, 1,442,577 audio recordings, published 2026-03-17, restricted the day after disclosure) [STRONG, re-fetched]; **Washington v. Sutter Health** (ambient-scribe consent class action, filed 2026-04-08) [STRONG]; **FTC "Active Listening" final orders** (2026-08-27) and **Hims & Hers** (2026-07-29) [STRONG, re-fetched]; **Ahpra's** AI guidance: an AI scribing tool "will generally require input of personal data and therefore require informed consent from your patient/client" and "there may be criminal implications if consent is not obtained before recording" [STRONG, read via curl]; **CVE-2026-85664** (Chroma 1.5.9, CVSS 8.7, published 2026-09-04, no fixed release) [STRONG, NVD API]. **Silent Period doctrine still holds:** none of the incidents is a vector-store breach; every one is a storage or consent failure around conversational data. Say so plainly. OAIC's site did not resolve from this environment, so every OAIC row is `[SECONDARY]` until opened in a browser.

## 9. Verification log (adversarial pass, the §3 quality gate)

1. *Claim:* "Vapi records by default." *Refute attempt:* re-fetched the HIPAA page and the call-recording reference independently of the research pass. *Result:* CONFIRMED verbatim ("By default, Vapi records your calls and stores logs and transcriptions"; `recordingEnabled` Default: `true`).
2. *Claim:* "Retell keeps data forever by default." *Result:* CONFIRMED verbatim ("By default, data is kept indefinitely (no automatic deletion)"; retention field default `null`).
3. *Claim:* "ElevenLabs keeps conversations two years by default; recording on by default." *Result:* CONFIRMED verbatim on both pages.
4. *Claim:* "Bland does not record by default." *Result:* CONFIRMED (`record` default `false`), and the audit table says so rather than rounding to "5 of 5 record".
5. *Claim:* "Deepgram's default transcript writes numbers as words." *Result:* CONFIRMED: `smart_format` Default `false`, `numerals` Default `false`, with the vendor's own phone-number example. AssemblyAI's `format_text` default `true` also confirmed, so B is framed as "depends on which vendor", not "all STT does this".
6. *Claim (first draft of this file):* "the scan caught 0 of 200 spoken phone numbers." *Refute attempt:* the generous tier. *Result:* NARROWED. 66 of 200 were overlapped by a `DATE_TIME` finding at 0.85, which the house rule counts as caught. The true statement is "recognised 0 of 200 as phone numbers; 66 were flagged as dates". The correct-label tier was added to the script so this is measured, not asserted. `check_numbers.py` forbids the unqualified phrasing.
7. *Claim:* "the call memory returned the wrong patient 199 of 200 times by phone." *Refute attempt:* is it 199 near-misses or one degenerate result? *Result:* the latter; 197 of 200 queries returned the same transcript, the true one was in the top 10 only 18 times. Kept, with the mechanism stated and the number registered as fragile.
8. *Claim:* "0 of 440 health items caught." *Refute attempt:* does the tool claim to detect health information? *Result, corrected in reviewer round 1:* the two tested configurations enable no medical recogniser, but Presidio ships an optional `MedicalNERRecognizer`, so the claim is reframed as "0 of 440 in the default and AU-extended configurations; the optional medical recogniser was not evaluated". At any confidence 9 of 440 were touched (driver-licence overlaps on `b12`, below threshold, individual scores not retained in the artifacts); `check_numbers.py` forbids "recognised none" without the tier.
9. *Claim (research pass):* "CVE-2026-85664 is a Chroma 1.5.9 memory-exhaustion CVE, CVSS 8.7." *Result:* CONFIRMED through the NVD JSON API (published 2026-09-04, v4.0 8.7, v3.1 7.5). CVE-2026-69111 (Milvus) likewise.
10. *Claim:* "chroma-core/chroma#7693 has merged." *Result:* NOT YET. Open as of 2026-09-14; latest comment is Belle's of 2026-09-13.
11. *Claim (research pass):* the OAIC items (three rows in this sweep's regulator table). *Result:* UNVERIFIABLE from here (DNS failure on oaic.gov.au); all marked `[SECONDARY]`, none may be cited until read on the regulator's site.
12. *Claim:* "the 'disclosed versus needed' ratio is a finding." *Result:* REJECTED as a finding; it is scripted. Kept as descriptive illustration only (§5).
13. **Whole-file numbers audit (REPORT-ENGINE §8 rule 9):** the listed figures in §2 to §5 were compared with their intended artifact fields; `reports/tools/check_numbers.py --issue 2026-09` passes against all three runs (683 numeric paths, 10 vary, all ten quoted as ranges). The checker skips percentages and does not validate run order or interpretation. Reviewer round 1 found one score (the driver-licence 0.01) with no artifact behind it and two per-run sequences printed out of run order; both are corrected above. Run-to-run variance: caveat 9.
14. **Separate-reviewer pass, round 1 (Codex, 2026-09-14): 28 findings, 9 confirmed, 13 narrowed, 6 refuted; every narrowing and refutation is applied in this revision** (disposition table in the working archive). Re-checked while folding: the run order, the AU-on differences, the installed medical recogniser, the allergy substitute count stated in §1, the allowlist gap (80 entries), the driver-licence overlaps (9 × `b12` per rendering, base score 0.3) and the ElevenLabs quick-start retention link all reproduce from the artifacts, a transcript reconstruction and live pages. One reviewer claim did not reproduce: the Synthflow Logs page still carried its opt-out sentence when re-fetched the same day; the cell's default remains undocumented either way, which is the point that matters.

## 10. Method caveats (write these into "How we measured")

1. **Synthetic and scripted.** Clinical content is Synthea's (real-format conditions, medications, names, DOBs; allergies are Synthea's where recorded, otherwise a scripted penicillin allergy; count in §1) but the dialogue is templated: five scenarios, fixed turn structure. The *amount* of disclosure per call is therefore ours, which is why §5 is descriptive only. The scan and memory results depend on the *shape* of identifiers, not the amount, and the shapes are real.
2. **No audio was processed.** The three renderings model documented STT output shapes with perfect recognition. Real transcripts add recognition errors (VoiceCodeBench v1: even the best of 12 systems recovered every workflow-critical value in only 68.7% of 300 recordings; corrected 2026-09-22 after the Week-2 reviewer pass, the earlier wording had misread the metric as token recall), which can change spans, labels and denominators in either direction, so these figures are neither an upper nor a lower bound on real transcripts; they are a controlled comparison of text shapes. The renderings also change several properties at once (§1), so no result here isolates one vendor setting, and the report must say so.
3. **Presidio ran on `en_core_web_lg`**, because its default configuration downloads that model itself on first use. Report #1 ran on the small model. This is generous to the tool on names and locations; it changes nothing about the pattern recognisers where the spoken-form gap lives.
4. **The tested configurations enable no medical recogniser.** Presidio ships an optional `MedicalNERRecognizer` (extra dependency, not enabled by default); it was not evaluated. The 0 of 440 must be reported as "the default and AU-extended configurations detected no health span at actionable confidence", never as "the tool cannot see health information". The report's point is what builders get by default and what they assume a scan covers.
5. **Scoring is generous to the tool** (any overlapping label counts; "6542 64290 2" flagged as a phone number counts as a caught Medicare number). The correct-label tier is reported beside it so a reader can see both.
6. **Single vector store, single embedding model, naive design.** The memory experiment uses Chroma's default ONNX MiniLM embeddings with no metadata filter. That is the unfiltered query shape Chroma's getting-started page demonstrates, but the use of it for caller identification is our design, not a quick-start recommendation, and not how a careful builder would do it. The 199 / 200 shows that, for this corpus, model and query template, an unfiltered semantic query did not act as a phone lookup; a builder who stores a phone field as metadata and filters on it would not see it (this collection stores only `region`, so no such filter was possible). Say so.
7. **Synthea names repeat** (shared surnames such as Lang), which is realistic and is why name-only lookup returned another caller first 72 to 73 times across three runs; adding DOB helps only slightly (61 to 62).
8. **Sample sizes** are 200 calls, 40 per scenario, 19 to 200 items per identifier kind; enough for the categorical findings (0 / 280, 172 / 200), not for decimal-point claims. Present percentages with counts.
9. **Run-to-run stability, measured.** Three tagged runs kept. The transcripts themselves cannot vary, so any variance is in Presidio's scoring or Chroma's approximate search. **Identical in all three runs:** every number in §2, §3 and §5 (all 683 numeric fields except the ten below), and the phone-number lookup in §4 (199 of 200 wrong, one hub transcript first 197 times, 3 in the top 3, 18 in the top 10). **Varied:** the two name-based memory lookups only. Wrong-top-1 moved by one (runs 1, 2, 3: 72 / 72 / 73 and 61 / 61 / 62); the matching top-3, top-10 and distinct-transcript counts moved by up to three (top-10: 179 / 179 / 176 and 186 / 185 / 185). Those are written as ranges in §4. Presidio's scoring did not vary at all.
10. **Vendor defaults are dated.** Every cell in §6 is true as of 2026-09-14 and will change; the matrix keeps history. The report must print the access date next to the table.
11. **Contact identifiers are fabricated, not reserved.** The generator draws ordinary-format AU and US phone numbers and addresses, and emails at real providers, without checking allocation; accidental correspondence to a real contact detail has not been excluded. The patient records themselves are Synthea-synthetic and no real-patient data was imported.

---

_Prevention is discussed only at the level disclosed in the report: extract structured fields and discard transcripts; never build memory from raw transcript text; scan what you hold._
