# Platform Posture Matrix

**What this is:** REPORT-ENGINE §3.8 standing data source, started with Report #3 (September 2026) as specified: per-platform retention defaults, compliance modes and BAA availability for the vendors an AI voice agent touches, re-verified quarterly, every row dated and sourced. Second longitudinal asset beside `INCIDENT-TRACKER.md`. **Append and re-date, never rewrite history**: when a default changes, add a row with the new date and keep the old one, because "this platform used to keep transcripts for two years by default" is itself a finding.

**Rules of entry.** Every cell carries the vendor's own page and the date we read it. `[STRONG]` = the vendor's developer documentation read directly. `[VENDOR MARKETING]` = the vendor's own site but not its docs (trust pages, pricing). `[SEARCH SNIPPET]` = the page refused to load and only a search excerpt was visible; not citable until someone opens it in a browser. "not documented" means we looked and the vendor does not say, which is a fact worth reporting in itself.

**Verification.** Built 2026-09-14 by a research pass, then the load-bearing cells (marked ✔) were re-fetched independently the same day and matched verbatim: Vapi default recording, Retell indefinite retention and default-stored list, ElevenLabs two-year default, Bland `record` default, Deepgram `smart_format` default.

_Last sweep: 2026-09-14 (Report #3, Week 1). Next re-verification due: 2026-12-14._

---

## 1. Summary: the five voice-agent platforms

| Platform | Records audio by default | Stores transcript by default | Compliance / retention mode exists | Its default state | BAA available | Default retention |
|---|---|---|---|---|---|---|
| **Vapi** | **Yes** ✔ (`recordingEnabled` default `true`) | Yes ✔ | Yes: HIPAA mode and Zero Data Retention, both org-level paid add-ons, mutually exclusive ✔ | Off (must be purchased and switched on in the Dashboard; cannot be enabled by API) | Yes: Enterprise or paid HIPAA add-on, on request | Pay-as-you-go: up to 14 days for calls, 30 days for chats; Enterprise configurable |
| **Retell AI** | **Yes** ✔ | Yes ✔ | Yes: `data_storage_setting` (everything / everything except PII / basic attributes only) plus `data_storage_retention_days` | `"everything"`; retention `null` | Yes: self-serve click-through, no fee | **Indefinite** ✔ ("no automatic deletion") unless retention days set (1 to 730) |
| **Bland AI** | **No** ✔ (`record` default `false`) | Yes (transcript, `concatenated_transcript` and summary in call details and logs) | Partial: org-level `recording_lifespan_days` (1 to 1825, or -1); "zero-retention processing" on the trust page only | not documented | Stated on the trust page; plan not named in docs | not documented (recording lifespan default not printed) |
| **ElevenLabs Agents** | **Yes** ("By default, audio recordings are enabled") | Yes (disabling audio keeps transcripts) | Yes: per-agent Zero Retention Mode; workspace ZRM (Enterprise) | Off ("history preservation enabled" by default) | Yes: Enterprise tier only, via account rep | **2 years** ✔ |
| **Synthflow AI** | Toggle "Save Recordings"; framed as opt-out; default not documented | Toggle "Save Transcripts"; default not documented | Yes: save toggles, 30-day auto-delete toggle, PII redaction toggle (no toggle's default is documented) | not documented | not documented (HIPAA badge on pricing only) | "depends on your plan" |

**Reading the table.** Three of five document recording on by default (Vapi, Retell, ElevenLabs); Bland documents it off but still stores the transcript and a summary; Synthflow does not document the initial state of its toggles, so it counts as unknown, never as on. Transcript storage by default is documented on for four of five and unknown for Synthflow. Every platform that documents a compliance mode's default ships it **off**. Four of five quick-start pages (checked below) do not mention retention, HIPAA or deletion; ElevenLabs' mentions and links "conversation retention" in one line, as a feature. (Reviewer round 1, 2026-09-14, corrected an earlier "four of five record, none of the quick-starts mention it" reading of this same table.)

## 2. Quick-start pages: do they mention retention, HIPAA or deletion?

| Platform | Page | Mentions retention / HIPAA / deletion | URL | Accessed |
|---|---|---|---|---|
| Vapi | Introduction · Phone calls · Core Models | No | https://docs.vapi.ai/quickstart/introduction · https://docs.vapi.ai/quickstart/phone · https://docs.vapi.ai/quickstart | 2026-09-14 |
| Retell | Build your first phone agent in 15 minutes | No | https://docs.retellai.com/get-started/quick-start | 2026-09-14 |
| Bland | Welcome to Bland · Send first call | No ("your data stays entirely secure from end-to-end" only) | https://docs.bland.ai/welcome-to-bland · https://docs.bland.ai/tutorials/send-first-call | 2026-09-14 |
| ElevenLabs | Quickstart | One line: "Conversation retention to view conversation history and improve its performance." No HIPAA, no deletion | https://elevenlabs.io/docs/eleven-agents/quickstart | 2026-09-14 |
| Synthflow | Build Agents with Synthflow AI · Create an Agent | No ("compliance-heavy scenarios" as a use-case label only) | https://docs.synthflow.ai/getting-started · https://docs.synthflow.ai/create-an-agent | 2026-09-14 |

## 3. Detail per vendor

### 3.1 Vapi (docs.vapi.ai)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Records by default ✔ | Yes | "By default, Vapi records your calls and stores logs and transcriptions." | https://docs.vapi.ai/security-and-privacy/hipaa | 2026-09-14 [STRONG] |
| Recording parameter | `artifactPlan.recordingEnabled` Default `true` | "Enable call recording (stored in `call.artifact.recording`) Default: `true`" | https://docs.vapi.ai/assistants/call-recording | 2026-09-14 [STRONG] |
| Logging | `loggingEnabled` default `true`; `pcapEnabled` default `true` | "Enable detailed call logs (stored in `call.artifact.logUrl`) Default: `true`" | same | 2026-09-14 [STRONG] |
| AI summary | Automatic for every call; disable with an empty `summaryPrompt` | "Call analysis automatically summarizes and evaluates every call for insights and quality control." | https://docs.vapi.ai/assistants/call-analysis | 2026-09-14 [STRONG] |
| Default retention | PAYG: up to 30 days chats, 14 days calls; Enterprise configurable | "Pay-As-You-Go: Up to 30 days for chats and 14 days for calls; Enterprise: Configurable retention policies" | https://docs.vapi.ai/assistants/call-recording | 2026-09-14 [STRONG] |
| HIPAA mode ✔ | Org-level, Dashboard only, add-on | "This is an organization-level setting ... and it cannot be enabled through the API." | https://docs.vapi.ai/security-and-privacy/hipaa | 2026-09-14 [STRONG] |
| HIPAA mode requires ✔ | Enterprise or paid add-on plus signed BAA | "HIPAA mode requires an Enterprise subscription or a separately purchased HIPAA add-on." | same | 2026-09-14 [STRONG] |
| What HIPAA mode does | Data still stored, in a private bucket; webhook URLs not directly downloadable | "call recordings and logs are stored in a private bucket and cannot be downloaded directly from the URLs returned in webhooks" | same | 2026-09-14 [STRONG] |
| Zero Data Retention | Separate org add-on | "Zero Data Retention (ZDR) is an organization add-on that stops Vapi from storing call content after a call ends." | https://docs.vapi.ai/security-and-privacy/zero-data-retention | 2026-09-14 [STRONG] |
| ZDR scope | No recordings, transcripts, messages, summaries, structured outputs | "Vapi does not retain recordings, transcripts, messages, summaries, or structured outputs." | same | 2026-09-14 [STRONG] |
| HIPAA vs ZDR ✔ | Mutually exclusive | "HIPAA mode and Zero Data Retention (ZDR) are mutually exclusive. Disable one before enabling the other." | https://docs.vapi.ai/security-and-privacy/hipaa | 2026-09-14 [STRONG] |
| End-of-call webhook | Carries `artifact.transcript`, `artifact.recording`, `artifact.messages` | example payload shows a full transcript string | https://docs.vapi.ai/server-url/events | 2026-09-14 [STRONG] |
| PHI endpoint | Only `/call` | "When using Vapi with PHI, you may only pass PHI through the `/call` endpoint." | https://docs.vapi.ai/security-and-privacy/hipaa | 2026-09-14 [STRONG] |
| Vendors under the hood | STT: Deepgram, Gladia, AssemblyAI, Speechmatics, Google, Azure; LLM: OpenAI, Anthropic, Azure OpenAI, Gemini, Groq and more; TTS: ElevenLabs, PlayHT, Cartesia, Deepgram, OpenAI, Azure and more | "Supported: Deepgram, Gladia, AssemblyAI, Speechmatics, Google, Azure" | https://docs.vapi.ai/security-and-privacy/data-flow | 2026-09-14 [STRONG] |

**Update 2026-09-22 (Week-2 reviewer pass, appended; the 2026-09-14 rows above stay as history):** the HIPAA page now reads "HIPAA is available as a paid compliance add-on with Usage only or any Success Package" (https://docs.vapi.ai/security-and-privacy/hipaa, read 2026-09-22 [STRONG]). The 14 September wording ("Enterprise subscription or a separately purchased HIPAA add-on") is no longer on the page. Report #3 says "paid add-on" and names both dates.

**Update 2026-10-01 (Week-3 reviewer pass, appended; the 2026-09-14 rows above stay as history):** the call-recording page no longer contains the sentence "Pay-As-You-Go: Up to 30 days for chats and 14 days for calls; Enterprise: Configurable retention policies". Its only retention text is now "Artifacts are automatically cleaned up based on your retention policy" and "Retention policies to automatically delete old recordings" (https://docs.vapi.ai/assistants/call-recording, read 2026-10-01 by fetching the page and its Markdown source [STRONG, absence]); "14 days" appears on neither, nor in `docs.vapi.ai/llms-full.txt`. `recordingEnabled: true` is still shown, beside a deprecation notice pointing to `artifactPlan`. Where Vapi now states a default retention period, if anywhere, was not established (the HIPAA, Zero Data Retention and data-flow pages do not state one); needs a human browser check. Report #3 keeps "up to 14 days for calls on pay-as-you-go" as the 14 September reading and discloses the move in its method section.

Not documented: which STT/LLM/TTS vendor a new assistant gets by default (API reference too large to fetch); any training-on-data statement; whether the end-of-call report carries the summary; ZDR plan tier.

### 3.2 Retell AI (docs.retellai.com)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Stored by default ✔ | Recordings, transcripts, logs and more | "Call logs, Transcriptions, Call recordings, Caller ID for inbound call, Callee ID for outbound call, Knowledge base retrieved contents logs, Dynamic variables, Metadata" | https://docs.retellai.com/accounts/privacy-disable | 2026-09-14 [STRONG] |
| Default retention ✔ | Indefinite | "By default, data is kept indefinitely (no automatic deletion)." | https://docs.retellai.com/accounts/data-retention | 2026-09-14 [STRONG] |
| Retention field ✔ | `data_storage_retention_days` 1 to 730, default `null` | "Type: integer (1–730) or `null` | Default: `null`" | same | 2026-09-14 [STRONG] |
| Storage mode | `data_storage_setting` default `everything` | "If not set, default value of 'everything' will apply." | https://docs.retellai.com/api-references/create-agent | 2026-09-14 [STRONG] |
| Opt-out and webhooks ✔ | Webhooks still carry transcript and recording | "You will continue to receive webhook events, where you can access the transcript, call recording, and other sensitive data in it" | https://docs.retellai.com/accounts/privacy-disable | 2026-09-14 [STRONG] |
| Recording link ✔ | Expires 10 minutes after the webhook when storage is off | "The call recording link will expire after 10 minutes upon receiving the webhook" | same | 2026-09-14 [STRONG] |
| BAA | Self-serve, free | "available for self-signing at click-agreements.retellai.com" · "There is no additional fee to sign these agreements." | https://docs.retellai.com/general/compliance | 2026-09-14 [STRONG] |
| BAA before PHI | Required | "A signed BAA is required before transmitting PHI through Retell." | same | 2026-09-14 [STRONG] |
| Webhooks | `call_ended` = all call fields except analysis; `call_analyzed` adds it | "All fields from the call object except `call_analysis`." | https://docs.retellai.com/features/webhook | 2026-09-14 [STRONG] |
| Internal logs | PII excluded by default | "Retell also excludes personal identifiers from its internal logs and product analytics by default" | https://docs.retellai.com/general/compliance | 2026-09-14 [STRONG] |
| Default LLM | OpenAI gpt-4.1 when unset | "Select the underlying text LLM. If not set, would default to gpt-4.1." | https://docs.retellai.com/api-references/create-retell-llm | 2026-09-14 [STRONG] |

Not documented: training-on-data statement; default STT vendor; subprocessor list (by email only).

### 3.3 Bland AI (docs.bland.ai)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Records by default ✔ | No, `record` default `false` | "To record your phone call, set `record` to true." | https://docs.bland.ai/api-v1/post/calls | 2026-09-14 [STRONG] |
| Transcript stored | Yes, in call details | "An array of phrases spoken during the call. Each index includes: id, created_at, text, user" | https://docs.bland.ai/api-v1/get/calls-id | 2026-09-14 [STRONG] |
| Call logs | Full transcript, recording, variables, per-turn data | "surfaces here with its full transcript, audio recording, extracted variables, and per-turn decision data" | https://docs.bland.ai/tutorials/call-logs | 2026-09-14 [STRONG] |
| Summary | Generated at call end | "A short summary of the call based off of the transcript that's generated when the call ends." | https://docs.bland.ai/api-v1/get/calls-id | 2026-09-14 [STRONG] |
| Retention control | `recording_lifespan_days` 1 to 1825 or -1; default not printed | "The lifespan of recordings in days. Must be between 1 and 1825 (inclusive) or `-1` to disable retention." | https://docs.bland.ai/api-v1/patch/org_properties | 2026-09-14 [STRONG] |
| Zero retention | Stated on trust page only | "Zero-retention processing available for sensitive workflows." | https://www.bland.ai/trust-security | 2026-09-14 [VENDOR MARKETING] |
| BAA | Trust page only | "Self-attested with BAA" | same | 2026-09-14 [VENDOR MARKETING] |
| Post-call webhook | Transcripts, concatenated transcript, summary, recording URL | fields "transcripts", "concatenated_transcript", "summary", "recording_url" | https://docs.bland.ai/tutorials/post-call-webhooks | 2026-09-14 [STRONG] |
| Third parties | Claims own models | "No third-party AI provider touches your call" | https://www.bland.ai/trust-security | 2026-09-14 [VENDOR MARKETING] |

Not documented: default of `recording_lifespan_days`; transcript/log retention; any API-level compliance toggle; BAA plan; training-on-data.

### 3.4 ElevenLabs Agents (elevenlabs.io/docs)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Records by default | Yes | "By default, audio recordings are enabled." | https://elevenlabs.io/docs/eleven-agents/customization/privacy/audio-saving | 2026-09-14 [STRONG] |
| Disabling audio | Transcripts still kept | "Disabling audio saving enhances privacy but limits the ability to review calls. However, transcripts can still be viewed." | same | 2026-09-14 [STRONG] |
| Default retention ✔ | 2 years | "By default, ElevenLabs retains conversation data for 2 years." | https://elevenlabs.io/docs/eleven-agents/customization/privacy/retention | 2026-09-14 [STRONG] |
| Retention options ✔ | Any days; -1 unlimited; 0 scheduled deletion | "Unlimited retention by setting the value to -1" | same | 2026-09-14 [STRONG] |
| Per-agent ZRM | Exists | "No transcripts or call metadata containing PII will be logged or stored by our systems post-call." | https://elevenlabs.io/docs/eleven-agents/customization/privacy/zrm | 2026-09-14 [STRONG] |
| ZRM retrieval | Webhooks only | "To retrieve information about calls made with ZRM-enabled agents, you must use post-call webhooks." | same | 2026-09-14 [STRONG] |
| Workspace ZRM | Enterprise; history kept by default | "Customers by default have history preservation enabled." | https://elevenlabs.io/docs/eleven-api/resources/zero-retention-mode | 2026-09-14 [STRONG] |
| BAA | Enterprise only | "Execution of a BAA, as may be required by HIPAA, is only available for Enterprise tier subscriptions." | https://elevenlabs.io/docs/eleven-agents/legal/hipaa | 2026-09-14 [STRONG] |
| HIPAA mode effect | ZRM plus LLM allowlist | "Only LLM from providers with whom we have a BAA in place are available as preconfigured options." | same | 2026-09-14 [STRONG] |
| Post-call webhook | Full transcript, summary, evaluation; audio as base64 | "full conversation transcript with turns" | https://elevenlabs.io/docs/eleven-agents/workflows/post-call-webhooks | 2026-09-14 [STRONG] |
| Training on data | Non-Enterprise: used unless the "Improve the models for everyone" toggle is off; Enterprise: not by default | "By default, we don't train on any data from our Enterprise customers, other than as may be necessary" | https://elevenlabs.io/docs/help-center/legal/is-my-data-used-to-improve-eleven-labs-ai-models | 2026-09-14 [STRONG] |
| LLM vendors | ElevenLabs, Google, OpenAI, Anthropic | "Certain LLMs available on our platform may be suitable for use in environments requiring HIPAA compliance" | https://elevenlabs.io/docs/eleven-agents/customization/llm | 2026-09-14 [STRONG] |

Not documented: default LLM for a new agent; per-agent ZRM default; whether post-call webhooks are on by default; whether ZRM changes the webhook payload.

### 3.5 Synthflow AI (docs.synthflow.ai)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Save Recordings toggle | Exists; default not stated | "When enabled, Synthflow retains the audio recording of every call the agent handles." | https://docs.synthflow.ai/security-and-compliance | 2026-09-14 [STRONG] |
| Save Transcripts toggle | Exists; default not stated | "When enabled, Synthflow retains the text transcript of every call." | same | 2026-09-14 [STRONG] |
| Opt-out framing | Framing only; states no default | "You can opt out of saving recordings, transcripts, and other sensitive data from the agent's Security & Compliance settings." (Re-fetched 2026-09-14 by the folding session and still present; the round-1 reviewer did not find it on the page the same day, so re-check next sweep.) | https://docs.synthflow.ai/logs | 2026-09-14 [STRONG] |
| 30-day retention toggle | Exists; initial state not documented (the quote describes what enabling does, not the default) | "Enabling this toggle automatically deletes all transcripts, recordings, and caller IDs after 30 days." | https://docs.synthflow.ai/security-and-compliance | 2026-09-14 [STRONG] |
| Retention window | Plan-dependent | "Retention depends on your plan." | https://docs.synthflow.ai/logs | 2026-09-14 [STRONG] |
| PII redaction | Transcripts and webhooks, not audio | "PII redaction automatically strips sensitive data from transcripts displayed in the platform" | https://docs.synthflow.ai/security-and-compliance | 2026-09-14 [STRONG] |
| Toggle effect on webhook | Disabling Save Transcripts removes it from webhooks | "disabling this toggle also removes transcript data from those surfaces" | same | 2026-09-14 [STRONG] |
| Post-call webhook | `call.transcript`, `call.recording_url`, `analysis` | "call" object includes "transcript", "recording_url" | https://docs.synthflow.ai/post-call-webhook | 2026-09-14 [STRONG] |
| BAA | Not mentioned; pricing shows a HIPAA badge and Enterprise "MSA/DPA support" | "MSA/DPA support, data handling review, workspace controls, and enterprise security review" | https://synthflow.ai/pricing | 2026-09-14 [VENDOR MARKETING] |

Not documented: defaults of every toggle (the page never uses the word "default"); BAA; per-plan retention; third-party vendors; training.

### 3.6 Twilio Programmable Voice (telephony layer)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Records by default | No | "Whether to record the call. Can be `true` to record the phone call, or `false` to not. The default is `false`." | https://www.twilio.com/docs/voice/api/call-resource | 2026-09-14 [STRONG] |
| Recording retention | Until deleted; metadata 40 days after deletion | "Recordings metadata are kept after deletion for a retention period of 40 days." | https://www.twilio.com/docs/voice/api/recording | 2026-09-14 [STRONG] |
| Storage billed | Per minute per month | "Storage $0.0005 / min per mo" | https://www.twilio.com/en-us/voice/pricing/us | 2026-09-14 [VENDOR MARKETING: pricing page; retagged 2026-09-22 per the matrix's own rule, was STRONG] |
| HIPAA recordings | HTTP auth required on recording URLs | "For Customers building HIPAA-compliant workflows with Recordings, we require customers to enforce at least HTTP Authentication." | https://www.twilio.com/docs/voice/api/recording | 2026-09-14 [STRONG] |
| BAA | Security Edition or Enterprise Edition | "HIPAA Accounts require Twilio Security Edition or Enterprise Edition." | https://www.twilio.com/docs/iam/twilio-editions/hippa | 2026-09-14 [STRONG] |
| Conversational Intelligence transcripts | Searchable 90 days | "Transcripts are indexed and available for search for 90 days." | https://www.twilio.com/docs/conversational-intelligence/api/transcript-resource | 2026-09-14 [STRONG] |
| Auto-transcribe / auto-redaction | Service-level flags, defaults not printed | "automatically redact PII from all transcripts made on this service" | https://www.twilio.com/docs/conversational-intelligence/api/service-resource | 2026-09-14 [STRONG] |
| Training on data | Opt-in via website only | "Data logging cannot be activated via API, only via www.twilio.com, as it requires additional consent." | same | 2026-09-14 [STRONG] |

Not documented / not fetched: the help-center retention and deletion articles (page body not served); defaults of `auto_transcribe`, `auto_redaction`, `data_logging`; media retention beyond the 90-day search window. The July 2026 spine note's "Twilio keeps recordings until deleted" line is consistent with the recording resource page above.

### 3.7 Deepgram (STT)

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Stores transcripts | No | "Deepgram does not store transcripts, so the Deepgram API response is the only opportunity to retrieve the transcript." | https://developers.deepgram.com/docs/live-streaming-audio | 2026-09-14 [STRONG] |
| Training | Only contractually included data; per-request `mip_opt_out=true` | "The only data we will store and use in future model training is the data that is contractually included through participation" | https://developers.deepgram.com/docs/the-deepgram-model-improvement-partnership-program | 2026-09-14 [STRONG] |
| Opt-out retention | Request duration only | "Data from opted-out requests is retained only for the duration necessary to process the request." | same | 2026-09-14 [STRONG] |
| BAA | On request | "We can provide our Business Associate Agreement to such customers upon request." | https://developers.deepgram.com/trust-security/data-privacy-compliance | 2026-09-14 [STRONG] |

Not documented: whether accounts are enrolled in the Model Improvement Program by default; audio retention when not opted out.

### 3.8 OpenAI API

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Training | Not unless opted in | "Data sent to the OpenAI API is not used to train or improve OpenAI models (unless you explicitly opt in to share data with us)." | https://developers.openai.com/api/docs/guides/your-data | 2026-09-14 [STRONG] |
| Default retention | Abuse-monitoring logs up to 30 days | "By default, abuse monitoring logs are generated for all API feature usage and retained for up to 30 days" | same | 2026-09-14 [STRONG] |
| `/v1/audio/transcriptions` | No training; no abuse-monitoring retention; ZDR eligible | table row "No | None | None | Yes" | same | 2026-09-14 [STRONG] |
| `/v1/realtime` | 30 days abuse monitoring; ZDR eligible | table row "No | 30 days | None | Yes" | same | 2026-09-14 [STRONG] |
| `/v1/chat/completions` | 30 days; ZDR with limitations | table row "No | 30 days | None, see below | Yes, see below" | same | 2026-09-14 [STRONG] |
| ZDR / Modified Abuse Monitoring | Prior approval via sales | "Get in touch with our sales team to learn more about these offerings and inquire about eligibility" | same | 2026-09-14 [STRONG] |
| BAA and PHI | Eyes Off provisioning | "once your org ID is provisioned with Eyes Off, BAA-eligible endpoints can be used for processing PHI, even if data is retained." | same | 2026-09-14 [STRONG] |
| BAA request | Email baa@openai.com | "email us at baa@openai.com with details about your company and use case" | https://help.openai.com/en/articles/8660679-how-can-i-get-a-business-associate-agreement-baa-with-openai | 2026-09-14 [SEARCH SNIPPET, page 403; still 403 from this environment 2026-09-22; the Week-2 reviewer opened it in a browser and reports the request route is stated, but nobody on our side has read it, so it stays uncitable] |

### 3.9 Anthropic API

| Fact | Value | Verbatim | URL | Accessed |
|---|---|---|---|---|
| Training | Not by default | "By default, we will not use your inputs or outputs from our commercial products (e.g. Claude for Work, Anthropic API, Claude Gov, etc.) to train our models." | https://privacy.claude.com/en/articles/7996868-is-my-data-used-for-model-training | 2026-09-14 [STRONG] |
| Default retention | Deleted within 30 days | "we automatically delete inputs and outputs on our backend within 30 days of receipt or generation" | https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-personal-data | 2026-09-14 [STRONG] |
| Platform docs | Not retained by default except Covered Models (30 days) | "Conversation content (your prompts and Claude's outputs) is not retained by default; the exception is Covered Models, which require 30-day retention." | https://platform.claude.com/docs/en/manage-claude/api-and-data-retention | 2026-09-14 [STRONG] |
| ZDR | Per org, via sales | "To request ZDR for your organization, contact the Anthropic sales team." | same | 2026-09-14 [STRONG] |
| BAA | Self-serve standard BAA in the Console, or negotiated | "Most organizations can enable it directly in the Claude Console with Anthropic's standard BAA" | same | 2026-09-14 [STRONG] |
| ZDR vs BAA | Covered Models need 30-day retention | "Covered Models require 30-day data retention and aren't available with zero data retention (ZDR) enabled." | https://privacy.claude.com/en/articles/8114513-business-associate-agreements-baa-for-commercial-customers | 2026-09-14 [STRONG] |
| BAA exclusions | Batch, Files, Skills, Code Execution, Computer Use, Web Fetch | "Batch API, Files API, Skills API, Code Execution, Computer Use, Web Fetch" | same | 2026-09-14 [STRONG] |

## 4. Speech-to-text number formatting: what the transcript looks like by default

This is the row the Report #3 scan finding rests on: whether a spoken phone number arrives in the transcript as digits or as words depends on a vendor setting, and the settings differ.

| Vendor | Setting | Documented default | Verbatim | URL | Accessed |
|---|---|---|---|---|---|
| **Deepgram** ✔ | `smart_format` | **`false`** | "`smart_format` boolean Default: `false`" · before: "i just ate thirty three grams of pasta" · after: "I just ate 33 grams of pasta" | https://developers.deepgram.com/docs/smart-format | 2026-09-14 [STRONG] |
| **Deepgram** | `numerals` | **`false`** | off: "My phone number is five five five two one two four three nine four"; on: "My phone number is 5 5 5 2 1 2 4 3 9 4" | https://developers.deepgram.com/docs/numerals | 2026-09-14 [STRONG] |
| AssemblyAI | `format_text` | `true` | "By default, `format_text` is `true`, so numbers, dates, and similar entities are formatted for readability." | https://www.assemblyai.com/docs/pre-recorded-audio/formatting | 2026-09-14 [STRONG] |
| AssemblyAI | verbatim mode | words when formatting is off | "a speaker saying 'one hundred' comes back as 'one hundred' rather than `100`" | same | 2026-09-14 [STRONG] |
| Azure Speech | inverse text normalization on display text | always on, not configurable; lexical form is the raw words | "my phone number is one eight hundred, four five six, eight nine ten" becomes "My phone number is 1-800-456-8910." | https://learn.microsoft.com/en-us/azure/ai-services/speech-service/display-text-format | 2026-09-14 [STRONG] |
| Google Speech-to-Text | no ITN parameter found; punctuation off by default | "By default, Speech-to-Text does not include punctuation marks in the results from speech recognition." | https://docs.cloud.google.com/speech-to-text/docs/automatic-punctuation | 2026-09-14 [STRONG] |
| OpenAI Whisper / STT API | not documented | no primary page states digits-vs-words behaviour or a toggle | https://developers.openai.com/api/docs/guides/speech-to-text | 2026-09-14 [STRONG, absence] |

**What this means for the scan.** Deepgram is the STT vendor Vapi lists first and one of its HIPAA-approved transcribers; its two number-formatting switches both default to off, so its default transcript renders a phone number as "five five five two one two four three nine four". AssemblyAI and Azure format numbers by default. A builder therefore gets one of three transcript shapes depending on which vendor the platform picked for them, and usually never sees the setting. The Report #3 scan tests all three shapes.

---

_Muzzle check: PASSES. This file records vendor defaults and public documentation only; no RAGLeakGuard mechanism, disclosed or otherwise, appears here._
