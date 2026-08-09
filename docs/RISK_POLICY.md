# Identifier risk policy

**Implemented policy:** `RLG-ID-RISK@1.0.0`.

This policy converts aggregate identifier findings into per-type severity labels,
an overall risk level, and an ordinal score. It is a prioritisation policy for an
alpha diagnostic scanner. It is not a probability of harm, a completeness claim,
a compliance determination, or proof that a store is safe.

## Inputs and output

The classification inputs are:

- finding counts keyed by identifier type;
- the number of records scanned;
- the number of records with one or more findings; and
- the requested policy version.

Source type, source path, report path, finding order, and dictionary insertion order
do not affect classification. The output is a severity for each identifier type, an
overall level (`LOW`, `MODERATE`, `ELEVATED`, or `HIGH`), and the corresponding
ordinal score from 0 to 3.

## Complete identifier severity matrix

The matrix covers all 16 default/global-US types and all five types in the only
implemented locale pack (`au`) at this version.

| Identifier type | Severity |
|---|---|
| `AU_MEDICARE` | `HIGH` |
| `AU_TFN` | `HIGH` |
| `CREDIT_CARD` | `HIGH` |
| `CRYPTO` | `HIGH` |
| `IBAN_CODE` | `HIGH` |
| `MEDICAL_LICENSE` | `HIGH` |
| `NRP` | `HIGH` |
| `US_BANK_NUMBER` | `HIGH` |
| `US_DRIVER_LICENSE` | `HIGH` |
| `US_ITIN` | `HIGH` |
| `US_PASSPORT` | `HIGH` |
| `US_SSN` | `HIGH` |
| `AU_ABN` | `MEDIUM` |
| `AU_PHONE` | `MEDIUM` |
| `EMAIL_ADDRESS` | `MEDIUM` |
| `LOCATION` | `MEDIUM` |
| `PERSON` | `MEDIUM` |
| `PHONE_NUMBER` | `MEDIUM` |
| `AU_ACN` | `LOW` |
| `DATE_TIME` | `LOW` |
| `IP_ADDRESS` | `LOW` |

A detector type may not be added to the default set or an implemented locale pack
without an explicit entry in this matrix. The runtime policy-definition check and
golden tests fail if the sets diverge.

## Unknown and custom identifier types

A truly unknown or caller-supplied type remains visible in the report with severity
`REVIEW`; Markdown-significant characters in its label are escaped so the label cannot
change the report table structure. It is conservatively treated as high-impact for the
overall calculation: below 25% flagged records it produces at least `ELEVATED`, and at or
above 25% it produces `HIGH`. This behavior prevents an unreviewed type from silently
lowering or normalising the report. Adding it as a supported type requires a reviewed
severity decision and policy-version change.

## Overall level and score

After aggregate validation, the rules are evaluated in this order:

1. No findings: `LOW` (score 0).
2. At least one `HIGH` or unknown/`REVIEW` type and at least 25% of records flagged:
   `HIGH` (score 3).
3. At least one `HIGH` or unknown/`REVIEW` type, or at least 50% of records flagged:
   `ELEVATED` (score 2).
4. Any other non-empty set of findings: `MODERATE` (score 1).

Both thresholds are inclusive. The implementation compares integers (`flagged * 4`
against `records`, and `flagged * 2` against `records`) rather than rounded display
percentages. For example, 24/100 is below the high-impact threshold, 25/100 is on it,
49/100 is below the prevalence threshold, and 50/100 is on it.

The score is only an ordinal encoding of the level:

| Level | Score |
|---|---:|
| `LOW` | 0 |
| `MODERATE` | 1 |
| `ELEVATED` | 2 |
| `HIGH` | 3 |

## Aggregate validation

Risk output is rejected rather than generated when aggregate counts are inconsistent.
Record counts and flagged-record counts must be non-negative integers; flagged records
cannot exceed scanned records or total findings; entity types must be non-empty strings;
and each included entity count must be a positive integer. Findings require at least one
flagged record, and flagged records require at least one finding. A zero-record scan is
valid only with zero flagged records and no findings.

These checks detect internally contradictory aggregate inputs. They do not prove that a
connector returned every source record or that detection itself was complete.

## Version and compatibility semantics

`1.0.0` is a source-controlled constant, not a value derived from detector registration,
configuration, timestamps, package metadata, or other mutable runtime state. A change to
the matrix, unknown-type treatment, aggregate validation, thresholds, level names, or
score mapping requires a deliberate policy-version change and review. This build rejects
requests for versions it does not implement instead of silently substituting the current
policy.

Every newly generated report records both the policy identifier and version. Reports made
before this contract have no version marker and remain **legacy unversioned** artifacts;
they are never retroactively labelled `1.0.0`. The compatibility reader returns no version
for those artifacts. Regenerating a report through the existing `build_report` call shape
uses the current policy and adds attribution, so byte-for-byte report consumers must accept
the additive policy and score lines.

## Privacy and remaining limitations

The policy consumes aggregate type/count data only. Policy attribution adds fixed public
identifiers and does not add detected values, document text, spans, record IDs,
collection/tenant names, secrets, exception text, or new local paths. The existing report
contract still includes the operator-supplied source and source path.

Severity is context-independent and jurisdiction-general at this version. A count cannot
express data subject vulnerability, exploitability, access controls, retention, business
purpose, or whether several findings refer to one person. Detection remains best-effort,
and a low or empty report is not proof of safety or compliance.
