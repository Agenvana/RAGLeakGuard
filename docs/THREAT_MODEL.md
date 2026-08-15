# Threat model

**Baseline:** WP7B's private bounded operator-snapshot confinement foundation passed independent
review at exact implementation head `128decb3e0d78825e884f6dce019898b568c6ba2` and was merged
through [PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) as merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955` on 2026-08-13. WP7D adds a bounded aggregate-only
operator-snapshot consumer for exact ChromaDB 1.5.9. RAGLeakGuard is an alpha security project;
direct/live source-store access remains disabled.

## Scope

In scope:

- synchronous library disablement of direct local Chroma access;
- private bounded copying, ownership, leasing, cleanup, and recovery for an operator-created
  filesystem snapshot;
- private exact-candidate Chroma migration validation, bounded two-pass enumeration, worker
  isolation/teardown, effect classification, and counter receipt inside a held work copy;
- public first-pass-only detection, aggregate equality, cleanup-gated completion, and atomic report
  finalization for the five-cell exact 1.5.9 operator-snapshot matrix;
- `scan` and `monitor` CLI validation and precedence;
- preservation of reports, authenticated monitor state, and the WP6 pending-alert outbox;
- detection, risk-policy, report, console, package, documentation, and release claim boundaries;
- protocol-v2 pending-alert recovery and delivery.

Out of scope because it is unavailable or not implemented:

- direct/live Chroma scanning, monitor new scans, and Chroma versions or environment tuples outside
  the finite WP7D matrix;
- every other source connector;
- public connector pagination, metadata expansion, detector completion, and version support;
- Prevent/Fix, erasure proof, Control Plane, certification, or compliance guarantees.

## Evidence and security decision

Executable endpoint tests established durable store mutation for ChromaDB 1.5.0 and 1.5.9 during
client construction or reads. Other Chroma versions have not established an acceptable read-only boundary.
Therefore, direct local Chroma entry points fail closed without importing Chroma or
accessing the source. [Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) was deferred,
not completed. Snapshot-backed scanning is activated only for exact 1.5.9 on Linux/ext4 Python
3.10–3.12, macOS 15/APFS Python 3.12, and Windows/NTFS Python 3.12. ChromaDB 1.5.0 remains private
evidence and is rejected publicly.

PyPI 0.1.0 contains the unsafe direct path and must not be used for Chroma scanning.

## Assets and objectives

| Asset | Security objective |
|---|---|
| Supplied source object/path | Do not inspect it in `read_chroma()`; reject legacy CLI `--path` before source access. |
| Operator production store | Never pass it to Chroma; direct paths fail before import, construction, filesystem access, embeddings, or network access. |
| Existing report/state | Preserve bytes exactly; leave absent artifacts absent; create no temporary artifact. |
| Operator-facing result | Return only bounded connector counters and detector aggregates after every completion gate; otherwise emit no clean, scan, baseline, report, change, or delivery success signal. |
| Monitor key and authenticated state | Preserve validation precedence, static failures, checkpoint integrity, and scope binding. |
| Existing pending alert | Recover without a new scan; only an accepted delivery may authorize the existing atomic clear transition. |
| Package and public claims | Keep Chroma optional and exact; describe only the finite operator-snapshot matrix and never claim live read-only, snapshot completeness, or production safety. |
| Operator-provided snapshot | Treat it as hostile and privacy-sensitive; never claim that WP7B proves its quiescence, completeness, provenance, or atomic multi-file consistency. |
| RAGLeakGuard work copy | Bound files, directories, depth, bytes, chunks, time, and free-space preflight; use restrictive permissions and do not return an incomplete copy. |
| Ownership controls and lease | Authenticate privacy-minimal control documents, hold an exclusive native lock while the copy is usable, and clean only positively proved direct descendants. |
| Private enumerator | Accept only the live held capability; enumerate completely within hard limits; expose counters only after child exit, semantic/effect agreement, and final capability validation. |
| Public detector aggregate | Permit only record/segment/UTF-8-byte completion, records with findings, total findings, and validated entity-type counts; require connector equality. |

## Actors and assumptions

- The operator controls command arguments and local artifact locations.
- Supplied objects, source paths, state, and stores may be hostile or privacy-sensitive.
- A local user, logger, dependency, receiver, or CI actor may observe outputs.
- The operator is responsible for creating a complete quiescent/full-filesystem snapshot before
  WP7B receives it; RAGLeakGuard cannot prove that external event.
- The process is not a sandbox; a compromised dependency inherits process permissions.
- The operator may misread a zero exit or familiar success phrase as evidence of a completed scan.

## Threats, controls, and residual risks

| Threat | Current control | Residual risk / limitation |
|---|---|---|
| Chroma mutates a production source during inspection | Every direct/live entry point is disabled; the active route copies a separately created operator snapshot before Chroma construction. | RAGLeakGuard does not prove snapshot provenance, quiescence, completeness, or transactional atomic consistency. |
| Traversal, link, reparse, mount, ADS, sparse-file, or replacement tricks escape confinement | WP7B rejects symlinked roots/parents, path overlap, cross-device entries, non-regular objects, hard links, sparse files, reparse points, and Windows named streams; it uses no-follow opens plus pre/post object identity checks. | A same-account administrator, kernel/filesystem compromise, or unexercised filesystem semantic can defeat process-level checks. |
| Mutable source yields a torn or incomplete work copy | Three source inventories, two work-copy inventories, source/copy content hashes, file/directory identities, count/size/depth ceilings, deadline checks, cancellation, and static failure prevent an observed inconsistency from returning a lease. | These checks narrow observable races; they do not create or prove transactionally atomic multi-file snapshot isolation, and a mutation can always occur after the final observation. |
| Attacker causes unbounded allocation or work | Hard maxima are 20,000 source files, 10,000 source directories, depth 16, 16 GiB per file, 64 GiB source bytes, 21,000 work files, 72 GiB work bytes, 1 MiB chunks, 1,800 seconds preparation, and 600 seconds cleanup/recovery; public values may only narrow them. | Free-space checks are time-of-check/time-of-use observations. A blocking kernel/filesystem call cannot be preempted by the cooperative monotonic deadline. |
| Cleanup deletes an operator path or an active work copy | Random exclusive workspaces, authenticated owner/snapshot/lease documents, resolved direct-child containment, filesystem-object identity, same-device no-follow recursive deletion, and an exclusive native lease are required before removal. | A crash can leave residue. Recovery deliberately stops on corrupt, forged, ambiguous, or actively leased candidates, so manual investigation may be required. Cleanup is deletion, not certified erasure. |
| Snapshot data or paths leak through the lifecycle | Control documents contain random identifiers only; raw fields stay inside the worker; IPC and public results are allowlisted aggregates; failures and success output are path-free; reports contain only `chroma-snapshot` plus escaped pseudonymous source ID. | The complete work copy necessarily contains the operator-provided bytes and is visible to the running account and administrators until cleanup. |
| Chroma observes or mutates the production source through the private layer | WP7C accepts only a re-authenticated live WP7B capability and starts the exact local client with the internally derived disposable payload as its working and persistence directory. Parent and child validate the held lease; the parent revalidates after worker exit and before the receipt. | The operator snapshot and its work copy remain sensitive. In-process malicious code, administrators, kernel compromise, and unproved platform behavior are outside this private process boundary. |
| Enumeration is incomplete, inconsistent, oversized, or mutates logical data | An authenticated ready-copy inventory precedes the worker. Exact migration/schema/catalog and record-bearing-table gates precede import; two explicitly paginated passes compare keyed collection, record, and canonical-content manifests plus counts. Every size, retained-entry, time, wait, IPC, and effect inventory has a hard ceiling. Post-exit semantic evidence must equal preflight evidence through a second final check immediately before capability validation and receipt creation. | Native calls can block below Python. Exact candidate evidence is environment-specific and can regress with transitive dependencies or runner changes. |
| Worker leaks data, starts another process, or attempts egress | The work path is supplied only as the controlled child working directory, not argv, environment, or IPC. The request contains fixed nonsensitive controls; the receipt contains counters only. Child stdout/stderr, nested processes, sockets, DNS, telemetry export, proxies, credentials, and embedding/model acquisition are denied; matrix jobs add OS-level outbound denial. | Python interception is not a general sandbox. The child inherits process permissions, and OS-level evidence proves only the exact tested environment. |
| Private candidate evidence is mistaken for broad connector support | Private modules remain unexported; the public wrapper accepts only exact 1.5.9 and the five named native tuples, while the ten-cell WP7C matrix remains private. | Transitive dependencies and runner images can regress; each immutable head still requires independent review. |
| Hostile path leaks through evaluation or errors | `read_chroma()` is a non-generator and raises one static public exception without coercion, formatting, attribute access, comparison, iteration, hashing, `str`, or `repr`. CLI output is also static. | Monitor scope authentication must process the operator-provided path string before pending recovery; this is not filesystem source access. |
| Failed snapshot scan corrupts an artifact or creates false evidence | No result survives detector, count, termination, revalidation, or cleanup uncertainty. Report build/write/fsync/replace/directory-sync failures preserve existing bytes or absence in tested recoverable paths and suppress success. | Power loss during namespace replacement/rollback and hostile storage semantics remain external. |
| Disabled monitor masks key/state or pending-alert failure | Webhook configuration and authenticated key/state validation retain precedence. A pending alert retains WP6 configuration, backoff, retry, transport, ambiguous-clear, and recovery semantics. | A permanently pending alert can block new scans indefinitely; new scans are independently disabled. |
| Pending recovery begins a source scan or creates a new alert | Recovery terminates after one due attempt or one established failure branch. It may only update retry metadata or atomically clear the existing pending entry. | Network-send and clear crashes remain ambiguous and may duplicate delivery. |
| Chroma re-enters through packaging | Base dependencies remain Chroma-free; the optional extra pins `chromadb==1.5.9`, and public runtime gates repeat that exact check. | Transitive dependencies are not fully locked. PyPI 0.1.0 remains unsafe for Chroma scanning until a separately authorized human action changes public package state. |
| Public prose overstates capability | English, Traditional Chinese, CLI help, architecture, threat model, security, contribution, release, and package claims are regression tested. | Historical artifacts require context and must not be read as current behavior. |
| Detector false negatives mistaken for absence | Reports state that detection is best-effort and absence is not proof of safety; findings are counted once on first-pass canonical segments and second-pass equality is independent. | No detector is complete; locale/model behavior and false negatives remain. |
| Alert replay or duplicate delivery | Existing HMAC framing, freshness, nonce cache, stable delivery ID, and durable atomic receiver interface remain unchanged. | Exactly-once, unconditional at-least-once, downstream processing, and human notification are not proved. |

WP7C classifies durable effects only inside the disposable work copy. Existing `chroma.sqlite3`
bytes may change only while exact schema, migrations, catalog, record queue, metadata, full-text,
sequence, configuration, and maintenance evidence remains equal. Existing native vector-segment
files may change only under a catalogued UUID directory and only for the explicit names
`data_level0.bin`, `header.bin`, `length.bin`, `link_lists.bin`, and `index_metadata.pickle`.
Creating or removing a path, changing any other path, exceeding 4,096 effect paths, or observing an
uncatalogued segment fails. The allowlist does not claim byte immutability, explain a dependency's
internal write, or make the operator source a Chroma target.

The ready-copy evidence is keyed by WP7B's 32-byte workspace authentication key and retained only
in the live capability. Parent semantic evidence uses a lease-scoped HMAC-derived key. The child
generates one random 32-byte session key for its two passes, with separate identity, content, and
collision-witness domains. Derived keys, the child key, and tokens remain process memory only and
are never IPC fields or receipt fields. Python cannot promise immediate secret zeroization, and
private types are not a sandbox against malicious code already executing in-process.

## Release and review triggers

Connector, state, report, dependency, release, egress, cryptographic, and public security-claim changes
require independent review. A passing test suite is evidence for the named commit and environment only.
It does not establish production safety or authorize merge, tag, package publication, yank, or release.
