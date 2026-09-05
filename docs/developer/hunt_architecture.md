# Hunt architecture

Status: **implemented**.

This ADR defines the current ownership and projection boundaries for `--hunt`.
It is intentionally about stable architecture, not the sequence in which the
hunters were migrated.

## Domain models stay hunter-specific

dumpex does not define a general `BaseEvidence` or `BaseReport` hierarchy.
Injection, hollowing, stomping, pipe, CS Beacon, YARA, and obfuscation retain
their own report, evidence, finding, and coverage-snapshot types. Their evidence
is not interchangeable: a YARA rule match, an injected PE candidate, a pipe
name, and a hollowed-image inconsistency do not share enough semantics to make a
common evidence base class honest.

Shared Hunt code is limited to primitives and reducers whose meaning is stable
across hunters, such as immutable scalar value objects, `CoverageReport`,
`HunterRecord`, deterministic summary reduction, region correlation, and the
ordered analyzer registry. A shared helper must not erase a hunter's domain
vocabulary merely to reduce class count.

## Ownership boundary

Each hunter package follows this division:

| Module | Owns |
|---|---|
| `domain.py` | Immutable domain evidence, the hunter report, hunter-local coverage state, and invariants that make an internally valid report |
| `report_facts.py` | Pure reduction from the domain report to verdict, score/confidence where applicable, coverage, limitations, and other facts consumed by more than one projector |
| `report_record.py` or `collect.py` | Typed conversion from one already-built domain report into the public `HunterRecord` and hunter-specific details record |
| `report_console.py` or the package console renderer | Presentation of the same report/facts for a human; layout, labels, truncation, and verbosity only |

Collection and detection belong before projection. Record and console
projectors consume the same report instance. A console projector must not
rescan memory or independently recalculate detection, score, confidence,
coverage, or limitation state. Cross-hunter summary code likewise reduces the
already-projected records rather than interpreting raw hunter evidence again.

## Console projection invariants

Console output may make retained evidence easier to inspect, but presentation
must not change the report it projects. In particular, verbosity, wrapping,
preview limits, and display escaping cannot change classification, finding
tags or IDs, scores, confidence, verdicts, review priority, coverage, structured
records, or exit behavior.

### Coverage has two presentation dimensions

`coverage.status` describes all evidence required by a hunter. Byte-scan
progress describes only the measurable memory workload, so a scan can be 100%
complete over eligible bytes while the overall status remains `partial`
because a stream, reference file, parsed header, or per-thread CONTEXT is
unavailable. The verdict card must state both facts rather than rendering a
bare `PARTIAL` or pairing it with a contradictory-looking zero-byte gap.

A byte figure describes a limitation only when it measures real unexamined
bytes. A limitation with no measurable extent, or a target for which the dump
captured zero bytes, remains a named/countable evidence gap instead of being
silently absorbed into the byte summary. Coverage presentation is bounded to
the available terminal width; additional reasons remain available in the full
`COVERAGE` section and in structured `coverage.limitations`.

The public examples and field interpretation are documented in
[Output and Evidence Schema](../user/OUTPUT_SCHEMA.md#the-console-row-states-two-dimensions).

### Dump-derived previews are bounded and terminal-safe

Every string derived from a dump must pass through the console-safety
projection before it is printed. This includes IOC strings extracted from
decoded content: an IOC recognizer may accept control bytes inside a matched
value, so escaping only the surrounding content preview is insufficient.
Structured output retains the original value.

Reusable byte previews live in `dumpex.ui.byte_preview`. They operate only on
bytes already retained by the report, never read the dump again, and follow
these rules:

- each preview shows a fixed-size leading byte prefix and explicitly reports
  the omitted byte or character count;
- UTF-8 text uses deterministic visible escapes for invalid bytes and for
  characters that could control or reorder terminal output;
- binary content uses lowercase hex, which is inert in a terminal;
- a SHA-256 covers the complete value whenever a text preview is truncated or
  the content is rendered as binary.

The obfuscation Base64 console projector applies separate bounds to the encoded
string, decoded text, decoded hex, and number of hits carrying content
previews. Every retained hit still keeps its VA, file offset, classification,
and size line. `plaintext` and `ioc_text` use escaped text; PE, shellcode,
binary, and high-entropy content use hex; PE output also reuses metadata already
parsed onto the classification. Full `raw` and `decoded` evidence remains in
the report and structured output.

## YARA is deliberately different

YARA exposes rule-oriented evidence. `matches` preserves match instances and
their string/rule metadata; `rules_hit` is the deterministic rule-name set or
sequence used by its public result. Neither is coerced into the generic
`Finding` vocabulary. YARA also has no score, confidence, lead count, or review
priority; those `HunterRecord` fields remain `null` for `hunter == "yara"`.
Keeping this distinction prevents rule-engine facts from acquiring semantics
that the engine did not establish.

## Deterministic structured output

Every structured-output boundary converts domain values through an explicit,
typed `to_dict()` or record projector. Output contains JSON-safe scalars,
arrays, and objects with stable ordering. Raw parser/library objects must never
fall through to `str(obj)`: default object representations can contain memory
addresses, host paths, or other non-deterministic and private values.

The public `HunterRecord` owns the common envelope; each hunter-specific details
record owns its closed payload. Coverage is serialized from the hunter's
authoritative coverage facts, and summary output is produced by the shared
deterministic reducer. JSON and console code must not maintain parallel copies
of those decisions.

## Cross-hunter investigation queue ordering

The `--hunt all` investigation queue keeps suspicion priority and evidence
availability as independent axes. Entries are ordered first by priority and,
within one priority level, by availability (`captured`, `partial`, then
`not_captured`). This makes the console's bounded action list lead with work
that can be performed from the current dump without allowing availability to
promote a less suspicious target across priority levels.

Priority reason codes must represent independent signals. Several scanners
recording failed reads against the same range whose bytes were never captured
are repeating one capture condition, not corroborating one another; that case
does not earn `MULTIPLE_SCOPES_SKIPPED`. Independent facts such as executable
private memory, RWX protection, or cross-hunter region correlation still raise
the target's priority even when its bytes were not captured. All contributing
relationships remain in `skipped_by` regardless of whether they add a priority
reason.

The public queue fields, ordering, and follow-up workflow are documented in
[Output and Evidence Schema](../user/OUTPUT_SCHEMA.md#hunt-investigation-actions).

Private-corpus handling is governed by `tests/corpus/README.md`; this ADR does
not duplicate that policy.
