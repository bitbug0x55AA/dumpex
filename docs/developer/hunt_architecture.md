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

Private-corpus handling is governed by `tests/corpus/README.md`; this ADR does
not duplicate that policy.
