# Thread evidence contract

Status: **implemented**. This contract covers shared thread acquisition and
its projections in `--threads`, `--report`, `--diff`, and thread-aware hunters.
Public compatibility details belong in
[Output Schema Migration](../user/OUTPUT_MIGRATION.md).

## Independent sources and bounded acquisition

`ThreadInfoListStream` supplies recorded starts, flags, and timing/status
fields. A thread's captured RIP/EIP comes independently from its base
`ThreadListStream` CONTEXT/WOW64_CONTEXT. Neither fact substitutes for the
other. Thread enumeration in `--threads` and report TID lookup use both streams.
An absent context is not a captured zero; zero is preserved as evidence but is
not a usable execution address or proof of divergent execution.

`parse_thread_info_stream` in `dumpex.core.memory` owns the stream layout.
All fields use the declared header and entry stride, bounded by the stream's
DataSize, file extent, and explicit count, stride, and total-byte ceilings
before reading. Invalid framing fails the stream; it never guesses offsets.
The upstream fixed-layout parser cannot safely supply these facts: short
reads can become zeros, extended strides can misalign entries, and its
single-member DumpFlags enum cannot represent combined flags.

A complete ThreadId is sufficient to retain a partial record. Every other
field must have its own captured bytes within the declared entry and stream
bounds; missing bytes are unknown, never zero. A record without a complete
ThreadId cannot be attributed and contributes a stream-truncation gap.
Keeping partial identified records also prevents fabricated removed threads
in `--diff`.

DumpFlags comes from the raw UINT32, with the upstream parsed value usable
only when it establishes a value. Zero confirms no flags; combined flags
retain every bit and render one tag per set bit. An unreadable value does not
establish absence of flags. `ERROR_THREAD` and `INVALID_INFO` disown all
record fields except ThreadId: StartAddress, CreateTime, ExitTime, KernelTime,
UserTime, and ExitStatus are unknown. The independent captured CONTEXT survives.

## Shared derivations and wire states

All five start-address consumers (`threads`, `report`, `diff`, injection,
and pipe) use `recorded_start_address`. A missing start is never replaced by
zero for module lookup, unbacked-thread scoring, or pipe proximity evidence.
An address with unreadable flags may remain visible but is unverified and
cannot contribute such evidence.

`threadRecord` and `reportThreadInfo` expose:

| Field | Contract |
|---|---|
| `start_address_state` | `recorded`, `invalid`, `unverified`, or `absent` |
| `dump_flags_state` | `resolved`, `unresolved`, or `absent` |
| `ip` / `ip_reg` | Captured RIP/EIP and register name, both present or both null |
| `ip_context_conflict` | True for captured context disputed by INVALID_CONTEXT, false when resolved without that dispute, null when flags cannot settle the question |

When `ip` is null, conflict is false: there is no captured value to dispute.
A captured zero can still conflict. Python records and the v2.20 schema
enforce start-state, flag-state, and address relationships in both directions.
An empty rendered flag list alone never establishes that flags were readable.

`ip_context_conflict_for` is the shared conflict derivation;
`enriched_thread_contexts` joins contexts to each TID's recorded start and
conflict state for commands and hunters. Rendered explanations consume the
same states: no record, invalid record, missing StartAddress bytes, and
unreadable flags must not be described as interchangeable causes.

## Report anchoring, membership, and scope

A TID card normally anchors on its recorded start (`anchor_source: tid`).
Without a usable start, a usable captured IP can anchor it instead
(`tid_current_ip`); the console identifies the substituted source and address.
This fallback examines real content and can change findings, verdict, coverage,
and exit status. An independently supplied report address remains explicit.

Other-thread membership is by start, current IP, or both in the card's region.
`region_membership` is `start`, `current`, or `start_and_current` on those
entries, and null on the anchor-thread entry, enforced bidirectionally by the
schema. `backing_module` and `module_context` always describe the recorded
start, including current-IP-only members. Such membership alone adds no new
finding; `unbacked_thread` still requires an established start.

`REPORT_CURRENT_IP_NOT_EXAMINED` and the console Scope line share one
classification. They distinguish absent context, captured zero, disputed or
unverifiable context, current IP outside the examined region, and no resolved
region. Conflict qualification applies even to zero or an IP inside the
region. A claim that only the thread's start was examined requires actual
containment of that start; with an independent address, the note names what
was examined instead. Missing StartAddress is distinct from missing module
evidence. These labels alone change no score or coverage.

## Coverage boundaries

- `THREAD_INFO_STREAM_TRUNCATED`: records without a full ThreadId leave the
  stream unable to settle the TID population.
- `THREAD_START_ADDRESS_UNAVAILABLE`: a delivered record cannot establish its
  start, including disowned fields, unreadable flags, or missing address bytes.
- `SOURCE_KEY_MISMATCH`: the base stream names a TID that a present thread-info
  stream does not describe; this is distinct from an unusable delivered record.

The first two gaps reach threads, report, diff, and injection. Per-TID mismatch
also reaches report and injection consistently with threads. Required gaps
make coverage partial and can move exit code 0 to 3; injection can become
INCONCLUSIVE instead of CLEAN. A report card whose own anchor thread is fully
described is not degraded by a different thread's per-TID gap.

Report records attribute the base stream as the `threads` coverage source;
its absence alone does not lower coverage status. Thread-info requirements
remain separate. `--threads` includes DumpFlags among thread-info-only fields
so degraded-source and per-TID mismatch limitations name the lost conflict
check as well as the lost start/timing evidence.

## Hunter context qualifications

Injection's `ThreadContext` and `RipHitEvidence` carry the recorded start and
tri-state conflict. Conflict defaults to None, not false, so omission cannot
assert confirmation. `InjectionEvidence` matches RIP hits to source contexts
by thread ID, IP/register, start address, and conflict state. `HuntThreadRef`
preserves starts and the same tri-state conflict on the wire.

`disputed_conflict_limitation` in `dumpex.hunt._finding` supplies the leading
qualification for `injection.allocation_correlation`,
`stomping.rip_in_anomalous_section_lead`, `stomping.verified_content_change`,
and `pipe.corroboration`. It names absent records versus unresolved flags
accurately. Qualification changes no score/confidence computation, even where
RIP correlation contributes to a score. CS Beacon has no corresponding scored
thread-reference projection in this contract.

`combine_conflicts` reduces True before None before False. Stomping publishes
`verified_changes[].rip_context_conflict` alongside `rip_in_changed_range`.
`VerifiedChangeEvidence.rip_conflicts` retains individual thread states and
must reduce to the combined value; caveat thread counts use those individual
states, never section counts. Pipe counts distinct TIDs rather than handles.

`injection.start_address_not_established` is an observation with a held-back
thread count and limitation, not a scored finding. It also contributes to
coverage: an unexamined start is not a checked negative. Removing fabricated
start-address evidence can reduce injection score from 1 to 0 while its
coverage-driven verdict becomes INCONCLUSIVE.
