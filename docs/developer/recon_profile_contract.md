# Recon `--profile` contract

Status: **implemented**. `--profile` is a released command in the current CLI
and is part of schema v2.13.

This document is the normative contract for the `--profile`
evidence-capability-map command. `dumpex/commands/profile.py`,
`dumpex/output/records.py`'s
`ProfileRecord` family, and the `PROFILE_*` entries in
`dumpex/output/coverage.py` implement against **this file alone**.

`--profile` is not a detector:

> Profile describes what evidence exists. Hunters interpret that
> evidence.

Nothing here produces a malicious/clean verdict, a confidence score, an
ATT&CK mapping, or duplicates a hunter's own detection logic. A capability
being "unavailable" means dumpex could not gather the evidence that
capability's real collector/hunter needs — never a claim that the
underlying activity is absent.

---

## Table of contents

- §0 Scope and non-goals
- §1 Shared vocabulary and ordering rules
- §2 The dump's own directory table: stream inventory
- §3 MINIDUMP_TYPE flags and memory-capture facts
- §4 The analysis-capability registry
- §5 Coverage and exit semantics
- §6 Complete code registry
- §7 Console and `to_dict()` shape

---

## §0 Scope and non-goals

### 0.1 What this contract covers

1. A loader fix (§2.5) closing the one directory-table-walk crash that
   would otherwise make "preserve unknown stream-type IDs" (§2.3)
   unreachable for a real dump.
2. The stream inventory (§2): one row per `MINIDUMP_DIRECTORY` entry,
   preserving duplicates and unrecognized numeric types.
3. MINIDUMP_TYPE flag decoding and memory-capture facts (§3), kept
   independent of each other by construction.
4. The closed, six-capability analysis matrix (§4).
5. Command-level coverage/exit semantics (§5), which are deliberately a
   DIFFERENT axis from any one capability's own availability.
6. The complete `LimitationCode`/`CapabilityLimitationCode` registry (§6).
7. Console and JSON record shape (§7).

### 0.2 Non-goals

- No malicious/clean verdict, finding, ATT&CK mapping, confidence, or
  risk score anywhere in the record or its console projection.
- No duplication or execution of hunter detection logic.
- No automatic hunter integration — shared hunter consumption of profile
  evidence is explicitly follow-on work, out of scope here.
- No new deep parser merely to improve the profile: every fact reported
  is read off an object `open_dump()` already parsed, or off the dump's
  own directory table/header — never a second walk of dump bytes.
- No full-memory scan, live-process query, or second evidence walk.
- No promise that an `available` capability guarantees complete capture
  of every relevant artifact — it states that the REQUIRED evidence for
  that capability exists, nothing about what a hunter would find in it.
- No schema or CLI change outside the released `--profile`/v2.13 contract.

---

## §1 Shared vocabulary and ordering rules

- **Source** — an internal key naming one piece of evidence a capability
  can require: `sysinfo`, `modules`, `threads`, `thread_info`,
  `memory_info`, `handles`, or the derived `memory_content` (§3.2). These
  are the exact strings that appear as `CapabilityLimitation.source` and
  as keys in `CoverageReport.sources` — never a display name.
- **Display name** — the human-facing minidump stream name for a source,
  used ONLY when rendering text (`dumpex.output.records.
  CAPABILITY_SOURCE_DISPLAY_NAMES`), never stored in a record field.
- Every ordering below is **directory order** (streams) or **frozen
  registry order** (capabilities) — never alphabetical, never
  insertion-order-of-a-dict, never sorted by count.
- `null` means "this fact could not be established"; an empty
  tuple/list/`0` means "established, and the answer is none/zero". The
  two are never conflated (§2.2, §3.2).
- Every closed-vocabulary field (`parser_state`, `status`, `code`) is
  validated at construction time by the record's own `__post_init__` —
  never left to caller discipline (see `dumpex/output/records.py`).

---

## §2 The dump's own directory table: stream inventory

### 2.1 What `streams` is

`ProfileRecord.streams` is one `ProfileStreamEntry` per entry in the
dump's own `mf.directories` (populated by `open_dump()`'s Phase 1,
independent of whether any per-stream parser in Phase 2 later succeeded)
— in **directory order**, `directory_index` equal to its position. A
duplicate stream type gets one row per physical entry (§2.4); an
unrecognized numeric type gets its own row too (§2.3). Nothing is merged,
deduplicated, or dropped.

### 2.2 The five stream states

Distinguished per entry:

| State (`parser_state`) | Meaning |
| --- | --- |
| `parsed` | Present; dumpex parsed it. A collection stream reports a real `record_count` — usually positive, but `0` when the stream declares more items than dumpex actually read (e.g. a truncated `HandleDataStream`: `NumberOfDescriptors > len(handles)`), together with a `detail` naming the shortfall (§2.2.1); a singular stream (`sysinfo`, `misc_info`) reports `record_count = null` — "empty" is not a meaningful state for a singular stream. |
| `present_empty` | Present; dumpex parsed it and verified it carries zero items, with nothing declared beyond what was read (no truncation). `record_count = 0`, `detail = null`. |
| `unparsed` | Present; dumpex has no parser registered for this stream type — either a recognized `MINIDUMP_STREAM_TYPE` member dumpex doesn't implement (e.g. `FunctionTableStream`), or a numeric type this build's minidump library has never heard of at all (§2.3). |
| `failed` | Present; dumpex attempted to parse it and the parse raised, OR the entry is directory-present with no recorded failure yet the parsed attribute is still `None` (unreachable through today's `open_dump()`, handled defensively the same way `dumpex.commands.handles`' own case-2 defense is — see `_UNPARSED_ATTR_STREAM_DETAIL` in `dumpex/commands/profile.py`). |
| `indeterminate` | Present, but ≥2 directory entries share this stream type and their combined outcome cannot be attributed to one entry (§2.4). |

"Absent" is not a per-entry state — it is the absence of any row for that
type at all.

#### 2.2.1 Item-level truncation stays `parsed`, never `present_empty`

A collection stream's own declared item count (today, only
`HandleDataStream.header.NumberOfDescriptors`) is checked *before*
deciding between `parsed` and `present_empty` — not after. `record_count
== 0` is only reported as `present_empty` when the stream's own declared
count is also `0` (or the stream type has no declared-count signal at
all): a genuinely, verifiably empty collection. A stream that declares
`NumberOfDescriptors = 100` but yields `len(handles) == 0` — the array
was truncated before a single descriptor could be read — is `parsed`
with `record_count = 0` and a `detail` naming the shortfall, the exact
same treatment a partial truncation (`declared=100, actual=10`) already
gets. Reporting it as `present_empty` would assert "verified empty",
which is not what the evidence shows — the 100 declared items are
genuinely unread, not genuinely absent. The same fact flows through to
capability gating (§4): `handles` lands in `truncated_source_names`
either way, so `handle_analysis`/`injector_handle_assessment` degrade to
`limited`/`REQUIRED_SOURCE_TRUNCATED` regardless of whether the
truncation left 10 items or 0.

### 2.3 Unrecognized stream types

`stream_type_id` is always the raw numeric `MINIDUMP_STREAM_TYPE` value.
`stream_type_name` is the enum member's own name, or `null` when the
numeric id is not a recognized member. An unrecognized type is always
`unparsed` (dumpex cannot parse a stream type it does not even recognize),
never dropped from `streams`.

### 2.4 Duplicate stream types: `indeterminate`

**Only applies to a DISPATCHED stream type** (§2.2's `unparsed` state
already covers everything else). A duplicated stream type dumpex has no
parser for at all (a recognized-but-unimplemented member like
`FunctionTableStream`, or any unrecognized numeric value, §2.3) has no
`mf.<attr>`/`_dumpex_stream_failures` slot for Phase 2 to entangle in the
first place — each such entry is independently, unambiguously
`unparsed`, never `indeterminate`. `_build_stream_inventory` checks
`DISPATCHED_STREAM_TYPES` membership *before* the duplicate-entry check
for exactly this reason: reversing the order would falsely claim
something was lost to entanglement, and would falsely downgrade
command-level coverage to `partial` (`PROFILE_STREAM_STATE_AMBIGUOUS`)
for a fact that isn't actually ambiguous at all.

`open_dump()`'s Phase 2 parse loop keeps exactly **one**
`mf.<attr>`/`_dumpex_stream_failures[stream_type]` pair **per stream
type**, overwritten by whichever duplicate directory entry's own
`setattr()` ran last. A later entry that raises does **not** clear an
earlier entry's own successful `mf.<attr>` value — so a recorded failure
for a type does not even guarantee `mf.<attr>` reflects a failed parse.
There is no way, from outside that loop, to recover which physical
directory entry the surviving state belongs to.

Every entry sharing an ambiguous stream type is therefore reported as
`indeterminate` with a non-null `detail` naming up to
`_MAX_DISPLAYED_DUPLICATE_INDEXES` (5) of the type's own directory
indexes plus a total count (never an unbounded list — `NumberOfStreams`
and `StreamType` are both attacker-controlled header fields, so building
an unbounded per-entry index list/string would be an easy algorithmic-
complexity DoS over a small, easily crafted file), rather than guessing
which one "really" produced the surviving `mf.<attr>`/failure state. This
is what drives `PROFILE_STREAM_STATE_AMBIGUOUS` (§5, §6) — `partial`,
never `complete`, whenever it fires.

**The ambiguity propagates past the inventory row.** Every other fact
this contract derives from the same `mf.<attr>`/`stream_failure()` pair —
`architecture` (§3.1, `sysinfo`), `captured_segment_count`/
`captured_bytes_total` (§3.2, `Memory64ListStream`/`MemoryListStream`),
and every capability source built from it (§4) — is *also* untrustworthy
whenever that stream type is ambiguous, even in the case where every
duplicate entry happened to parse without error: `mf.<attr>` still only
ever reflects ONE of them, and there is no way to know it is the "right"
one. `dumpex.commands.profile._stream_source_observation()` and
`_memory_content_observation()` both check the ambiguous-type set
*before* consulting `stream_failure()`/`mf.<attr>` at all, folding an
ambiguous source into the same `FAILED` state as a genuine parse failure
(§4.5) — there is no separate "ambiguous" capability status/limitation
code; `FAILED` is the closed vocabulary's existing conservative answer
for "this evidence exists but cannot be trusted." `architecture` and the
memory-capture byte/segment counts are nulled the same way, directly in
`collect_profile()`/`_build_memory_capture()`, rather than left to report
a confident value sourced from data the record's own `streams` entry
next to it already calls indeterminate.

### 2.5 Loader fix: the directory walk itself must not crash, and must not fabricate or drop entries

The installed minidump library's own
`MINIDUMP_DIRECTORY.parse()` raised `ValueError` for any raw `StreamType`
value that is neither a recognized `MINIDUMP_STREAM_TYPE` member nor
greater than `LastReservedStream` (0xFFFF, the real Microsoft
`MINIDUMP_USER_STREAM` range, which the library instead silently
**drops** — returns `None` without even reading that entry's own
`Location` — per Microsoft's own "a tool that doesn't understand a user
stream should ignore it" documented guidance). That exception was
uncaught inside `MINIDUMP_DIRECTORY.parse()` and propagated straight out
of `open_dump()`'s Phase 1 try/except, aborting the **entire** dump open
with `exit(1)` — for a dump that may otherwise be perfectly analyzable,
and for every dumpex command, not just `--profile`.

§2.3's own requirement ("preserve unknown stream-type IDs") would
otherwise be unreachable for a real dump — only exercisable through a
hand-built test fixture. `dumpex.core.memory._parse_directory_entry()`
closes this gap: **every** unrecognized `StreamType` value — whether
`>0xFFFF` or a gap value in the named range — is preserved as its own
row (the raw int, with `Location`/Rva/DataSize parsed normally), never
crashing and never silently dropped. This is a deliberate departure from
the upstream library's own `>0xFFFF` drop: the current contract
("Every directory entry is represented" / "preserve unknown stream-type
IDs rather than silently dropping them") make no exception for a real
`MINIDUMP_USER_STREAM`, so none is made here either.

**The walk is also bounded against the file's own real size.**
`header.NumberOfStreams` is an attacker-controlled `uint32` with no
required relationship to the file's actual length. Reading past EOF does
not raise — `file.read(n)` silently returns fewer than `n` bytes (`b''`
at the very end), and `int.from_bytes(b'', ...)` is `0`, a real,
recognized `MINIDUMP_STREAM_TYPE.UnusedStream` value — so an unbounded
walk fabricates additional plausible-looking directory entries out of a
file that does not actually contain them: a file of only tens of bytes
declaring a near-`uint32`-max stream count previously turned into
minutes of CPU time and a `directories` list to match, none of it real.
`open_dump()` now bounds the walk to `(file_size - StreamDirectoryRva) //
12` entries before reading a single one, and records the shortfall
(`dumpex.core.memory.directory_truncated_count(mf)`) rather than
inventing rows to cover it — surfaced by `--profile` as
`PROFILE_DIRECTORY_TRUNCATED` (§6.1), never silently.

---

## §3 MINIDUMP_TYPE flags and memory-capture facts

### 3.1 Raw vs. recognized flags

- `raw_flags` — the header's own 64-bit `MINIDUMP_TYPE` union value,
  verbatim, or `null` only when the header's own trailing union+Flags
  bytes were themselves truncated
  (`dumpex.core.memory._correct_header_union`). This is a **directory/
  header** fact (§5), independent of any capability.
- `recognized_flags` — the `MINIDUMP_TYPE` member names whose bit is set
  in `raw_flags`, in `MINIDUMP_TYPE`'s own declaration order (never
  alphabetical, never bit-value order). Always `[]` when `raw_flags` is
  `null`.
- `unrecognized_flag_bits` — bits set in `raw_flags` that no known
  `MINIDUMP_TYPE` member covers; `0` when every set bit is recognized;
  `null` iff `raw_flags` is `null`.

### 3.2 Memory-capture facts are independent of the flag

**Do not infer `MiniDumpWithFullMemory` from `Memory64ListStream` alone.
Report the raw flag and observed memory evidence independently.**

`ProfileMemoryCapture.full_memory_flag_set` is read **only** from
`raw_flags`. `memory64_list_present`/`memory_list_present` (directory
presence) and `captured_segment_count`/`captured_bytes_total` (read off
`dumpex.core.memory.get_memory_segments()`, the same Memory64-preferred-
over-MemoryList table `read_region()` already resolves VAs against) are
read **only** from the dump's own directory table and parsed segment
lists. Neither side may ever be derived from the other — a
`MiniDumpNormal` dump that nonetheless carries a captured
`Memory64ListStream` reports `full_memory_flag_set: false` alongside a
real, positive `captured_segment_count`, and a `MiniDumpWithFullMemory`
dump with nothing actually captured reports `full_memory_flag_set: true`
alongside `captured_segment_count: null`. Both are real, reportable
mismatches, not something this contract's implementation may reconcile.

`captured_segment_count`/`captured_bytes_total` are `null` only when
**neither** `Memory64ListStream` nor `MemoryListStream` ever parsed at
all; they are `0`/`0` when one parsed but carried zero segments
(present-empty, not absent).

The **derived** `memory_content` source used by §4's capability registry
answers "are captured memory BYTES actually readable" — `PRESENT`/
`PRESENT_EMPTY` from the same segment table, `FAILED` from either
underlying stream's own parser failure (Memory64List preferred), `ABSENT`
only when neither stream was even captured.

---

## §4 The analysis-capability registry

### 4.1 Closed vocabulary

`ProfileRecord.capabilities` always contains **exactly** these six ids,
in this order (`dumpex.output.records.CAPABILITY_IDS`):

1. `memory_region_analysis`
2. `module_analysis`
3. `injection_artifact_analysis`
4. `thread_analysis`
5. `handle_analysis`
6. `injector_handle_assessment`

Each entry's `status` is one of `available` / `limited` / `unavailable`
(`CapabilityStatus`), enforced consistent with its own `limitations`
tuple at construction time (§4.3).

### 4.2 Per-capability required/optional sources

Chosen to match dumpex's **actual current** collectors/hunters — never
invented for `--profile` alone. `Required` is a tuple of OR-**groups**:
each group is one or more alternative source names where **at least
one** must be usable; a single-member group is an ordinary hard
requirement.

| Capability | Required (OR-groups) | Optional | Backing collector/hunter |
| --- | --- | --- | --- |
| `memory_region_analysis` | (`memory_info`) | — | `dumpex.commands.list_cmd` (`--list`) |
| `module_analysis` | (`modules`) | — | `dumpex.commands.modules` (`--modules`) |
| `injection_artifact_analysis` | (`memory_info` **or** `thread_info`) | `modules`, `threads`, `memory_content` | `dumpex.hunt.injection` — its own not-evaluated gate is literally `evaluation_sources=("memory_info", "thread_info")` (`dumpex.hunt.injection.report_facts.project_coverage_report`), an OR-group: the hunter still runs — and reports real per-region `PE_HEADER_READ_FAILED`/`_SHORT_READ` facts — on either stream alone, and even with zero captured memory bytes. `memory_content`, `modules` (known/unknown classification), and `threads` (unbacked-region correlation) are therefore optional enrichment, matching the hunter's own `SourceRequirement`-only (never evaluation-group) treatment of them. |
| `thread_analysis` | (`threads` **or** `thread_info`) | `modules` | `dumpex.commands.threads` (`--threads`) — its own gate is `evaluation_sources=("threads", "thread_info")`: `collect_threads()` builds real records from `ThreadInfoListStream` alone when `ThreadListStream` is absent (reporting a specific field-level limitation, never `not_evaluated`), confirmed by reading `collect_threads()` directly. |
| `handle_analysis` | (`handles`) | — | `dumpex.commands.handles` (`--handles`) |
| `injector_handle_assessment` | (`handles`) | `threads` | The SAME `HandleDataStream` evidence `handle_analysis` uses, answering a DIFFERENT analytical question (discussion #94's "handle-based assessment of potential injector activity") that no dumpex hunter implements yet — this capability id exists so that future work's evidence boundary is already visible today (§0.2's own "no automatic hunter integration" non-goal). |

`required_sources` on the record itself is the flattened, deduplicated,
order-preserving union of every required group's members — a **static**
per-`capability_id` fact that never varies by which member happened to
satisfy a group in any one instance (e.g. `thread_analysis` always
reports `required_sources: ["threads", "thread_info"]`, whether the dump
actually had one, the other, or both).

### 4.3 Status derivation (closed, deterministic)

```
for group in required_groups:
    satisfied = any(member's effective state == "ok" for member in group)
    if satisfied:
        # every OTHER, unsatisfied member of this SAME group degrades to
        # an optional-like gap instead of being silently dropped
        limitations += OPTIONAL_SOURCE_* for each non-"ok" sibling
    else:
        required_ok = False
        limitations += REQUIRED_SOURCE_* for every member (all failed to satisfy)

if not required_ok:
    status = unavailable
else:
    limitations += OPTIONAL_SOURCE_* for each non-"ok" optional source
    status = limited if limitations else available
```

A source's "effective state" is `"ok"` for `PRESENT`/`PRESENT_EMPTY`
(§4.3's own "present-empty satisfies a required source" rule — matching
`--handles`' own case-4 "present-empty is complete, not a failure"
philosophy — a region table verified to hold zero entries is examinable
evidence, not a gap), `"indeterminate"` when that source's own stream
type is ambiguous (§2.4, checked *before* consulting its
`SourceObservation.state` at all — see §4.5), `"failed"` for `FAILED`,
`"absent"` otherwise.

Enforced at construction time by `ProfileCapabilityEntry.__post_init__`
(`dumpex/output/records.py`) — a caller cannot construct
`status="available"` while still attaching a `REQUIRED_SOURCE_*`
limitation, or `status="unavailable"` with none at all. A limitation's
`source` must be one of the capability's own `required_sources ∪
optional_sources` (not narrowed to exactly one half — an OR-group's
unsatisfied sibling legitimately carries an `OPTIONAL_SOURCE_*` code
while its own name still lives in `required_sources`). **Missing
optional corroboration may make a capability `limited`, but must never
erase available preferred-source evidence** — `required_sources` stays
on the record regardless of `status`.

### 4.4 Missing `HandleDataStream`

A missing `HandleDataStream` makes **both** `handle_analysis` and
`injector_handle_assessment` `unavailable`, each carrying exactly one
`REQUIRED_SOURCE_ABSENT` limitation whose rendered `detail` is a plain
evidence-boundary sentence ("HandleDataStream is not present in this
dump") — it must never produce or imply a clean/negative finding (no
"no suspicious handles", no "clean").

### 4.5 Consistency with the stream inventory (§2)

A capability's own source gating (§4.3) must never disagree with that
same stream's own row in `streams` (§2) — enforced by construction, not
merely by convention:

1. **Directory-present, never-parsed (§2.2's defensive `failed` row).**
   `dumpex.commands.profile._stream_source_observation()` is the ONE
   function both the capability registry and (indirectly, by
   construction) the stream inventory's own resolution agree through:
   both fall back to `has_stream_directory()` before calling a
   directory-present, object-`None` stream `ABSENT`, so this case always
   gates the corresponding capability's effective state as `"failed"`
   (→ `REQUIRED_SOURCE_FAILED`/`OPTIONAL_SOURCE_FAILED`), never
   `"absent"`.
2. **Ambiguous (duplicate-entry) stream types (§2.4).**
   `dumpex.commands.profile._member_effective_state()` checks the
   ambiguous-type set *first*, before `stream_failure()`/`mf.<attr>` are
   consulted at all — so a capability can never read `available`/
   `limited` off a stream whose own inventory row reads `indeterminate`,
   even when every duplicate entry happened to parse without error. This
   produces a DEDICATED `*_SOURCE_INDETERMINATE` limitation (§6.2) —
   deliberately NOT `*_SOURCE_FAILED`, whose fixed template asserts
   "could not be parsed", a specific factual claim that is not always
   true here (every duplicate entry may have parsed cleanly; dumpex
   simply cannot attribute the surviving state to one of them).
   Publishing the `FAILED` wording for a genuinely unattributable — not
   necessarily failed — evidence gap would itself be a fabricated
   negative finding, exactly what #95's own correctness requirements
   forbid.

---

## §5 Coverage and exit semantics

Command-level coverage (`--profile`'s own `CommandResult.coverage`)
answers **"did profiling itself complete"**, not "is every capability
available" — a capability being unavailable because a dump legitimately
never captured optional forensic evidence is a fact ABOUT THE DUMP, and
must never, by itself, downgrade command-level coverage.

- **`complete` / exit 0** — the directory/header facts needed to
  evaluate the profile were read successfully, even when one or more
  capabilities are `unavailable`.
- **`partial` / exit 3** — a usable profile is produced but:
  - the raw `MINIDUMP_TYPE` flags could not be read
    (`PROFILE_FLAGS_UNAVAILABLE`), or
  - the architecture could not be read (`PROFILE_ARCHITECTURE_UNAVAILABLE`
    — `SystemInfoStream` absent; a *failed* `SystemInfoStream` renders via
    the generic `SOURCE_FAILED` template instead), or
  - a present stream's own parser state could not be determined
    accurately because of a duplicate directory entry
    (`PROFILE_STREAM_STATE_AMBIGUOUS`, §2.4), or
  - the dump's own header declared more directory entries than the file
    is actually large enough to hold (`PROFILE_DIRECTORY_TRUNCATED`,
    §2.5), or
  - captured memory content came from the `MemoryListStream` fallback
    because the preferred, richer `Memory64ListStream` genuinely failed
    to parse (`PROFILE_MEMORY_CONTENT_FALLBACK`, §3.2) — the real
    fallback data is still reported, never nulled, but the fact that the
    richer stream failed must not stay silent.
- **`not_evaluated` / exit 4** — no defensible capability profile can be
  constructed at all (`PROFILE_DIRECTORY_UNAVAILABLE`: the header itself
  never parsed). Unreachable through today's `open_dump()` — a header
  that fails to parse aborts the whole dump open with exit 1 before any
  command runs — handled the same "fail closed for a state that could
  occur if internals changed" way `dumpex.commands.handles`' own case 1
  is. `collect_profile()` short-circuits BEFORE computing the stream
  inventory, capability matrix, or any other completeness check in this
  state — not merely before returning them: a stray leftover `mf.<attr>`
  on a hand-built (non-`open_dump()`) `mf` must never let
  `summary.capability_summary` assert a capability is `available` in the
  same result that says no defensible profile could be constructed.
  `collect_profile()` returns **zero** records and an all-zero
  `capability_summary` in this state.

This table (§6.1's own status column) is the authoritative enumeration
of every `PROFILE_*` command-level code — this section is a summary of
it, not a second source of truth; the two are re-synchronized by hand
whenever a code is added and must never drift.

---

## §6 Complete code registry

### 6.1 Command-level (`dumpex.output.coverage.LimitationCode`)

| Code | Status | Source | Fields |
| --- | --- | --- | --- |
| `PROFILE_DIRECTORY_UNAVAILABLE` | not_evaluated | `profile_directory` | none |
| `PROFILE_FLAGS_UNAVAILABLE` | partial | `profile_directory` | none |
| `PROFILE_ARCHITECTURE_UNAVAILABLE` | partial | `sysinfo` | none |
| `PROFILE_STREAM_STATE_AMBIGUOUS` | partial | `profile_directory` | `affected_count` = number of ambiguous **stream types** (not entries) |
| `PROFILE_DIRECTORY_TRUNCATED` | partial | `profile_directory` | `affected_count` = `dumpex.core.memory.directory_truncated_count(mf)`: directory entries `header.NumberOfStreams` declared that the file was not actually large enough to back (§2.5) |
| `PROFILE_MEMORY_CONTENT_FALLBACK` | partial | `memory_content` | `detail` (required) = Memory64ListStream's own parser error text. Fires when Memory64ListStream (preferred) genuinely failed to parse but MemoryListStream (fallback) still produced real segment data — `memory_capture`'s own counts are kept (real, trustworthy data), but the fact that the richer preferred stream failed is a genuine coverage gap and must not stay silent. Never fires when Memory64ListStream is instead *ambiguous* (§2.4) — that case is `PROFILE_STREAM_STATE_AMBIGUOUS`/`memory_content`'s own INDETERMINATE fold instead, a different fact with different wording. |

### 6.2 Capability-level (`dumpex.output.records.CapabilityLimitationCode`)

A **separate, closed vocabulary** from §6.1 — these describe one
capability's own evidence gap, never command-level coverage, and never
become a `dumpex.output.coverage.CoverageLimitation`.

| Code | Meaning |
| --- | --- |
| `REQUIRED_SOURCE_ABSENT` | A member of a required OR-group (§4.2) with NO OTHER member satisfying that same group is not present in the dump at all — the whole group, and therefore the capability, is blocked. |
| `REQUIRED_SOURCE_FAILED` | Same, but dumpex genuinely attempted to parse the source and it raised. |
| `REQUIRED_SOURCE_INDETERMINATE` | Same, but the source's own stream type has duplicate directory entries (§2.4) — its parse outcome cannot be attributed to any one entry, so neither ABSENT nor FAILED would be a true statement. |
| `REQUIRED_GROUP_MEMBER_ABSENT` | A member of a required OR-group is absent, but a DIFFERENT member of that SAME group already satisfies the group — the capability degrades to `limited`, not `unavailable`. Deliberately NOT `OPTIONAL_SOURCE_ABSENT`: this source is still a genuine `required_sources` member, and that code's fixed wording ("optional corroborating evidence") would be false for it. |
| `REQUIRED_GROUP_MEMBER_FAILED` | Same, but the unsatisfied sibling is present and could not be parsed. |
| `REQUIRED_GROUP_MEMBER_INDETERMINATE` | Same, but the unsatisfied sibling is ambiguous (§2.4). |
| `OPTIONAL_SOURCE_ABSENT` | A source that is PURELY optional (never a member of any required OR-group) is absent — degrades to `limited`, never erases available required-source evidence. Construction-time enforced (`ProfileCapabilityEntry.__post_init__`) to never name a `required_sources` member — that combination must use `REQUIRED_GROUP_MEMBER_*` instead. |
| `OPTIONAL_SOURCE_FAILED` | Same, but present and could not be parsed. |
| `OPTIONAL_SOURCE_INDETERMINATE` | Same, but ambiguous (duplicate directory entries, §2.4). |
| `REQUIRED_SOURCE_TRUNCATED` | A required-group member (satisfying its own group, whether that group has one member or several) is present, unambiguous, and genuinely parsed — but the underlying stream declares MORE items than dumpex actually read (e.g. `HandleDataStream`'s own `NumberOfDescriptors` exceeding `len(handles)`). The group is still satisfied — real, if incomplete, data exists, so this degrades to `limited`, never `unavailable` — but the shortfall must not stay silent. Distinct from `REQUIRED_GROUP_MEMBER_*`, which describes an UNSATISFIED sibling; a truncated source IS the satisfying one (or the capability's only option), just incompletely so — and is therefore allowed on a single-member group's sole member, unlike `REQUIRED_GROUP_MEMBER_*`. |
| `OPTIONAL_SOURCE_TRUNCATED` | `REQUIRED_SOURCE_TRUNCATED`'s companion for a PURELY optional source. |

`ProfileCapabilityEntry.required_source_groups` carries the actual
OR-group structure (a tuple of groups, each a tuple of alternative
source names) that `required_sources` alone — the flattened,
order-preserving union, kept for convenience and validated to always
equal exactly that derivation — cannot express. A consumer that only has
`to_dict()`'s output (e.g. a future JSON schema validator) can still
reproduce §4.3's status derivation from `required_source_groups` plus
`limitations` alone, with no access to `ambiguous_types` or any other
out-of-band collector state.

Each `CapabilityLimitation`'s `detail` is derived, never caller-composed,
from `(code, source)` via `dumpex.output.records.
render_capability_limitation()` — the SAME function the console renderer
calls (`dumpex.commands.profile.render_profile_console`), so the console
line and the JSON `detail` can never read two different sentences for
the same `(code, source)` pair.

---

## §7 Console and `to_dict()` shape

`ProfileRecord.to_dict()`:

```json
{
  "architecture": "AMD64",
  "raw_flags": 2,
  "recognized_flags": ["MiniDumpWithFullMemory"],
  "unrecognized_flag_bits": 0,
  "memory_capture": {
    "full_memory_flag_set": true,
    "memory64_list_present": true,
    "memory_list_present": false,
    "captured_segment_count": 3,
    "captured_bytes_total": 4096
  },
  "streams": [
    {
      "directory_index": 0,
      "stream_type_id": 7,
      "stream_type_name": "SystemInfoStream",
      "parser_state": "parsed",
      "record_count": null,
      "detail": null
    }
  ],
  "capabilities": [
    {
      "capability_id": "handle_analysis",
      "status": "unavailable",
      "required_source_groups": [["handles"]],
      "required_sources": ["handles"],
      "optional_sources": [],
      "limitations": [
        {"code": "REQUIRED_SOURCE_ABSENT", "source": "handles",
         "detail": "HandleDataStream is not present in this dump"}
      ]
    },
    {
      "capability_id": "thread_analysis",
      "status": "limited",
      "required_source_groups": [["threads", "thread_info"]],
      "required_sources": ["threads", "thread_info"],
      "optional_sources": ["modules"],
      "limitations": [
        {"code": "REQUIRED_GROUP_MEMBER_ABSENT", "source": "thread_info",
         "detail": "ThreadInfoListStream is not present in this dump, but a different required-group member for this capability already is -- treated as a degraded (not blocking) gap"},
        {"code": "OPTIONAL_SOURCE_ABSENT", "source": "modules",
         "detail": "ModuleListStream is not present in this dump (optional corroborating evidence)"}
      ]
    }
  ]
}
```

`architecture`/`stream_type_name`/capability ids/limitation codes are
never dump-derived free text — they are dumpex's own display names for a
closed-vocabulary integer enum or this registry's own frozen ids, so
console rendering treats them like any other dumpex-produced string.
`ProfileStreamEntry.detail` (a parser exception's own text, or this
module's own duplicate-entry explanation) IS potentially dump-influenced
(an exception message can embed bytes read from the dump) and is
`console_safe()`-escaped at the print site, exactly like every other
recon renderer's own `coverage.reasons` projection.

`render_profile_console()` consumes only the collected records and
`CoverageReport` — it takes no `mf` parameter and performs no capability
recomputation or dump re-read.

---
