# Recon `--process`/`--sysinfo`/`--handles` contract (issue #37)

**Status: decision record, revision 3.** Revision 2 fixed two confirmed
P0 defects from revision 1 (IAT directory attribution, containment vs.
exact-match module resolution) but left several things wrong or
underspecified, confirmed again this round by reading
`.venv/Lib/site-packages/minidump/minidumpfile.py` in full and
`dumpex/commands/sysinfo.py:93-119` directly (not from memory). Every
correction below is marked "rev2 error" or "rev2 gap" so the fix is
traceable; unmarked text is unchanged from rev2.

Grounded, as before, in the current tree plus this round's additional
direct reads: `.venv/Lib/site-packages/minidump/minidumpfile.py` (full),
`.venv/Lib/site-packages/minidump/structures/peb.py:125-140` (the
environment-block loop's exact termination logic), and `dumpex/commands/
sysinfo.py:93-119` (confirming which fields `mi`/`peb` actually back).

## 0. What exists today (baseline) — one correction this round

Unchanged from rev2 except:

- **`minidumpfile.py:82-88`, `_parse()`**: only `self.__parse_peb()` is
  exception-guarded. `self.__parse_directories()` (lines 103-…, which
  performs `self.handles = MinidumpHandleDataStream.parse(dir,
  self.file_handle)` at line 161) has **no exception handling at all** —
  every branch of its `elif` chain runs unguarded, sequentially, inside
  one loop. **Rev2 claimed an exception from `HandleDataStream` parsing
  "is caught by `MinidumpFile._parse()`'s broad handler, leaving
  `mf.handles = None`" — this is wrong.** A `HandleDataStream` parse
  exception propagates straight out of `__parse_directories()`, out of
  `_parse()`, past the `return mf` in `MinidumpFile.parse()` (the
  `@staticmethod` in `minidumpfile.py:48-54`), and out of `open_dump()`
  entirely — the caller receives **no `mf` object at all**, not an `mf`
  with `mf.handles is None`. This is a whole-dump-open failure, not a
  per-command coverage state, and it is not unique to handles — any
  stream's parser raising in `__parse_directories()` has the same effect
  (this is a pre-existing, general gap in how dumpex uses the library,
  not something introduced by this redesign). §3.5 defines exactly what
  `--handles` *can* and *cannot* distinguish given this real constraint.
- **`dumpex/commands/sysinfo.py:110-111`, confirmed by direct re-read**:
  `cpu_current_mhz`/`cpu_max_mhz` **are** sourced from `mi`
  (`MINIDUMP_MISC_INFO`/`_INFO_2`'s `ProcessorCurrentMhz`/
  `ProcessorMaxMhz`). **Rev2 incorrectly speculated `misc_info` "no
  longer backs any remaining field" post-redesign and punted the
  `SYSINFO_MISC_INFO_UNAVAILABLE` question to #41** — this was simply
  wrong; the two CPU-speed fields were never proposed for removal (§2.1)
  and still come from `misc_info` today. §2.6 now states this
  definitively instead of deferring it.
- **`structures/peb.py:125-140`, the environment-block loop, read again
  at the exact termination condition**: `while (env_len :=
  env_buffer.find(b"\x00\x00")) and (env_len != -1):`. Python's `and`
  makes this `False` (loop does not run) in **two different cases** that
  the resulting `[]` cannot be told apart from afterward: `env_len == 0`
  (double-null found at position 0 — a **verified, well-formed** empty
  block) and `env_len == -1` (**no terminator found at all** within the
  read window — a genuinely malformed/truncated block, `-1 and (-1 !=
  -1)` = `-1 and False` = `False`, loop never runs). **Rev2's claim that
  "`[]` unambiguously means captured-but-empty" is wrong** — the library
  collapses "verified empty" and "malformed, no terminator ever found"
  into the identical observable `[]`. Same ambiguity applies to a
  **partial** capture: if the block starts with real entries but a later
  terminator falls outside the captured memory segment, the loop simply
  stops (its own re-read is bounded by `buff_reader.current_segment.
  end_address`), silently keeping only the entries found so far with no
  "was this the true end or a lucky segment boundary" signal. §2.3
  replaces trusting `peb.environment_variables` at face value with a
  dumpex-owned bounded re-walk that tracks this distinction explicitly.

## 1. `--process`

### 1.1 Fields and exact JSON names

Unchanged from rev2:

| field | type | source |
|---|---|---|
| `process_name` | `string \| null` | basename of the selected path (§1.2) |
| `pid` | `integer \| null` | `MINIDUMP_MISC_INFO.ProcessId` only (§1.4) |
| `process_path` | `string \| null` | `peb.image_path` |
| `command_line` | `string \| null` | `peb.command_line` |
| `process_start_utc` | `string \| null` | `MINIDUMP_MISC_INFO.ProcessCreateTime` (§1.7) |
| `image_base_address` | hex address \| `null` | `peb.image_base_address` |
| `iat` | object | §1.5 |
| `identity_evidence` | object | §1.6 |
| `peb_extended` | object — key present iff `--verbose` | §1.3 |

### 1.2 Evidence precedence

Unchanged from rev2 — `resolve_module_by_base(base_address, modules)`
(exact `==`, not `addr_to_module()`'s containment) remains the primitive
#38 must add.

### 1.3 `peb_extended` — presence rule clarified (rev2 gap: not stated)

The key's presence depends **only** on `--verbose`, never on whether PEB
itself is available: `--process --verbose` always includes
`peb_extended` in the JSON, and its seven fields (`being_debugged,
window_title, dll_path, standard_input, standard_output, standard_error,
peb_address`) are all `null` when `peb` is unavailable — the same
"always present, nullable" convention every other field on this schema
uses, just gated as a whole object on `--verbose`. This avoids a second,
data-dependent layer of "is the key even there" ambiguity on top of the
verbosity gate.

### 1.4 PID has no fallback chain

Unchanged from rev2.

### 1.5 IAT shape — three refinements this round

Directory attribution (Import Directory index 1 for descriptors, IAT
Directory index 12 for `table_va`/`table_size`/bounds-checking) and the
`import_by` tagged discriminator are unchanged from rev2's correction.
Three gaps closed this round:

**1. Per-field nullability on a name/DLL read failure (rev2 gap: not
stated).** Per issue #39's "preserve captured IAT targets" instruction
(already applied to the whole-entry case in rev2), the same rule applies
field-by-field, not just to `symbol`/`ordinal`: if the DLL name's own
bytes fail to read (`IAT_NAME_READ_FAILED`), the entry is **still
reported**, with `dll: null` (never a placeholder string) — `import_by`/
`symbol`/`ordinal`/`iat_slot_va`/`resolved_target_va` keep whatever
values were independently recoverable, since a DLL-name read failure and
a symbol-name read failure are independent bounded reads at different
addresses. Each such per-field loss adds one `IAT_NAME_READ_FAILED`
occurrence (`affected_count`), not a separate code per field name.

**2. `slot_in_bounds: false` is a diagnostic, not a completeness gap
(rev2 error).** Rev2 listed every `IAT_*` code, including
`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS`, as driving `partial` coverage. That
is wrong for this one code specifically: `slot_in_bounds` only exists
because the read/walk **succeeded** — nothing failed, nothing was left
unexamined, dumpex simply found a suspicious value and is reporting it.
Treating a successfully-completed, informative check as an evaluation
gap would misrepresent a MORE complete result as a LESS complete one.
§1.8 corrects this: `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` is diagnostic-only
(same tier as `PROCESS_MODULE_BASE_UNMATCHED`/`_IDENTITY_MISMATCH`),
never a `completeness_checks` entry.

**3. Missing read-operation cap (rev2 gap).** Issue #39's own safety
requirements list "cumulative bytes/**read operations**" — two
independent bounds, not one. Rev2 only froze a byte budget
(`MAX_IAT_BYTES_READ`). Added: `MAX_IAT_READ_OPERATIONS = 8192` — a cap
on the total count of individual bounded-read calls across the whole
walk (guards against a pathological many-tiny-reads pattern a pure byte
budget wouldn't catch, e.g. thousands of 1-byte reads staying under the
byte cap while still hanging). Reaching this cap mid-walk fires
`IAT_ENTRIES_TRUNCATED` (the existing code, not a new one — the
observable effect, "walk stopped before naturally finishing," is
identical regardless of which of the two budgets triggered it).

All other `MAX_IAT_*` constants unchanged from rev2: `MAX_IAT_DLLS =
256`, `MAX_IAT_ENTRIES_PER_DLL = 4096`, `MAX_IAT_TOTAL_ENTRIES = 65536`,
`MAX_IAT_NAME_LENGTH = 512`, `MAX_IAT_BYTES_READ = 16 * 1024 * 1024`.

### 1.6 `identity_evidence` — `module_claim` redesigned to preserve a disagreeing claim (rev2 P0, this round's fix)

**Rev2 error, corrected here**: when `resolve_module_by_base()` finds no
exact match, rev2 set `module_claim.base_address`/`name` to `null` —
correctly representing "no exact match," but losing any independent
signal ModuleListStream might still offer about what the main module
*actually* is, which is exactly the data a genuine base-conflict
diagnostic needs. Fixed by adding a second, explicit lookup that only
runs when the exact-base match already failed:

```json
"module_claim": {
  "match_state": "unregistered",
  "base_address": null,
  "name": null,
  "name_matched_candidate": {
    "base_address": "0x00007ff600010000",
    "name": "malware.exe"
  },
  "name_matched_candidate_ambiguous": false
}
```

- `match_state`/`base_address`/`name`: unchanged meaning from rev2 —
  populated only when `match_state == "resolved"` (exact base match
  found).
- **`name_matched_candidate`** (new): populated only when `match_state ==
  "unregistered"` (exact match failed, `ModuleListStream` itself present)
  **and** a module exists whose basename (case-insensitive) equals
  `peb_claim.name`'s basename. Found via a second, deterministic pass
  over `modules` (first match by the list's own source order — no
  re-sort, matching this document's existing ordering convention) —
  reusing `dumpex.core.memory.module_name_only()`'s existing
  case-insensitive basename comparison, not a new string-matching rule.
  When found, this is a **positive base-conflict signal**: "PEB claims
  this image is `malware.exe` based at `0xAAAA`; `ModuleListStream`'s own
  `malware.exe` entry is actually loaded at `0xBBBB`" — a stronger,
  more specific claim than "no exact match" alone, and the concrete
  "independent main-module candidate, kept side by side" the review asked
  for. `null` (not an empty object) when no such candidate exists —
  `match_state == "unregistered"` alone, with nothing further to say.
- **`name_matched_candidate_ambiguous`**: `true` when more than one
  module shares that basename (rare, but not assumed impossible) — only
  the first (by source order) is reported in `name_matched_candidate`,
  and this flag says so explicitly rather than silently picking one of
  several candidates with no trace of the ambiguity.

**New diagnostic codes**, replacing rev2's single
`PROCESS_MODULE_BASE_UNMATCHED` with two tiers of a genuinely different
strength:

- `PROCESS_MODULE_BASE_UNMATCHED` — `match_state == "unregistered"` **and**
  `name_matched_candidate is null` (no exact match, nothing to corroborate
  or contradict either).
- `PROCESS_MODULE_BASE_CONFLICT` (**new**) — `match_state ==
  "unregistered"` **and** `name_matched_candidate` is non-null: the
  stronger, positive disagreement signal.
- `PROCESS_MODULE_NAME_AMBIGUOUS` (**new**) — `name_matched_candidate_
  ambiguous == true`, reported alongside (not instead of) whichever of
  the above two also fired.
- `PROCESS_MODULE_IDENTITY_MISMATCH`, `PROCESS_MAIN_IMAGE_PE_INVALID`,
  `PROCESS_MAIN_IMAGE_READ_FAILED`, `PROCESS_MAIN_IMAGE_SHORT_READ`:
  unchanged from rev2.

None of these are coverage-affecting (§1.8) — same reasoning as rev2:
optional corroboration, never required for completeness.

### 1.7 `process_start_utc` edge cases — range check added before conversion (rev2 gap)

**Rev2 error, corrected here**: rev2 relied solely on catching a
`datetime.fromtimestamp()` exception, which is platform-dependent — on
some platforms a negative or very large value converts successfully
(e.g. a pre-1970 or post-2106 date) without raising, even though
`ProcessCreateTime` is structurally a `UINT32` seconds-since-epoch field
(`MiscInfoStream.py`) whose only structurally valid range is `[0,
0xFFFFFFFF]` regardless of what any given host's C library happens to
accept. Corrected rule — validate the **type and range** before ever
calling `fromtimestamp()`:

```python
def classify_process_create_time(value):
    if not isinstance(value, int) or isinstance(value, bool):
        return "invalid"          # wrong type entirely
    if value == 0:
        return "unset"
    if not (0 <= value <= 0xFFFFFFFF):
        return "invalid"          # cannot be a real MINIDUMP_MISC_INFO field value
    return "ok"
```

`"unset"` → `null` + `PROCESS_START_TIME_UNSET` (unchanged from rev2).
`"invalid"` → `null` + `PROCESS_START_TIME_INVALID` (now fires for
out-of-range/negative values too, not only a `fromtimestamp()`
exception — closing the platform-dependent gap). `"ok"` → format as
`"%Y-%m-%d %H:%M:%S UTC"` (unchanged).

### 1.8 Coverage and exit semantics — field-level, not object-level (rev2 P1, this round's fix)

**Rev2 error, corrected here**: rev2's `not_evaluated` trigger,
`EvaluationRequirement(sources=("misc_info","peb"))`, only inspects each
source's `SourceState` — whether the `mi`/`peb` **objects** exist. But
`mi`/`peb` can each exist while contributing **zero** usable identity
fields: `MINIDUMP_MISC_INFO`'s `ProcessId`/`ProcessCreateTime` are each
independently gated by their own `Flags1` bit (confirmed earlier
research: a v1/v2 struct can be present with either or both bits unset),
and PEB's `image_path`/`command_line` can each independently be a
genuinely empty string (`peb.py`'s `read_unicode_string_property`
returns `""` for a zero-length string — not a failure, just nothing
there) — which this codebase's own existing convention (`peb.py:63-64`,
`sysinfo.py:105-107`, `... or None`) already treats as equivalent to
unavailable. A dump could therefore have both `mi` and `peb` as real,
non-`None` objects while **none** of the five identity-bearing fields
(`pid`, `process_start_utc`, `process_path`, `command_line`,
`image_base_address`) actually resolve to anything — under rev2's
object-level check this would incorrectly avoid `not_evaluated` even
though zero identity facts exist. Fixed with a field-level evaluation
group, hand-built (not derived by the generic `EvaluationRequirement`
reducer, which only understands `SourceState`, an object-presence
concept) — following the same `caller_buildable` precedent `--pid`'s own
`PID_NO_USABLE_FALLBACK` already set for a business fact the generic
reducer cannot infer from source state alone:

```python
identity_fields_available = (
    bool(mi and mi.ProcessId),
    bool(mi and mi.ProcessCreateTime),
    bool(peb and peb.image_path),
    bool(peb and peb.command_line),
    bool(peb and peb.image_base_address),
)
```

- **`not_evaluated`** (exit 4): **none** of the five are true — new
  code `PROCESS_SOURCES_ABSENT` (name unchanged from rev2, trigger
  condition corrected from object-presence to field-availability).
- **`partial`** (exit 3), two tiers:
  - **Object-level** (source itself entirely absent — unchanged from
    rev2): `mi is None` → `PROCESS_MISC_INFO_UNAVAILABLE` (covers both
    `pid`/`process_start_utc` at once); `peb is None` →
    `PROCESS_PEB_UNAVAILABLE` (covers `process_path`/`command_line`/
    `image_base_address` at once).
  - **Field-level** (**new** — source object present, one specific field
    still unavailable): `mi` present but `ProcessId` falsy →
    `PROCESS_PID_UNAVAILABLE`; `mi` present but `ProcessCreateTime`
    falsy → `PROCESS_START_TIME_UNSET`/`_INVALID` (§1.7, already
    field-level, unchanged); `peb` present but `image_path` empty →
    `PROCESS_PATH_UNAVAILABLE`; `peb` present but `command_line` empty →
    `PROCESS_COMMAND_LINE_UNAVAILABLE`; `peb` present but
    `image_base_address` falsy → `PROCESS_IMAGE_BASE_UNAVAILABLE`.
  - Plus, unchanged from rev2: any `IAT_*` completeness code **except**
    `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` (§1.5, now diagnostic-only); any
    of `PROCESS_MAIN_IMAGE_PE_INVALID`/`_READ_FAILED`/`_SHORT_READ`
    (dual-purpose, §1.6).
  - `PROCESS_MODULE_BASE_UNMATCHED`/`_CONFLICT`/`_IDENTITY_MISMATCH`/
    `_NAME_AMBIGUOUS`: diagnostic-only, never coverage-affecting
    (unchanged reasoning from rev2).
- **`complete`** (exit 0): all five identity fields resolved (whether
  directly or, for `process_name`/`process_path`, via the module-name
  fallback), IAT evaluated (including a validly-empty result), and
  `identity_evidence.diagnostics`/`module_claim` non-null entries do not
  by themselves downgrade this.

### 1.9 Console and summary — `iat.present=false` wording split (rev2 gap: single wording for two different meanings)

`summary = {"count": 1}`, unchanged. Console field block unchanged from
rev2. IAT section text now distinguishes the two different reasons
`present` can be `false`, rather than one shared `"(none captured)"`
string:

```
  Import Address Table
    <"N import(s) across M DLL(s)"                          if iat.present>
    <"(none -- valid PE with no imports)"                   if iat.present == false AND no
                                                               partial-driving IAT_* code fired>
    <"(unavailable -- see coverage below)"                   if iat.present == false AND a
                                                               partial-driving IAT_* code fired>
```

## 2. `--sysinfo`

### 2.1 Removed fields

Unchanged from rev2.

### 2.2 Added: `environment_variables`

Unchanged shape from rev2; §2.3 replaces how it's derived.

### 2.3 `environment_variables` — independent, bounded re-walk replaces trusting `peb.environment_variables` (rev2 P1, this round's fix)

**Rev2 error, corrected here**: §0's finding this round shows
`peb.environment_variables == []` is genuinely ambiguous between three
different underlying states the library itself cannot distinguish after
the fact — verified-empty, malformed/no-terminator-ever-found, and a
capture that ran out mid-block. Trusting `peb.environment_variables` at
face value (rev2's approach) cannot satisfy #37/#38's "preserve...
special Windows entries" and null-vs-`[]`-vs-partial requirements,
because the ambiguity already happened one layer down, inside the
library, before dumpex ever sees the list.

Fix: `--sysinfo` (via #38's shared layer) performs its **own**, bounded,
termination-tracking walk of the raw environment block — reusing the
*offsets* `PEB_OFFSETS[...]["environment_variables"]` already resolves
(`peb.py:21,41`, i.e. the same `process_parameters`-relative field the
library itself reads) but re-implementing the scan loop itself so the
termination outcome is observable, not silently discarded:

```python
def walk_environment_block(mf, peb, max_bytes=65536, max_entries=2048):
    """Returns (state, entries) where state is one of:
    'absent' (peb is None), 'present_empty' (verified terminator at
    offset 0), 'present' (>=1 entries, verified terminator found),
    'partial' (>=1 entries found, but max_bytes/max_entries or the
    captured memory segment ran out before a terminator), 'unparseable'
    (zero entries AND no terminator ever found within bounds)."""
    ...
```

Mirrors this codebase's own `SourceState` vocabulary
(`ABSENT`/`PRESENT_EMPTY`/`PRESENT`/`FAILED`) closely enough to be
modeled as its **own coverage source**, `"environment_block"` — a
derived source (the walk attempt itself, not a single named minidump
stream), following the exact precedent `coverage.py` already documents
for `"thread_context"` ("a derived source: 'at least one thread's CONTEXT
was successfully parsed'"). `--sysinfo`'s coverage sources dict grows
from five entries to **six**: `sysinfo, misc_info, peb, threads, modules,
environment_block`.

- `state == "absent"` (`peb is None`) → `environment_variables = null`,
  no new limitation (subsumed by the existing `SYSINFO_PEB_UNAVAILABLE`).
- `state == "present_empty"` → `environment_variables = []`. `complete`
  for this source.
- `state == "present"` → `environment_variables` = the walked list (see
  reconstruction below). `complete`.
- `state == "partial"` (**new** — not representable at all under rev2's
  model) → `environment_variables` = the entries found so far (not
  discarded — same "preserve what's known" precedent as IAT/handles), plus
  new code `ENVIRONMENT_BLOCK_TRUNCATED` (`caller_buildable`, source
  `"environment_block"`) → drives `partial`.
- `state == "unparseable"` (**new**) → `environment_variables = null`
  (this is NOT a verified empty capture — treating it as `[]` would be
  exactly the "false empty result" #37 warns against), plus new code
  `ENVIRONMENT_BLOCK_UNPARSEABLE` → drives `partial` (not
  `not_evaluated` — `peb` itself, and everything else on `SysInfoRecord`,
  may still be fully valid; only this one field's evidence is bad).

**Special `=`-prefixed entry reconstruction**: unchanged algorithm from
rev2 (split the library's mangled `name=""` output on `value`'s own
first `=`), now applied to entries produced by dumpex's own walk rather
than the library's `peb.environment_variables` list — the reconstruction
logic itself doesn't change, only which raw entries it runs against.

### 2.4 Sensitivity

Unchanged from rev2.

### 2.5 Console — full section layout (rev2 gap: only a two-line sketch)

```
  ═══ ENVIRONMENT ═══
    Current Directory      <current_directory or "(unknown)">
    Environment Variables  <"N captured (--verbose or --json to view)" if state in
                             (present, present_empty, partial)>
                            <"(unavailable)" if state == absent>
                            <"(unparseable -- see coverage below)" if state == unparseable>
    [~] <coverage.reasons entries mentioning environment_block, if any -- same
         "[~] " convention as every other command>
```

`--verbose`: prints every `name=value` pair from `environment_variables`
(unchanged from rev2) — including a `state == "partial"` result's
partial list, clearly still under the section header noting truncation
above it.

### 2.6 Full field table, source count, and exit semantics — corrected (rev2 error: wrong field count, wrong claim about `misc_info`)

**Rev2 errors, corrected here**: the field table actually lists **15**
fields, not "14" as rev2's prose said; and `misc_info` demonstrably still
backs `cpu_current_mhz`/`cpu_max_mhz` post-redesign (§0), so rev2's "#41
must confirm whether `SYSINFO_MISC_INFO_UNAVAILABLE` is still meaningful"
hedge is resolved, not deferred: **it is meaningful, unchanged, kept.**

| # | field | type |
|---|---|---|
| 1 | `dump_file` | `string \| null` |
| 2 | `hostname` | `string \| null` |
| 3 | `username` | `string \| null` |
| 4 | `os` | `string \| null` |
| 5 | `os_version` | `string \| null` |
| 6 | `architecture` | `string \| null` |
| 7 | `product_type` | `string \| null` |
| 8 | `processors` | `integer \| null` |
| 9 | `cpu_vendor` | `string \| null` |
| 10 | `cpu_current_mhz` | `integer \| null` |
| 11 | `cpu_max_mhz` | `integer \| null` |
| 12 | `thread_count` | `integer \| null` |
| 13 | `module_count` | `integer \| null` |
| 14 | `current_directory` | `string \| null` |
| 15 | `environment_variables` | `list[{name,value}] \| null` |

`summary = {"count": 1}`, unchanged. Coverage/exit semantics: **all
five existing `SourceRequirement`s stay, unmodified** —
`SYSINFO_SYSTEM_INFO_UNAVAILABLE` (`sysinfo`), `SYSINFO_MISC_INFO_
UNAVAILABLE` (`misc_info` — confirmed still backing `cpu_current_mhz`/
`cpu_max_mhz`, §0), `SYSINFO_PEB_UNAVAILABLE` (`peb`),
`SYSINFO_THREADS_UNAVAILABLE` (`threads`), `SYSINFO_MODULES_UNAVAILABLE`
(`modules`) — **plus** the new sixth, `environment_block` (§2.3). #41
implements against six `SourceRequirement`s, not five, and does not
decide anything about `misc_info`'s continued relevance — that is
settled here.

## 3. `--handles`

### 3.1 Source

Unchanged from rev2.

### 3.2 Record shape

Unchanged from rev2 (no `object_infos` field, per §3.3).

### 3.3 `ObjectInfos` — omitted in every mode

Unchanged from rev2.

### 3.4 Ordering

Unchanged from rev2 — numeric ascending by `.Handle`, stable ties.

### 3.5 Coverage and exit semantics — real per-stream isolation, corrected again (rev3 P0, this round's actual fix)

**Rev3 error, corrected here**: rev3 correctly identified that
`__parse_directories()` has no exception handling around the
`HandleDataStream` branch, but concluded from that alone that isolating
its failure was unachievable without "an invasive fork" and declined to
specify one. Reading the rest of `__parse_directories()`
(`minidumpfile.py:180-214`, not read in earlier rounds) shows this
conclusion was too pessimistic: the loop's *only* other guarded call is
`self.__parse_thread_context()` (`minidumpfile.py:215-218`, unrelated to
handles) — every stream-type branch, `HandleDataStream` included, calls
a **public** classmethod (`MinidumpThreadList.parse`,
`MinidumpModuleList.parse`, ..., `MinidumpHandleDataStream.parse`, all
importable from `minidump.streams`, none name-mangled or private).
Duplicating this one dispatch loop — not forking the installed package,
just writing dumpex's own equivalent orchestration that calls the same
public parser classes — is a normal, bounded amount of code, not the
"~80-line invasive fork" rev3 dismissed it as. `dumpex.core.memory.
open_dump()` is redesigned to do exactly this, replacing its current
`MinidumpFile.parse(path)` call:

```python
from minidump.header import MinidumpHeader
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams import (
    MinidumpThreadList, MinidumpModuleList, MinidumpMemoryList, MinidumpSystemInfo,
    MinidumpThreadExList, MinidumpMemory64List, CommentStreamA, CommentStreamW,
    ExceptionList, MinidumpHandleDataStream, MinidumpUnloadedModuleList,
    MinidumpMiscInfo, MinidumpMemoryInfoList, MinidumpThreadInfoList,
)
from minidump.minidumpfile import MinidumpFile
from minidump.structures.peb import PEB

# Mirrors __parse_directories()'s own elif dispatch (minidumpfile.py:115-
# 189) exactly -- same stream types, same target attribute, same parser
# classmethod -- just wrapped per-branch instead of left unguarded.
_STREAM_DISPATCH = {
    MINIDUMP_STREAM_TYPE.ThreadListStream:         ("threads", MinidumpThreadList),
    MINIDUMP_STREAM_TYPE.ModuleListStream:         ("modules", MinidumpModuleList),
    MINIDUMP_STREAM_TYPE.MemoryListStream:         ("memory_segments", MinidumpMemoryList),
    MINIDUMP_STREAM_TYPE.SystemInfoStream:         ("sysinfo", MinidumpSystemInfo),
    MINIDUMP_STREAM_TYPE.ThreadExListStream:       ("threads_ex", MinidumpThreadExList),
    MINIDUMP_STREAM_TYPE.Memory64ListStream:       ("memory_segments_64", MinidumpMemory64List),
    MINIDUMP_STREAM_TYPE.CommentStreamA:           ("comment_a", CommentStreamA),
    MINIDUMP_STREAM_TYPE.CommentStreamW:           ("comment_w", CommentStreamW),
    MINIDUMP_STREAM_TYPE.ExceptionStream:          ("exception", ExceptionList),
    MINIDUMP_STREAM_TYPE.HandleDataStream:         ("handles", MinidumpHandleDataStream),
    MINIDUMP_STREAM_TYPE.UnloadedModuleListStream: ("unloaded_modules", MinidumpUnloadedModuleList),
    MINIDUMP_STREAM_TYPE.MiscInfoStream:           ("misc_info", MinidumpMiscInfo),
    MINIDUMP_STREAM_TYPE.MemoryInfoListStream:     ("memory_info", MinidumpMemoryInfoList),
    MINIDUMP_STREAM_TYPE.ThreadInfoListStream:     ("thread_info", MinidumpThreadInfoList),
}

def open_dump(path):
    mf = MinidumpFile()
    mf.filename = path
    mf.file_handle = open(path, "rb")

    # Identical to MinidumpFile.__parse_header() (minidumpfile.py:90-101):
    # reads only the directory table's StreamType/Rva/DataSize fields --
    # no per-stream parser runs here, so this phase cannot itself raise
    # the way a specific stream's own parser can.
    mf.header = MinidumpHeader.parse(mf.file_handle)
    for i in range(mf.header.NumberOfStreams):
        mf.file_handle.seek(mf.header.StreamDirectoryRva + i * 12, 0)
        d = MINIDUMP_DIRECTORY.parse(mf.file_handle)
        if d:
            mf.directories.append(d)

    # The actual fix: each stream's own parse is now individually
    # try/except-guarded -- one stream raising no longer aborts every
    # other stream's parse, or the dump-open call as a whole.
    stream_failures = {}   # {MINIDUMP_STREAM_TYPE: str(exception)}
    for d in mf.directories:
        entry = _STREAM_DISPATCH.get(d.StreamType)
        if entry is None:
            continue   # unrecognized/not-yet-implemented stream type --
                        # same silent skip as __parse_directories()'s own
                        # unhandled-branch/`else` case (minidumpfile.py:
                        # 195-208), not a failure.
        attr_name, parser_cls = entry
        try:
            setattr(mf, attr_name, parser_cls.parse(d, mf.file_handle))
        except Exception as e:
            stream_failures[d.StreamType] = str(e)
            # mf.<attr_name> stays at its MinidumpFile.__init__ default
            # (None) -- isolated; every OTHER branch still runs.

    try:
        if mf.sysinfo and mf.threads:
            mf.peb = PEB.from_minidump(mf)
    except Exception:
        pass   # unchanged from the library's own __parse_peb() behavior
               # (minidumpfile.py:85-88, 231-235)

    mf._dumpex_stream_failures = stream_failures   # new attribute
    return mf
```

This is a genuine re-implementation of `MinidumpFile._parse()`'s three
phases using the library's own public parser classes, not a private-API
hack or an upstream patch — every class in `_STREAM_DISPATCH` is a
plain, public, importable classmethod, confirmed by direct citation
above, not inferred. It is also a **general** `open_dump()` robustness
improvement: `SourceState.FAILED` — defined in `coverage.py` from the
start (`"FAILED is reserved for a future command whose source access can
genuinely raise and recover"`, `coverage.py:99-111`) but **never
reachable by any of today's six commands**, since none of their
`mf.<stream>` accesses were ever wrapped — becomes reachable for
`sysinfo`/`misc_info`/`peb`(-dependencies)/`threads`/`modules`/`handles`
alike: `observe_source()`'s callers (`--sysinfo` §2.6, `--process` §1.8,
`--handles` below) now check `d.StreamType in mf._dumpex_stream_failures`
before falling back to `bool(mf.X)`, mapping a failed-but-directory-
present stream to `SourceState.FAILED` rather than conflating it with
`ABSENT`. This document only specifies the `--handles` consumption in
full below; #38 should thread the same `_dumpex_stream_failures` check
into `--sysinfo`/`--process`'s existing `observe_source()` calls too,
since the primitive is shared and the distinction (never-present vs.
present-but-failed) is exactly what `SourceState.FAILED` already exists
to carry.

**Corrected, achieved four-state model** for `--handles`:

1. **No `HandleDataStream` directory entry in `mf.directories` at all**
   → `not_evaluated`, `HANDLES_UNAVAILABLE` (unchanged from rev2/rev3).
2. **Directory present, `MINIDUMP_STREAM_TYPE.HandleDataStream in mf.
   _dumpex_stream_failures`** (**new, now real** — the exact case rev3
   said was structurally impossible; it is not, given the fix above) →
   `not_evaluated`, new code **`HANDLES_PARSE_FAILED`** — distinct
   wording from `HANDLES_UNAVAILABLE` even though both map to exit 4
   (§4's message-template table), since "the dump was never captured
   with handle data" and "the dump has a HandleDataStream but this
   library/build could not parse it" are different, actionable facts.
3. **Directory present, parsed successfully (`mf.handles` is a real
   object), some or all descriptors fail dumpex's own `HandleRecord`
   normalization** → unchanged from rev3: `partial` +
   `HANDLE_DESCRIPTOR_INVALID` when some records survive; `not_evaluated`
   + `HANDLES_ALL_DESCRIPTORS_INVALID` when none do (both are
   normalization-layer failures, one level up from case 2's
   library-parse-layer failure — kept as separate codes since they are
   genuinely different failure layers an analyst would investigate
   differently).
4. **Directory present, parsed successfully, `mf.handles.handles` is
   `[]`** → `complete`, zero records (unchanged).
5. **Directory present, parsed successfully, every descriptor normalizes
   cleanly** → `complete` (unchanged).

Every other command gains the same benefit incidentally (a genuinely
malformed `ModuleListStream`, say, no longer prevents `--threads` from
running), but this document only freezes the `--handles`-facing contract
above; retrofitting `SourceState.FAILED` into the other five pre-existing
commands' own coverage wording is #38's implementation detail, not a new
public-behavior decision this document needs to make (their existing
`SourceRequirement`/code shapes are unchanged — only which `SourceState`
`observe_source()` computes for them changes, and `FAILED` was always a
legal, already-specified state for every one of those `SourceRequirement`
declarations, per `coverage.py`'s own design from day one).

### 3.6 Framing

Unchanged from rev2.

### 3.7 Console and summary

Per-type `summary.by_type` approved (unchanged from rev2); console table
layout unchanged, now covering all five §3.5 cases explicitly:

```
═══ HANDLES ═══
  <"HandleDataStream not present in this dump">                   [case 1]
  <"HandleDataStream present but could not be parsed: {detail}">  [case 2]
  <"0 handles usable -- N descriptor(s) failed to normalize">     [case 3, 100% loss]
  <N handle(s) captured>                                          [cases 3 (partial loss)/4/5]
  By type: ...                                                    [only when records non-empty]
  <"N descriptor(s) could not be normalized -- see coverage.limitations"> [case 3, partial loss only]

  <handle table>

  <coverage.reasons, "[~] " lines>
```

## 4. New codes' rendered message templates (rev2 gap: codes named, no frozen text)

Every new `LimitationCode`/diagnostic code introduced by this document,
with its frozen rendered sentence — following `coverage.py`'s own "no
free-text escape hatch" rule (`render_limitation()`'s per-code branches),
so #38–#42 implement against fixed wording, not invent it:

| code | rendered template |
|---|---|
| `PROCESS_SOURCES_ABSENT` | "no process identity evidence available (MiscInfo and PEB both absent or empty)" |
| `PROCESS_MISC_INFO_UNAVAILABLE` | "MiscInfo stream not present in this dump" |
| `PROCESS_PEB_UNAVAILABLE` | "PEB not available (requires sysinfo + thread list)" |
| `PROCESS_PID_UNAVAILABLE` | "MiscInfo present but does not supply a ProcessId" |
| `PROCESS_START_TIME_UNSET` | "MiscInfo's ProcessCreateTime is zero (not recorded)" |
| `PROCESS_START_TIME_INVALID` | "MiscInfo's ProcessCreateTime is not a valid 32-bit timestamp" |
| `PROCESS_PATH_UNAVAILABLE` | "PEB present but ImagePathName is empty" |
| `PROCESS_COMMAND_LINE_UNAVAILABLE` | "PEB present but CommandLine is empty" |
| `PROCESS_IMAGE_BASE_UNAVAILABLE` | "PEB present but ImageBaseAddress is not set" |
| `PROCESS_MODULE_BASE_UNMATCHED` | "no module in ModuleListStream matches the PEB-reported image base exactly" |
| `PROCESS_MODULE_BASE_CONFLICT` | "a module named {name} is loaded at {module_base}, not the PEB-reported image base {peb_base}" |
| `PROCESS_MODULE_NAME_AMBIGUOUS` | "{count} modules share the name {name}; only the first is reported" |
| `PROCESS_MODULE_IDENTITY_MISMATCH` | "PEB image path basename ({peb_name}) disagrees with the matched module's own name ({module_name})" |
| `PROCESS_MAIN_IMAGE_PE_INVALID` | "the PE header at the PEB-reported image base is not structurally valid" |
| `PROCESS_MAIN_IMAGE_READ_FAILED` | "could not read the PE header at the PEB-reported image base" |
| `PROCESS_MAIN_IMAGE_SHORT_READ` | "read fewer bytes than required for the PE header at the PEB-reported image base" |
| `IAT_DIRECTORY_READ_FAILED` | "could not read the IAT directory" |
| `IAT_DIRECTORY_SHORT_READ` | "read fewer bytes than declared for the IAT directory" |
| `IAT_DESCRIPTOR_READ_FAILED` | "{count} import descriptor(s) could not be read" |
| `IAT_DESCRIPTOR_SHORT_READ` | "{count} import descriptor(s) read short" |
| `IAT_THUNK_READ_FAILED` | "{count} IAT/INT thunk slot(s) could not be read" |
| `IAT_THUNK_SHORT_READ` | "{count} IAT/INT thunk slot(s) read short" |
| `IAT_NAME_READ_FAILED` | "{count} DLL or import name string(s) could not be read" |
| `IAT_UNTERMINATED_TABLE` | "no null terminator found before the descriptor/thunk cap; table treated as truncated" |
| `IAT_CYCLE_DETECTED` | "a repeated address was found while walking the import table; walk stopped" |
| `IAT_BOUNDS_EXCEEDED` | "an RVA or count in the import directory exceeds plausible bounds" |
| `IAT_ENTRIES_TRUNCATED` | "the import table walk stopped after reaching its own read/byte budget" |
| `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` | "{count} IAT slot(s) fall outside the declared IAT directory range" *(diagnostic-only, §1.5/§1.8 — never a completeness gap)* |
| `HANDLES_UNAVAILABLE` | "HandleDataStream not present in this dump (not captured with handle data)" |
| `HANDLES_PARSE_FAILED` | "HandleDataStream present but could not be parsed: {detail}" |
| `HANDLES_ALL_DESCRIPTORS_INVALID` | "HandleDataStream present but no descriptor could be normalized" |
| `HANDLE_DESCRIPTOR_INVALID` | "{count} handle descriptor(s) could not be normalized" |
| `ENVIRONMENT_BLOCK_UNPARSEABLE` | "environment block present but no entries could be parsed (malformed or no terminator found)" |
| `ENVIRONMENT_BLOCK_TRUNCATED` | "environment block capture ended before a terminator was found; entries may be incomplete" |

## 5. CSV — not applicable (rev2 gap: this section was dropped by an editing mistake, restored)

`--csv` was removed from this codebase before this redesign began
(`tests/unit/test_cli_args.py:83-85` asserts it now fails argparse
entirely; no CSV path remains in `dumpex/output/*.py`). There is no CSV
output surface to freeze for `--process`/`--sysinfo`/`--handles`
specifically — a statement of current fact, not a decision.

## 6. Compatibility decision: immediate removal, no hidden alias

Unchanged from rev2 (including the corrected `v2.11`→`v2.12` citation).

## 7. Summary of new codes, structures, and primitives

**New `LimitationCode` members** (superset of rev2, this round's
additions in *italics* inline): `PROCESS_SOURCES_ABSENT`,
`PROCESS_MISC_INFO_UNAVAILABLE`, `PROCESS_PEB_UNAVAILABLE`,
`PROCESS_START_TIME_UNSET`, `PROCESS_START_TIME_INVALID`,
*`PROCESS_PID_UNAVAILABLE`, `PROCESS_PATH_UNAVAILABLE`,
`PROCESS_COMMAND_LINE_UNAVAILABLE`, `PROCESS_IMAGE_BASE_UNAVAILABLE`*,
`IAT_DIRECTORY_READ_FAILED`, `IAT_DIRECTORY_SHORT_READ`,
`IAT_DESCRIPTOR_READ_FAILED`, `IAT_DESCRIPTOR_SHORT_READ`,
`IAT_THUNK_READ_FAILED`, `IAT_THUNK_SHORT_READ`, `IAT_NAME_READ_FAILED`,
`IAT_UNTERMINATED_TABLE`, `IAT_CYCLE_DETECTED`, `IAT_BOUNDS_EXCEEDED`,
`IAT_ENTRIES_TRUNCATED`, `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS`
(diagnostic-only), `HANDLES_UNAVAILABLE`, *`HANDLES_PARSE_FAILED`,
`HANDLES_ALL_DESCRIPTORS_INVALID`*, `HANDLE_DESCRIPTOR_INVALID`,
*`ENVIRONMENT_BLOCK_UNPARSEABLE`, `ENVIRONMENT_BLOCK_TRUNCATED`*.

**New non-coverage diagnostic codes**: `PROCESS_MODULE_BASE_UNMATCHED`,
*`PROCESS_MODULE_BASE_CONFLICT`, `PROCESS_MODULE_NAME_AMBIGUOUS`*,
`PROCESS_MODULE_IDENTITY_MISMATCH`, `PROCESS_MAIN_IMAGE_PE_INVALID`,
`PROCESS_MAIN_IMAGE_READ_FAILED`, `PROCESS_MAIN_IMAGE_SHORT_READ`.

**New primitives**: `dumpex.core.memory.resolve_module_by_base()` (§1.2,
unchanged); the environment-block bounded walk,
`walk_environment_block()` (§2.3, replaces trusting
`peb.environment_variables`); *`open_dump()` redesigned with full
per-stream parse isolation* (§3.5, this round's fix — not merely a
directory pre-scan as previously described; a real re-implementation of
`MinidumpFile._parse()`'s three phases with each stream's parser
individually guarded, exposing `mf._dumpex_stream_failures` and making
`SourceState.FAILED` reachable for every stream, not just `handles`).

**New frozen constants**: `MAX_IAT_DLLS = 256`,
`MAX_IAT_ENTRIES_PER_DLL = 4096`, `MAX_IAT_TOTAL_ENTRIES = 65536`,
`MAX_IAT_NAME_LENGTH = 512`, `MAX_IAT_BYTES_READ = 16 * 1024 * 1024`,
*`MAX_IAT_READ_OPERATIONS = 8192`*.

**New coverage source**: `--sysinfo` gains a sixth source,
`"environment_block"` (§2.3), alongside the five unchanged existing ones.

## Non-goals respected

No production code changes in this document (the `open_dump()` body in
§3.5 is a frozen contract for #38 to implement, not a patch applied
here); no TEB walk, `PEB.Ldr`/loader-graph validation, candidate
reconstruction, or second full-memory scan; no `peb_trusted` boolean,
confidence score, or verdict vocabulary anywhere in §1.6. **Updated this
round**: the `HandleDataStream`-parse-abort gap previously flagged as
out of scope is now fully specified and in scope (§3.5) — achieved via
dumpex re-implementing `MinidumpFile._parse()`'s three phases with the
library's own public parser classes, not via a fork of the installed
package or an upstream patch, so this remains within what #37 can
responsibly freeze.

## What #38–#44 do next

- **#38**: shared process-metadata layer — §1.2/§1.4/§1.7/§1.8's
  field-level PID/start-time/path/cmdline/image-base availability model
  (not object-presence), `resolve_module_by_base()` (§1.2),
  `walk_environment_block()` (§2.3), and the redesigned `open_dump()`
  with full per-stream parse isolation (§3.5) — the last one is the
  highest-leverage addition this revision makes, since `--sysinfo`/
  `--process`'s own `observe_source()` calls should also start consulting
  `mf._dumpex_stream_failures` (§3.5's closing paragraph), not just
  `--handles`.
- **#39**: bounded IAT parser against §1.5's directory split, per-field
  nullability-on-failure rules, the diagnostic-only status of
  `slot_in_bounds`, and both frozen budgets (bytes + read operations).
- **#40**: wires `--process`, including §1.6's `module_claim`/
  `name_matched_candidate` structure and §1.8's field-level coverage
  model.
- **#41**: wires `--sysinfo`'s new shape, including the sixth
  `environment_block` source (§2.3/§2.6) and the full console layout
  (§2.5) — `misc_info`'s continued relevance is settled here, not left
  for #41 to decide.
- **#42**: wires `--handles`, including §3.5's five-case model (now
  achieved in full, `HANDLES_PARSE_FAILED` included) and the
  `HANDLES_ALL_DESCRIPTORS_INVALID` code.
- **#43**: atomic cutover, unchanged scope from rev2.
- **#44**: docs/CHANGELOG updates, end-to-end validation.

Every later child issue should re-read this document's relevant section
before starting, including the corrections marked "rev2 error"/"rev2
gap"/"rev3 error" above.
