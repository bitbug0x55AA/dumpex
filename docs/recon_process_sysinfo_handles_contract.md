# Recon `--process`/`--sysinfo`/`--handles` contract (issue #37)

**Status: frozen decision record, revision 4 — self-contained.**

This document is the complete, normative contract for the v2.13 Recon
redesign. Issues #38–#44 implement against **this file alone**: every
rule needed to build the three commands is written out here in full.
There are no back-references to an earlier draft ("unchanged from the
previous revision", "as in the earlier draft") anywhere in the normative
body — those drafts were never published and must not be consulted. Appendix A keeps a non-normative record of what each
revision corrected, purely so a reader can see why a rule is worded the
way it is; nothing in Appendix A adds, removes, or qualifies a
requirement.

Everything below is grounded in the tree as it exists at the time of
writing. Appendix B lists every file (and the specific construct) that
was read directly to write this contract, so each claim about current
behavior can be re-checked rather than taken on trust.

---

## Table of contents

- §0 Scope, non-goals, and how the pieces fit
- §1 Shared vocabulary, formatting, and ordering rules
- §2 Loader contract: `open_dump()` with per-stream isolation
- §3 `--process`
- §4 `--sysinfo`
- §5 `--handles`
- §6 Complete code registry (limitations and diagnostics)
- §7 CSV, compatibility/cutover, and schema v2.13
- §8 Acceptance gate: verification matrix and required tests
- Appendix A — revision history (non-normative)
- Appendix B — sources read (non-normative)

---

## §0 Scope, non-goals, and how the pieces fit

### 0.1 What this contract covers

1. A **loader change** (§2) that isolates a single failing minidump
   stream so it can no longer abort the whole dump open. This is a
   prerequisite for `--handles`, and it changes observable coverage for
   commands that already ship, so it is frozen here as public behavior,
   not left as an implementation detail (§2.4).
2. `--process` (§3): the consolidated command replacing `--pid` and
   `--peb`.
3. `--sysinfo` (§4): process-identity fields removed, environment
   evidence added.
4. `--handles` (§5): a new command over `HandleDataStream`.
5. The complete code registry (§6), compatibility decision (§7), and the
   acceptance gate every later child is checked against (§8).

### 0.2 Non-goals (frozen)

- **No production code changes are made by this document.** Every code
  block below is a frozen specification for #38–#42 to implement, not a
  patch applied here.
- No raw TEB↔PEB consensus, `PEB.Ldr` walk, loader-graph validation,
  main-image reconstruction, or second full-memory scan. Those belong to
  #47/#48 and are downstream of #44.
- No `peb_trusted` boolean, no confidence score, no verdict, no
  `DETECTED` semantics, no ATT&CK mapping, and no hunter score anywhere
  in the three commands' output. Recon diagnostics are **observations**
  (§1.6).
- Delay Import descriptors (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`, index
  13) are **out of scope** for v2.13 (§3.5.1).
- Type-specific decoding of `GrantedAccess` is out of scope for v2.13
  (§5.2).

### 0.3 Dependency order

```
#37 (this contract)
  └─ #38  shared layer: open_dump() isolation (§2), resolve_module_by_base()
  │        (§3.3), normalization helpers (§3.2), walk_environment_block() (§4.2),
  │        parse_handle_stream() (§5.1), and build_coverage_report()'s
  │        retain_completeness_checks_when_not_evaluated opt-in (§3.7.3)
  ├─ #39  bounded IAT parser (§3.5), plus parse_pe_header()'s additive
  │        declared_directory_count/directories_complete fields (§3.5.2)
  ├─ #40  --process wiring (§3)
  ├─ #41  --sysinfo wiring (§4)
  ├─ #42  --handles wiring (§5)
  ├─ #43  atomic CLI/schema v2.13 cutover (§7)
  └─ #44  docs, CHANGELOG, end-to-end validation (§8)
```

§2 is claimed by #38 and must land before #42, because `--handles`'
`HANDLES_PARSE_FAILED` state (§5.5 case 2) is unreachable without it.

---

## §1 Shared vocabulary, formatting, and ordering rules

### 1.1 Coverage status and exit codes

The existing mapping is reused unchanged
(`dumpex/output/coverage.py`'s `exit_code_for`):

| `coverage.status` | exit code | meaning for these three commands |
|---|---|---|
| `complete` | 0 | every requested claim was evaluated. A structurally valid PE with **no imports** is `complete`, not failed. A present-but-empty `HandleDataStream` is `complete` with zero records. A verified-empty environment block is `complete`. |
| `partial` | 3 | useful records exist, but at least one requested source/read/parse was incomplete. |
| `not_evaluated` | 4 | the command's sole evidence is absent — e.g. `--handles` on a dump with no `HandleDataStream`, or `--process` with no usable process-identity source at all. |

`execution_status` stays an independent axis: all three commands report
`completed` unless the command itself aborted, regardless of coverage.

### 1.2 Source states

`SourceState` (already defined in `coverage.py`) is used with its
existing meanings: `absent`, `present_empty`, `present`, `failed`.
Before v2.13, `failed` was documented as unreachable for every recon
command, because no `mf.<stream>` access was ever wrapped. §2 makes it
reachable; §2.4 freezes what that means for the commands that already
ship.

### 1.3 Address, handle, and mask formatting

The rule already stated in `dumpex/output/records.py`'s module docstring
applies unchanged, and is extended to the two new record types:

- A field is a **fixed-width lowercase hex string** (`0x` + 16 hex
  digits, via `hex_address()`) if and only if it is a real address,
  pointer, or handle value: `image_base_address`, `peb_address`,
  `iat.table_va`, `iat.import_directory_va`, `entries[].iat_slot_va`,
  `entries[].resolved_target_va`, `module_claim.base_address`,
  `handle`, and the three PEB standard-handle fields.
- Every other numeric field is a **plain JSON integer**: `pid`,
  `table_size`, `import_directory_size`, `ordinal`, `attributes`,
  `granted_access`, `handle_count`, `pointer_count`, all counts.
  `granted_access` in particular stays a raw integer on the wire even
  though analysts read masks in hex — console rendering formats it as
  hex (§5.6); the record type does not.
- Timestamps are strings formatted `"%Y-%m-%d %H:%M:%S UTC"`.

### 1.4 `null` versus `[]` versus `""`

- `null` means **evidence unavailable**: the source was absent, failed,
  or produced nothing dumpex is willing to call a value.
- `[]` means **evidence captured and genuinely empty** — a verified
  empty environment block, a valid PE with zero imports, a present
  `HandleDataStream` with zero descriptors.
- The empty string is **never** emitted. A source string that is empty,
  or that normalizes to nothing (§3.2), becomes `null`. This matches the
  existing `... or None` convention already used by
  `dumpex/commands/sysinfo.py` and `dumpex/commands/peb.py`.
- A key is never omitted to signal absence. Every field in every record
  below is always present with a `null` value when unavailable. The one
  and only exception is `process.peb_extended`, whose presence is gated
  on `--verbose` (§3.6) — and even then, presence depends **only** on
  the flag, never on the data.

### 1.5 Ordering (deterministic, frozen)

- `iat.entries`: import-descriptor order as it appears in the Import
  Directory, then thunk index ascending within each descriptor. Never
  re-sorted by name, address, or anything else.
- `environment_variables`: the order the entries appear in the
  environment block. Duplicates are preserved, in place.
- `handles` records: numeric ascending by raw handle value; ties (which
  a malformed dump can produce) keep source order — a stable sort.
- `summary.by_type` (§5.6): count descending, then type name ascending
  (case-sensitive, `"(unnamed)"` sorts as written).
- `identity_evidence.diagnostics` and `iat.diagnostics`: the frozen code
  order given in §6.2. At most one entry per code per record.
- `coverage.limitations`: the order the command declares its
  `completeness_checks`, exactly as `build_coverage_report()` already
  preserves.

No collection is ever ordered by a set/dict iteration, and no ordering
depends on host locale, filesystem order, or hash randomization.

### 1.6 Two tiers: limitations versus diagnostics

Recon emits two structurally different things, and they must never be
conflated:

**Coverage limitations** (`CoverageLimitation`, in
`coverage.limitations`) state that *something could not be evaluated*.
Any limitation makes the status `partial` (or `not_evaluated`), per
`build_coverage_report()`'s existing reduction. A limitation therefore
may only be emitted for a genuine evaluation gap.

**Diagnostics** (`ProcessDiagnostic`, §3.4.4, in
`identity_evidence.diagnostics` and `iat.diagnostics`) state that a
check *ran successfully and found something worth telling the analyst*.
A diagnostic can never change `coverage.status` and is never constructed
as a `CoverageLimitation`. This is the "optional-check coverage
isolation" rule: a successfully completed, informative check must not
make a MORE complete result look LESS complete.

Diagnostics carry no verdict semantics. They have exactly two severity
values, `info` and `warning`; there is no `critical`, no
`DETECTED`/`SUSPICIOUS` vocabulary, no score, no confidence, and no
ATT&CK reference. A diagnostic describes a disagreement between two
pieces of captured evidence — nothing more.

### 1.7 Source display names added in v2.13

`coverage.py`'s `_SOURCE_DISPLAY_NAMES` currently has no entry for the
new source names, so a `SOURCE_FAILED` limitation over one of them would
render the raw key. v2.13 adds exactly these entries:

| source key | display name |
|---|---|
| `sysinfo` | `SystemInfoStream` |
| `handles` | `HandleDataStream` |
| `memory_info` … | *(existing entries unchanged)* |
| `environment_block` | `Environment block` |
| `main_image` | `PEB-reported main image` |

### 1.8 Frozen constants

| constant | value | governs |
|---|---|---|
| `MAX_IAT_DLLS` | `256` | import descriptors walked |
| `MAX_IAT_ENTRIES_PER_DLL` | `4096` | thunks per descriptor |
| `MAX_IAT_TOTAL_ENTRIES` | `65536` | thunks overall |
| `MAX_IAT_NAME_LENGTH` | `512` | bytes read for one DLL/symbol name |
| `MAX_IAT_BYTES_READ` | `16 * 1024 * 1024` | cumulative bytes across the IAT walk |
| `MAX_IAT_READ_OPERATIONS` | `8192` | count of individual bounded reads across the IAT walk |
| `MAX_ENV_BYTES` | `65536` | cumulative bytes across the environment walk |
| `MAX_ENV_ENTRIES` | `2048` | entries kept from the environment block |
| `MAX_HANDLE_DESCRIPTORS` | `65536` | descriptors parsed from `HandleDataStream` |
| `MAX_HANDLE_STRING_BYTES` | `4096` | bytes read for one `TypeName`/`ObjectName` |

Two independent IAT budgets (bytes **and** read operations) exist
because a byte budget alone does not catch a pathological
many-tiny-reads pattern: thousands of one-byte reads stay far under
16 MiB while still hanging the walk.

---

## §2 Loader contract: `open_dump()` with per-stream isolation

### 2.1 Baseline: what the installed library does today

Read directly from `.venv/Lib/site-packages/minidump/minidumpfile.py`:

- `MinidumpFile._parse()` (lines 82–88) calls `__parse_header()`, then
  `__parse_directories()`, then `__parse_peb()` — only the last is
  wrapped in `try/except`.
- `__parse_directories()` (lines 103–218) is one `elif` chain over
  `self.directories`. **No branch has any exception handling**,
  including `self.handles = MinidumpHandleDataStream.parse(dir,
  self.file_handle)` at line 161. Its only guarded call is
  `self.__parse_thread_context()` at lines 215–218, which runs **after**
  the loop and is wrapped.
- Therefore a parse exception in **any** stream propagates out of
  `__parse_directories()`, out of `_parse()`, past `MinidumpFile.parse()`
  (lines 48–54), and out of `dumpex.core.memory.open_dump()`'s
  `MinidumpFile.parse(path)` call. Today `open_dump()` catches it, prints
  `"[!] Could not parse … as a minidump file"`, and calls `sys.exit(1)`.
  The caller never receives an `mf` at all — not an `mf` whose one bad
  stream is `None`.
- `__parse_thread_context()` (lines 220–229) populates
  `thread.ContextObject` for every thread, choosing `CONTEXT` for AMD64
  and `WOW64_CONTEXT` for INTEL. `dumpex.core.memory.get_thread_contexts()`
  depends on this attribute, and so, transitively, do the stomping, pipe,
  and cs-beacon hunters.
- `__parse_peb()` (lines 231–235) returns early unless both `sysinfo`
  and `threads` parsed, then assigns `PEB.from_minidump(self)`.

Consequence, frozen as a fact: today, one malformed stream in an
otherwise readable dump costs the analyst **every** command, with exit 1
and no structured output.

### 2.2 Frozen `open_dump()`

`dumpex.core.memory.open_dump()` is redesigned to reproduce
`MinidumpFile._parse()`'s three phases using the library's own **public**
parser classes, with each stream individually guarded. This is not a
fork of the installed package and not an upstream patch; every class in
`_STREAM_DISPATCH` below is a public, importable classmethod.

```python
from minidump.header import MinidumpHeader
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams import (
    MinidumpThreadList, MinidumpModuleList, MinidumpMemoryList,
    MinidumpSystemInfo, MinidumpThreadExList, MinidumpMemory64List,
    CommentStreamA, CommentStreamW, ExceptionList,
    MinidumpUnloadedModuleList, MinidumpMiscInfo,
    MinidumpMemoryInfoList, MinidumpThreadInfoList,
)
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.streams.ContextStream import CONTEXT, WOW64_CONTEXT
from minidump.minidumpfile import MinidumpFile
from minidump.structures.peb import PEB

# Mirrors __parse_directories()'s own elif dispatch (minidumpfile.py:
# 115-189) exactly -- same stream types, same target attribute, same
# parser -- just wrapped per-branch instead of left unguarded.
# HandleDataStream deliberately does NOT use the library's
# MinidumpHandleDataStream.parse: see §5.1.
_STREAM_DISPATCH = {
    MINIDUMP_STREAM_TYPE.ThreadListStream:         ("threads", MinidumpThreadList.parse),
    MINIDUMP_STREAM_TYPE.ModuleListStream:         ("modules", MinidumpModuleList.parse),
    MINIDUMP_STREAM_TYPE.MemoryListStream:         ("memory_segments", MinidumpMemoryList.parse),
    MINIDUMP_STREAM_TYPE.SystemInfoStream:         ("sysinfo", MinidumpSystemInfo.parse),
    MINIDUMP_STREAM_TYPE.ThreadExListStream:       ("threads_ex", MinidumpThreadExList.parse),
    MINIDUMP_STREAM_TYPE.Memory64ListStream:       ("memory_segments_64", MinidumpMemory64List.parse),
    MINIDUMP_STREAM_TYPE.CommentStreamA:           ("comment_a", CommentStreamA.parse),
    MINIDUMP_STREAM_TYPE.CommentStreamW:           ("comment_w", CommentStreamW.parse),
    MINIDUMP_STREAM_TYPE.ExceptionStream:          ("exception", ExceptionList.parse),
    MINIDUMP_STREAM_TYPE.HandleDataStream:         ("handles", parse_handle_stream),   # §5.1
    MINIDUMP_STREAM_TYPE.UnloadedModuleListStream: ("unloaded_modules", MinidumpUnloadedModuleList.parse),
    MINIDUMP_STREAM_TYPE.MiscInfoStream:           ("misc_info", MinidumpMiscInfo.parse),
    MINIDUMP_STREAM_TYPE.MemoryInfoListStream:     ("memory_info", MinidumpMemoryInfoList.parse),
    MINIDUMP_STREAM_TYPE.ThreadInfoListStream:     ("thread_info", MinidumpThreadInfoList.parse),
}


def open_dump(path: str) -> MinidumpFile:
    # Phase 0 -- unchanged, existing behavior, still exit 1.
    if not os.path.exists(path):
        print(RED(f"[!] File not found: {path}"))
        sys.exit(1)

    mf = MinidumpFile()
    mf.filename = path

    # Phase 1 -- header + directory table. Identical to
    # MinidumpFile.__parse_header() (minidumpfile.py:90-101): reads only
    # each directory entry's StreamType/Rva/DataSize, so no per-stream
    # parser runs here. A failure in this phase means the file is not a
    # usable minidump AT ALL -- there is no per-stream evidence to
    # salvage -- so it keeps today's exact message and exit code, which
    # tests/unit/test_open_dump.py already asserts.
    try:
        mf.file_handle = open(path, "rb")
        mf.header = MinidumpHeader.parse(mf.file_handle)
        for i in range(mf.header.NumberOfStreams):
            mf.file_handle.seek(mf.header.StreamDirectoryRva + i * 12, 0)
            d = MINIDUMP_DIRECTORY.parse(mf.file_handle)
            if d:
                mf.directories.append(d)
            # A falsy directory entry is an unknown UserStream -- the
            # library logs and skips it (minidumpfile.py:98-101); so do we.
    except Exception as e:
        print(RED(f"[!] Could not parse {path} as a minidump file: "
                  f"{type(e).__name__}: {e}"))
        print(DIM("    The file may be corrupted, truncated, or not a Windows "
                  "minidump (.dmp) at all."))
        sys.exit(1)

    # Phase 2 -- the actual fix: each stream's own parse is individually
    # guarded, so one stream raising no longer aborts every other
    # stream's parse or the dump-open call as a whole.
    stream_failures = {}          # {MINIDUMP_STREAM_TYPE: "ExcType: message"}
    for d in mf.directories:
        entry = _STREAM_DISPATCH.get(d.StreamType)
        if entry is None:
            continue              # unrecognized / not-yet-implemented stream
                                  # type -- the same silent skip
                                  # __parse_directories()'s own unhandled
                                  # branches take (minidumpfile.py:165-208),
                                  # not a failure.
        attr_name, parse = entry
        try:
            setattr(mf, attr_name, parse(d, mf.file_handle))
        except Exception as e:
            stream_failures[d.StreamType] = f"{type(e).__name__}: {e}"
            # mf.<attr_name> stays at its MinidumpFile.__init__ default
            # (None) -- isolated; every OTHER branch still runs.

    # Phase 3a -- thread contexts. REQUIRED: reproduces
    # MinidumpFile.__parse_thread_context() (minidumpfile.py:220-229)
    # exactly, including its guard, so thread.ContextObject consumers
    # (dumpex.core.memory.get_thread_contexts, and through it the
    # stomping/pipe/cs-beacon hunters) do not regress.
    try:
        if mf.sysinfo and mf.threads:
            for thread in mf.threads.threads:
                mf.file_handle.seek(thread.ThreadContext.Rva)
                if mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
                    thread.ContextObject = CONTEXT.parse(mf.file_handle)
                elif mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
                    thread.ContextObject = WOW64_CONTEXT.parse(mf.file_handle)
    except Exception:
        pass   # same swallow-and-continue as the library's own guard

    # Phase 3b -- PEB. Same precondition and same swallow as
    # __parse_peb()/_parse() (minidumpfile.py:85-88, 231-235).
    try:
        if mf.sysinfo and mf.threads:
            mf.peb = PEB.from_minidump(mf)
    except Exception:
        pass

    mf._dumpex_stream_failures = stream_failures
    return mf
```

Three properties of this body are themselves frozen, because dropping
any of them would be a silent regression:

1. **File-not-found and header/directory failures keep exit 1** and
   today's exact messages. Per-stream isolation applies to phase 2 only.
2. **Thread-context parsing is preserved** (phase 3a), including its
   partial-failure guard: a dump whose fifth thread has a bad
   `ThreadContext.Rva` keeps the four contexts parsed before it, exactly
   as today, because the loop is inside one guarded block.
3. **Phase ordering is preserved**: contexts before PEB, PEB last, both
   gated on `sysinfo and threads`.

### 2.3 `_dumpex_stream_failures` and the shared accessor

`mf._dumpex_stream_failures` is a `dict[MINIDUMP_STREAM_TYPE, str]`. It
is **always** set (empty dict when nothing failed), so no consumer needs
`getattr(..., {})` defensiveness against an `mf` that came from
`open_dump()`. Consumers never read the dict directly; #38 adds one
helper next to `open_dump()`:

```python
def stream_failure(mf, stream_type) -> "str | None":
    """The failure detail for `stream_type`, or None when that stream
    parsed (or was never present). The single place any command asks
    'did this stream fail to parse?'."""
```

and one observation helper that replaces every command's hand-rolled
`observe_source(name, present=bool(mf.X), items=...)` for stream-backed
sources:

```python
def observe_stream(mf, name, stream_type, obj, items):
    """SourceState.FAILED (with detail) when stream_type is in
    mf._dumpex_stream_failures; otherwise exactly today's
    observe_source() absent/present_empty/present inference."""
```

`SourceObservation.detail` carries the failure string and is meaningful
only in the `failed` state — already the model's documented rule.

Because `mf` objects built by tests/fixtures do not go through
`open_dump()`, `stream_failure()` must treat a missing attribute as "no
failures" rather than raising.

### 2.4 Global FAILED-stream behavior (all commands) — frozen

Per-stream isolation changes observable behavior for commands that
already ship. The complete per-command, per-source state matrix is
frozen here, not deferred. It is derived from each command's **actual**
existing declarations (`evaluation_sources` / `completeness_checks`), so
a reader can check it against the code rather than against intent.

| command | source | declared as | `absent` → | `failed` → |
|---|---|---|---|---|
| `--list` | `memory_info` | evaluation + completeness | `not_evaluated` (4), `SOURCE_ABSENT` | **`partial` (3)**, `SOURCE_FAILED`, zero records |
| `--modules` | `modules` | evaluation + completeness | `not_evaluated` (4), `SOURCE_ABSENT` | **`partial` (3)**, `SOURCE_FAILED`, zero records |
| `--threads` | `threads` | evaluation group member + completeness | group rule (below) | **`partial` (3)**, `SOURCE_FAILED` |
| `--threads` | `thread_info` | evaluation group member + completeness | group rule (below) | **`partial` (3)**, `SOURCE_FAILED` |
| `--threads` | `modules` | completeness only | `partial` (3), `MODULE_CLASSIFICATION_UNAVAILABLE` | **`partial` (3)**, `SOURCE_FAILED` |
| `--sysinfo` | `sysinfo`, `misc_info`, `threads`, `modules` | completeness only | `partial` (3), each source's own `SYSINFO_*` code | **`partial` (3)**, `SOURCE_FAILED` |
| `--sysinfo` | `peb` | completeness only | `partial` (3), `SYSINFO_PEB_UNAVAILABLE` | n/a — see below |
| `--sysinfo` | `environment_block` | neither (§4.3.3) | — | — |
| `--process` | `process_identity` | evaluation (derived, §3.7.4) | `not_evaluated` (4), `PROCESS_SOURCES_ABSENT` | n/a — derived |
| `--process` | `misc_info` | completeness only | `partial` (3), `PROCESS_MISC_INFO_UNAVAILABLE` | **`partial` (3)**, `SOURCE_FAILED` |
| `--process` | `peb` | completeness only | `partial` (3), `PROCESS_PEB_UNAVAILABLE` | n/a — see below |
| `--process` | `modules` | observed always; completeness **only when the fallback could have run** — PEB path unavailable *and* image base normalized (§3.7.2) | `PROCESS_MODULE_FALLBACK_UNAVAILABLE` in that case, otherwise nothing | `SOURCE_FAILED` in that case, otherwise nothing |
| `--process` | `main_image`, `iat` | completeness only (derived) | see §3.7.2 | n/a — derived |
| `--handles` | `handles` | completeness only (bare name; fires on `failed` alone) | see §5.5 case 1 | `SOURCE_FAILED` alongside §5.5 case 2's own code |
| `--handles` | `handle_records` | evaluation (derived, §5.5) | `not_evaluated` (4), case-dependent code | n/a — derived |

Rules:

- **`--threads` with a `failed` stream exits 3, not 0.** Two consequences
  are frozen explicitly, because the naive reading gets both wrong:
  - `--threads` declares `SourceRequirement("modules", …)`, so a corrupt
    `ModuleListStream` gives `--threads` a `SOURCE_FAILED` limitation and
    **exit 3** — not exit 0. Every thread's `module_context` becomes
    `unavailable` (already its documented meaning when the stream is
    unusable), and no thread record is lost.
  - `collect_threads()`'s early return, currently gated on
    `not bool(mf.threads) and not bool(mf.thread_info)`, would return
    `complete`/exit 0 with zero records when both streams are `failed`,
    because it builds a coverage report with no completeness checks at
    all. #38 **must** re-gate that branch on both sources being
    `SourceState.ABSENT` specifically; a `failed` stream falls through to
    the normal path, which produces `SOURCE_FAILED` and exit 3.
- **A derived source never has a `failed` state.** `process_identity`,
  `handle_records`, `main_image`, and `iat` are computed by dumpex from
  evidence that has already been observed; their own failure modes are
  the codes in §3.7.2/§5.5, not `SOURCE_FAILED`.
- **A `SourceRequirement`'s `absent_code` does not apply to `failed`.**
  `_derive_required_source_limitation()` returns `SOURCE_FAILED` for a
  failed source regardless of the requirement's chosen absence code, so
  `MODULE_CLASSIFICATION_UNAVAILABLE`, `SYSINFO_*_UNAVAILABLE`, and
  `PROCESS_MISC_INFO_UNAVAILABLE` never render for a failed stream. That
  is correct — "not present in this dump" would be a false statement
  about a stream that is present — and it is why the matrix's two
  columns differ.

- **Rendered wording for the general case is the existing
  `SOURCE_FAILED` template**, which
  already exists in `coverage.py`: `"{display name} present but could
  not be read: {detail}"`. No new code and no new wording is introduced
  for the general case. `--handles` is the single exception (§5.5 case
  2), because "captured without handle data" and "captured with handle
  data that will not parse" are different, actionable facts an analyst
  acts on differently, and both must survive dedup in
  `combine_coverage_reports()`.
- **A `failed` source never triggers `not_evaluated` on its own.**
  `build_coverage_report()` already implements this: only `absent`
  members of an evaluation group can produce `not_evaluated`. Evaluation
  was attempted and hit an error — that is `partial` territory.
- **The `peb` source never becomes `failed` in v2.13.** The PEB is
  derived (phase 3b), not a directory entry; a `PEB.from_minidump()`
  exception continues to leave `mf.peb is None`, observed as `absent`,
  rendered by the existing `SYSINFO_PEB_UNAVAILABLE`/`PEB_UNAVAILABLE`
  wording. §4.2 removes the one case where that behavior was actively
  misleading (a malformed environment block destroying the entire PEB)
  by making the environment walk independent, not by changing the PEB's
  own state vocabulary.
- **Exit-code change, stated plainly**: a dump with one malformed stream
  and otherwise readable evidence previously exited **1** with no
  structured output, for every command. Every such case now exits **3**
  (`partial`) — including when the failed stream is the command's only
  source, as for `--list` and `--modules`. There is **no generalized
  "sole evidence failed, therefore exit 4" rule**: a `failed` source is
  never `absent`, so it can never satisfy an evaluation group's
  all-absent condition, and only the two derived sources in the matrix
  above (`process_identity`, `handle_records`) reach exit 4 by their own
  per-command rules. **The matrix is the only normative statement of
  per-source outcomes**; where prose elsewhere summarizes it, the matrix
  wins. This is a deliberate improvement, and it is the only
  compatibility change §2 makes to existing commands. Commands' existing
  `SourceRequirement`/code declarations are otherwise untouched: only
  which `SourceState` is computed for them changes, and `failed` was
  always a legal state for every one of those declarations.

### 2.5 Required loader tests (#38)

These are gate items, not suggestions. They need a byte-level minidump
builder; #38 adds `tests/fixtures/minidump_bytes.py`, which emits a
valid header plus a directory table and per-stream payloads, so no real
`.dmp` is required (the suite's no-external-fixtures rule in
`tests/conftest.py` stands).

**Parity, valid dumps** — for a synthetic dump exercising
`SystemInfoStream`, `ThreadListStream`, `ModuleListStream`,
`Memory64ListStream`, `MiscInfoStream`, and `MemoryInfoListStream`,
`open_dump(path)` must produce, versus `MinidumpFile.parse(path)`:

1. the same set of populated stream attributes, with equal record counts
   per stream;
2. the same `thread.ContextObject` presence per thread, and equal
   `Rip`/`Eip` values — asserted through
   `get_thread_contexts()` so the hunters' actual consumption path is
   covered, not just the attribute;
3. the same `mf.peb` availability and equal `image_path`,
   `command_line`, `image_base_address`, and `address`;
4. an equivalent reader: `mf.get_reader().get_buffered_reader()` reads
   the same bytes at the same VAs;
5. `mf._dumpex_stream_failures == {}`.

**Isolation, malformed dumps** — for a dump whose `HandleDataStream`
payload is deliberately corrupt while every other stream is valid:

6. `open_dump()` returns an `mf` (no `SystemExit`, no propagated
   exception);
7. `mf.handles is None` and
   `stream_failure(mf, MINIDUMP_STREAM_TYPE.HandleDataStream)` is a
   non-empty string;
8. every other stream is populated exactly as in the valid case, thread
   contexts included;
9. `--modules`/`--threads`/`--sysinfo`/`--list` on that dump exit 0, not
   1 — none of them consumes `HandleDataStream`, so their evidence is
   untouched;
10. `--handles` on that dump exits 4 with `HANDLES_PARSE_FAILED`, not
    `HANDLES_UNAVAILABLE` (§5.5).

**Malformed non-handle stream** — corrupt `ModuleListStream` only:

11. `--modules` exits **3** with a `SOURCE_FAILED` limitation naming
    `ModuleListStream` and zero records; `--threads` also exits **3**,
    with the same `SOURCE_FAILED` limitation (it declares `modules` as a
    completeness source), every thread record still present, and each
    record's `module_context == "unavailable"`. `--threads` exiting 0
    here would be a contract violation, not a nicety: its module
    classification genuinely did not run.
12. corrupt `ThreadListStream` **and** absent `ThreadInfoListStream`:
    `--threads` exits 3 with `SOURCE_FAILED`, **not** 0 — the
    re-gated early return (§2.4) must not treat a failed stream as an
    absent one.

**Unchanged failure modes**:

13. missing file → exit 1, `"File not found"`;
14. non-minidump/garbage and empty file → exit 1, `"Could not parse"` —
    i.e. `tests/unit/test_open_dump.py` continues to pass unmodified.

### 2.6 Residual risks explicitly not solved in v2.13

- A stream parser that **hangs** rather than raising is not caught by a
  `try/except`. The one known instance,
  `MinidumpHandleDescriptor.walk_objectinfo()`'s
  cycle-detection-free `NextInfoRva` chain, is removed from dumpex's
  path entirely by §5.1 (dumpex never walks `ObjectInfos`). No other
  unbounded loop over dump-controlled data was found in the parsers
  `_STREAM_DISPATCH` calls; if one is later found, it is a new issue,
  not a silent contract change.
- A `UnicodeDecodeError` inside `PEB.from_minidump()`'s
  `read_unicode_string_property()` (e.g. an odd `Length` on
  `ImagePathName`) still costs the **whole** PEB and surfaces as
  `PROCESS_PEB_UNAVAILABLE`/`SYSINFO_PEB_UNAVAILABLE`. v2.13 decouples
  only the environment block (§4.2), which is the case that produced a
  *false* result rather than an honest absence. Field-level PEB read
  decoupling belongs to #47/#48.

---

## §3 `--process`

Replaces `--pid` and `--peb`. `result.kind` is `"process"`.
`summary` is `{"count": 1}` — one record, always emitted, even when every
field is `null`.

### 3.1 Complete JSON shape

```json
{
  "process_name": "malware.exe",
  "pid": 4242,
  "process_path": "C:\\Users\\x\\Desktop\\malware.exe",
  "command_line": "\"C:\\Users\\x\\Desktop\\malware.exe\" -k",
  "process_start_utc": "2026-08-14 01:15:05 UTC",
  "image_base_address": "0x00007ff600010000",
  "iat": {
    "table_present": true,
    "table_va": "0x00007ff600021000",
    "table_size": 1024,
    "import_directory_present": true,
    "import_directory_va": "0x00007ff600020000",
    "import_directory_size": 280,
    "has_entries": true,
    "dll_count": 3,
    "entry_count": 42,
    "entries": [
      {
        "dll": "KERNEL32.dll",
        "import_by": "name",
        "symbol": "CreateFileW",
        "ordinal": null,
        "iat_slot_va": "0x00007ff600021018",
        "resolved_target_va": "0x00007ffb12345678",
        "slot_in_bounds": true
      }
    ],
    "diagnostics": []
  },
  "identity_evidence": {
    "misc_info_claim": {
      "pid": 4242,
      "process_create_time_utc": "2026-08-14 01:15:05 UTC",
      "raw_pid": null,
      "raw_process_create_time": null
    },
    "peb_claim": {
      "image_base_address": "0x00007ff600010000",
      "image_path": "C:\\Users\\x\\Desktop\\malware.exe",
      "name": "malware.exe",
      "raw_image_base_address": null,
      "raw_image_path": null,
      "raw_command_line": null
    },
    "module_claim": {
      "match_state": "resolved",
      "base_address": "0x00007ff600010000",
      "name": "malware.exe",
      "path": "C:\\Users\\x\\Desktop\\malware.exe",
      "name_matched_candidate": null,
      "name_matched_candidate_ambiguous": false
    },
    "main_image_pe": {
      "checked": true,
      "valid": true,
      "reason": null
    },
    "selected_path_source": "peb",
    "diagnostics": []
  },
  "peb_extended": { "…": "present only with --verbose, see §3.6" }
}
```

Field summary:

| field | type | source |
|---|---|---|
| `process_name` | `string \| null` | basename of the selected path (§3.3) |
| `pid` | `integer \| null` | `MINIDUMP_MISC_INFO.ProcessId` only (§3.3.2) |
| `process_path` | `string \| null` | selected path (§3.3) |
| `command_line` | `string \| null` | `peb.command_line`, normalized |
| `process_start_utc` | `string \| null` | `MINIDUMP_MISC_INFO.ProcessCreateTime` |
| `image_base_address` | hex address \| `null` | `peb.image_base_address`, normalized |
| `iat` | object (never `null`) | §3.5 |
| `identity_evidence` | object (never `null`) | §3.4 |
| `peb_extended` | object — key present iff `--verbose` | §3.6 |

### 3.2 Normalization comes first (coverage is derived from normalized values)

Coverage is **never** computed from raw truthiness. Every raw value is
run through its normalizer first; field availability, limitations, and
status are then derived from the normalized result. A truthy-but-invalid
raw value must not count as evaluated identity evidence.

```python
def normalize_pid(raw):
    """MINIDUMP_MISC_INFO.ProcessId -> int | None."""
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None                 # wrong type entirely
    if not (1 <= raw <= 0xFFFFFFFF):
        return None                 # 0 is the library's unset value and is
                                    # not a dumpable process; out-of-range
                                    # cannot be a real UINT32 PID
    return raw


def classify_process_create_time(raw):
    """-> 'ok' | 'unset' | 'invalid'. Range-checked BEFORE any
    datetime conversion: datetime.fromtimestamp() is platform-dependent
    and happily converts values a UINT32 field cannot hold."""
    if not isinstance(raw, int) or isinstance(raw, bool):
        return "invalid"
    if raw == 0:
        return "unset"
    if not (0 <= raw <= 0xFFFFFFFF):
        return "invalid"
    return "ok"


def normalize_windows_path(raw):
    """PEB/module path string -> str | None. Strips trailing NULs and
    surrounding whitespace; '' and whitespace-only become None (the
    codebase's existing `... or None` convention). Never truncates,
    never rewrites separators, never lowercases: the stored value is
    evidence."""


def normalize_command_line(raw):
    """Same rules as normalize_windows_path, minus any path
    interpretation. A command line that is genuinely empty is None."""


def normalize_image_base(raw):
    """peb.image_base_address -> int | None. Requires a plain int (not
    bool), 0 < raw <= 0xFFFFFFFFFFFFFFFF, and 0x1000 alignment. An
    unaligned or zero value is a read artifact, not a plausible mapped
    image base."""
```

**Nothing is discarded by a normalizer.** When a normalizer rejects a
value that was structurally present, the public field becomes `null` and
the rejected raw value is preserved verbatim in `identity_evidence`,
under the claim object belonging to the source it came from:

| public field | normalizer | raw kept at | raw JSON type |
|---|---|---|---|
| `pid` | `normalize_pid` | `misc_info_claim.raw_pid` | integer, or a string when the raw value was not an integer at all |
| `process_start_utc` | `classify_process_create_time` | `misc_info_claim.raw_process_create_time` | integer, or a string for a non-integer |
| `image_base_address` | `normalize_image_base` | `peb_claim.raw_image_base_address` | hex string when the raw value is an int in `uint64` range, otherwise a string |
| `process_path` | `normalize_windows_path` | `peb_claim.raw_image_path` | string |
| `command_line` | `normalize_command_line` | `peb_claim.raw_command_line` | string |

Every `raw_*` key is always present, and is `null` whenever
normalization succeeded **or** the source was absent — so "a normalizer
rejected something" is machine-detectable as `field is null and raw_field
is not null`, with no third state to disambiguate. A raw value that is
itself absent (the source object exists but the attribute is `None`) is
`null`, not the string `"None"`: nothing was seen, so there is nothing to
preserve.

`misc_info_claim.process_create_time_utc` is the formatted timestamp when
`classify_process_create_time()` returned `"ok"` and `null` otherwise; it
is the same value as the top-level `process_start_utc` and exists so both
MiscInfo claims sit next to their raw counterparts in one object.

Rejection of a structurally present value emits a limitation
(`PROCESS_IMAGE_BASE_INVALID`, `PROCESS_START_TIME_INVALID`, …) — it is
a genuine evaluation gap: dumpex saw bytes it will not certify.

### 3.3 Evidence precedence

#### 3.3.1 The precedence table

| claim | preferred source | approved fallback | never |
|---|---|---|---|
| `pid` | `MINIDUMP_MISC_INFO.ProcessId` | **none** (§3.3.2) | thread ID, exception TID |
| `process_start_utc` | `MINIDUMP_MISC_INFO.ProcessCreateTime` | none | thread create time |
| `process_path` | `peb.image_path` | module resolved by `image_base_address` (§3.3.3) | any string scan |
| `process_name` | basename of the **selected** `process_path` | — | module name chosen independently of the path |
| `command_line` | `peb.command_line` | none | — |
| `image_base_address` | `peb.image_base_address` | none (§3.3.4) | module base |

`identity_evidence.selected_path_source` records which one actually won:
`"peb"`, `"module"`, or `null` when neither produced a path.

#### 3.3.2 PID has no fallback chain

`--pid`'s thread-list and exception-stream fallbacks are **not** carried
into `--process`. `PID_THREAD_LIST_FALLBACK` and
`PID_EXCEPTION_TID_FALLBACK` describe cross-checks that yield a TID, not
a PID; `#36`'s "a thread ID must never be presented as a PID" is
enforced structurally by giving `--process` exactly one PID source. When
`normalize_pid()` returns `None`, `pid` is `null` and either
`PROCESS_MISC_INFO_UNAVAILABLE` (stream absent) or
`PROCESS_PID_UNAVAILABLE` (stream present, field unusable) fires.
`PidRecord.exc_tid` has no successor field.

#### 3.3.3 The module fallback, and `resolve_module_by_base()`

#38 adds:

```python
def resolve_module_by_base(base_address, modules):
    """The module whose baseaddress == base_address EXACTLY, or None.
    Deliberately NOT addr_to_module(), whose containment test
    (baseaddress <= addr < endaddress) would match the main image for
    any address inside it -- here the question is 'is a module
    REGISTERED at exactly this base', and containment would answer a
    different, weaker question."""
```

The fallback runs only when the preferred path is unavailable **and**
`normalize_image_base()` produced a usable base **and** `modules` is
present. It contributes `process_path` (the module's own full path,
normalized) and, through it, `process_name`.

#### 3.3.4 Image base has no fallback

`image_base_address` is a PEB claim. The module list's own base for a
name-matched candidate is recorded as an independent claim in
`module_claim` (§3.4.3) and is **never** promoted into
`image_base_address`. A fallback must never overwrite or relabel a
preferred source's evidence; §3.4 keeps both claims side by side and
lets the analyst see the disagreement.

### 3.4 `identity_evidence`

Always present, never `null`. Its sub-objects are always present with
`null` members when their source is unavailable.

#### 3.4.1 `misc_info_claim`

```json
"misc_info_claim": {
  "pid": 4242 | null,
  "process_create_time_utc": "2026-08-14 01:15:05 UTC" | null,
  "raw_pid": null | 0 | "not-an-int",
  "raw_process_create_time": null | 4294967296
}
```

This object exists so MiscInfo's two identity claims are attributable
and auditable on the same terms as the PEB's (§3.2): a PID of `0` or a
`ProcessCreateTime` beyond `0xFFFFFFFF` is rejected for the public field
and preserved here, so an analyst can see exactly what the dump
contained without dumpex certifying it. All four members are `null` when
`misc_info` is absent or failed.

#### 3.4.2 `peb_claim`

```json
"peb_claim": {
  "image_base_address": "0x00007ff600010000" | null,
  "image_path": "C:\\…\\malware.exe" | null,
  "name": "malware.exe" | null,
  "raw_image_base_address": null | "0x0000000000000abc",
  "raw_image_path": null | "<raw string>",
  "raw_command_line": null | "<raw string>"
}
```

`name` is the basename of `peb_claim.image_path` (via
`ntpath.basename`, the existing `module_name_only()` rule — Windows
paths must not be split with `os.path.basename` on a POSIX analysis
host). It is the PEB's own name claim, independent of whichever path
`process_name` was ultimately derived from.

#### 3.4.3 `module_claim`

```json
"module_claim": {
  "match_state": "resolved" | "unregistered" | "unavailable",
  "base_address": "0x00007ff600010000" | null,
  "name": "malware.exe" | null,
  "path": "C:\\…\\malware.exe" | null,
  "name_matched_candidate": null | {
    "base_address": "0x00007ff600010000",
    "name": "malware.exe",
    "path": "C:\\Windows\\Temp\\malware.exe"
  },
  "name_matched_candidate_ambiguous": false
}
```

- `match_state`:
  - `"resolved"` — `resolve_module_by_base()` found an exact match.
    `base_address`/`name`/`path` are that module's own values.
  - `"unregistered"` — `ModuleListStream` is present (and the image base
    normalized) but no module is registered at that exact base.
    `base_address`/`name`/`path` are `null`.
  - `"unavailable"` — `ModuleListStream` is absent/failed, or the image
    base did not normalize, so the question could not be asked at all.
    `base_address`/`name`/`path`/`name_matched_candidate` are all
    `null`; `name_matched_candidate_ambiguous` is `false`, not `null` —
    it is a plain boolean in every state, and "no candidate was found"
    is not ambiguity. This state is **not** a conflict signal and emits
    no diagnostic.
- `path` is the module's complete recorded path, kept alongside
  `base_address` and the derived `name`. It exists so the ModuleList
  claim is preserved in full and the selected fallback source is
  auditable: when `selected_path_source == "module"`, the value that won
  is visible here, attributable to ModuleListStream, and comparable to
  `peb_claim.image_path`.
- `name_matched_candidate` is populated **only** when `match_state ==
  "unregistered"` and some module's basename equals
  `peb_claim.name`'s basename (case-insensitive, reusing
  `module_name_only()`). Found by a second deterministic pass in the
  module list's own source order — no re-sort. It carries the full
  triple (base, name, path), for the same auditability reason.
  This is a **positive** base-conflict signal — "the PEB says this image
  is `malware.exe` based at `0xAAAA`; ModuleListStream's own
  `malware.exe` entry is loaded at `0xBBBB`" — which is strictly more
  informative than "no exact match". `null` (not `{}`) when there is no
  such candidate.
- `name_matched_candidate_ambiguous` is `true` when more than one module
  shares that basename. Only the first (source order) is reported; the
  flag says so rather than silently picking one.

#### 3.4.4 `main_image_pe` and the `ProcessDiagnostic` shape

```json
"main_image_pe": { "checked": true, "valid": false, "reason": "no PE\\0\\0 signature at e_lfanew" }
```

`checked` is `false` (with `valid: null`, `reason: null`) when there was
no normalized image base to check, or the memory at that base was not
captured. `reason` is `parse_pe_header()`'s own `reason` string, which
that function already produces from a closed set of structural
conditions; it is copied verbatim, never composed.

Every diagnostic, in either array, has exactly this shape:

```json
{
  "code": "PROCESS_MODULE_BASE_CONFLICT",
  "severity": "warning",
  "message": "a module named malware.exe is loaded at 0x…, not the PEB-reported image base 0x…",
  "affected_count": null,
  "details": { "name": "malware.exe", "module_base": "0x…", "peb_base": "0x…" }
}
```

- `code`: from §6.2's closed list.
- `severity`: `"info"` or `"warning"` only, fixed per code in §6.2.
- `message`: rendered from the code's frozen template in §6.2 — never
  caller-composed free text, the same rule `render_limitation()` already
  enforces for limitations.
- `affected_count`: `null` for one-shot diagnostics; a positive integer
  for aggregating ones (`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS`).
- `details`: a closed, per-code key set, frozen in §6.2. Addresses inside
  `details` follow §1.3's hex rule.
- At most **one** entry per code per record; repeated occurrences
  aggregate into `affected_count`. Array order is §6.2's declaration
  order, making the array a deterministic function of which codes fired.

### 3.5 `iat`

Always present as an object, never `null`. Its three presence booleans
are defined in §3.5.2 and are not interchangeable.

#### 3.5.1 Scope: standard imports only

Descriptors come from `IMAGE_DIRECTORY_ENTRY_IMPORT` (data directory
index **1**). `table_va`/`table_size` come from
`IMAGE_DIRECTORY_ENTRY_IAT` (index **12**), and index 12 is also what
`slot_in_bounds` is checked against. The two are different directories
and must not be conflated.

`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (index 13) is **out of scope for
v2.13**. Delay-loaded imports are not reported, not counted, and their
absence is not a limitation. Adding them is a future issue that must
extend this section first.

#### 3.5.2 Directory presence versus entry count — three independent booleans

`#36` requires the IAT's public shape to report **table presence**, VA,
and size. Presence of a table and presence of imports are different
facts, and a single `present` flag cannot carry both: "the PE declares an
IAT directory but imports nothing" and "the PE declares no IAT directory
at all" are distinguishable evidence, and collapsing them would discard
it. The record therefore carries three independent booleans, each with
one meaning:

| field | type | `true` when |
|---|---|---|
| `import_directory_present` | `true \| false \| null` | data directory index **1** is declared and has a non-zero RVA |
| `table_present` | `true \| false \| null` | data directory index **12** is declared and has a non-zero RVA |
| `has_entries` | `true \| false` | `entry_count > 0` |

**"Not in the list" is not the same as "not declared".**
`parse_pe_header()` builds `data_directories` by reading
`NumberOfRvaAndSizes`, capping it at 16, and then appending `(rva, size)`
pairs until either the count is reached or the next 8-byte entry would
run past the end of the buffer — at which point it simply `break`s. A
short list therefore has two completely different causes that the list
alone cannot distinguish: the image declared few directories, or the
image declared many and the bytes were not captured. Treating both as
"the directory does not exist" would let a truncated header read be
reported as **"this image imports nothing," complete, exit 0** — a false
claim about the evidence, which is exactly what this contract exists to
prevent.

#39 therefore extends `parse_pe_header()`'s result with two additive
fields (no existing key changes meaning, so the stomping hunter's own
`data_directories[5]` use is unaffected):

| new key | type | meaning |
|---|---|---|
| `declared_directory_count` | `int \| None` | `min(NumberOfRvaAndSizes, 16)` as actually read. **`None`** — never `0` — when that field's own four bytes were not captured, i.e. when `parse_pe_header()` skips its `if num_rva_sizes_off + 4 <= len(data)` guard entirely |
| `directories_complete` | `bool` | `declared_directory_count is not None and len(data_directories) == declared_directory_count` |

The `None` is load-bearing. `0` would mean "this image declares no data
directories at all", a positive claim, and would send both indices down
the `false` branch below — reproducing the very "this image imports
nothing, exit 0" failure this section exists to prevent, one level
further up.

Presence of one directory index `i` is then resolved in three states,
never two:

| condition | `*_present` | meaning |
|---|---|---|
| `declared_directory_count is None` | **`null`** | the count itself was not captured — nothing can be said about any index |
| `i >= declared_directory_count` | `false` | the image positively declares no such directory |
| `i < len(data_directories)` and the pair is `(0, 0)` | `false` | declared, but a zero RVA means no directory |
| `i < len(data_directories)` and the RVA is non-zero | `true` | present; `*_va`/`*_size` populated |
| `i < declared_directory_count` but `i >= len(data_directories)` | **`null`** | declared, but its bytes were not captured — **undetermined** |

A `null` is never a claim. When either index resolves to `null`, one
`IAT_DIRECTORY_TABLE_INCOMPLETE` limitation fires, coverage is
`partial`, and exit is 3. Its `affected_count` is **optional**, because
the two undetermined cases know different amounts:

| case | `affected_count` | rendered as |
|---|---|---|
| `declared_directory_count` known, list short | `declared_directory_count - len(data_directories)` | "{count} declared data directory entr(y/ies) were not captured; import/IAT directory presence is undetermined" |
| `declared_directory_count is None` | `null` | "the data directory table was not captured; import/IAT directory presence is undetermined" |

Reporting a fabricated count in the second case would be worse than
reporting none: the number of missing entries is genuinely unknown. `IAT_BOUNDS_CHECK_UNAVAILABLE` (§6.2) does
**not** fire in that case: that diagnostic asserts the image declares no
IAT directory, which is precisely what is unknown here.

`IAT_DIRECTORY_TABLE_INCOMPLETE` is suppressed when
`PROCESS_MAIN_IMAGE_PE_INVALID` fired, since no walk was attempted at
all and the invalid-PE code already accounts for it. The two are not
usually redundant: a directory array truncated *after* the point
`opt_hdr_size` places the section table still leaves
`parse_pe_header()` returning `valid=True`, which is exactly the
crafted-header case this code exists for.

`has_entries: false` on its own never means "this image imports
nothing". That claim is supported only when
`import_directory_present == false` **and** `coverage.status ==
"complete"`.

Frozen consequences of each determined combination:

| `import_directory_present` | `table_present` | outcome |
|---|---|---|
| `false` | `false` or `true` | no descriptors walked, `entries: []`, `has_entries: false`, `dll_count`/`entry_count` = `0`. **No `IAT_*` limitation** — a PE that imports nothing has no imports to miss, so this is `complete`. |
| `true` | `true` | the normal case; `slot_in_bounds` is a real boolean on every entry. |
| `true` | `false` | descriptors **are** walked and entries **are** reported — the imports themselves are fully recoverable from directory 1 alone. There is no range to check slots against, so `slot_in_bounds` is `null` on **every** entry, `table_va`/`table_size` are `null`, and one `info` diagnostic `IAT_BOUNDS_CHECK_UNAVAILABLE` is emitted (§6.2). **No limitation, coverage unaffected**: the requested claim — which symbols this image imports — was fully evaluated; only an optional corroborating check had no reference range (§1.6). |
| `null` | anything | undetermined: no descriptors walked, `entries: []`, `has_entries: false`, and `IAT_DIRECTORY_TABLE_INCOMPLETE` → `partial`, exit 3. No diagnostic. |
| `true` | `null` | descriptors **are** walked and entries reported; `slot_in_bounds` is `null` on every entry, `table_va`/`table_size` are `null`, and `IAT_DIRECTORY_TABLE_INCOMPLETE` → `partial`, exit 3. No `IAT_BOUNDS_CHECK_UNAVAILABLE` — whether a range exists is unknown, not answered. |

`slot_in_bounds` is therefore typed `true | false | null`. `null` means
"the check could not be performed", and which of the two reasons applies
is read off `table_present`: `false` → the image declares no IAT
directory (a determined answer, reported as a diagnostic, coverage
unaffected); `null` → the directory table itself was not fully captured
(undetermined, reported as a limitation, `partial`). It never means
anything else.

#### 3.5.3 Entry shape and per-field nullability

```json
{
  "dll": "KERNEL32.dll" | null,
  "import_by": "name" | "ordinal",
  "symbol": "CreateFileW" | null,
  "ordinal": 42 | null,
  "iat_slot_va": "0x…" | null,
  "resolved_target_va": "0x…" | null,
  "slot_in_bounds": true | false | null
}
```

- `import_by` is a tagged discriminator: `"name"` → `symbol` may be
  populated and `ordinal` is always `null`; `"ordinal"` → `ordinal` is
  populated and `symbol` is always `null`.
- **Captured targets are preserved.** A failed read never deletes an
  entry, and never deletes the sibling fields that read independently.
  If a DLL name's bytes fail to read, the entry is still reported with
  `dll: null` — never a placeholder string — and `import_by`, `symbol`,
  `ordinal`, `iat_slot_va`, `resolved_target_va` keep whatever was
  independently recoverable. A DLL-name read and a symbol-name read are
  separate bounded reads at different addresses; one failing says
  nothing about the other. Each such loss adds one occurrence to
  `IAT_NAME_READ_FAILED`'s `affected_count` — one code, not one code per
  field name.
- `slot_in_bounds` is `false` when the entry's `iat_slot_va` falls
  outside the declared index-12 range, and `null` when there is no such
  range to check against (§3.5.2). A `false` is a **diagnostic**, not a
  gap: the walk succeeded and found a suspicious value (§3.5.5).

#### 3.5.4 Budgets and truncation attribution

All six budgets in §1.8 apply. Reaching any of them stops the walk and
emits exactly one `IAT_ENTRIES_TRUNCATED` limitation whose **`scope`
names the budget that actually triggered**, with that budget's own
limit and consumption — reusing the existing budget-attribution fields
(`scope` + `budget_limit` + `budget_consumed`) and the existing
`_render_budget_clause()` format:

| `scope` value | triggering constant |
|---|---|
| `iat_dlls` | `MAX_IAT_DLLS` |
| `iat_entries_per_dll` | `MAX_IAT_ENTRIES_PER_DLL` |
| `iat_total_entries` | `MAX_IAT_TOTAL_ENTRIES` |
| `iat_bytes_read` | `MAX_IAT_BYTES_READ` |
| `iat_read_operations` | `MAX_IAT_READ_OPERATIONS` |

`scope`, `budget_limit`, and `budget_consumed` are all **required** on
this code; a bare truncation with no budget attribution is rejected at
construction. `MAX_IAT_NAME_LENGTH` is not in this table: hitting it
truncates one name, which is reported as that entry's name being
unavailable (`IAT_NAME_READ_FAILED`), not as the walk stopping.

Rendered example:

```
the import table walk stopped after reaching a read budget (budget: iat_bytes_read, limit=16777216 consumed=16777216)
```

#### 3.5.5 `iat.diagnostics[]` — the one legal home for IAT observations

`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` is **a diagnostic code, not a
`LimitationCode`.** It is never added to `LimitationCode`, never
constructed as a `CoverageLimitation`, never passed to
`completeness_checks`, and therefore structurally incapable of
downgrading coverage. It lives in `iat.diagnostics[]`, using §3.4.4's
shape:

```json
{
  "code": "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS",
  "severity": "warning",
  "message": "3 IAT slot(s) fall outside the declared IAT directory range",
  "affected_count": 3,
  "details": {
    "table_va": "0x00007ff600021000",
    "table_size": 1024,
    "first_out_of_bounds_slot_va": "0x00007ff6000ff000"
  }
}
```

`affected_count` is the total number of out-of-bounds slots;
`first_out_of_bounds_slot_va` is the lowest such slot VA in walk order,
so the diagnostic points at something concrete without carrying an
unbounded list. `iat.diagnostics` is `[]` when nothing fired — never
`null`.

Every `IAT_*` code **other than these two diagnostics** —
`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` and `IAT_BOUNDS_CHECK_UNAVAILABLE`
(§3.5.2) — **is** a `LimitationCode` and does drive `partial` (§6.1).
The two diagnostics are mutually exclusive, and neither is ever a
`LimitationCode`.

### 3.6 `peb_extended` (verbose only)

`--process --verbose` always includes the key; `--process` without it
never does. Presence depends **only** on the flag — never on whether the
PEB is available — so there is no second, data-dependent layer of "is
the key even there" on top of the verbosity gate.

```json
"peb_extended": {
  "peb_address": "0x…" | null,
  "being_debugged": true | false | null,
  "window_title": "…" | null,
  "dll_path": "…" | null,
  "standard_input": "0x…" | null,
  "standard_output": "0x…" | null,
  "standard_error": "0x…" | null
}
```

These are exactly the `--peb`-only fields that survive: they are
**retained under `--process --verbose`, not retired**. All seven are
`null` when the PEB is unavailable. `current_directory` and
`environment_variables`, the other two `--peb` fields, move to
`--sysinfo` (§4) and do **not** appear here — they are host/session
context, not process identity.

The v2.13 schema declares `peb_extended` as an optional property of the
process record (the only optional property in these three records), with
`additionalProperties: false` and all seven keys required when present.

### 3.7 Coverage: two disjoint groups

`--process` computes coverage from **field coverage** only. Consistency
checks are isolated and can never move the status.

#### 3.7.1 Field availability (drives status)

Derived from normalized values (§3.2), never from raw truthiness:

```python
pid_available          = normalize_pid(getattr(mi, "ProcessId", None)) is not None
start_time_available   = classify_process_create_time(
                             getattr(mi, "ProcessCreateTime", None)) == "ok"
image_base_available   = normalize_image_base(
                             getattr(peb, "image_base_address", None)) is not None
command_line_available = normalize_command_line(
                             getattr(peb, "command_line", None)) is not None
# Fallback-aware: the PATH claim is available if EITHER source produced one.
path_available         = (normalize_windows_path(getattr(peb, "image_path", None)) is not None
                          or module_fallback_path is not None)
```

`process_name` has no independent availability: it is available exactly
when `path_available` is true.

#### 3.7.2 Status rules

- **`not_evaluated`** (exit 4): **none** of the five availability flags
  is true → `PROCESS_SOURCES_ABSENT`. This is a field-level test, not an
  object-level one: `mi` and `peb` can both be real objects while
  contributing zero usable identity fields (each of
  `ProcessId`/`ProcessCreateTime` is independently gated by its own
  `Flags1` bit, `image_path`/`command_line` can each be a genuinely
  empty string that `read_unicode_string_property()` returns as `""`,
  and a normalizer can reject every value it was given).
  The reducer only understands `SourceState`, so the field-level fact is
  expressed as a **derived source**, `process_identity` (§3.7.4): its
  observation is `ABSENT` when no flag is true and `PRESENT` (record
  count = number of true flags) otherwise, and `--process` passes
  `EvaluationRequirement(sources=("process_identity",),
  all_absent_code=PROCESS_SOURCES_ABSENT)`. That reuses `--peb`'s
  existing single-source shape rather than adding a second reduction
  path, and it keeps the "objects present, nothing usable" case
  reachable at exit 4 — which a hand-built `caller_buildable`
  limitation could not do, since `completeness_checks` only ever
  produces `partial`. The field-level limitations explaining **why**
  nothing was usable survive alongside it, via the opt-in below.
- **`partial`** (exit 3) when any of these fired:
  - *Object-level*, and `absent` is **not** the same as `failed` here
    (§2.4): `misc_info` **absent** → `PROCESS_MISC_INFO_UNAVAILABLE`
    (covers `pid` and `process_start_utc` together); `misc_info`
    **failed** → `SOURCE_FAILED` with the parser detail, since
    "MiscInfo stream not present in this dump" would be a false
    statement about a stream that is present. `peb` **absent** →
    `PROCESS_PEB_UNAVAILABLE` (covers `process_path`, `command_line`,
    `image_base_address` together); `peb` has no `failed` state at all
    (§2.4). Either way, when an object-level code fires, the
    corresponding field-level codes are **suppressed** — one absence is
    reported once.
  - *Field-level* (source object present, one field unusable):
    `PROCESS_PID_UNAVAILABLE`, `PROCESS_START_TIME_UNSET`,
    `PROCESS_START_TIME_INVALID`, `PROCESS_PATH_UNAVAILABLE`,
    `PROCESS_COMMAND_LINE_UNAVAILABLE`,
    `PROCESS_IMAGE_BASE_UNAVAILABLE`, `PROCESS_IMAGE_BASE_INVALID`.
  - `PROCESS_PATH_UNAVAILABLE` fires **only when both** the preferred
    PEB path and the approved module fallback are unavailable. A PEB
    with an empty `ImagePathName` whose image base resolves to a
    registered module with a path is `complete` on the path claim, with
    `selected_path_source == "module"`.

    Its wording is deliberately **neutral about why the fallback
    failed**. The four ways it can fail are genuinely different — the
    image base never normalized, `ModuleListStream` is absent, it failed
    to parse, or it parsed and registered nothing at that base — and
    only the last one licenses the statement "no module is registered at
    the image base". Attribution is therefore carried by a **separate**
    limitation, chosen from the fallback's own state, and emitted only
    when the fallback was actually needed (i.e. the PEB path was
    unavailable):

    | fallback state when needed | attribution |
    |---|---|
    | image base did not normalize | `PROCESS_IMAGE_BASE_UNAVAILABLE`/`_INVALID`, already fired |
    | `modules` absent | `PROCESS_MODULE_FALLBACK_UNAVAILABLE` |
    | `modules` failed | `SOURCE_FAILED` for `modules`, with the parser detail |
    | `modules` present, no exact base match | no extra limitation — `PROCESS_MODULE_BASE_UNMATCHED`/`_CONFLICT` (§6.2) already describes it, and the check did run |

    Mechanically: `--process` appends `SourceRequirement("modules",
    absent_code=PROCESS_MODULE_FALLBACK_UNAVAILABLE)` to
    `completeness_checks` **only when the fallback could actually have
    run**:

    ```python
    fallback_was_needed = (peb_path_unavailable
                           and normalize_image_base(...) is not None)
    ```

    Both conjuncts matter. Without the first, a dump whose PEB supplied
    a path would be penalised for a missing optional corroborator.
    Without the second, a dump whose image base never normalized would
    report `PROCESS_MODULE_FALLBACK_UNAVAILABLE` (or a `SOURCE_FAILED`
    for `modules`) on top of `PROCESS_IMAGE_BASE_INVALID` — blaming
    `ModuleListStream` for a lookup that was never attempted, and
    contradicting the attribution table directly above, which assigns
    that case to the image-base codes alone.

    When `fallback_was_needed` is false, `modules` stays a pure observer
    (§3.7.4): absent or failed, it emits nothing and cannot affect
    status.
  - *Main image*: `PROCESS_MAIN_IMAGE_READ_FAILED`,
    `PROCESS_MAIN_IMAGE_SHORT_READ`, `PROCESS_MAIN_IMAGE_PE_INVALID`.
    These are genuine gaps — the IAT could not be evaluated from that
    image — and they are the reason `main_image` is its own coverage
    source.
  - *IAT*: any `IAT_*` limitation from §6.1.
- **`complete`** (exit 0): all five availability flags true, the IAT
  evaluated (a valid PE with zero imports counts as evaluated), and no
  limitation from the lists above. Non-empty
  `identity_evidence.diagnostics` or `iat.diagnostics`, and any
  `module_claim` state including `"unregistered"`, do **not** downgrade
  this.

#### 3.7.3 `not_evaluated` must not swallow the reasons

`build_coverage_report()` today, once any evaluation group is all-absent,
short-circuits: it emits the group's own limitation, re-surfaces any
`FAILED` completeness **source**, and explicitly skips every pre-built
`CoverageLimitation` ("a pre-built business fact never applies when
nothing was evaluated"). That reasoning is right for a genuinely empty
dump — but it is exactly wrong here. `PROCESS_SOURCES_ABSENT` says *that*
no identity evidence was usable; `PROCESS_PID_UNAVAILABLE`,
`PROCESS_START_TIME_INVALID`, and their siblings say *why*, per field,
and they were computed from evidence that really was examined. Dropping
them would leave an analyst with an exit code and a single sentence, and
would contradict §8.3 item 5.

#38 therefore adds one **opt-in** keyword to `build_coverage_report()`:

```python
build_coverage_report(sources, *, evaluation_sources=None,
                      evaluation_groups=None, completeness_checks=None,
                      retain_completeness_checks_when_not_evaluated=False)
```

Frozen semantics:

- Default `False` — every existing command's output is byte-identical to
  today. Only `--process` (§3.7.2) and `--handles` (§5.5) pass `True`.
- When `True` and a group fires, `status` is still `not_evaluated` and
  the exit code is still 4. The flag changes **which limitations are
  reported**, never the status.
- Limitation order is frozen as: the group's own limitation first, then
  the retained `completeness_checks` in caller-declared order, then the
  `FAILED`-source limitations the reducer already re-surfaces today.
- Retained entries are only the pre-built `CoverageLimitation`s.
  `SourceRequirement`/bare-name checks keep today's behavior exactly:
  a `FAILED` source is re-surfaced, an `ABSENT` one is not (it would
  merely repeat what the group limitation already said).
- Every retained limitation still passes `_validate_limitation_against_
  sources()`. The flag relaxes nothing about correctness.

#### 3.7.4 Coverage sources

`coverage.sources` for `--process` has exactly six keys:
`process_identity`, `misc_info`, `peb`, `modules`, `main_image`, `iat`.

- `process_identity` is a derived source ("at least one of the five
  normalized identity fields resolved"). It is the command's only
  `evaluation_sources` member (§3.7.2) and is never a
  `SourceRequirement` — it would otherwise report the same fact twice.
- `modules` is always observed, but is a `SourceRequirement` **only
  conditionally** (§3.7.2 — when the PEB supplied no path, so the
  fallback was actually needed). Outside that case it is pure optional
  corroboration: absent or failed, it emits no limitation and cannot
  affect status.
- `main_image` is a derived source ("the PE header at the PEB-reported
  image base was read and structurally validated"), following the
  precedent `coverage.py` already documents for `thread_context`.
- `iat` is a derived source ("the import walk ran"). Its state follows
  §3.5.2: `present` (count = `entry_count`) when entries were recovered,
  `present_empty` when the walk ran and found none — whether because the
  image declares no import directory or because a declared one is empty.
  Both are `complete`, not a gap: the walk answered the question. The
  source is `absent` only when there was no normalized image base or no
  captured main image to walk at all, which is already reported by
  `PROCESS_IMAGE_BASE_*`/`PROCESS_MAIN_IMAGE_*` and emits no `iat`
  limitation of its own.

### 3.8 Console layout

```
═══ PROCESS ═══
  [~] <coverage.reasons, one "[~] " line each, if any>

  Process Name           malware.exe
  PID                    4242 (0x1092)
  Path                   C:\Users\x\Desktop\malware.exe
  Command Line           "C:\Users\x\Desktop\malware.exe" -k
  Start Time (UTC)       2026-08-14 01:15:05 UTC
  Image Base             0x00007ff600010000

  Import Address Table
    <"42 import(s) across 3 DLL(s)"                    if iat.has_entries>
    <"(none -- this image declares no imports)"        if not iat.import_directory_present>
    <"(none -- import directory present, zero entries)"
                                                       if iat.import_directory_present
                                                          AND not iat.has_entries AND no
                                                          partial-driving IAT_* code fired>
    <"(unavailable -- see coverage below)"             if not iat.has_entries AND a
                                                          partial-driving IAT_* code fired>
    <table of entries, --verbose only>

  Identity
    <one line per identity_evidence.diagnostics entry, "[!] " prefix for
     severity=warning, "[i] " for severity=info -- message text only>
    <nothing at all when diagnostics is empty>
```

Rules:

- An unavailable field prints `(unknown)` in its value column, never a
  blank or a guessed value.
- The default console stays concise and surfaces **actionable
  conflicts** — the `Identity` block prints diagnostics and nothing
  else. The complete check/provenance matrix (every claim, its source,
  its raw value, every check that ran and passed) is `--verbose` only:

```
  Evidence Matrix                                     [--verbose only]
    Claim          Selected      PEB              ModuleList
    path           peb           C:\…\malware.exe C:\Windows\Temp\malware.exe
    image base     peb           0x00007ff6…      0x00007ff6…  (unregistered)
    name           peb           malware.exe      malware.exe
    Checks         main-image PE: valid | base match: unregistered |
                   name candidate: ambiguous=false
```

- `--verbose` also prints the IAT entry table and the `peb_extended`
  block under an `Extended PEB` header.

### 3.9 Summary

`summary = {"count": 1}`. No other keys. IAT counts live on the record
(`iat.dll_count`, `iat.entry_count`), not in the summary, so a consumer
reads them from one place.

---

## §4 `--sysinfo`

`result.kind` stays `"sysinfo"`. `summary = {"count": 1}`.

### 4.1 Removed and added fields

**Removed** (they move to `--process`, or are dropped):

| removed field | where it goes |
|---|---|
| `pid` | `--process.pid` |
| `process_start_utc` | `--process.process_start_utc` |
| `image_path` | `--process.process_path` |
| `command_line` | `--process.command_line` |
| `process_user_time_seconds` | dropped (no successor) |
| `process_kernel_time_seconds` | dropped (no successor) |

The console `Process` section is removed entirely.
`cpu_current_mhz`/`cpu_max_mhz` are **not** removed — they are sourced
from `MINIDUMP_MISC_INFO`'s `ProcessorCurrentMhz`/`ProcessorMaxMhz`,
which is why `misc_info` remains a required `--sysinfo` source and
`SYSINFO_MISC_INFO_UNAVAILABLE` remains meaningful. #41 does not
re-decide this.

**Added**: `current_directory` and `environment_variables`.

### 4.2 Complete field table (15 fields)

| # | field | type | source |
|---|---|---|---|
| 1 | `dump_file` | `string \| null` | basename of the dump path |
| 2 | `hostname` | `string \| null` | `COMPUTERNAME` from the environment walk |
| 3 | `username` | `string \| null` | `USERNAME` from the environment walk |
| 4 | `os` | `string \| null` | `SystemInfoStream` (+ the Win11 build correction already in `_os_display_name()`) |
| 5 | `os_version` | `string \| null` | `SystemInfoStream` |
| 6 | `architecture` | `string \| null` | `SystemInfoStream` |
| 7 | `product_type` | `string \| null` | `SystemInfoStream` |
| 8 | `processors` | `integer \| null` | `SystemInfoStream` |
| 9 | `cpu_vendor` | `string \| null` | `SystemInfoStream` |
| 10 | `cpu_current_mhz` | `integer \| null` | `MiscInfo` |
| 11 | `cpu_max_mhz` | `integer \| null` | `MiscInfo` |
| 12 | `thread_count` | `integer \| null` | `ThreadListStream` (`null`, not `0`, when the stream is absent) |
| 13 | `module_count` | `integer \| null` | `ModuleListStream` (same rule) |
| 14 | `current_directory` | `string \| null` | `peb.current_directory`, normalized |
| 15 | `environment_variables` | `list[{name,value}] \| null` | §4.3 |

`hostname`/`username` now derive from the independent environment walk
(§4.3) rather than from `peb.environment_variables`, so they survive the
case where the library's own PEB build was lost to a bad environment
block.

### 4.3 `environment_variables`: an independent bounded walk

#### 4.3.1 Why the library's list cannot be trusted as-is

`minidump/structures/peb.py`'s environment loop is:

```python
while (env_len := env_buffer.find(b"\x00\x00")) and (env_len != -1):
```

Python's `and` makes this `False` in **two** different cases that the
resulting `[]` cannot distinguish afterward: `env_len == 0` (a verified,
well-formed empty block) and `env_len == -1` (`-1 and False` → `False`
— no terminator found anywhere in the read window, i.e. a malformed or
truncated block). A **partial** capture is equally invisible: the loop's
re-read is bounded by `buff_reader.current_segment.end_address`, so if a
later terminator falls outside the captured segment the loop simply
stops and keeps whatever it had, with no signal that it did.

Worse, that whole loop runs **inside** `PEB.from_minidump()`. An
exception anywhere in it (an environment VA that is not in any captured
segment, `current_segment` being `None`, an odd-length UTF-16 buffer)
propagates out of `from_minidump()` and is swallowed by
`_parse()`/phase 3b, leaving `mf.peb is None`. Malformed environment
evidence therefore masquerades as a total PEB absence.

#### 4.3.2 The frozen walk

#38 adds `walk_environment_block(mf)`, which **never reads `mf.peb`**.
It re-derives every pointer itself, so it works even when the library's
PEB build was lost:

```python
def walk_environment_block(mf, max_bytes=MAX_ENV_BYTES,
                           max_entries=MAX_ENV_ENTRIES):
    """-> (state, entries, detail). Never raises."""
```

**Architecture and offsets.** `is_x64 = (mf.sysinfo.ProcessorArchitecture
!= PROCESSOR_ARCHITECTURE.INTEL)`, matching the library's own rule.
`ptr_size` is 8 for x64 and 4 for x86. Offsets come from the library's
own `PEB_OFFSETS[int(is_x64)]` table — the same constants the library
reads, not a second hand-copied table:

| step | x86 | x64 |
|---|---|---|
| `TEB → PEB` | `+0x30` | `+0x60` |
| `PEB → ProcessParameters` | `+0x10` | `+0x20` |
| `ProcessParameters → Environment` | `+0x48` | `+0x80` |

The PEB pointer is read at `mf.threads.threads[0].Teb + off["peb"]`.
Note that `PEB.from_minidump()` never assigns `peb.process_parameters`
(it keeps the value in a local), so that attribute is always `None` on
the library's object and must not be used as a shortcut — the walk
re-reads it.

**Read semantics.**

- Every pointer read is a bounded `read(ptr_size)` through the buffered
  reader. A raised exception (`"Memory address … is not in process
  memory space"`, `"Would read over segment boundaries!"`) or a short
  read (fewer than `ptr_size` bytes) is a **failed pointer read**, not a
  zero pointer: state `pointer_unreadable`, with `detail` naming which
  step failed.
- A pointer that reads successfully but is `0` is also
  `pointer_unreadable`, with a detail naming the null step — a null
  `ProcessParameters` or `Environment` pointer is not an empty
  environment.
- The block is read forward in bounded chunks from the environment VA,
  never in one unbounded `read(segment_end - position)`.
- The block is read forward in bounded chunks from the environment VA,
  never in one unbounded `read(segment_end - position)`.

**The walk operates on UTF-16 code units, not on bytes.** This is the
single most error-prone rule in the whole contract, so it is spelled out
completely:

- The block's grammar is: a sequence of NUL-terminated UTF-16LE strings,
  followed by one additional NUL **code unit** that terminates the block.
  A NUL code unit is **two** zero bytes; the block terminator that
  follows the last entry's own terminator therefore appears as **four**
  consecutive zero bytes.
- `b"\x00\x00"` on its own is **one UTF-16 NUL code unit** — an entry
  terminator, not a block terminator. Searching the raw bytes for
  `b"\x00\x00"` and calling the first hit "the end of the block" is
  precisely the upstream bug this walk exists to avoid; it would stop at
  the end of the *first* entry.
- The walk is therefore: starting at the block VA, repeatedly read one
  NUL-terminated UTF-16LE string. A **zero-length** string — i.e. a NUL
  code unit sitting exactly where the next entry would start — is the
  block terminator. Every other string is one entry.
- **Alignment**: every read position is an even offset from the block
  VA. A chunk boundary that lands mid-code-unit carries its trailing
  byte into the next chunk rather than decoding half a code unit, and a
  terminator split across two chunks is found normally, because the
  scan is over the reassembled code-unit stream and never restarts at a
  chunk boundary. Two zero bytes at an **odd** offset are the high byte
  of one code unit plus the low byte of the next, not a terminator, and
  are never treated as one.
- An entry whose bytes cannot be decoded as UTF-16LE (including an odd
  number of bytes before the terminator) is undecodable: the walk stops
  there and the entry is never emitted with replacement characters — a
  mangled name/value is worse than a stated gap.
- **Budgets**: `max_bytes` (65536) cumulative bytes read, `max_entries`
  (2048) entries kept. Reaching either stops the walk.

**Verified-empty requires a fully captured, well-formed terminator.** A
verified empty block is `00 00 00 00` — a zero-length entry followed by
the block terminator, which is what a well-formed empty block written by
Windows contains. `present_empty` is reported **only** when all four
bytes are captured and zero. A block whose capture ends after two zero
bytes, or whose second code unit is not captured at all, is
`unparseable`, never `present_empty` — a truncated capture must not be
promoted into "the process had no environment".

**States** (a closed set of seven):

| state | meaning |
|---|---|
| `unsupported` | `sysinfo` or `threads` absent/empty — no TEB to start from, and the same precondition the PEB itself needs |
| `architecture_unsupported` | `sysinfo` present with a `ProcessorArchitecture` that is neither AMD64 nor INTEL (e.g. ARM64) — see below |
| `pointer_unreadable` | one of the three pointer steps failed, short-read, or was null |
| `present_empty` | four captured zero bytes at the block start |
| `present` | ≥ 1 entries **and** a verified block terminator |
| `partial` | ≥ 1 entries, block terminator never verified (budget, segment end, or an undecodable entry stopped the walk) |
| `unparseable` | 0 entries **and** no verified block terminator within bounds |

**Why `architecture_unsupported` is its own state.**
`PEB.from_minidump()` computes `is_x64 = not (ProcessorArchitecture ==
INTEL)`, so it treats **every** non-INTEL architecture — ARM64 included
— as x64 and applies x64 offsets. On an ARM64 dump the library therefore
still produces a `PEB` object, quite possibly populated with values read
at the wrong offsets, and `mf.peb` is **not** `None`. Folding that case
into `unsupported` (whose limitation is suppressed because
`SYSINFO_PEB_UNAVAILABLE` is assumed to cover it) would report
`environment_variables: null` with `SYSINFO_PEB_UNAVAILABLE` never
firing, and the command would exit **0** while silently omitting the
environment. `architecture_unsupported` therefore always emits its own
`ENVIRONMENT_ARCHITECTURE_UNSUPPORTED` limitation and drives `partial`,
regardless of the PEB's state.

dumpex's own walk does **not** copy the library's guess: it selects
offsets only for AMD64 (x64 table) and INTEL (x86 table), and refuses to
walk anything else rather than reading a plausible-looking pointer from
the wrong offset. Widening this to ARM64 requires a real offset table
and is a separate issue.

The `present_empty`/`unparseable` split is the whole point: an
`unparseable` block must never be reported as a captured empty
environment.

#### 4.3.3 State → output, limitation, and coverage

| state | `environment_variables` | `coverage.sources["environment_block"]` | limitation | status floor |
|---|---|---|---|---|
| `unsupported` | `null` | `absent` | **none** — suppressed (see below) | unchanged |
| `architecture_unsupported` | `null` | `absent` | `ENVIRONMENT_ARCHITECTURE_UNSUPPORTED`, **never suppressed** | `partial` |
| `pointer_unreadable` | `null` | `failed` (`detail` set) | `ENVIRONMENT_BLOCK_UNREADABLE`, **never suppressed** | `partial` |
| `present_empty` | `[]` | `present_empty` | none | unchanged |
| `present` | the walked list | `present` | none | unchanged |
| `partial` | the entries found so far (never discarded) | `present` | `ENVIRONMENT_BLOCK_TRUNCATED` | `partial` |
| `unparseable` | `null` | `failed` (`detail` set) | `ENVIRONMENT_BLOCK_UNPARSEABLE` | `partial` |

**Duplicate-absence suppression, frozen.** `environment_block` is a
sixth entry in `coverage.sources` but is deliberately **not** declared
as a `SourceRequirement` in `completeness_checks`. Every gap it produces
is a hand-built `caller_buildable` limitation, emitted under exactly the
rules above. Consequences:

- The reducer never auto-derives a second absence/failure limitation for
  this source, so `SYSINFO_PEB_UNAVAILABLE` and an environment code can
  never both describe the same single fact.
- `unsupported` emits nothing at all — and **only** this state is
  suppressed on that basis. Its preconditions (`sysinfo and threads`)
  are exactly the ones `__parse_peb()` itself checks, so `mf.peb` is
  provably `None` whenever it fires and `SYSINFO_PEB_UNAVAILABLE`
  provably explains it. No other state can make that guarantee, which is
  why `architecture_unsupported` was split out of it.
- `pointer_unreadable`, `unparseable`, and `partial` **always** emit,
  regardless of the PEB's state. Each is a fact dumpex's own independent
  walk established — *this* pointer step failed, *this* block has no
  terminator, *this* capture stopped early — and none of them is
  implied by `SYSINFO_PEB_UNAVAILABLE`, which says only that the
  library's PEB build did not produce an object.

  Suppressing `pointer_unreadable` when the PEB happens to be absent
  would recreate the exact failure this whole walk exists to remove: a
  specific, independently-confirmed environment failure disappearing
  behind a generic PEB absence. The two limitations are not duplicates
  — one names the concrete step that failed, the other names the
  overall consequence — so both are reported, environment first. §4.7
  freezes the exact position that produces this order.

`ENVIRONMENT_BLOCK_TRUNCATED` uses the same budget attribution as the
IAT (§3.5.4). `scope` is required, one of:

| `scope` | meaning | `budget_limit`/`budget_consumed` |
|---|---|---|
| `environment_bytes` | `MAX_ENV_BYTES` reached | required |
| `environment_entries` | `MAX_ENV_ENTRIES` reached | required |
| `captured_segment` | the dump's captured memory ended first | both `null` |
| `undecodable_entry` | an odd-length / undecodable entry stopped the walk | both `null` |

### 4.4 Special `=`-prefixed entry reconstruction

Windows records per-drive working directories as entries whose name
begins with `=` (e.g. `=C:=C:\Users\x`). A naive `split("=", 1)` yields
`name=""`, `value="C:=C:\Users\x"`, losing the real name. The walk
therefore applies, to each raw entry:

1. Split once on the first `=`.
2. If the resulting name is empty and the value itself contains an `=`,
   re-split the value on **its** first `=` and reconstruct
   `name = "=" + left`, `value = right`.
3. An entry with no `=` at all keeps the whole string as `name` and
   `""` as `value` — this is how a genuinely nameless/valueless block
   entry is preserved rather than dropped.

Entries stay a **list of `{name, value}` records**, never a map:
duplicate names, `=`-prefixed names, and order are all real forensic
evidence a dict would silently destroy.

### 4.5 Sensitivity

Environment variables routinely carry tokens, session identifiers, user
names, and full user paths. The contract's position, frozen:

- dumpex **never silently redacts** environment evidence. Redaction
  without a trace would corrupt the record an analyst is relying on.
- The console prints only a **count** by default; the values require
  `--verbose` or `--json` (§4.6). That is a deliberate
  don't-shoulder-surf default, not a security control.
- The existing `--redact-paths` option continues to apply to path-shaped
  output where it already applies; this contract adds no new redaction
  mode and no new opt-out.
- Documentation (#44) must state that `--sysinfo --json` output can
  contain secrets and should be handled at the same sensitivity as the
  dump itself.

### 4.6 Console layout

The `Process` section is gone. The OS/Host/CPU/Dump-File sections are
unchanged. One new section is added, after `Host`:

```
  ═══ ENVIRONMENT ═══
    Current Directory      <current_directory or "(unknown)">
    Environment Variables  <"N captured (--verbose or --json to view)"   if state in
                              (present, present_empty, partial)>
                           <"(unavailable)"                             if state in
                              (unsupported, pointer_unreadable)>
                           <"(not supported for this architecture)"     if state ==
                              architecture_unsupported>
                           <"(unparseable -- see coverage below)"       if state == unparseable>
    [~] <coverage.reasons entries naming environment_block, if any>
```

With `--verbose`, every `name=value` pair is printed under that header,
in walk order. For `state == "partial"` the truncation `[~]` line is
printed **above** the list, so a reader sees the list is incomplete
before reading it.

### 4.7 Coverage and exit semantics

`coverage.sources` has **six** keys: `sysinfo`, `misc_info`, `peb`,
`threads`, `modules`, `environment_block`.

`completeness_checks` keeps the five existing `SourceRequirement`s
unchanged — `SYSINFO_SYSTEM_INFO_UNAVAILABLE`,
`SYSINFO_MISC_INFO_UNAVAILABLE`, `SYSINFO_PEB_UNAVAILABLE`,
`SYSINFO_THREADS_UNAVAILABLE`, `SYSINFO_MODULES_UNAVAILABLE` — and there
is no sixth `SourceRequirement` (§4.3.3).

**Order, frozen as one rule.** Any hand-built environment limitation is
inserted **immediately before** the `peb` requirement, giving exactly:

```
sysinfo, misc_info, <environment limitation, if any>, peb, threads, modules
```

`build_coverage_report()` preserves `completeness_checks` order verbatim,
so this is the order of `coverage.limitations` and of the console's
`[~]` lines. The specific environment failure is read before the general
PEB consequence — an analyst should see "environment block pointers
could not be read: X" and only then "PEB not available", not the other
way round. The five existing checks keep their relative order among
themselves, so no already-shipped `--sysinfo` reason sequence changes
for a dump with no environment limitation.

`--sysinfo` never reports `not_evaluated`: `dump_file` is derived from
the dump path itself and is always available, so there is always
something evaluated. That is unchanged from today.

---

## §5 `--handles`

New command. `result.kind` is `"handles"`.

### 5.1 Source: a dumpex-owned bounded parse

`--handles` reports `HandleDataStream` descriptors. The stream is parsed
by dumpex's own `parse_handle_stream(directory, file_handle)` (#38),
registered in `_STREAM_DISPATCH` (§2.2) in place of the library's
`MinidumpHandleDataStream.parse`. Three reasons, each grounded in the
installed library's code:

1. `MinidumpHandleDescriptor.parse()` calls `walk_objectinfo()` for v2
   descriptors, which follows a `NextInfoRva` chain with **no cycle
   detection** — a self-referential chain from a crafted dump hangs
   forever, and a hang is not something `try/except` can isolate.
   dumpex never needs that data (§5.3), so it never walks it.
2. `MINIDUMP_STRING.parse()` reads a dump-controlled UINT32 `Length` and
   immediately does `buff.read(ms.Length)` — an unbounded read of up to
   4 GiB. `parse_handle_stream()` bounds every string read at
   `MAX_HANDLE_STRING_BYTES`.
3. `MINIDUMP_STRING.get_from_rva()` returns the literal placeholder
   string `'<STRING_DECODE_FAILED>'` on a decode error. dumpex must
   never emit that as an object name; a failed decode becomes `null`
   plus a field-level limitation (§5.2.1) — **not** a reason to discard
   the descriptor.

#### 5.1.1 Stream framing — frozen

The library seeks to `Location.Rva`, reads the 16-byte
`MINIDUMP_HANDLE_DATA_STREAM` header (`SizeOfHeader`,
`SizeOfDescriptor`, `NumberOfDescriptors`, `Reserved`), and then reads
descriptors from immediately after it — **ignoring `SizeOfHeader`
entirely**, and trusting `NumberOfDescriptors` without checking it
against the stream's own size. `parse_handle_stream()` validates the
framing first, in this order:

1. `Location.DataSize >= 16`, and the 16-byte header reads fully.
   Otherwise → **parse failure** (§5.5 case 2).
2. `SizeOfHeader` must be `>= 16` and `<= Location.DataSize`. The
   descriptor array starts at `Location.Rva + SizeOfHeader`, **not** at
   a hardcoded `+16` — a header the producer declared as larger carries
   fields dumpex does not know, and reading descriptors from the wrong
   offset would silently produce garbage records rather than an error.
   Otherwise → **parse failure**.
3. `SizeOfDescriptor` must be exactly **32** (`MINIDUMP_HANDLE_DESCRIPTOR`)
   or exactly **40** (`MINIDUMP_HANDLE_DESCRIPTOR_2`: the same seven
   fields plus `ObjectInfoRva` and `Reserved0`, both 4 bytes). Any other
   value → **parse failure**, not a truncation: dumpex cannot know the
   layout, so no descriptor can be trusted, and guessing 32 (as the
   library's `else` branch effectively does by falling through to the v2
   parser) would misread every field.
4. The number of descriptors dumpex will actually read is
   `usable = min(NumberOfDescriptors, MAX_HANDLE_DESCRIPTORS,
   (Location.DataSize - SizeOfHeader) // SizeOfDescriptor)`. A trailing
   run of bytes shorter than one whole descriptor is **not** parsed —
   a partial descriptor has no recoverable field set.
5. When `usable < NumberOfDescriptors`, one `HANDLE_STREAM_TRUNCATED`
   limitation is emitted with
   `affected_count = NumberOfDescriptors - usable` — the count of
   descriptors the stream *claims* exist that dumpex did not read,
   whether the cause was the budget or the stream's own size. `usable`
   descriptors are still parsed and reported: a truncated tail never
   discards a readable head.

The distinction between rules 1–3 (parse failure, exit 4) and rules 4–5
(truncation, exit 3) is deliberate: 1–3 mean *nothing* in the stream can
be located reliably; 4–5 mean the located records are fine and only the
tail is missing.

`parse_handle_stream()` reuses the library's public
`MINIDUMP_HANDLE_DATA_STREAM`, `MINIDUMP_HANDLE_DESCRIPTOR`, and
`MINIDUMP_HANDLE_DESCRIPTOR_2` classes for the fixed-size structures
(including the existing `SizeOfDescriptor == 32` discriminator between
v1 and v2), and:

- caps descriptors at `MAX_HANDLE_DESCRIPTORS`; a declared
  `NumberOfDescriptors` beyond that is truncated, emitting
  `HANDLE_STREAM_TRUNCATED`;
- validates that the declared descriptor count actually fits in
  `Location.DataSize` before allocating anything;
- reads `TypeName`/`ObjectName` through a bounded reader, mapping any
  failure to `None`;
- returns an object exposing `.header` and `.handles`, where each
  handle exposes exactly `Handle`, `TypeName`, `ObjectName`,
  `Attributes`, `GrantedAccess`, `HandleCount`, `PointerCount`, and
  `ObjectInfos` (**always `[]`, never walked**).

That attribute set is deliberately identical to the library's
`MinidumpHandleDescriptor`, so `dumpex.core.memory.get_handles()` and
its existing hunt consumers (the pipe hunter reads `TypeName` and
`ObjectName`) keep working unchanged.

### 5.2 Record shape

One record per descriptor:

```json
{
  "handle": "0x0000000000000234",
  "type_name": "File",
  "type_name_status": "ok",
  "object_name": "\\Device\\NamedPipe\\mypipe",
  "object_name_status": "ok",
  "attributes": 0,
  "granted_access": 1179785,
  "handle_count": 1,
  "pointer_count": 32
}
```

| field | type | rule |
|---|---|---|
| `handle` | fixed-width hex string | never `null` — see §5.2.2 |
| `type_name` | `string \| null` | `null` for both "no name" and "name unreadable"; `type_name_status` says which |
| `type_name_status` | `"ok" \| "unnamed" \| "unreadable"` | never `null`; see §5.2.1 |
| `object_name` | `string \| null` | same rule, resolved independently |
| `object_name_status` | `"ok" \| "unnamed" \| "unreadable"` | never `null`; see §5.2.1 |
| `attributes` | `integer \| null` | raw `OBJ_*` bitmask, undecoded |
| `granted_access` | `integer \| null` | **raw mask, undecoded in v2.13.** Type-specific permission decoding is a later feature; a wrong decode is worse than a raw number |
| `handle_count` | `integer \| null` | raw |
| `pointer_count` | `integer \| null` | raw |

No field is ever a placeholder string. `'<STRING_DECODE_FAILED>'` never
reaches a record.

#### 5.2.1 An unnamed handle and an unreadable name are different facts

`null` alone cannot carry both, and conflating them is a real loss: most
`Key`/`File` handles have names, an unnamed one is unremarkable, but a
name that *should* be there and could not be read is a coverage gap an
analyst must know about.

The two name fields fail **independently** — they are separate RVAs and
separate bounded reads — so one shared discriminator cannot describe
them. A handle with `TypeNameRva == 0` and a perfectly readable
`ObjectName` is common, and a handle whose type name read while its
object name did not is exactly the case an analyst needs spelled out.
The record therefore carries **two** discriminators, each computed from
its own RVA only:

| status value | when, for that one field | that field's value | limitation |
|---|---|---|---|
| `"ok"` | its RVA is non-zero and the string read and decoded to a **non-empty** value | the decoded string | none |
| `"unnamed"` | its RVA is `0`, **or** its RVA is non-zero and the string read successfully with `Length == 0` (decoding to `""`) | `null` | none — either way the dump positively records no name, and nothing was lost |
| `"unreadable"` | its RVA is non-zero but the read failed, exceeded `MAX_HANDLE_STRING_BYTES`, or failed to decode | `null` | see below |

A non-zero RVA whose `MINIDUMP_STRING.Length` is `0` decodes to `""`,
which §1.4 forbids on the wire. The value therefore becomes `null` — and
the status must be `"unnamed"`, not `"ok"`, because `"ok"` promises a
non-`null` value and nothing was actually lost here. Classifying it as
`"unreadable"` would be equally wrong: the read succeeded.

`type_name_status` and `object_name_status` are set independently, so all
nine combinations are representable and none is ambiguous — including
`("unnamed", "unreadable")`, which the earlier single-field design
rendered as if both names were unreadable.

An `"unnamed"` field is normal and never drives `partial`. An
`"unreadable"` field drives `partial` (exit 3) through one **field-level**
`HANDLE_STRING_READ_FAILED` limitation for the whole result, whose
`affected_count` is the number of **descriptors** with at least one
`"unreadable"` field — descriptors, not fields, so a handle that lost
both names counts once. The descriptor itself is fully reported either
way, with every other field intact.

#### 5.2.2 Descriptor normalization can only fail one way

A descriptor is discarded — and counted by `HANDLE_DESCRIPTOR_INVALID` /
`HANDLES_ALL_DESCRIPTORS_INVALID` (§5.5 case 3) — **only** when its
`Handle` value is unusable: not an integer, or outside `uint64` range.
That is the one field with no meaningful `null` representation: a record
keyed by nothing identifies nothing, and §5.4 orders by it.

Everything else is preserved in place:

- a failed/undecodable `TypeName`/`ObjectName` → §5.2.1, record kept;
- an `Attributes`/`GrantedAccess`/`HandleCount`/`PointerCount` field
  that could not be read → that field is `null`, record kept (the four
  are read from the same fixed-size descriptor, so in practice they fail
  only together with the whole descriptor, but the rule is stated so no
  implementation invents a discard path for them).

This keeps "one record per `HandleDataStream` descriptor" true for every
descriptor whose handle value is readable, which is what #37 requires.

### 5.3 `ObjectInfos` — omitted in every mode

`ObjectInfos` is **not** exposed in the default output, not under
`--verbose`, and not in JSON. It carries opaque, type-dependent,
version-dependent byte blobs with no stable public shape worth freezing,
reaching it requires the unbounded chain walk of §5.1 item 1, and nothing in
the DFIR workflow this command serves consumes it. This is a deliberate
scope decision, not an oversight: exposing it later is an additive
schema change, un-exposing it would not be.

### 5.4 Ordering

Numeric ascending by raw handle value, with a **stable** sort so equal
values (which only a malformed dump produces) keep the stream's own
order. Not sorted by type or name; not re-ordered by `--verbose`.

### 5.5 Coverage: five distinguishable states

All four states #37 requires — absent stream, present-empty stream,
partially normalized descriptors, present-but-failed parse — stay
distinguishable, plus the fully clean case.

1. **No `HandleDataStream` directory entry in `mf.directories`** →
   `not_evaluated` (exit 4), `HANDLES_UNAVAILABLE`. The dump was never
   captured with handle data.
2. **Directory present, parse raised** (`stream_failure(mf,
   HandleDataStream)` is set, `mf.handles is None`) → `not_evaluated`
   (exit 4), with **two** limitations: `HANDLES_PARSE_FAILED` (from the
   evaluation group) and a `SOURCE_FAILED` for the `handles` source
   carrying the parser's own error text. The pairing is deliberate: the
   group-derived limitation cannot carry a `detail` (§6.1), and
   `build_coverage_report()` already surfaces a `FAILED` completeness
   source even when a group short-circuits to `not_evaluated` — which
   is exactly why `handles` is declared as a bare completeness check
   (§5.5's sources list). This state is reachable only because of §2:
   before the loader change the whole dump open died. `HANDLES_PARSE_FAILED`
   must **never** be conflated with `HANDLES_UNAVAILABLE`: "not captured
   with handle data" and "captured, but the handle data will not parse"
   send an analyst to different next steps (re-collect vs. investigate
   the dump's integrity), and both map to exit 4 without becoming the
   same reason string.
3. **Parsed, but some or all descriptors have an unusable `Handle`
   value** (§5.2.2 — the only normalization failure that discards a
   record) → `partial` (exit 3) + `HANDLE_DESCRIPTOR_INVALID` (with
   `affected_count`) when at least one record survives; `not_evaluated`
   (exit 4) + `HANDLES_ALL_DESCRIPTORS_INVALID` when none do. These are
   normalization-layer failures, one level above case 2's parse-layer
   failure, and stay separate codes because an analyst investigates them
   differently. Surviving records are always emitted — partial loss
   never discards what parsed.
4. **Parsed, `handles` is empty** → `complete` (exit 0), zero records,
   `SourceState.PRESENT_EMPTY`. A present-empty stream is a complete
   answer, not a failure.
5. **Parsed, every descriptor normalizes** → `complete` (exit 0).

Two `partial` drivers compose with the cases above without changing
them, because neither costs a record:

- `HANDLE_STREAM_TRUNCATED` — the tail dumpex did not read (§5.1.1
  rules 4–5).
- `HANDLE_STRING_READ_FAILED` — descriptors whose type/object name was
  unreadable (§5.2.1). It never turns case 5 into case 3: those records
  are complete apart from one string, and discarding them would destroy
  exactly the handle an analyst most wants to see.

A dump can therefore be `complete` on records while `partial` on names,
which is reported as `partial` — the honest answer.

`coverage.sources` has two keys:

- `handles` — the stream itself: `absent` (case 1), `failed` with detail
  (case 2), `present_empty` (case 4), `present` (cases 3 and 5). It is
  declared in `completeness_checks` as a **bare source name**, whose only
  effect is to surface the `SOURCE_FAILED` detail in case 2: it
  contributes nothing when the stream is present, and its absence in
  case 1 is already covered by the group.
- `handle_records` — a **derived** source: the usable normalized records.
  `absent` for cases 1, 2, and 3-all-invalid; `present_empty` for case
  4; `present` (count) otherwise.

`evaluation_sources` is
`EvaluationRequirement(sources=("handle_records",), all_absent_code=<c>)`
where `<c>` is chosen by the command from the three cases that leave
`handle_records` absent: `HANDLES_UNAVAILABLE` (1),
`HANDLES_PARSE_FAILED` (2), `HANDLES_ALL_DESCRIPTORS_INVALID`
(3-all-invalid). All three are `absent_capable` with
`fixed_source="handle_records"`.

`--handles` passes
`retain_completeness_checks_when_not_evaluated=True` (§3.7.3) for the
same reason `--process` does: in case 3-all-invalid the exit-4 result
must still carry `HANDLE_STREAM_TRUNCATED` and
`HANDLE_STRING_READ_FAILED` if they fired, since those say what went
wrong with the descriptors the aggregate code only counts.

The derived source exists because the reducer's `not_evaluated` branch
fires only when every group member is `ABSENT` — a `failed` stream (case
2) or a present stream whose descriptors are all unusable
(3-all-invalid) would otherwise be unable to reach exit 4 at all. This
is the same single-source-`EvaluationRequirement`-with-a-dedicated-code
shape `--peb` already uses, applied to a derived source, so no new
reduction path is introduced.

### 5.6 Console and summary

```
═══ HANDLES ═══
  <"HandleDataStream not present in this dump">                    [case 1]
  <"HandleDataStream is present in this dump but could not be parsed"> [case 2 --
     the parser's error text follows in the "[~]" coverage lines below]
  <"0 handles usable -- N descriptor(s) failed to normalize">      [case 3, total loss]
  <"N handle(s) captured">                                         [cases 3 partial / 4 / 5]
  By type: File 12, Key 5, Event 3, (unnamed) 1                    [only when records non-empty]
  <"N descriptor(s) could not be normalized -- see coverage.limitations">
                                                                   [case 3, partial loss]

  Handle              Type            Access      Cnt  Ptr  Object
  0x0000000000000234  File            0x0012019f    1   32  \Device\NamedPipe\mypipe
  0x0000000000000238  Key             0x00020019    1    3  (unnamed)
  0x000000000000023c  (unreadable)    0x00000001    1    2  (unreadable)

  [~] <coverage.reasons lines>
```

- `Access` is rendered as `0x%08x` in the console while remaining a
  plain integer in JSON (§1.3).
- Each `null` name prints `(unnamed)` or `(unreadable)` according to
  **its own** status field — `type_name_status` for the Type column,
  `object_name_status` for the Object column. The console keeps exactly
  the distinction the record does (§5.2.1), so a reader scanning the
  table is never told a handle is anonymous when its name was lost, and
  a handle with one good name and one lost one shows both truthfully.
- `summary = {"count": N, "by_type": {…}}`, with `by_type` keyed by
  `type_name`, ordered count-descending then name-ascending (§1.5).
  A `null` `type_name` is keyed `"(unnamed)"` or `"(unreadable)"`
  according to `type_name_status` alone — `object_name_status` never
  affects bucketing — so the two never merge. `by_type` is `{}` when
  there are no records.

### 5.7 Framing

Every user-facing string describes **captured** evidence. `--handles`
reports the handles a dump recorded at capture time; it never queries a
live process, and no console or JSON text may imply that it does. The
command's help text is: `"List handles captured in the dump's
HandleDataStream"`.

---

## §6 Complete code registry

### 6.1 New `LimitationCode` members

Every entry below is a real `LimitationCode`, gets one `_CODE_SPECS`
entry (the mechanical `set(_CODE_SPECS) == set(LimitationCode)` test in
`tests/unit/test_output_coverage.py` enforces that), and drives
`partial` or `not_evaluated`. The rendered template is frozen text: no
call site composes it.

| code | source | fields | rendered template |
|---|---|---|---|
| `PROCESS_SOURCES_ABSENT` | `process_identity` | `scope` | "no usable process identity evidence available (MiscInfo and the PEB supplied no usable PID, start time, path, command line, or image base)" |
| `PROCESS_MISC_INFO_UNAVAILABLE` | `misc_info` | `scope` | "MiscInfo stream not present in this dump" |
| `PROCESS_PEB_UNAVAILABLE` | `peb` | `scope` | "PEB not available (requires sysinfo + thread list)" |
| `PROCESS_PID_UNAVAILABLE` | `misc_info` | — | "MiscInfo present but does not supply a usable ProcessId" |
| `PROCESS_START_TIME_UNSET` | `misc_info` | — | "MiscInfo's ProcessCreateTime is zero (not recorded)" |
| `PROCESS_START_TIME_INVALID` | `misc_info` | — | "MiscInfo's ProcessCreateTime is not a valid 32-bit timestamp" |
| `PROCESS_PATH_UNAVAILABLE` | `peb` | — | "no process path available: the PEB supplied none and no usable ModuleList fallback was available" |
| `PROCESS_COMMAND_LINE_UNAVAILABLE` | `peb` | — | "PEB present but CommandLine is empty" |
| `PROCESS_IMAGE_BASE_UNAVAILABLE` | `peb` | — | "PEB present but ImageBaseAddress is not set" |
| `PROCESS_MODULE_FALLBACK_UNAVAILABLE` | `modules` | `scope` | "ModuleListStream not present, so the approved process-path fallback could not run" |
| `PROCESS_IMAGE_BASE_INVALID` | `peb` | — | "PEB's ImageBaseAddress is not a plausible mapped image base (raw value preserved in identity_evidence)" |
| `PROCESS_MAIN_IMAGE_READ_FAILED` | `main_image` | — | "could not read the PE header at the PEB-reported image base" |
| `PROCESS_MAIN_IMAGE_SHORT_READ` | `main_image` | — | "read fewer bytes than required for the PE header at the PEB-reported image base" |
| `PROCESS_MAIN_IMAGE_PE_INVALID` | `main_image` | — | "the PE header at the PEB-reported image base is not structurally valid" |
| `IAT_DIRECTORY_TABLE_INCOMPLETE` | `iat` | `affected_count` | "{count} declared data directory entr(y/ies) were not captured; import/IAT directory presence is undetermined" |
| `IAT_DIRECTORY_READ_FAILED` | `iat` | — | "could not read the IAT directory" |
| `IAT_DIRECTORY_SHORT_READ` | `iat` | — | "read fewer bytes than declared for the IAT directory" |
| `IAT_DESCRIPTOR_READ_FAILED` | `iat` | `affected_count` | "{count} import descriptor(s) could not be read" |
| `IAT_DESCRIPTOR_SHORT_READ` | `iat` | `affected_count` | "{count} import descriptor(s) read short" |
| `IAT_THUNK_READ_FAILED` | `iat` | `affected_count` | "{count} IAT/INT thunk slot(s) could not be read" |
| `IAT_THUNK_SHORT_READ` | `iat` | `affected_count` | "{count} IAT/INT thunk slot(s) read short" |
| `IAT_NAME_READ_FAILED` | `iat` | `affected_count` | "{count} DLL or import name string(s) could not be read" |
| `IAT_UNTERMINATED_TABLE` | `iat` | — | "no null terminator found before the descriptor/thunk cap; table treated as truncated" |
| `IAT_CYCLE_DETECTED` | `iat` | — | "a repeated address was found while walking the import table; walk stopped" |
| `IAT_BOUNDS_EXCEEDED` | `iat` | — | "an RVA or count in the import directory exceeds plausible bounds" |
| `IAT_ENTRIES_TRUNCATED` | `iat` | `scope`, `budget_limit`, `budget_consumed` (all required) | "the import table walk stopped after reaching a read budget (budget: {scope}, limit={limit} consumed={consumed})" |
| `ENVIRONMENT_ARCHITECTURE_UNSUPPORTED` | `environment_block` | `detail` | "environment block not walked: unsupported processor architecture ({detail})" |
| `ENVIRONMENT_BLOCK_UNREADABLE` | `environment_block` | `detail` | "environment block pointers could not be read: {detail}" |
| `ENVIRONMENT_BLOCK_UNPARSEABLE` | `environment_block` | — | "environment block present but no entries could be parsed (malformed, or no terminator found)" |
| `ENVIRONMENT_BLOCK_TRUNCATED` | `environment_block` | `affected_count`, `scope` (required), `budget_limit`/`budget_consumed` (required for the two byte/entry budgets, `null` for the other two) | "environment block capture ended before a terminator was found; {count} entry(ies) kept (budget: {scope}, limit={limit} consumed={consumed})" — the budget clause is omitted when `scope` is `captured_segment` or `undecodable_entry` |
| `HANDLES_UNAVAILABLE` | `handle_records` | `scope` | "HandleDataStream not present in this dump (not captured with handle data)" |
| `HANDLES_PARSE_FAILED` | `handle_records` | `scope` | "HandleDataStream is present in this dump but could not be parsed" — the parser's own error text arrives on the companion `SOURCE_FAILED` limitation (§5.5 case 2) |
| `HANDLES_ALL_DESCRIPTORS_INVALID` | `handle_records` | `scope` | "HandleDataStream present but no descriptor could be normalized" — the descriptor count is on `coverage.sources["handles"].record_count` |
| `HANDLE_DESCRIPTOR_INVALID` | `handles` | `affected_count` | "{count} handle descriptor(s) could not be normalized" |
| `HANDLE_STRING_READ_FAILED` | `handles` | `affected_count` | "{count} handle(s) have a type or object name that could not be read or decoded" |
| `HANDLE_STREAM_TRUNCATED` | `handles` | `affected_count` | "HandleDataStream declares more descriptors than dumpex will parse; {count} descriptor(s) were not read" |

Capability flags:

- `absent_capable` (usable as a `SourceRequirement.absent_code`, or as a
  single-source `EvaluationRequirement.all_absent_code`):
  `PROCESS_MISC_INFO_UNAVAILABLE` (`fixed_source="misc_info"`),
  `PROCESS_PEB_UNAVAILABLE` (`"peb"`), `PROCESS_SOURCES_ABSENT`
  (`"process_identity"`), `PROCESS_MODULE_FALLBACK_UNAVAILABLE`
  (`"modules"`), `HANDLES_UNAVAILABLE`, `HANDLES_PARSE_FAILED`, and
  `HANDLES_ALL_DESCRIPTORS_INVALID` (all three
  `fixed_source="handle_records"`).

  `PROCESS_MODULE_FALLBACK_UNAVAILABLE` **must** carry this flag: §3.7.2
  uses it as a `SourceRequirement.absent_code`, and
  `SourceRequirement.__post_init__` rejects any code outside
  `_ABSENT_CAPABLE_CODES` at construction time. Declaring it
  caller-buildable-only would make the configuration this contract
  specifies raise on the first call.
- `caller_buildable` only: every other code in the table.
- `group_capable`: none. No code here describes a multi-source group.

**No `absent_capable` code may interpolate a field the derivation path
cannot set.** `build_coverage_report()`'s all-absent branch constructs
its limitation as `CoverageLimitation(code=…, source=…, scope="dump",
related_sources=…)` and sets nothing else — no `detail`, no
`affected_count`. Every template above that is reachable through that
path is therefore fixed text, and anything variable is carried by a
companion limitation or by `coverage.sources` instead. A template with a
`{detail}`/`{count}` placeholder that renders as `None` is the failure
mode this rule exists to prevent.

The three handle codes are `absent_capable` because `--handles` selects
among them at call time for one single-source evaluation group
(§5.5); `PROCESS_SOURCES_ABSENT` likewise (§3.7.2).

### 6.2 Diagnostic codes (never limitations)

These are **not** `LimitationCode` members. They are never constructed
as `CoverageLimitation`s and never appear in `coverage.limitations`;
they appear only in `identity_evidence.diagnostics` or
`iat.diagnostics`, in the order listed here.

| # | code | array | severity | `details` keys | message template |
|---|---|---|---|---|---|
| 1 | `PROCESS_MODULE_BASE_UNMATCHED` | identity | `info` | `peb_base` | "no module in ModuleListStream is registered at the PEB-reported image base {peb_base}" |
| 2 | `PROCESS_MODULE_BASE_CONFLICT` | identity | `warning` | `name`, `module_base`, `peb_base` | "a module named {name} is loaded at {module_base}, not the PEB-reported image base {peb_base}" |
| 3 | `PROCESS_MODULE_NAME_AMBIGUOUS` | identity | `info` | `name`, `count` | "{count} modules share the name {name}; only the first is reported" |
| 4 | `PROCESS_MODULE_IDENTITY_MISMATCH` | identity | `warning` | `peb_name`, `module_name` | "PEB image path basename ({peb_name}) disagrees with the matched module's own name ({module_name})" |
| 5 | `PROCESS_PATH_SOURCE_FALLBACK` | identity | `info` | `module_path` | "process path was taken from ModuleListStream ({module_path}); the PEB supplied none" |
| 6 | `IAT_BOUNDS_CHECK_UNAVAILABLE` | iat | `info` | `import_directory_va` | "the image declares no IAT directory, so slot bounds could not be checked" |
| 7 | `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` | iat | `warning` | `table_va`, `table_size`, `first_out_of_bounds_slot_va` | "{count} IAT slot(s) fall outside the declared IAT directory range" |

Firing rules:

- 1 and 2 are mutually exclusive: `match_state == "unregistered"` with
  no `name_matched_candidate` → 1; with one → 2 (the stronger, positive
  disagreement).
- 3 is reported **alongside** whichever of 1/2 also fired, never instead
  of it.
- 4 fires only when `match_state == "resolved"` and the resolved
  module's name disagrees with `peb_claim.name`.
- `match_state == "unavailable"` fires none of 1–4: nothing was checked,
  so there is nothing to observe.
- 6 and 7 are mutually exclusive: 6 fires exactly when
  `table_present == false` while entries were walked (§3.5.2), and 7
  requires the range 6 says is missing.
- None of 1–7 ever changes `coverage.status`.

### 6.3 Retired codes

`PID_SOURCES_ABSENT`, `PID_THREAD_LIST_FALLBACK`,
`PID_EXCEPTION_TID_FALLBACK`, `PID_NO_USABLE_FALLBACK`, and
`PEB_UNAVAILABLE` lose their last production call sites when `--pid` and
`--peb` are removed (§7.2). They stay in `LimitationCode` and
`_CODE_SPECS` — historical documents that contain them must remain
renderable, and removing an enum member is a wire-visible change with no
benefit.

---

## §7 CSV, compatibility, and schema v2.13

### 7.1 CSV: not applicable

`--csv` was removed from this codebase before this redesign began:
`tests/unit/test_cli_args.py` asserts that `--csv out.csv` now fails
argparse with `"unrecognized arguments"`, and no CSV writer remains
under `dumpex/output/`. There is therefore no CSV surface to freeze for
these three commands. This is a statement of current fact, not a new
decision, and #44 must not "restore parity" by adding one.

### 7.2 Compatibility: immediate removal, no hidden deprecation alias

`--pid` and `--peb` are removed **immediately**, in the single v2.13
cutover (#43). There is no hidden alias, no deprecation release, and no
`--pid`-forwards-to-`--process` shim. Reasons, frozen:

- The evidence semantics change, not just the name: `--pid`'s
  thread-list/exception fallbacks are deliberately gone (§3.3.2), so an
  alias would silently return a *different* answer under the old flag —
  worse than a clean argparse error.
- The result `kind` changes (`pid`/`peb` → `process`), so a JSON
  consumer must change regardless; a CLI-only alias would not spare it.
- `argparse` already gives a precise, actionable failure for a removed
  flag.

`#43` must additionally print a one-line pointer for the two removed
flags in the CLI help epilogue (`"--pid and --peb were replaced by
--process in v2.13"`), so a user of the old flags is redirected rather
than left guessing. That is help text, not a working alias.

**Historical schema files stay frozen.** `dumpex/schemas/` keeps every
`dumpex-output-v2.0 … v2.12` file byte-identical; v2.13 is a new file.
Documents produced by older versions must keep validating against their
own schema version.

### 7.3 Schema v2.13 changes

- `SCHEMA_VERSION` becomes `"2.13"`.
- `result.kind` enum: **add** `"process"`, `"handles"`; **remove**
  `"pid"`, `"peb"` (from the v2.13 file only — v2.12 and earlier keep
  them).
- **Add** `$defs.processRecord` (§3.1) and `$defs.handleRecord` (§5.2).
- **Remove** `$defs.pidRecord`, `$defs.pebRecord` from the current file.
- `$defs.sysInfoRecord`: remove `pid`, `process_start_utc`,
  `image_path`, `command_line`, `process_user_time_seconds`,
  `process_kernel_time_seconds`; add `current_directory`,
  `environment_variables` (§4.2).
- `processRecord` is the only record in the schema with an **optional**
  property (`peb_extended`); everything else keeps
  `additionalProperties: false` with every key required.
- `coverage.limitations[].code` stays a plain string, not an enum — the
  schema does not need a bump for each new code, exactly as its existing
  description says.
- `identity_evidence.diagnostics[]` and `iat.diagnostics[]` get a shared
  `$defs.processDiagnostic` with `severity` constrained to
  `["info", "warning"]` — a schema-level guarantee that no verdict
  vocabulary can appear there.

---

## §8 Acceptance gate

### 8.1 Requirement → section map

| #37 acceptance criterion | frozen in |
|---|---|
| Exact console, JSON, ordering, nullability, address formatting, coverage, diagnostics, exit-code contracts | §1, §3.1/3.8, §4.2/4.6, §5.2/5.6, §6 |
| Process field-to-source precedence and mismatch behavior unambiguous | §3.3, §3.4 |
| Standard-IAT vs delay-import scope explicit | §3.5.1 |
| Former PEB-only field retention/removal explicit | §3.6, §4.1 |
| Environment sensitivity and null-vs-empty semantics explicit | §1.4, §4.3.3, §4.5 |
| Typed diagnostics for PEB/module disagreement, invalid PE, bounded read failures | §6.1 (`PROCESS_MAIN_IMAGE_*`), §6.2 |
| PEB and module claims preserved side by side; fallback never overwrites | §3.3.4, §3.4.3 |
| No `peb_trusted`, no verdict semantics | §0.2, §1.6, §6.2, §7.3 |
| Concise default console; full matrix under verbose | §3.8 |
| Field coverage separated from optional consistency checks | §1.6, §3.7 |
| TID never emitted as PID | §3.3.2 |
| Present-empty handle stream is complete | §5.5 case 4 |
| Every later child implements without inventing public behavior | this document in full |

### 8.2 Follow-up review items → resolution

| review item | resolution |
|---|---|
| Make the contract self-contained | This revision. No normative rule references an unpublished draft; Appendix A is explicitly non-normative. |
| Freeze complete JSON and console shapes in one place | §3.1, §3.5.2–§3.5.3, §3.6, §3.8; §4.2, §4.6; §5.2, §5.6 |
| Preserve thread-context parsing in the new loader | §2.2 phase 3a (required, with its guard and ordering) |
| Parity/regression coverage for the loader change | §2.5 items 1–14 |
| Freeze global FAILED-stream behavior | §2.4 (table, wording, exit-code change, compatibility tests) |
| Retain the four handle states | §5.5 (five states; `HANDLES_PARSE_FAILED` explicitly never conflated with `HANDLES_UNAVAILABLE`) |
| Coverage from normalized values, not raw truthiness | §3.2, §3.7.1 |
| Fallback-aware path coverage | §3.7.2 (`PROCESS_PATH_UNAVAILABLE` only when both sources fail) |
| Preserve the complete ModuleList claim | §3.4.3 (`path` on both `module_claim` and `name_matched_candidate`) |
| Decouple the environment walk from `PEB.from_minidump()` | §4.3.2 (walk never reads `mf.peb`; re-derives TEB→PEB→ProcessParameters→Environment) |
| Freeze environment architecture and read semantics | §4.3.2 (pointer widths, offsets, failure/short-read/null rules, UTF-16 alignment, even-offset double-NUL termination, budgets) and §4.3.3 (state→JSON/limitation/exit) |
| Avoid duplicate absence limitations | §4.3.3 (no sixth `SourceRequirement`; explicit suppression rules) |
| Legal structured location for diagnostic-only IAT observations | §3.5.5 (`iat.diagnostics[]`; not a `LimitationCode` at all) |
| Truncation wording matches the triggering budget | §3.5.4 (five IAT `scope` values), §4.3.3 (four environment `scope` values) |

### 8.2.1 Second-pass review items → resolution

| review item | resolution |
|---|---|
| FAILED-stream exit semantics contradicted `--threads`' own `modules` requirement | §2.4's per-command/per-source matrix; §2.5 item 11 now requires `--threads` exit **3**, and item 12 covers the early-return re-gating |
| Invalid PID/start time had nowhere to be preserved | §3.2's raw-preservation table and §3.4.1's `misc_info_claim.raw_pid`/`raw_process_create_time` |
| Unsupported architecture could exit 0 with a silently missing environment | §4.3.2's `architecture_unsupported` state and §6.1's `ENVIRONMENT_ARCHITECTURE_UNSUPPORTED`, which is never suppressed |
| Handle string failure conflicted with one-record-per-descriptor, and `null` conflated unnamed with unreadable | §5.2.1's per-field `type_name_status`/`object_name_status` discriminators + `HANDLE_STRING_READ_FAILED`; §5.2.2 limits record discard to an unusable `Handle` value |
| `iat.present` could not express table presence, and `slot_in_bounds` had no value for a missing index 12 | §3.5.2's three booleans (`table_present`, `import_directory_present`, `has_entries`), `slot_in_bounds: null`, and `IAT_BOUNDS_CHECK_UNAVAILABLE` |
| Environment termination confused a UTF-16 NUL code unit with the block terminator | §4.3.2's code-unit walk, zero-length-entry terminator, and four-captured-zero-bytes rule for `present_empty` |
| `HandleDataStream` framing was not fully frozen | §5.1.1 (header size, descriptor offset, 32/40-byte descriptors only, `usable` formula, parse-failure vs truncation) |
| `PROCESS_SOURCES_ABSENT` wording was inaccurate | §6.1 — now "no usable process identity evidence available …" |

### 8.2.2 Third-pass review items → resolution

| review item | resolution |
|---|---|
| `not_evaluated` short-circuit would swallow the field-level limitations that explain *why* | §3.7.3's opt-in `retain_completeness_checks_when_not_evaluated`, used by `--process` and `--handles` only; §8.3 item 5 now asserts both the aggregate code and the per-field codes |
| One `name_status` could not describe two independently-failing name fields | §5.2.1's `type_name_status` + `object_name_status`, with all nine combinations representable; console and `by_type` rules updated |
| Suppressing `ENVIRONMENT_BLOCK_UNREADABLE` re-created the generic-PEB-absence masking the walk exists to prevent | §4.3.3 — it is now **never** suppressed; only `unsupported` (where the walk never started) stays suppressed |
| A generalized "sole failed evidence → exit 4" rule contradicted the matrix, and §3.7.2 conflated `absent` with `failed` | §2.4 — the generalized rule is deleted and the matrix declared normative; §3.7.2 now states `absent` → `PROCESS_MISC_INFO_UNAVAILABLE`, `failed` → `SOURCE_FAILED` |
| JSON examples drifted from the field tables | §5.2 (`type_name_status`/`object_name_status`), §3.4.2 (`raw_command_line`), §3.4.3 (`name_matched_candidate_ambiguous` is `false`, never `null`) |
| §3.5.5 still called every non-`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` `IAT_*` code a limitation | §3.5.5 — now excludes both IAT diagnostics |

### 8.2.3 Fourth-pass review items → resolution

| review item | resolution |
|---|---|
| An undeclared data directory and an uncaptured one were both read as "no directory", so a truncated header could report "imports nothing", complete | §3.5.2 — `parse_pe_header()` gains `declared_directory_count`/`directories_complete`; `*_present` becomes three-state, and the undetermined state fires `IAT_DIRECTORY_TABLE_INCOMPLETE` (§6.1) |
| `PROCESS_PATH_UNAVAILABLE` asserted "no module registered at the image base" in cases where that check never ran | §6.1 — neutral fixed wording; §3.7.2 adds a per-state attribution table and the conditional `SourceRequirement("modules", …)` with the new `PROCESS_MODULE_FALLBACK_UNAVAILABLE` |
| A non-zero RVA with `Length == 0` decodes to `""`, which §1.4 forbids, leaving `"ok"` with a `null` value | §5.2.1 — a successful read of an empty string is `"unnamed"`, not `"ok"` and not `"unreadable"` |
| §4.3.3 and §4.7 specified opposite orderings for the environment limitation | §4.7 — one frozen sequence, environment inserted immediately before the `peb` requirement |
| Loader-test count references were stale | §8.2/§8.3 — both now say items 1–14 |

### 8.2.4 Fifth-pass review items → resolution

| review item | resolution |
|---|---|
| An uncaptured `NumberOfRvaAndSizes` became `declared_directory_count = 0`, i.e. a positive "declares no directories" claim, reproducing the false "no imports"/exit 0 one level up | §3.5.2 — the field is now `int \| None`; `None` forces both `*_present` to `null`, and `IAT_DIRECTORY_TABLE_INCOMPLETE` carries an optional `affected_count` with a count-free rendering |
| `PROCESS_MODULE_FALLBACK_UNAVAILABLE` was used as a `SourceRequirement.absent_code` while being declared caller-buildable-only, which `SourceRequirement.__post_init__` rejects at construction | §6.1 — declared `absent_capable` with `fixed_source="modules"`, and added to the doc test's `_ABSENT_CAPABLE` tuple |
| The conditional `modules` requirement fired even when an invalid image base made the fallback impossible, blaming `ModuleListStream` for a lookup never attempted | §3.7.2 — condition narrowed to PEB path unavailable **and** image base normalized |
| §8.3's IAT example asserted `import_directory_present: null` for a capture that had already passed index 1 | §8.3 item 6b — replaced with four cases keyed to where truncation actually stops |

### 8.3 Tests required before #37 closes

These are the completion-gate assertions. Items 1–2 are contract-document
tests and land with this revision; 3–6 are behavioral and land with the
implementing child, but their expected outcome is frozen here so the
child cannot re-decide it.

1. **The contract is independently readable.** A test over
   `docs/recon_process_sysinfo_handles_contract.md` asserts: no
   normative back-reference to an unpublished earlier draft (matched as
   "rev"/"revision" followed by a lower revision number) outside
   Appendix A; every §6.1
   code appears in the message-template table exactly once; every §6.2
   diagnostic code is absent from the §6.1 limitation table (and vice
   versa); every required top-level section is present.
   *(Lands with this revision: `tests/unit/test_recon_contract_doc.py`.)*
2. **Diagnostic codes cannot become limitations.** The same test asserts
   that no §6.2 code appears in `dumpex.output.coverage.LimitationCode`
   — mechanically, against the live enum, so a later child that adds one
   there fails immediately. *(Lands with this revision.)*
3. **Loader isolation preserves thread contexts and unaffected
   streams.** §2.5 items 1–14 (13–14 are the unchanged exit-1 paths).
   *(#38.)*
4. **Malformed environment evidence cannot become a false captured-empty
   result.** Four cases, each with a distinct outcome:
   `00 00 00 00` at the block start → `[]` + `complete`; only two
   captured zero bytes → `null` + `ENVIRONMENT_BLOCK_UNPARSEABLE` +
   exit 3; a block terminator split across two read chunks → found
   normally, `present`, exit 0; two zero bytes at an odd offset inside a
   real entry → **not** treated as a terminator, so the entry after it
   is still returned. *(#38/#41.)*
4b. **An unsupported architecture cannot exit 0 with a silently missing
   environment.** An ARM64 dump — for which the library still builds a
   non-`None` `mf.peb`, so `SYSINFO_PEB_UNAVAILABLE` never fires —
   yields `environment_variables: null`,
   `ENVIRONMENT_ARCHITECTURE_UNSUPPORTED`, and exit **3**. *(#38/#41.)*
5. **Invalid raw process values cannot count as evaluated evidence.** A
   `ProcessCreateTime` of `0x1_0000_0000`, a `ProcessId` of `0`, and an
   unaligned `image_base_address` each yield `null` on the public field,
   the matching `*_INVALID`/`*_UNAVAILABLE` limitation, a preserved raw
   value at its §3.2 location (`misc_info_claim.raw_pid`,
   `misc_info_claim.raw_process_create_time`,
   `peb_claim.raw_image_base_address`), and do **not** count toward the
   five availability flags. A dump where all five are invalid exits
   **4** with `PROCESS_SOURCES_ABSENT`, even though both source objects
   exist — **and** `coverage.limitations` still contains the per-field
   codes (`PROCESS_PID_UNAVAILABLE`, `PROCESS_START_TIME_INVALID`,
   `PROCESS_IMAGE_BASE_INVALID`, …) in declaration order after the
   aggregate one, per §3.7.3. An exit-4 result whose only limitation is
   the aggregate code is a contract violation: the analyst is told
   nothing was usable but never why. *(#38/#40.)*
5b. **A handle whose name is unreadable is still reported.** A
   descriptor with a non-zero `ObjectNameRva` that fails to decode
   yields a record with `object_name: null`, `object_name_status:
   "unreadable"`, every other field intact, one
   `HANDLE_STRING_READ_FAILED`, and exit 3. Three further shapes must be
   distinguishable in the same run: `TypeNameRva == ObjectNameRva == 0`
   → both statuses `"unnamed"`, exit 0; `TypeNameRva == 0` with a
   readable object name → `("unnamed", "ok")`, exit 0, and the console
   Type column prints `(unnamed)`; a readable type name with an
   unreadable object name → `("ok", "unreadable")`, counted **once** by
   `affected_count`. No descriptor is ever dropped for a name failure.
   *(#38/#42.)*
6. **Fallbacks never erase preferred-source claims, and diagnostic-only
   observations never downgrade coverage.** A dump whose PEB image base
   has no registered module but whose ModuleListStream contains a
   same-named module at a different base yields `image_base_address`
   still equal to the PEB value, a populated `name_matched_candidate`
   with its `path`, a `PROCESS_MODULE_BASE_CONFLICT` diagnostic — and
   `coverage.status == "complete"`, exit 0, with an empty
   `coverage.limitations`. Likewise, an out-of-bounds IAT slot produces
   an `iat.diagnostics` entry and exit 0; and an image with an import
   directory but no IAT directory yields `table_present: false`,
   `slot_in_bounds: null` on every entry, one
   `IAT_BOUNDS_CHECK_UNAVAILABLE` diagnostic, and exit 0 with the
   entries still fully reported. *(#40.)*
6b. **An uncaptured directory table cannot be reported as "no imports".**
   Four images, each with a distinct outcome — note that truncation is
   prefix-ordered, so *which* index is lost depends on where the capture
   stops:
   - declares 16 directories, capture stops after index 5:
     `import_directory_present` is **determined** (index 1 was
     captured) and entries are walked; `table_present: null` (index 12
     was not), so `slot_in_bounds` is `null` on every entry, plus
     `IAT_DIRECTORY_TABLE_INCOMPLETE` with `affected_count == 10` and
     exit **3**;
   - declares 16 directories, capture stops after index 0: both
     `import_directory_present` and `table_present` are `null`, no
     descriptors are walked, `IAT_DIRECTORY_TABLE_INCOMPLETE` with
     `affected_count == 15`, exit **3**;
   - `NumberOfRvaAndSizes` itself uncaptured: `declared_directory_count
     is None`, both flags `null`, `IAT_DIRECTORY_TABLE_INCOMPLETE` with
     `affected_count: null` and the count-free wording, exit **3**;
   - declares 2 directories, both captured:
     `import_directory_present: false`, exit **0**.

   No case emits `IAT_BOUNDS_CHECK_UNAVAILABLE`: that diagnostic asserts
   the image declares no IAT directory, which none of the first three
   established. *(#39/#40.)*
6c. **A handle name that is present-but-empty is not a read failure.**
   A descriptor with `ObjectNameRva != 0` whose `MINIDUMP_STRING.Length`
   is `0` yields `object_name: null`, `object_name_status: "unnamed"`,
   **no** `HANDLE_STRING_READ_FAILED`, and exit 0 — asserted for both
   the type and object fields independently. *(#38/#42.)*

---

## Appendix A — revision history (non-normative)

Kept only so a reader can see why a rule is worded as it is. **No
requirement lives here.** Nothing in this appendix qualifies, extends, or
excuses anything in §0–§8.

- **rev1** — first draft of the field/coverage model.
- **rev2** — fixed two P0 defects: IAT directory attribution (Import
  directory index 1 vs IAT directory index 12 had been conflated), and
  module resolution by exact base rather than `addr_to_module()`
  containment.
- **rev3** — corrected four things rev2 got wrong: that a
  `HandleDataStream` parse exception is caught by the library (it is
  not — it aborts the whole dump open); that `misc_info` no longer backs
  any `--sysinfo` field (it backs both CPU-speed fields); that
  `peb.environment_variables == []` unambiguously means captured-empty
  (it collapses verified-empty with never-terminated); and that
  `datetime.fromtimestamp()` raising is a sufficient timestamp check (it
  is platform-dependent). Added `MAX_IAT_READ_OPERATIONS`,
  `name_matched_candidate`, and per-field IAT nullability.
- **rev4 (this revision)** — made the document self-contained (every
  "unchanged from rev2/rev3" replaced with the complete rule); moved the
  loader contract to its own section and completed it (thread-context
  preservation, exit-1 preservation for header/directory failures,
  global FAILED-stream behavior, parity tests); made process coverage
  normalization-first with preserved raw claims; made path coverage
  fallback-aware; added `path` to the ModuleList claims; decoupled the
  environment walk from `PEB.from_minidump()` and froze its architecture
  and read semantics; removed the duplicate environment-absence
  limitation; moved `IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` out of
  `LimitationCode` into `iat.diagnostics[]`; gave both truncation codes
  budget attribution; replaced the library's handle parse with a bounded
  dumpex-owned one; and added the §8 acceptance gate.
- **rev4, fifth review pass** — three defects introduced by the fourth
  pass plus one wrong test example, mapped in §8.2.4: an uncaptured
  directory-count field still collapsed into a positive "declares
  nothing" claim; the new fallback code was used in a position its own
  capability declaration forbade; the conditional `modules` requirement
  fired in a case where the fallback could not run at all; and §8.3's
  worked example contradicted the prefix-ordered truncation it was
  meant to illustrate.
- **rev4, fourth review pass** — four defects and one stale count,
  mapped in §8.2.3: an undeclared data directory and an uncaptured one
  were both read as "no directory", so a truncated PE header could be
  reported as "this image imports nothing", complete;
  `PROCESS_PATH_UNAVAILABLE` asserted a module check that had not run;
  a non-zero name RVA with `Length == 0` had no legal status; §4.3.3 and
  §4.7 specified opposite orderings for the same limitation; and the
  loader-test count references were stale.
- **rev4, third review pass** — six further defects, all introduced or
  left behind by the second pass and mapped in §8.2.2: the
  `process_identity` short-circuit would have discarded the field-level
  limitations that explain an exit-4 result; one `name_status` could not
  describe two independently-failing handle name fields; suppressing
  `ENVIRONMENT_BLOCK_UNREADABLE` behind a PEB absence re-created the
  masking the independent walk exists to prevent; a generalized
  failed-stream exit rule contradicted the per-command matrix, and
  §3.7.2 still conflated `absent` with `failed`; three JSON examples had
  drifted from their own field tables; and one sentence still classified
  every non-`IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS` `IAT_*` code as a
  limitation.
- **rev4, second review pass** — eight defects found by review of the
  above and fixed in place (§8.2.1 maps each to its section): the
  FAILED-stream exit table contradicted `--threads`' own `modules`
  requirement; invalid PID/start-time raw values had nowhere to live; an
  unsupported architecture could exit 0 with the environment silently
  missing; handle string failures contradicted one-record-per-descriptor
  and conflated "unnamed" with "unreadable"; `iat.present` could not
  express table presence and left `slot_in_bounds` untypeable when the
  IAT directory is missing; the environment terminator rule confused a
  UTF-16 NUL code unit with the block terminator; `HandleDataStream`
  framing was underspecified; and `PROCESS_SOURCES_ABSENT`'s wording
  claimed absence for a present-but-unusable source. Two further
  defects surfaced while fixing those: `--threads`' early return would
  have reported `complete` for two failed streams, and three
  group-derived codes interpolated fields that derivation path cannot
  set.

## Appendix B — sources read (non-normative)

Direct reads behind the claims above, so each can be re-checked:

- `dumpex/output/coverage.py` — `SourceState` (incl. the "FAILED is
  currently N/A for all six recon commands" note), `observe_source()`,
  `_CODE_SPECS`/`_CodeSpec` (`absent_capable`/`group_capable`/
  `caller_buildable`/`allowed_fields`), `_SOURCE_DISPLAY_NAMES`,
  `_render_source_failed()`, `_render_budget_clause()`,
  `_validate_optional_budget_fields()`, `SourceRequirement`,
  `EvaluationRequirement`, `build_coverage_report()`, `exit_code_for()`.
- `dumpex/output/records.py` — the address-vs-integer type rule,
  `hex_address()`, `SysInfoRecord`, `PidRecord`, `PebRecord`.
- `dumpex/commands/sysinfo.py` — which fields `mi`/`peb`/`si` actually
  back today, the five existing `SourceRequirement`s, console layout.
- `dumpex/commands/peb.py` — the `--peb` field set and its
  `PEB_UNAVAILABLE` not_evaluated path.
- `dumpex/core/memory.py` — `open_dump()`'s current behavior,
  `get_thread_contexts()`, `get_handles()`, `module_name_only()`,
  `addr_to_module()`.
- `dumpex/core/pe_utils.py` — `parse_pe_header()`'s `data_directories`
  (capped at 16, truncatable) and `reason` strings.
- `dumpex/output/envelope.py` — `SCHEMA_VERSION = "2.12"`.
- `dumpex/schemas/dumpex-output-v2.12.schema.json` — `result.kind` enum,
  `sourceObservation`, `coverageLimitation`, `pebRecord`.
- `tests/unit/test_open_dump.py` — the exit-1 behaviors §2.2 preserves.
- `tests/unit/test_cli_args.py` — `--csv` is rejected by argparse.
- `tests/conftest.py` — the no-external-fixtures rule §2.5 works within.
- `.venv/Lib/site-packages/minidump/minidumpfile.py` — `_parse()`,
  `__parse_header()`, `__parse_directories()` (unguarded per-stream
  parses), `__parse_thread_context()`, `__parse_peb()`.
- `.venv/Lib/site-packages/minidump/structures/peb.py` — `PEB_OFFSETS`,
  `read_unicode_string_property()`, `from_minidump()` (incl. the
  never-assigned `peb.process_parameters` and the environment loop's
  exact termination condition).
- `.venv/Lib/site-packages/minidump/streams/HandleDataStream.py` —
  descriptor v1/v2 layouts, `MinidumpHandleDescriptor.parse()`,
  `walk_objectinfo()`'s cycle-detection-free chain.
- `.venv/Lib/site-packages/minidump/common_structs.py` —
  `MINIDUMP_STRING.parse()`'s unbounded `read(Length)` and
  `get_from_rva()`'s `'<STRING_DECODE_FAILED>'` placeholder.
- `.venv/Lib/site-packages/minidump/minidumpreader.py` — the buffered
  reader's `move()`/`read()` exceptions ("not in process memory space",
  "Would read over segment boundaries!").
