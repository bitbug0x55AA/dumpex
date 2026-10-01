# Memory module layout

Status: **implemented**. `dumpex.core.memory` remains the import path every
command, hunter and test uses, and it is a bounded compatibility entry
point: every definition it supports lives in an owner module, and the
legacy module keeps only re-exports, the stream dispatch table, the
process-lifetime handle-layout cache and the delegating entry points its
patch seams require. This document states which module owns each name and
how the modules may depend on one another. Behavioural contracts stay in
the [thread evidence contract](thread_evidence_contract.md), the
[recon process/sysinfo/handles contract](recon_process_sysinfo_handles_contract.md)
and the [profile contract](recon_profile_contract.md).

## Owners

The owners form four layers. File access (`dumpex.core.dumpfile`) reads
the dump file. Interpretation (`dumpex.core.dumpquery`) reads a loaded
dump. Verdict policy (`dumpex.core.verdict`) scores indicator dimensions
and reads no dump at all. Presentation (`dumpex.ui.memory_presentation`)
formats values it is given.

| Module | Owns |
|---|---|
| `dumpex.core.dumpfile.loader` | Opening a dump: the MINIDUMP_HEADER union correction (`_correct_header_union`, `_HEADER_*`), directory-entry parsing that keeps unknown stream ids (`_parse_directory_entry`), the file-size-bounded directory walk, per-stream parse isolation, the thread-context and PEB phases (`load_minidump`), its two failure types (`DumpFileNotFoundError`, `DumpFormatError`), and the loader facts recorded on the dump (`stream_failure`, `peb_failure`, `has_stream_directory`, `directory_truncated_count`) |
| `dumpex.core.dumpfile.handle_stream` | The bounded HandleDataStream parser (`parse_bounded_handle_stream`), descriptor-layout validation (`validated_descriptor_layout`, `_descriptor_class_size`, `_BoundedDescriptorReader`), bounded name reads (`_read_handle_string`), the parsed shapes and error types, the caps (`MAX_HANDLE_DESCRIPTORS`, `MAX_HANDLE_STRING_BYTES`, `_DESCRIPTOR_PROBE_BYTES`), and the declared/truncated descriptor counts |
| `dumpex.core.dumpfile.thread_info_stream` | The single-layout ThreadInfoListStream parser (`parse_bounded_thread_info_stream`, `_parse_thread_info_entry`, `_THREAD_INFO_LAYOUT` and the entry-size bounds), the parsed shapes and framing error, the caps (`MAX_THREAD_INFO_ENTRIES`, `MAX_THREAD_INFO_RAW_BYTES`), and the declared/truncated record counts |
| `dumpex.core.dumpfile.stream_state` | Stream-state observation over a recorded parser failure: `stream_observation` (failed/absent/empty/present) and `handle_stream_state` (absent/failed/parsed, with `UNPARSED_HANDLE_STREAM_DETAIL`) |
| `dumpex.core.dumpfile.segments` | The captured-memory segment table and its Memory64List-over-MemoryList precedence (`_memory_segments`), the per-dump address-ordered index memoized on the dump object (`_segments_by_va`), VA-to-file-offset mapping (`segment_file_offset`) and captured-range accounting (`captured_range_length`) |
| `dumpex.core.dumpfile.reads` | The checked single-segment read (`read_region`), the clamped reader that never raises (`clamped_reader`), the spanning read across contiguous segments (`read_region_spanning`), and `RegionReadError` |
| `dumpex.core.dumpquery.threads` | Thread records and contexts: the DumpFlags vocabulary (`DUMP_FLAG_*`, `_DUMP_FLAG_TAGS`, `_DUMP_FLAGS_INFO_INVALID`, `DUMP_FLAGS_*`), the start-address states (`START_ADDRESS_*`), the `RawThreadInfo` placeholder and the record-presence test (`_is_real_thread_info`), the DumpFlags reader (`dump_flags_value`), the stream readers (`get_thread_infos`, `get_thread_contexts`), and the interpretations and join the entry points delegate to (`thread_dump_flags_state`, `thread_dump_flags_tags`, `thread_start_address`, `thread_context_conflict`, `join_thread_contexts`) |
| `dumpex.core.dumpquery.lookup` | Module, memory-info and handle stream accessors (`get_modules`, `get_memory_regions`, `get_handles`), address-to-module and address-to-region lookup (`addr_to_module`, `_get_region_at`), allocation grouping (`group_regions_by_allocation`), module base names (`module_name_only`), protection and state names (`prot_str`), address arguments (`parse_hex_or_int`, `SYSTEM_RANGE`), and read-size resolution (`MAX_REGION_READ`, `resolve_read_size`) |
| `dumpex.core.dumpquery.strings` | String extraction over captured bytes (`_extract_strings_from_data`), IOC string extraction and its encoding vocabulary (`_extract_ioc_strings`, `_IOC_ENC_*`, `IOC_STRING_ENCODING_WIDTHS`), and the committed-memory string search with its telemetry (`search_committed_regions`, `StringSearchStats`) |
| `dumpex.core.verdict` | The indicator dimensions (`INDICATOR_DIMS`), the verdict tiers (`VERDICT_*`) and the rule that maps dimensions to a tier (`verdict_for`) |
| `dumpex.ui.memory_presentation` | The address annotation (`address_label`), the hexdump context around a hit (`_hexdump_context`), the colored verdict line (`_verdict`), and the lines `open_dump()` prints for a missing or unparseable dump (`dump_not_found_lines`, `dump_format_error_lines`) |
| `dumpex.core.memory` | The compatibility entry points listed below, the stream dispatch table (`_STREAM_DISPATCH`, `DISPATCHED_STREAM_TYPES`, `STREAM_ATTR_NAMES`) and the process-lifetime handle-layout cache (`_HANDLE_DESCRIPTOR_LAYOUT_CACHE`) |

The name-by-name map from the baseline `memory.py` to these owners is the
`owners` table for `dumpex.core.memory` in
`tests/fixtures/decomposition_baseline/golden/surface_structure.json`.
The [decomposition baseline](decomposition_baseline.md) keeps it complete.

## Compatibility entry points

Tests replace readers, parsers, caps, caches and thread interpretations by
assigning to `dumpex.core.memory.<name>` (the `legacy_patch_targets`
inventory in `seams.json`). A replacement reaches only code that reads the
name from `dumpex.core.memory` at call time. So every consumer of such a
name is an entry point defined in `dumpex.core.memory`. The entry point
looks the name up in its own namespace on each call and passes it to the
owner explicitly:

| Entry point | Passes from `dumpex.core.memory` | To |
|---|---|---|
| `open_dump` | `_STREAM_DISPATCH`, `CONTEXT`, `WOW64_CONTEXT`, `PEB` | `loader.load_minidump`; prints `memory_presentation.dump_not_found_lines`/`dump_format_error_lines` on stdout and exits 1 |
| `parse_handle_stream` | `_handle_descriptor_layout`, `MINIDUMP_HANDLE_DESCRIPTOR`/`_2`, `MAX_HANDLE_DESCRIPTORS` | `handle_stream.parse_bounded_handle_stream` |
| `_handle_descriptor_layout` | `_HANDLE_DESCRIPTOR_LAYOUT_CACHE`, `MINIDUMP_HANDLE_DESCRIPTOR`/`_2`, `_descriptor_class_size` | `handle_stream.validated_descriptor_layout` |
| `parse_thread_info_stream` | `MAX_THREAD_INFO_ENTRIES` | `thread_info_stream.parse_bounded_thread_info_stream` |
| `observe_stream`, `handle_stream_evidence` | the failure `stream_failure` reports | `stream_state.stream_observation`, `stream_state.handle_stream_state` |
| `va_to_file_offset`, `va_range_captured_bytes` | `_memory_segments` | `segments.segment_file_offset`, `segments.captured_range_length` |
| `get_memory_segments`, `read_region_clamped` | `_memory_segments`, `clamped_reader` | (called directly) |
| `dump_flags_state`, `recorded_start_address`, `ip_context_conflict_for` | `_is_real_thread_info`, `dump_flags_value` | `threads.thread_dump_flags_state`, `threads.thread_start_address`, `threads.thread_context_conflict` |
| `dump_flags_tags` | `dump_flags_value` | `threads.thread_dump_flags_tags` |
| `enriched_thread_contexts` | `get_thread_infos`, `get_thread_contexts`, `recorded_start_address`, `ip_context_conflict_for` | `threads.join_thread_contexts` |
| `_resolve_size` | `MAX_REGION_READ` | `lookup.resolve_read_size` |
| `_search_string_in_memory` | `read_region`, `MAX_REGION_READ` | `strings.search_committed_regions` |
| `addr_label` | the file offset `va_to_file_offset` resolves | `memory_presentation.address_label` |

`_STREAM_DISPATCH` maps the two dumpex-owned stream types to the entry
points `parse_handle_stream` and `parse_thread_info_stream`. A cap or
layout replaced on `dumpex.core.memory` therefore also bounds the streams
`open_dump()` parses. The handle-layout cache is process-lifetime state
held on `dumpex.core.memory`. It is filled on the first handle-stream parse,
never at import, and a failed derivation leaves it empty. The segment
index is memoized on each dump object, keyed on the identity of its
segment list.

Each entry point consults its names in the order the owner needs them.
The layout is derived only after the handle stream's own framing has been
checked. The segment table is not consulted for a falsy address or a
non-positive size. `dump_flags_state`, `recorded_start_address` and
`ip_context_conflict_for` ask whether a record is present before they
read its DumpFlags, and read none for a missing record;
`ip_context_conflict_for` asks nothing for a thread without a captured
IP. The thread join reads the ThreadInfoListStream records
before the captured contexts. Read-size resolution consults the
memory-info stream only when no size was requested.

Every other owner-defined name is bound in `dumpex.core.memory` by an
explicit import of the owner's own object. A private name that no shipped
file or test uses through the legacy path is not re-exported. The loader
helpers `_correct_header_union` and `_parse_directory_entry`, the
DumpFlags tables `_DUMP_FLAG_TAGS` and `_DUMP_FLAGS_INFO_INVALID`, and the
IOC encoding tags `_IOC_ENC_*` are examples; code that needs one imports
it from its owner.

## Dependency rules

- An owner module imports only owners of its own layer or a lower one, by
  module path, plus the modules outside the family its layer names: a
  file-access owner imports file-access owners and `dumpex.output.coverage`
  (`stream_state` only); an interpretation owner imports file-access and
  interpretation owners; `dumpex.core.verdict` imports no dumpex module;
  presentation imports `dumpex.core.verdict` and `dumpex.ui.colors`.
- No owner imports `dumpex.core.memory`, a hunter, a command or the
  records package, directly or through another module. Only presentation
  loads the console layer, and presentation loads no file-access or
  interpretation owner: it formats the values the entry points hand it.
- The import graph between owners is acyclic. The package `__init__`
  modules of `dumpex.core.dumpfile` and `dumpex.core.dumpquery` bind
  nothing, so importing one owner loads only the owners it declares.
- No owner function reads, as its own global, a name tests replace on
  `dumpex.core.memory`; such a name reaches the owner as an argument.
- Each top-level name is defined in exactly one of `dumpex.core.memory`
  and the owner modules. A cap or vocabulary another module needs is
  imported, never restated.
- Importing an owner reads no dump, opens no file and creates no mutable
  module state. Every value an owner binds at top level is immutable,
  except the read-only vocabulary tables whose baseline type is a dict
  (`IOC_STRING_ENCODING_WIDTHS`, `INDICATOR_DIMS`). No production or
  script file writes to either of them: no item store or delete, augmented
  assignment, mutating method call or rebinding of the module attribute.
- `dumpex.core.memory` imports every owner module, so a build that follows
  imports statically (the PyInstaller executable) carries all of them.

## Where changes go

`dumpex.core.memory` is not an append location. New code goes in its
owner module; a new entry point joins `dumpex.core.memory` only when an
existing supported patch seam requires one. A behaviour change lands in
its owner, in its own reviewed change, with the affected baseline
expectations updated there; a relocation never changes a contract golden.

| Change | Owner |
|---|---|
| Loading, stream parsing, stream-state observation | `dumpex.core.dumpfile` |
| Captured-range reads, including contiguous reads across adjacent segments and their use by command consumers | `dumpex.core.dumpfile.reads` and `segments`; the consuming command |
| Thread record, start-address, current-IP or conflict semantics | `dumpex.core.dumpquery.threads` |
| Module, region, allocation or handle lookup; read-size budgets | `dumpex.core.dumpquery.lookup` |
| String search order, per-region hit granularity, telemetry, per-region read ceiling, and string/IOC extraction | `dumpex.core.dumpquery.strings` |
| Hit classification (image, private, mapped), which hits get a card, registered-image handling, card and hit budgets, and the all-image diagnostic | `dumpex.commands.report` (`collect_report`'s string mode) |
| Indicator dimensions, verdict tiers and the scoring rule | `dumpex.core.verdict` |
| Console wording and coloring of addresses, hexdumps, verdicts and open failures | `dumpex.ui.memory_presentation`, or the renderer that replaces it. The entry points `open_dump` and `addr_label` keep their names and patch seams; the stream `open_dump()` prints its failure lines as part of its console behaviour, changed only in its own reviewed change |
| Capture-bound evidence objects and shared address resolution (capture, region, allocation, captured range) | A new internal core module that reads captured bytes through `dumpex.core.dumpfile.reads` and `segments` and resolves modules and regions through `dumpex.core.dumpquery.lookup`. It is not `dumpex.core.memory`, and it adds no second reader |

The string search knows nothing about modules. It reports at most one hit
per committed region, the ASCII form's first occurrence or, only when the
ASCII form is absent from that region, the UTF-16LE form's first
occurrence, and it reports hits in `MEM_IMAGE` regions like any other.
Which of those hits are set aside as registered-image matches is decided by
`collect_report`. A change that keeps registered-image matches as evidence
therefore changes `collect_report`; one that also needs several hits from
one region changes the search's per-region granularity in
`dumpex.core.dumpquery.strings`. The search's per-region granularity and
its indifference to modules are pinned in
`tests/unit/test_memory_baseline_characterization.py`; `collect_report`'s
registered-image handling in `tests/unit/test_report_cmd.py` and
`tests/integration/test_report_hierarchy.py`. A change that alters either
updates those expectations itself.

Importing `dumpex.core.memory` reads no file, loads every owner and no
hunter or command module, and leaves the handle-layout cache empty. The
release gate `scripts/frozen_layout_smoke.py` reads the built executable's
archive and fails when any `dumpex` module is missing from it.

`tests/unit/test_memory_layout.py` enforces these rules.
`tests/unit/test_memory_patch_seams.py` and the decomposition baseline
check that every legacy seam still reaches its consumer.
