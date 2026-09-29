# Memory module layout

Status: **implemented** for dump loading, stream parsing, stream-state
observation and captured-range access. `dumpex.core.memory` remains the
import path every command, hunter and test uses. The code that reads the
dump file itself lives in owner modules under `dumpex.core.dumpfile`.
This document states which module owns each name and how the modules may
depend on one another. Behavioural contracts stay in the
[thread evidence contract](thread_evidence_contract.md), the
[recon process/sysinfo/handles contract](recon_process_sysinfo_handles_contract.md)
and the [profile contract](recon_profile_contract.md).

## Owners

| Module | Owns |
|---|---|
| `dumpex.core.dumpfile.loader` | Opening a dump: the MINIDUMP_HEADER union correction (`_correct_header_union`, `_HEADER_*`), directory-entry parsing that keeps unknown stream ids (`_parse_directory_entry`), the file-size-bounded directory walk, per-stream parse isolation, the thread-context and PEB phases (`load_minidump`), its two failure types (`DumpFileNotFoundError`, `DumpFormatError`), and the loader facts recorded on the dump (`stream_failure`, `has_stream_directory`, `directory_truncated_count`) |
| `dumpex.core.dumpfile.handle_stream` | The bounded HandleDataStream parser (`parse_bounded_handle_stream`), descriptor-layout validation (`validated_descriptor_layout`, `_descriptor_class_size`, `_BoundedDescriptorReader`), bounded name reads (`_read_handle_string`), the parsed shapes and error types, the caps (`MAX_HANDLE_DESCRIPTORS`, `MAX_HANDLE_STRING_BYTES`, `_DESCRIPTOR_PROBE_BYTES`), and the declared/truncated descriptor counts |
| `dumpex.core.dumpfile.thread_info_stream` | The single-layout ThreadInfoListStream parser (`parse_bounded_thread_info_stream`, `_parse_thread_info_entry`, `_THREAD_INFO_LAYOUT` and the entry-size bounds), the parsed shapes and framing error, the caps (`MAX_THREAD_INFO_ENTRIES`, `MAX_THREAD_INFO_RAW_BYTES`), and the declared/truncated record counts |
| `dumpex.core.dumpfile.stream_state` | Stream-state observation over a recorded parser failure: `stream_observation` (failed/absent/empty/present) and `handle_stream_state` (absent/failed/parsed, with `UNPARSED_HANDLE_STREAM_DETAIL`) |
| `dumpex.core.dumpfile.segments` | The captured-memory segment table and its Memory64List-over-MemoryList precedence (`_memory_segments`), the per-dump address-ordered index memoized on the dump object (`_segments_by_va`), VA-to-file-offset mapping (`segment_file_offset`) and captured-range accounting (`captured_range_length`) |
| `dumpex.core.dumpfile.reads` | The checked single-segment read (`read_region`), the clamped reader that never raises (`clamped_reader`), the spanning read across contiguous segments (`read_region_spanning`), and `RegionReadError` |
| `dumpex.core.memory` | The compatibility entry points listed below, the stream dispatch table, the process-lifetime handle-layout cache, and -- until their owners are assigned -- DumpFlags and start-address interpretation, thread-context joins, region and module lookup, size resolution (`MAX_REGION_READ`, `_resolve_size`), string and IOC extraction and search, verdict tiers, and address/hexdump presentation |

The name-by-name map from the baseline `memory.py` to these owners is the
`owners` table for `dumpex.core.memory` in
`tests/fixtures/decomposition_baseline/golden/surface_structure.json`.
The [decomposition baseline](decomposition_baseline.md) keeps it complete.

## Compatibility entry points

Tests replace readers, parsers, caps and caches by assigning to
`dumpex.core.memory.<name>` (the `legacy_patch_targets` inventory in
`seams.json`). A replacement reaches only code that reads the name from
`dumpex.core.memory` at call time. So every consumer of such a name is an
entry point defined in `dumpex.core.memory`. The entry point looks the name
up in its own namespace on each call and passes it to the owner
explicitly:

| Entry point | Passes from `dumpex.core.memory` | To |
|---|---|---|
| `open_dump` | `_STREAM_DISPATCH`, `CONTEXT`, `WOW64_CONTEXT`, `PEB` | `loader.load_minidump`; reports `DumpFileNotFoundError`/`DumpFormatError` on stdout and exits 1 |
| `parse_handle_stream` | `_handle_descriptor_layout`, `MINIDUMP_HANDLE_DESCRIPTOR`/`_2`, `MAX_HANDLE_DESCRIPTORS` | `handle_stream.parse_bounded_handle_stream` |
| `_handle_descriptor_layout` | `_HANDLE_DESCRIPTOR_LAYOUT_CACHE`, `MINIDUMP_HANDLE_DESCRIPTOR`/`_2`, `_descriptor_class_size` | `handle_stream.validated_descriptor_layout` |
| `parse_thread_info_stream` | `MAX_THREAD_INFO_ENTRIES` | `thread_info_stream.parse_bounded_thread_info_stream` |
| `observe_stream`, `handle_stream_evidence` | the failure `stream_failure` reports | `stream_state.stream_observation`, `stream_state.handle_stream_state` |
| `va_to_file_offset`, `va_range_captured_bytes` | `_memory_segments` | `segments.segment_file_offset`, `segments.captured_range_length` |
| `get_memory_segments`, `read_region_clamped` | `_memory_segments`, `clamped_reader` | (called directly) |

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
non-positive size.

Every other owner-defined name is bound in `dumpex.core.memory` by an
explicit import of the owner's own object. A private name that no shipped
file or test uses through the legacy path is not re-exported. The loader
helpers `_correct_header_union` and `_parse_directory_entry` are
examples; code that needs one imports it from its owner.

## Dependency rules

- An owner module imports only the lower-level owners it needs, by module
  path, and `dumpex.output.coverage` (`stream_state` only). It never
  imports `dumpex.core.memory`, a hunter, a command, the records package or
  the console layer, directly or through another module.
- The import graph between owners is acyclic. `dumpex/core/dumpfile/__init__.py`
  binds nothing, so importing one owner loads only the owners it declares.
- No owner function reads, as its own global, a name tests replace on
  `dumpex.core.memory`; such a name reaches the owner as an argument.
- Each top-level name is defined in exactly one of `dumpex.core.memory`
  and the owner modules. A cap or vocabulary another module needs is
  imported, never restated.
- Importing an owner reads no dump, opens no file and creates no mutable
  module state; every value an owner binds at top level is immutable.
- `dumpex.core.memory` imports every owner module, so a build that follows
  imports statically (the PyInstaller executable) carries all of them.

New loading, parsing or captured-range access code goes in its owner
module, not in `dumpex.core.memory`. A new entry point joins
`dumpex.core.memory` only when an existing supported patch seam requires
one.

`tests/unit/test_memory_layout.py` enforces these rules.
`tests/unit/test_memory_patch_seams.py` and the decomposition baseline
check that every legacy seam still reaches its consumer.
