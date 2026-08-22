# CLI Reference

This page is the complete command reference for `dumpex`. For a first
investigation, start with the [README quick start](../README.md#quick-start).
For help interpreting hunt results, use the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Command shape

```text
dumpex DUMPFILE COMMAND [OPTIONS]
python -m dumpex DUMPFILE COMMAND [OPTIONS]
```

Exactly one command is required. Addresses, sizes, and thread IDs accept the
formats documented for their individual options.

## Commands

| Mode | Purpose |
|---|---|
| `--list` | List captured memory regions |
| `--modules` | List loaded modules |
| `--threads` | List threads with analysis |
| `--extract ADDR` | Extract raw bytes from the region containing `ADDR` |
| `--strings ADDR` | Extract strings from the region containing `ADDR` |
| `--process` | Show consolidated process identity (PID, path, command line, start time, image base, IAT) — replaces `--pid`/`--peb` (removed in v2.13, no alias) |
| `--handles` | List captured handle descriptors from `HandleDataStream` |
| `--profile` | Describe dump evidence and the analysis-capability map (an evidence boundary, not a verdict) |
| `--sysinfo` | Show dump identity (size/SHA-256/dump time), OS, host, CPU, and environment |
| `--diff REFERENCE` | Compare the primary target dump against a reference dump |
| `--report` | Generate a focused triage report |
| `--hunt TTP` | Run `injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, `obfuscation`, or `all` |

## Command-specific options

These sections mirror the groups shown by `dumpex --help`. They are modifiers
for the named commands, not additional command entry points.

### Memory and extraction options

| Option | Applies to | Description |
|---|---|---|
| `-s SIZE`, `--size SIZE` | extraction, strings | Region size in hexadecimal |
| `-o FILE`, `--output FILE` | extraction, report | Write extracted region bytes |
| `--filter PROT` | list | Filter by protection name, such as `PAGE_EXECUTE_READWRITE` |

### String scan options

| Option | Applies to | Description |
|---|---|---|
| `--grep REGEX` | strings | Keep strings matching a regular expression |
| `--min-len N` | strings | Minimum string length; default `6` |
| `--strings-encoding ascii\|unicode\|both` | strings | String encoding to scan; default `both` |

### Diff and display options

| Option | Applies to | Description |
|---|---|---|
| `--diff-scope modules\|threads\|memory\|all` | diff | Optional evidence-type filter for `--diff`; default `all` |
| `--verbose` | process, handles, sysinfo, diff, hunt | Include routine regions or additional detail. Console only — `--json` always carries every record (see [Verbose recon output](#verbose-recon-output)) |

### Hunt options

| Option | Applies to | Description |
|---|---|---|
| `--yara-dir DIR` | YARA hunt | Use an explicit directory of `.yar`/`.yara` files instead of packaged rules |
| `--ref-dir DIR` | stomping hunt | Directory of analyst-supplied reference modules, matched by basename |
| `--rules-file FILE` | rule-driven hunts | Use an explicit `rules.yaml`, `.yml`, or `.json` file instead of packaged defaults |
| `--triage-skipped` | `--hunt all` | Opt-in budgeted deep-content triage of the skipped-target investigation queue (see below) |

### Report options

| Option | Applies to | Description |
|---|---|---|
| `--report-tid TID` | report | Anchor a report to a thread ID in hexadecimal or decimal |
| `--report-addr ADDR` | report | Anchor a report to a memory address |
| `--report-string STRING` | report | Search memory and report on each matching region |

`--ref-dir` enables the optional on-disk-versus-memory content comparison for
module stomping. The structural section-protection check still runs without
it. See [Detection Methodology](DETECTION_METHODOLOGY.md#module-stomping).

`--rules-file` fails closed: if the file is missing, unreadable, fails to
parse, or does not satisfy the rules schema, dumpex exits non-zero rather
than silently falling back to the packaged or built-in rule defaults. A run
that asked for a specific ruleset never produces a verdict from a different
one.

`--triage-skipped` performs a REAL, budgeted content read of each target in
`--hunt all`'s own skipped-target investigation queue (see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#skipped-target-investigation-queue)),
reusing `--report`'s own triage collector directly — never spawning a second
`dumpex` process, and never the unbounded, up-to-256-MiB-per-region read
`--report` itself allows. Three fixed limits bound the whole pass (a
per-target byte cap, a whole-run byte cap, and a maximum target count); once
either is exhausted, remaining targets are marked `budget_deferred` rather
than read past the intended budget. This is genuinely more expensive than
the default metadata-only pass — expect real, if bounded, additional I/O
and CPU time proportional to the queue's size — which is why it is opt-in
rather than automatic. It has no effect on a single-hunter `--hunt <name>`
run (there is no investigation queue to triage), and it never changes a
hunt's detection verdicts, coverage status, or exit code — only the
advisory `investigation_actions[].triage`/`.recommended_actions` fields and
the console's SKIPPED TARGET ACTIONS section.

## Output and evidence options

| Option | Description |
|---|---|
| `--json FILE` | Write structured JSON results |
| `--txt FILE` | Write an ANSI-free copy of console output |
| `--force` | Allow replacement of an existing output file; never permits replacing an input dump |
| `--case-id ID` | Record a case or ticket identifier in JSON metadata |
| `--analyst NAME` | Record the analyst name or handle in JSON metadata |
| `--redact-paths` | Reduce absolute evidence, rules, YARA, reference, and (for `--extract`) output/artifact paths to basenames in JSON metadata |

Output files are not overwritten unless `--force` is present. dumpex also
refuses any output path that resolves to an input dump path, and refuses to
run at all if two of `--output`/`--json`/`--txt` (or `--extract`'s own
auto-generated default filename) would resolve to the same file — a later
write silently clobbering an earlier one's output is never allowed, even
with `--force`.

`--json` routes through a single contract for every mode:
`--list`/`--modules`/`--threads`/`--process`/`--sysinfo`/`--handles`/
`--profile`/`--diff`/`--extract`/`--strings`/`--report`/`--hunt` all use
the v2 contract (canonical records, `null` for missing values, normalized
hex addresses — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#v2-structured-output)).
All twelve commands support `--json` on this same v2.13 contract, the
single atomic cutover that replaced `--pid`/`--peb` (result kinds
`"pid"`/`"peb"`) with `--process`/`--handles`/`--profile` (result kinds
`"process"`/`"handles"`/`"profile"`) with no hidden alias between the
old and new flags;
`--hunt` was the last to migrate — its `result.kind` is `"hunt"` and
`result.data.records` holds one `hunterRecord` per hunter.
`--diff` produces a `kind: "comparison"` result with a two-entry
`meta.evidence` array (`baseline`/`target`) instead of the single-dump
`meta` shape the other ten use — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#comparison-records).
`--extract` is the first command to populate the top-level `artifacts[]`
(the `--output` file it wrote) and `diagnostics.warnings[]` (e.g. an
MZ-header-detected warning) — both are siblings of `result`, not nested
under it — see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#extract-and-strings-records).
`--report` produces a `kind: "report"` result, one `triageCardRecord` per
triage card (see [Output and Evidence Schema](OUTPUT_SCHEMA.md#report-records)),
and also populates `artifacts[]` for its own optional `--output` extract.
For the v2-routed modes, the process exit code also
reports coverage independent of `--json`: `0` for complete coverage,
`3` for partial (e.g. `--threads` on a dump missing `ThreadInfoListStream`
while the base thread list is still present, or `--extract`/`--strings`
reading fewer bytes than requested), `4` when the one stream the command
needed is entirely absent (e.g. `--modules` when `ModuleListStream`
itself isn't in the dump at all). `--hunt` follows the same convention now
too — `0`/`3`/`4` based on whether every selected hunter, any hunter, or
none reached a conclusive result — instead of its old unconditional `0`.

See [Output and Evidence Schema](OUTPUT_SCHEMA.md) for formats and metadata.

## Verbose recon output

`--verbose` changes what `--process` and `--handles` **print**. It never
changes what they collect: the records, coverage, limitations, summary
counts and exit code are identical with and without it, so `--json` is
always the complete, lossless evidence surface.

### `--handles`

Handle records are populated only when the dump captured
`HandleDataStream`; a dump without that stream reports `--handles` as
`not_evaluated` rather than an empty inventory (see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#v2-structured-output)).

The default console folds **anonymous** handle rows — rows whose object
name the descriptor positively records as absent — into per-type counts:

```text
  13 anonymous handle(s) not shown (no object name recorded): Event 9, Semaphore 3, Key 1
  These rows are captured evidence and are complete in structured output -- use --verbose to show all.
```

Those rows are still captured, still counted in the headline and the
`By type:` line, and still in `--json`. `--verbose` prints all of them.

Only the **object** name decides whether a row is anonymous, so a handle
with a captured object name is never folded whatever its type says.

Anonymous `Process`, `Thread`, `Token`, `Section` and `Job` handles are
**never** folded — those are the ones a cross-process access question
turns on — and neither is any row whose type or object name could not be
**read**. Every other anonymous row folds, including one whose descriptor
recorded no type name either (some dump writers record none for any
handle); the fold line always names the type and its exact count, so
nothing disappears unnamed.
The two states are different facts and the console keeps them apart:

- `(unnamed)` — the descriptor records no name. Nothing was lost.
- `(unreadable)` — a name should have been there and the bounded read
  or decode failed. Evidence was lost, and the run reports it as a
  coverage limitation.

Common NT Object Manager names are explained under `Object name notes`.
For example, `\KnownDlls` is an Object Manager **directory**, not a
filesystem path and not a list of DLLs; the handle descriptor records
its name only, and the objects inside it are not captured by it. dumpex
never expands such a directory from the machine running the analysis.

Each printed row is followed by its own `Rights` line, naming what that
row's mask permits **for the object type the descriptor recorded**:

```text
  0x000000000000005c  Key             0x00020019    2  65536  \REGISTRY\...\Versions
      └─ Rights   KeyRead
  0x00000000000001dc  Thread          0x001fffff    6  131062  (unnamed)
      └─ Rights   AllAccess
  0x000000000000006c  WindowStation   0x000f037f    1    1  WinSta0
      └─ Type     EnumDesktops · ReadAttributes · AccessClipboard · CreateDesktop ·
                  WriteAttributes · AccessGlobalAtoms · ExitWindows · Enumerate · ReadScreen
         Standard Delete · ReadControl · WriteDac · WriteOwner
```

Where Windows documents a combination, dumpex shows a display name that
maps to it: `0x00020019` on a `Key` is `KEY_READ`, shown `KeyRead`,
rather than its four components repeated on every `Key` row. The
displayed spelling is dumpex's own — no header defines `KeyRead` or
`AllAccess` — and it maps to a constant whose defining header is recorded
**per constant**, not per object type. Most are Win32 SDK (`winnt.h`;
`winuser.h` for `Desktop` and `WindowStation`). `DIRECTORY_*` and
`EVENT_QUERY_STATE` have no Win32 SDK definition and are documented by
Microsoft under the WDK's `ntifs.h`. `SYMBOLIC_LINK_*`, `THREAD_ALERT`,
`SEMAPHORE_QUERY_STATE` and `IO_COMPLETION_QUERY_STATE` have no
Microsoft page naming them, so they carry **no confirmed header at all**
— only an attribution, where there is one. A composite built on one is
marked `[source unconfirmed]` in the `Aliases used` block rather than
being described like `KEY_READ`, and a bare single-bit right name with
the same problem — `QueryState` decoded from `SEMAPHORE_QUERY_STATE`
alone, with no alias involved — is marked `[?]` right on the `Rights`
line, since it would otherwise print identically to `Timer`'s confirmed
`QueryState`. Neither mark ever attaches to `AllAccess` on an
`IoCompletion` row: that alias is its own confirmed `winnt.h` constant,
regardless of the type's other, unconfirmed bit.
Several types are mixed: `IoCompletion` takes `IO_COMPLETION_MODIFY_STATE`
and `IO_COMPLETION_ALL_ACCESS` from `winnt.h` and only its `QueryState`
bit from outside the SDK, and `Event`, `Semaphore` and `Thread` are mixed
too — `Timer`, which looks the same, is not.
A display name is type-qualified wherever the bare word would be
ambiguous (`FileGenericRead`, since `GENERIC_READ` is a different bit).
A list too long for one line splits into `Type` (rights that object type
defines) and `Standard` (the rights every type shares).

Every composite the table used is then expanded once beneath it, so the
capabilities inside a short name stay findable — searching a `--txt`
transcript for `AdjustPrivileges` reaches the `TokenWrite` rows through
this block:

```text
  Aliases used
    Each display name maps to one Windows SDK, WDK or native constant, and what
    that constant contains depends on the object type it was read against.
      Key      KeyRead    = QueryValue · EnumerateSubKeys · Notify · ReadControl
      Token    TokenWrite = AdjustPrivileges · AdjustGroups · AdjustDefault · ReadControl
```

An expansion may end in `UnknownBits(0x…)`. In this block that means the
bits are **included by the constant** but have no individually documented
right name — not that dumpex failed to read them, which is what the same
token means on a `Rights` line. The block spells that out whenever one
appears.

`AllAccess` on a `Process` or `Thread` also depends on the dump's
Windows version. `winnt.h` defines `PROCESS_ALL_ACCESS` as `0x001f0fff`
before Vista and `0x001fffff` after it (`THREAD_ALL_ACCESS`:
`0x001f03ff` → `0x001fffff`), so `--handles` reads the dump's own
`SYSTEM_INFO.MajorVersion` and picks the matching one. A full process
handle in an XP dump reads `AllAccess`; the same mask in a Windows 10
dump is a partial handle and is listed right by right, because there it
genuinely is one. A dump whose version cannot be read gets the modern
values.

`AllAccess` is expanded **per object type**, because it names that
type's own `*_ALL_ACCESS` constant: on a `Process` it includes
terminating it and writing its memory, on an `Event` it is querying and
setting the event. Two `AllAccess` rows of different types are not the
same capability.

The same bit means different things for different object types, so the
decode is only valid for the type the descriptor recorded — and it is
printed on the row that recorded it, in the table's own order, so there
is no second table to look anything up in. `File`, `Process`, `Thread`,
`Token`, `Section`, `Job`, `Directory`, `SymbolicLink`, `Event`,
`Mutant`, `Semaphore`, `Timer`, `Key`, `IoCompletion`, `Desktop` and
`WindowStation` are decoded; a type whose rights have no authoritative
public definition (`TpWorkerFactory`, `ALPC Port`, …) is left as
captured rather than guessed at.

The `Access` column still prints the exact captured mask — once, as the
aligned value you scan, compare and copy — and `granted_access` is
unchanged in `--json` and in every historical schema; the names are
derived text, nothing more. A zero mask reads `(no rights)`; an absent
one still reads `(unknown)` in the column and gets no `Rights` line at
all. Bits that were not decoded are kept at their raw value as
`UnknownBits(0x…)` (no documented right for that type) or
`TypeSpecificUnavailable(0x…)` (dumpex has no right table for that
type), never guessed. Decoded rights are **observations** about what a
captured handle permitted — not proof it was used, and not a
maliciousness verdict.

### `--process`

`--verbose` adds three blocks:

- **The import table**, with headers and a legend for its address pair.
  Each row reads `IAT Slot VA -> Resolved Target VA`: the slot is the
  address where the import pointer is stored, and the target is the
  address stored in that slot in the captured process memory. A slot
  outside the recorded import directory bounds is flagged with `*` — an
  observation about the dump's directory framing, not a verdict about
  the import. The table covers the standard Import Address Table
  (`IMAGE_DIRECTORY_ENTRY_IMPORT`) only; Delay Import descriptors
  (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`) are out of scope for v2.13 —
  they are not walked, not reported, and their absence from the table
  is not a coverage limitation.
- **`Identity Verification`**, which shows the selected path and name,
  the source they came from, and one line per independent check with an
  explicit state: `[OK]`, `[!!]` (conflict), or `[--]` (could not be
  evaluated). The checks are ModuleList registration of the PEB image
  base, PEB/ModuleList process-name agreement, PE-header validity at the
  image base, and whether another module competes for the same name. The
  raw per-source claims follow underneath. A conflict is an
  **observation**: it never becomes a maliciousness verdict, a command
  failure, or a change to the exit code.
- **`Extended PEB`**, the fields the retired `--peb` command used to
  print, also published as `peb_extended` in `--json`.

Every string in these blocks that came out of the dump — paths, names,
DLL and API names, window title — is escaped before it reaches the
terminal, so a hostile name cannot forge dumpex's own output. `--json`
keeps the exact decoded bytes.

### `--sysinfo`

Environment variables routinely carry tokens, session identifiers, user
names, and full user paths. `--sysinfo --json` output can contain these
secrets and should be handled at the same sensitivity as the dump
itself. dumpex never silently redacts environment evidence — the
console prints only a count by default (values require `--verbose` or
`--json`), which is a don't-shoulder-surf default, not a security
control; `--redact-paths` reduces path-shaped output to basenames but
adds no redaction for environment values themselves.

## `--profile`

`--profile` (issue #95) answers a different question than the other
recon commands: not "what did the process do", but "what can this dump
actually support analyzing, and why". `--verbose` is accepted (it is
recorded in `meta.execution.options` like every other command) but has
no effect on `--profile`'s own console or JSON output — the report is
always complete either way, unlike `--process`/`--handles` where it
gates real projection differences. It reports two things, kept
structurally separate and never mixed into a verdict:

**The dump's own stream inventory** — one row per entry in the dump's
own `MINIDUMP_DIRECTORY` table, in directory order (never sorted,
deduplicated, or merged). Each row carries its raw numeric stream-type
ID — kept even when this build's `minidump` library doesn't recognize
it, so an unrecognized type is a row of its own, never dropped — and a
`parser_state`:

| `parser_state` | Meaning |
|---|---|
| `parsed` | Present, and dumpex parsed it (a real count, or none for a singular stream). |
| `present_empty` | Present, parsed, and verified to hold zero items. |
| `unparsed` | Present, but dumpex has no parser registered for this stream type. |
| `failed` | Present, and the parse attempt raised — the error text is carried alongside. |
| `indeterminate` | Two or more directory entries share this same stream type, so the one surviving parsed-or-failed state can't be attributed to any one of them with confidence. |

**The analysis-capability map** — a frozen, ordered registry of six
capability IDs (`memory_region_analysis`, `module_analysis`,
`injection_artifact_analysis`, `thread_analysis`, `handle_analysis`,
`injector_handle_assessment`), always reported in that same order. Each
is `available`, `limited`, or `unavailable`, derived deterministically
from whether the streams that capability needs are present and parsed —
never from anything resembling a hunt result. A capability reads
`unavailable` because required evidence is missing, never because
`--profile` looked and found nothing suspicious; it carries no score,
confidence, or ATT&CK mapping.

**Command coverage and capability availability are deliberately
independent axes.** A small, cleanly-captured dump can be `--profile`
complete — the command itself read everything it needed, exit code `0`
— while several capabilities are `unavailable`, because the dump itself
never captured what *those* capabilities need. An unavailable capability
is an evidence boundary, not a clean or malicious finding, and never
lowers `--profile`'s own coverage status.

The example below is a complete, valid v2.13 document — it validates
as-is against `dumpex-output-v2.13.schema.json`
(`tests/integration/test_cli_reference_json_examples.py` extracts this
exact fenced block and validates it in CI, the same way
[docs/SOC_QUICKSTART.md](SOC_QUICKSTART.md)'s own "Sanitized `--json`
examples" are kept honest). It is `--profile --verbose` on a dump that
captured system info, modules, threads, and memory evidence but no
`HandleDataStream` — all six capabilities are present, in the registry's
fixed order, with a genuine mix of `available` and `unavailable`:

```json
{
  "meta": {
    "schema_version": "2.13",
    "tool": { "name": "dumpex", "version": "<installed version>" },
    "execution": {
      "started_at": "2026-03-14T09:12:01Z", "finished_at": "2026-03-14T09:12:02Z",
      "duration_seconds": 1.0, "command": "profile",
      "options": { "verbose": true }, "case_id": null, "analyst": null
    },
    "evidence": [
      { "id": "primary", "role": "primary", "file_name": "sample.dmp",
        "size_bytes": 22, "sha256": "11bc45c81995f224b81b8e4de5a9607e4b028fa2475499bfa10545ab69cd6aab" }
    ],
    "runtime": { "python_version": "3.12.13", "minidump_version": "0.0.24",
      "yara_version": "4.5.4", "pyyaml_version": "6.0.3" }
  },
  "result": {
    "kind": "profile",
    "execution_status": "completed",
    "coverage": {
      "status": "complete", "reasons": [],
      "sources": {
        "sysinfo": { "state": "present", "record_count": 1, "detail": null },
        "modules": { "state": "present", "record_count": 1, "detail": null },
        "threads": { "state": "present", "record_count": 1, "detail": null },
        "thread_info": { "state": "present", "record_count": 1, "detail": null },
        "memory_info": { "state": "present", "record_count": 1, "detail": null },
        "handles": { "state": "absent", "record_count": null, "detail": null },
        "memory_content": { "state": "present", "record_count": 1, "detail": null },
        "profile_directory": { "state": "present", "record_count": 1, "detail": null }
      },
      "limitations": []
    },
    "summary": { "stream_count": 6, "capability_summary": { "available": 4, "limited": 0, "unavailable": 2 } },
    "data": {
      "records": [
        {
          "architecture": "AMD64",
          "raw_flags": 2,
          "recognized_flags": ["MiniDumpWithFullMemory"],
          "unrecognized_flag_bits": 0,
          "memory_capture": {
            "full_memory_flag_set": true,
            "memory64_list_present": true,
            "memory_list_present": false,
            "captured_segment_count": 1,
            "captured_bytes_total": 4096
          },
          "streams": [
            { "directory_index": 0, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
              "parser_state": "parsed", "record_count": null, "detail": null },
            { "directory_index": 1, "stream_type_id": 4, "stream_type_name": "ModuleListStream",
              "parser_state": "parsed", "record_count": 1, "detail": null },
            { "directory_index": 2, "stream_type_id": 3, "stream_type_name": "ThreadListStream",
              "parser_state": "parsed", "record_count": 1, "detail": null },
            { "directory_index": 3, "stream_type_id": 17, "stream_type_name": "ThreadInfoListStream",
              "parser_state": "parsed", "record_count": 1, "detail": null },
            { "directory_index": 4, "stream_type_id": 16, "stream_type_name": "MemoryInfoListStream",
              "parser_state": "parsed", "record_count": 1, "detail": null },
            { "directory_index": 5, "stream_type_id": 9, "stream_type_name": "Memory64ListStream",
              "parser_state": "parsed", "record_count": 1, "detail": null }
          ],
          "capabilities": [
            { "capability_id": "memory_region_analysis", "status": "available",
              "required_source_groups": [["memory_info"]], "required_sources": ["memory_info"],
              "optional_sources": [], "limitations": [] },
            { "capability_id": "module_analysis", "status": "available",
              "required_source_groups": [["modules"]], "required_sources": ["modules"],
              "optional_sources": [], "limitations": [] },
            { "capability_id": "injection_artifact_analysis", "status": "available",
              "required_source_groups": [["memory_info", "thread_info"]],
              "required_sources": ["memory_info", "thread_info"],
              "optional_sources": ["modules", "threads", "memory_content"], "limitations": [] },
            { "capability_id": "thread_analysis", "status": "available",
              "required_source_groups": [["threads", "thread_info"]],
              "required_sources": ["threads", "thread_info"],
              "optional_sources": ["modules"], "limitations": [] },
            { "capability_id": "handle_analysis", "status": "unavailable",
              "required_source_groups": [["handles"]], "required_sources": ["handles"],
              "optional_sources": [],
              "limitations": [{ "code": "REQUIRED_SOURCE_ABSENT", "source": "handles",
                "detail": "HandleDataStream is not present in this dump" }] },
            { "capability_id": "injector_handle_assessment", "status": "unavailable",
              "required_source_groups": [["handles"]], "required_sources": ["handles"],
              "optional_sources": ["threads"],
              "limitations": [{ "code": "REQUIRED_SOURCE_ABSENT", "source": "handles",
                "detail": "HandleDataStream is not present in this dump" }] }
          ]
        }
      ]
    }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [], "errors": [] }
}
```

`full_memory_flag_set` (the header's own `MiniDumpWithFullMemory` flag)
and `memory64_list_present`/`captured_segment_count` (what was actually
captured) are read independently and never inferred from each other — a
dump whose flag says `MiniDumpNormal` can still carry a real, positive
`captured_segment_count`, and the two facts are reported side by side
rather than collapsed into one boolean.

See [docs/recon_profile_contract.md](recon_profile_contract.md) for the
complete field-by-field contract, the full closed limitation-code
registry, and the per-capability required/optional source rules.

## Examples

### Recon

```bash
dumpex sample.dmp --sysinfo
dumpex sample.dmp --process
dumpex sample.dmp --process --verbose
dumpex sample.dmp --handles
dumpex sample.dmp --handles --verbose
dumpex sample.dmp --profile
dumpex sample.dmp --modules
dumpex sample.dmp --threads
dumpex sample.dmp --list
dumpex sample.dmp --list --filter PAGE_EXECUTE_READWRITE
```

When running from a source checkout without an installed console entry point,
replace `dumpex` with `python -m dumpex`.

### TTP hunting

```bash
# Run every hunter
dumpex sample.dmp --hunt all

# Run a single hunter
dumpex sample.dmp --hunt injection
dumpex sample.dmp --hunt hollowing
dumpex sample.dmp --hunt stomping --ref-dir C:\Windows\System32
dumpex sample.dmp --hunt pipe
dumpex sample.dmp --hunt cs-beacon
dumpex sample.dmp --hunt yara
dumpex sample.dmp --hunt obfuscation

# Use explicit analyst-controlled rules
dumpex sample.dmp --hunt all --rules-file case-rules.yaml
dumpex sample.dmp --hunt yara --yara-dir case-yara

# Deep-triage the skipped-target queue under an explicit budget
dumpex sample.dmp --hunt all --triage-skipped
```

### Focused report

Use exactly one report anchor:

```bash
dumpex sample.dmp --report --report-tid 0x1234
dumpex sample.dmp --report --report-addr 0x7ff600001000
dumpex sample.dmp --report --report-string "powershell"
```

### Diff

```bash
dumpex suspect.dmp --diff clean-reference.dmp
dumpex suspect.dmp --diff clean-reference.dmp --diff-scope memory
```

The positional dump is always the analysis target; the dump passed to
`--diff` is the baseline/reference. Thus "added", "new", and "changed to"
records describe the positional dump relative to the reference.
`--diff-scope` is not a standalone command; it only narrows an existing
`--diff` comparison. The older `--diff-mode` spelling remains accepted as
a hidden compatibility alias for existing scripts.

### Extraction and strings

```bash
dumpex sample.dmp --extract 0x7ff600001000 --size 0x1000 --output region.bin
dumpex sample.dmp --strings 0x7ff600001000 --min-len 8
dumpex sample.dmp --strings 0x7ff600001000 --strings-encoding unicode --grep "(?i)https?://"
```

### Case-ready output

```bash
dumpex sample.dmp --hunt all \
  --json result.json \
  --txt transcript.txt \
  --case-id CASE-1234 \
  --analyst analyst01
```

Add `--redact-paths` when the JSON will leave the analyst workstation.
