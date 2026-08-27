# Hunt targeted-rescan contract

Status: **planned and not implemented**. `--hunt-addr` is not present in the
released CLI. This is the live final design for the outstanding targeted-rescan
work; it does not authorize behavior changes to current full-scope `--hunt`.

## Scope and vocabulary

A targeted invocation asks one supported hunter to evaluate an investigator-
selected half-open virtual-address range. It is supplementary evidence, not a
mutation of an earlier report and not an automatic claim that an original
coverage gap has been closed.

- **Requested range:** `[addr, addr + size)`.
- **Closure identity:** `(hunter, source, scope, base_address, size)`.
- **Capture state:** whether the requested bytes were available: `none`,
  `partial`, or `complete`.
- **Coverage status:** whether the applicable algorithm ran to completion:
  `not_evaluated`, `partial`, or `complete`.
- **Bypassed cap:** the one per-target oversize cap that targeted mode is
  explicitly allowed to ignore.
- **Retained budget:** every other time, byte, candidate, hit, validation, and
  retained-evidence limit. These remain fail-closed.

Targeted mode reuses existing detection rules, scores, evidence types,
limitation meanings, and `NOT_DETECTED_IN_SCANNED_SCOPE`. It adds no “targeted
detection” verdict and no new `SkipCause` value.

## CLI contract

```text
dumpex <dump> --hunt <identity> --hunt-addr <address> --size <size>
```

`--hunt-addr` is a modifier, not a mode. It belongs with the existing memory
range options and uses the same `parse_hex_or_int()` grammar as `--size`:
`0x`-prefixed hexadecimal or plain decimal. The existing `--size`/`-s` flag is
reused; no second size option is introduced.

### Flag relationships

- `--hunt-addr` requires both `--hunt <identity>` and `--size`.
- `--size` without `--hunt-addr` remains inert for ordinary `--hunt`, exactly as
  it is now. It is not an error and does not make the invocation targeted.
- `--hunt-addr` rejects `--hunt all`; `all` is a selection mode, not an analyzer.
- `--hunt-addr` rejects an unknown hunter and the known but unsupported
  `injection` and `hollowing` hunters.
- `--triage-skipped` is temporarily unavailable and is rejected before opening
  the dump, including with a targeted single-hunter invocation.
- A modifier supplied with another mutually exclusive mode is rejected.

### Range validation

Validation occurs before opening the dump:

1. `addr` and `size` must parse with `parse_hex_or_int()`.
2. `0 <= addr <= 0xffffffffffffffff`.
3. `size` is a positive integer.
4. Compute `end = addr + size` with checked arithmetic and require
   `end <= 2**64`. Equality is legal because `end` is exclusive and is never
   dereferenced.
5. `size <= 256 MiB` for pipe, stomping, YARA, and CS Beacon.
6. `size <= 32 MiB` for obfuscation.

There is no wraparound, clamp, inferred size, silent range expansion, or silent
contraction. A short capture reports a short read against the requested range.

### Range and descriptor boundaries

Hunters keep their native scan unit: region for pipe/stomping, segment for
YARA/CS Beacon, and region+layer for obfuscation. The requested bytes are
captured once and passed to the hunter; targeted mode does not introduce a new
chunking algorithm.

An address outside every relevant region/segment is valid investigator input.
It produces no captured bytes and a read-failed/not-evaluated closure, not a CLI
shape error and never a clean result.

When the requested range crosses a region/segment descriptor boundary:

- capture continues across the whole requested range so `captured_size` and
  `capture_state` describe actual byte availability;
- source eligibility and evaluation are based only on the descriptor containing
  `base_address`;
- evaluation stops at that descriptor's end rather than borrowing different
  state/type/protection facts from the next descriptor; and
- the closure is partial and carries
  `SCAN_REGION_EVALUATION_TRUNCATED` with the affected requested target.

This separation prevents a fully captured cross-boundary range from being
reported as fully evaluated. The new limitation is caller-buildable, uses the
closure's source, permits `scope` and `targets`, and maps to the existing
`scan_truncated` relationship cause.

## Capability matrix

The matrix is closed for the first release:

| Hunter | Scan unit | Granted source | Granted scopes | Per-target cap bypassed |
|---|---|---|---|---|
| `injection` | — | none; capability is `None` | — | none |
| `hollowing` | — | none; capability is `None` | — | none |
| `pipe` | region | `pipe_name_scan` | empty | `PIPE_SCAN_MAX` = 8 MiB |
| `stomping` | region | `ioc_string_scan` | empty | `IOC_SCAN_MAX` = 5 MiB |
| `cs-beacon` | segment | `segment_scan` | empty | `CS_MAX_SEG_SCAN` = 50 MiB |
| `yara` | segment | `segment_scan` | empty | `YARA_MAX_SEG_SCAN` = 50 MiB |
| `obfuscation` | region+layer | `encoding_scan` | `sleep_mask`, `entropy`, `decode` | layer-specific caps below |

Empty scopes mean there is no finer targetable subdivision. Obfuscation always
attempts three closures in fixed `sleep_mask`, `entropy`, `decode` order; there
is no public layer-selection flag. The requested range is captured once and
shared by all three layers.

For obfuscation the authorized bypass is:

| Closure | Bypassed cap(s) |
|---|---|
| `sleep_mask` | `SLEEP_MASK_REGION_MAX` = 10 MiB |
| `entropy` | `ENTROPY_SCAN_MAX` = 10 MiB |
| `decode` | `DECODE_SCAN_MAX` = 2 MiB and `XOR_SCAN_MAX` = 512 KiB |

`decode` bypasses both caps because leaving the inner XOR cap active would make
the granted decode rescan silently partial while the outer cap appeared to have
been bypassed.

## Budget contract

Budgets are fresh per invocation and shared only where the hunter already uses
a shared per-invocation budget. No accounting carries between commands. A
targeted grant bypasses only the cap named above.

### Pipe retained budgets

| Budget | Value |
|---|---|
| `PIPE_C2_BUDGET_MAX_HITS` | 200 |
| `PIPE_C2_BUDGET_MAX_RETAINED` | 2 MiB |
| `PIPE_C2_BUDGET_TIME_SECONDS` | 30 s |
| `PIPE_NAME_BUDGET_MAX_HITS` | 500 |
| `PIPE_NAME_BUDGET_MAX_RETAINED` | 1 MiB |
| `PIPE_NAME_BUDGET_TIME_SECONDS` | 30 s |
| `PIPE_MAX_MATCHES_PER_REGION` | 50 |
| `PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION` | 5 |
| `PIPE_C2_CONTEXT_BYTES` | 512 bytes per match |
| `PIPE_C2_TOKEN_PREVIEW` | 256 retained bytes |
| `PIPE_NAME_MAX_CHARS` | 512 retained characters |

### Stomping retained budgets

| Budget | Value |
|---|---|
| `PE_VALIDATE_READ_MAX` | 4096 bytes |
| `REF_FILE_MAX_READ` | 64 MiB |
| `MAX_DIFF_RANGES` | 20 |
| `MAX_DIFF_RANGES_SCAN` | 200,000 |

The targeted source is only `ioc_string_scan`. Module registration, PE-header,
reference-file, and section-diff coverage remain independent sources; a clean
IOC closure must not claim those sources were evaluated or close their gaps.

### YARA and CS Beacon retained budgets

| Hunter | Budget | Value |
|---|---|---|
| YARA | `YARA_MATCH_TIMEOUT` | 30 s per match call |
| YARA | `YARA_MAX_TOTAL_HITS` | 2000 |
| YARA | `YARA_MAX_STRINGS_PER_MATCH` | 50 |
| YARA | `YARA_SCAN_DEADLINE_SECONDS` | 300 s |
| YARA | `YARA_MAX_TOTAL_BYTES_SCANNED` | 512 MiB |
| CS Beacon | `CS_MAX_CANDIDATES` | 20,000 |
| CS Beacon | `CS_MAX_DECODED_BYTES` | 64 MiB |
| CS Beacon | `CS_MAX_HITS` | 100 |
| CS Beacon | `CS_SCAN_DEADLINE_SECONDS` | 60 s |
| CS Beacon | `CS_MAX_TOTAL_SCANNED_BYTES` | 500 MiB |
| CS Beacon | `CS_CONFIG_DECODE_MAX` | 8192 bytes per candidate |

### Obfuscation retained budgets

| Budget | Value | Consumer |
|---|---|---|
| `ENCODING_BUDGET_TIME_SECONDS` | 60 s | sleep-mask polling and decode |
| `ENCODING_BUDGET_MAX_ATTEMPTS` | 2000 | decode |
| `ENCODING_BUDGET_MAX_RETAINED` | 32 MiB | decode |
| `ENCODING_BUDGET_MAX_HITS` | 500 | decode |
| maximum bytes read | 128 MiB | decode |
| `SLEEP_MASK_MAX_CANDIDATES` | 10 per region | sleep mask |
| `SLEEP_MASK_MAX_WINDOWS` | 200,000 per region | sleep-mask candidate recovery |
| `SLEEP_MASK_VALIDATE_SAMPLE` | 2 MiB chunks | sleep-mask validation |
| `XOR_STRUCTURAL_WINDOW` | 128 KiB | decode |
| `DECOMPRESS_MAX_OUTPUT` | 8 MiB | decode |

Entropy has no separate time/hit/candidate budget, and sleep-mask retains full
decoded candidate buffers. The lower 32 MiB request ceiling is therefore a
required safety bound. Deadlines are cooperative: an in-flight operation may
finish before the next poll. Implementations must size worker memory for the
captured buffer, up to ten retained sleep-mask buffers, and existing bounded
decode state (approximately 400 MiB worst case), while still enforcing every
retained limit.

Budget-exhaustion gaps are not made targetable by this design. The grants cover
oversized per-target skips only; retrying a source whose global budget was
already exhausted requires a separate design.

If an original skipped target is larger than the request ceiling, generated
follow-up guidance may offer one capped command only. It must label that command
supplementary/partial, preserve unresolved `coverage_effect`, and must not imply
that repeated chunks automatically close the original gap.

## Evidence and coverage semantics

### Closure and evaluation

One invocation produces one closure for pipe, stomping, YARA, and CS Beacon,
and three layer closures for obfuscation. Identity always uses the requested
base and size, regardless of capture outcome.

Per-closure status is derived from two independent gates:

1. prerequisites for that source are ready; and
2. the requested bytes actually reach that source's algorithm under the source
   eligibility/minimum-input rules.

If either gate fails, the closure is `not_evaluated`. If both hold and any read,
short-read, boundary, timeout, hit-cap, candidate-cap, or retained-budget gap
applies, it is `partial`; otherwise it is `complete`.

The source-specific input gate is:

| Source | Eligibility based on descriptor containing `base_address` | Minimum captured input |
|---|---|---|
| `pipe_name_scan` | `State == MEM_COMMIT` | 1 byte |
| `ioc_string_scan` | committed `MEM_IMAGE` with executable protection | 1 byte |
| YARA `segment_scan` | selected captured segment; no extra region filter | 1 byte |
| CS Beacon `segment_scan` | selected captured segment; no extra region filter | 1 byte |
| `encoding_scan/sleep_mask` | layer's existing committed private/image eligibility | layer's existing minimum |
| `encoding_scan/entropy` | layer's existing committed private/image eligibility | 256 bytes |
| `encoding_scan/decode` | committed private/image, excluding system-DLL image regions | 1 byte |

Candidate-pattern minimums inside an algorithm do not make the closure
not-evaluated; receiving eligible input and legitimately finding no candidate is
still evaluation.

Across closures, `HunterRecord.coverage.status` is `complete` only when every
closure is complete, `not_evaluated` only when every closure is not evaluated,
and `partial` otherwise. Each obfuscation layer attributes shared-budget
exhaustion only when that layer observed or was prevented by the exhaustion;
one layer must not inherit another layer's limitation blindly.

### Negative-result rule

`NOT_DETECTED_IN_SCANNED_SCOPE` is allowed only when every required closure was
evaluated completely and the existing detection logic produced no match. It is
never inferred from capture state alone. A complete capture can still have
partial evaluation because of a retained budget; a partial capture can be
not-evaluated if it never reaches the algorithm's minimum input.

Explicit gaps remain in `coverage.limitations`. Targeted execution produces a
fresh report and does not delete, mutate, or retroactively resolve limitations
in another result. Cross-boundary signatures are evaluated only within the
actual contiguous input given to the algorithm; targeted mode must not invent
bytes across an uncaptured gap or concatenate unrelated descriptors.

When a source does not run, add `TARGETED_SOURCE_NOT_EVALUATED` through the
required-source derivation path. It is absent-capable (not caller-buildable),
uses source `targeted_scan`, permits an optional closure scope, and renders a
reason without claiming one particular cause. Prerequisite limitations remain
present alongside it.

Targeted coverage sources are deliberately narrow:

| Hunter | Required source(s) | Completeness checks retained | Observational only |
|---|---|---|---|
| pipe | `pipe_name_scan` | requested-range read/short-read, both pipe-name and C2 budget exhaustion, boundary truncation | dump-wide `memory_info`, `handle_data` |
| stomping | `ioc_string_scan` | requested-range read/short-read and boundary truncation | `memory_info`, modules, headers, reference files, section diffs |
| YARA | `segment_scan` | read/short-read, match failure/timeout, hit/byte/deadline caps, rule compilation, match-context verification, boundary truncation | none |
| CS Beacon | `segment_scan` | read/short-read, candidate/decode/hit/byte/deadline caps, boundary truncation | `memory_info`, thread context |
| obfuscation | `encoding_scan` per layer | that layer's read/short-read/budget state and boundary truncation | `memory_info` |

For stomping in particular, completion of `ioc_string_scan` is independent of
module/reference comparison. A targeted IOC result cannot assert that stomping
as a whole was ruled out.

## Structured output

Targeted results add `details.targeted_scope`, one item per closure:

```json
{
  "source": "encoding_scan",
  "scope": "entropy",
  "base_address": "0x0000000010000000",
  "size": 1048576,
  "captured_size": 524288,
  "capture_state": "partial",
  "coverage_status": "partial"
}
```

The item is closed and deterministic:

- `source`: granted public coverage source.
- `scope`: layer name or `null` for an unscoped source.
- `base_address`: fixed-width normalized requested address.
- `size`: requested positive byte count.
- `captured_size`: actual available bytes, or `null` when unavailable.
- `capture_state`: `none`, `partial`, or `complete`.
- `coverage_status`: `not_evaluated`, `partial`, or `complete`.

`captured_size` measures byte availability, not a byte-precise “algorithm
examined through here” offset. Coverage status carries honest algorithm-level
completion where scanners are candidate-, window-, hit-, or deadline-bounded.

`targeted_scope` is added only for targeted results. Full-scope detail records
omit the key completely; they do not emit `targeted_scope: null`. The field is
optional in the new schema chosen when the feature ships and is never added
retroactively to v2.13 or any historical schema. Full-scope JSON and golden
fixtures therefore remain byte-for-byte unaffected by this design.

Console output labels the normalized range and prints each closure in the fixed
order above, clearly separating capture from evaluation and retaining ordinary
limitations/diagnostics. It does not print a clean banner when coverage is
partial or not evaluated. JSON uses the typed record conversion; no raw parser
object is serialized.

There is currently no Hunt CSV exporter. A future exporter must derive from the
same `HunterRecord`, coverage, and targeted-scope facts rather than inventing a
parallel result model.

## Diagnostics, ordering, and exit codes

The only new limitation codes are:

| Code | Construction | Allowed fields | Meaning |
|---|---|---|---|
| `TARGETED_SOURCE_NOT_EVALUATED` | absent-capable | `scope` | a required targeted closure did not run |
| `SCAN_REGION_EVALUATION_TRUNCATED` | caller-buildable | `scope`, `targets` | evaluation stopped at the first descriptor boundary while capture continued |

All other failure and budget conditions reuse current codes. The two registries
must stay complete and fail closed; neither new code is a diagnostic-only value.

Targeted mode names exactly one hunter. Obfuscation closure order is always
`sleep_mask`, `entropy`, `decode`; evidence, limitations, and diagnostics keep
their existing deterministic ordering.

Argument-shape and range failures use `parser.error()` and exit 2. Unknown,
`all`, and known-but-unsupported hunter capability failures use the established
user-facing Hunt error path and exit 1. A successfully executed targeted command
uses the existing `exit_code_for(coverage.status)` mapping: complete 0, partial
3, not evaluated 4. Detection status does not introduce another exit mapping.

## Compatibility invariants

- `--hunt-addr` remains absent until the feature lands atomically with its
  range, capability, executor, CLI, record, and schema support.
- v2.13 and older schemas remain frozen.
- Current `--hunt <identity>` and `--hunt all` retain their selection,
  detection, scoring, ordering, console/JSON shape, diagnostics, and exit codes.
- Full-scope details omit `targeted_scope`; existing golden fixtures are not
  regenerated for this feature.
- Targeted execution reuses the same report/evidence architecture and the same
  built-in registry boundary; it does not dynamically inject analyzers.
