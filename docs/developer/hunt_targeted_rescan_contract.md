# Hunt targeted-rescan contract

Status: **implemented**. `--hunt-addr` is a released CLI modifier and every
analyzer in the capability matrix below is reachable through it. The internal
request/context/observation boundary carries it (`dumpex.hunt._request.HuntRequest`,
`dumpex.hunt._execution.HuntExecutionContext`,
`dumpex.hunt._observation`). The capability matrix is registered as
`AnalyzerSpec.targeted_capability` -- grants plus a `request_ceiling` -- and
`HuntRequest` resolves it through `AnalyzerRegistry.select_targeted_scopes()`
and enforces the ceiling. An obfuscation targeted request carries all three
layers as one `targeted_scopes` set (one request = one invocation = one
capture), and the observation layer splits execution identity
(`ObservationKey`) from per-`(source, scope)` closures (`ObservationClosure`),
so one expensive run projects `pipe_name` and `c2_context` closures (or the
three obfuscation layers) independently without duplicate scanning.

All five targeted executors are implemented, each registered as its analyzer's
`AnalyzerSpec.targeted_adapter` and reachable through
`AnalyzerRegistry.resolve_targeted_adapter()`:

- `dumpex.hunt.encoding.targeted.run_targeted_encoding` runs the sleep-mask,
  entropy, and decode layers over one captured range -- reading only the
  captured prefix, bypassing only each layer's per-region size cap -- and
  returns an `ObservationResult` with one independent closure per layer plus a
  `TargetedEncodingEvidence` payload (each layer's own scan result and the
  containing-allocation `ScanTarget`).
- `dumpex.hunt.yara_hunt.targeted.run_targeted_yara` and
  `dumpex.hunt.cs_beacon.targeted.run_targeted_cs_beacon` hand their own
  scanner a single-segment slice of the captured segment containing the
  requested base -- virtual base at `hunt_addr`, size the requested (clipped)
  extent, dump-file offset displaced by the slice's distance from the segment
  base, so hit VAs and file offsets stay absolute -- bypassing only
  `YARA_MAX_SEG_SCAN` / `CS_MAX_SEG_SCAN`. Each returns one `segment_scan`
  closure plus a `TargetedYaraEvidence` / `TargetedCSBeaconEvidence` payload
  (matches or config hits, the scanner's diagnostics, YARA's `RulesProvenance`
  or CS Beacon's per-hit corroboration, and the containing-segment
  `ScanTarget`).
- `dumpex.hunt.pipe.targeted.run_targeted_pipe` runs the pipe-name and
  C2-context passes over one clipped range in a single read, bypassing only
  `PIPE_SCAN_MAX`, and returns an `ObservationResult` with one independent
  `pipe_name` closure and one `c2_context` closure plus a `TargetedPipeEvidence`
  payload (the range's string leads, its C2 records, the scan's frozen
  coverage, and the containing-allocation `ScanTarget`). Both budgets are
  registered on `context.budgets`, so several ranges rescanned on one context
  share one cumulative allowance instead of each getting a fresh one. They are
  registered *before* the range is read, so each deadline bounds the read as
  well as the passes that follow it -- a targeted range runs up to the whole
  request ceiling, so reading it is scan work an investigator waits on, not free
  setup -- and a range both budgets are already spent for is never read at all.
  Because
  C2 records are retained against that range's own pipe-name hits, a pipe-name
  pass its own budget cut short leaves the `c2_context` closure `partial` too.
  That exhaustion is reported once, by the `pipe_name` closure that owns the
  budget, and never merged into the C2 one; `c2_context` carries the dependency
  through its own `partial` status and its own diagnostic instead.
- `dumpex.hunt.stomping.targeted.run_targeted_stomping` runs the unscored
  IOC-string scan over one clipped range, bypassing only `IOC_SCAN_MAX`, and
  returns an `ObservationResult` with a single `ioc_string_scan` closure plus a
  `TargetedStompingEvidence` payload (the range's IOC hits, whether its only
  tokens were weak ones, the scan's frozen coverage, and the
  containing-allocation `ScanTarget`). It projects no closure for any other
  stomping source. A range attributed to a whitelisted network module keeps
  full scope's rule -- the network IOC pattern set is not applied -- but the
  closure says so through `SCAN_REGION_SEARCH_INCOMPLETE`/
  `pattern_set_withheld` and is `partial`, because a scan that applied fewer
  patterns cannot carry a full-search negative.

Every other budget is retained at its full-scope value in all five. The
descriptor-boundary rule (`dumpex.hunt._targeted`: clip to the containing
descriptor, `SCAN_REGION_EVALUATION_TRUNCATED`, the sub-descriptor caveat, the
synthetic region/segment shims, and the unexamined-suffix target) is shared in
both scan units, so pipe/stomping/obfuscation reuse one region implementation
and YARA/CS Beacon one segment implementation; only the coverage-to-status
reduction stays analyzer-local.

How exact a budget's remaining target can be is a property of the scan
algorithm, not of the targeted layer:

- A stop before a single byte is read always names the exact unexamined suffix:
  the whole request.
- **CS Beacon** names the exact residual for a mid-walk stop too. The marker
  walk sweeps the buffer once per XOR key in a fixed order, so once the last
  key's pass is under way every offset below its cursor has been searched by
  every key, and `ScanDiagnostics.budget_stop_offset` bounds the gap. During an
  earlier key's pass a later key has not looked at the segment at all; the
  cursor is then withheld and the whole slice stands.
- **YARA** cannot. `compiled.match()` runs a whole rule file over the whole
  buffer at once, so a hit-cap or deadline stop leaves "rule files k..n did not
  run over these bytes" -- a rule-set residual, not a byte range. Those gaps
  name the whole evaluated slice.
- **Pipe** cannot either. Each pattern sweeps the whole buffer, and a budget
  stop is recorded per region rather than per offset, so a cut pass leaves the
  whole evaluated range as its target.

Where a byte-exact residual is unavailable the target is always a conservative
superset, never narrower than what is actually unresolved: naming a narrower
range would send a rescan past the bytes that stopped early. A rule-set
residual for YARA would need a new limitation shape and is not in this release.

The public surface is one atomic cutover, delivered in schema v2.14: the
`--hunt-addr` CLI modifier, `summary.scan_scope`, and `details.targeted_scope`.
Command routing resolves selection, capability, and the request ceiling through
the analyzer registry (`AnalyzerRegistry.targeted_identities()` /
`targeted_source()` / `select_targeted_scopes()`); there is no CLI-owned hunter
or capability allowlist. Each analyzer additionally registers a
`targeted_report_projector`, which feeds the rescan's own evidence to that
analyzer's ordinary `aggregate.build_report()`, so a targeted verdict is scored
and classified by the same authority full scope uses.
`dumpex.hunt._targeted_record` then rebuilds the record's coverage from the
observation's closures and restates `status`/`verdict_level` to agree with it;
`dumpex.hunt._targeted_console` renders the one card. None of this changes
full-scope `--hunt` behavior.

### The one deliberate full-scope change

Targeted mode reuses the analyzers' own scanners rather than forking them, so a
defect in a shared scanner is fixed in one place and both paths change together.
There is exactly one such fix, and it is intentional:

`dumpex.hunt.stomping.memory_scan._classify_ioc_hits` resolves an IOC token's
`offset`/`va` from its match position inside a decoded string.
`_extract_ioc_strings` reports each run's BYTE offset in the region and its
DECODED text, so a match's `m.start()` is a CHARACTER index -- and the two units
only coincide for a single-byte encoding. A token found in a UTF-16LE run was
therefore reported at half its true distance into the run. The index is now
scaled by the run's own encoding width from
`dumpex.core.memory.IOC_STRING_ENCODING_WIDTHS`.

- This changes full-scope output: a UTF-16LE IOC token's reported `offset` and
  `va` move from `run_offset + character_index` to
  `run_offset + character_index * 2`. The corrected address is the one an
  investigator extracts or pivots on, so shipping targeted mode on top of the
  old arithmetic would have propagated a wrong address to a second consumer.
- `ASCII` and `ASCII-URL` are unchanged: their width is 1, so the scaling is the
  identity.
- Nothing else moves. Which tokens match, how many hits a region yields, the
  weak/strong classification, whitelist handling, scoring, and every coverage
  semantic are untouched -- only the address arithmetic for a multi-byte
  encoding.

Both paths are pinned: `tests/hunt/test_stomping_memory_scan.py` covers
`_classify_ioc_hits` directly and the encoding-width map's parity with the
extractor, and `tests/hunt/test_stomping_ioc_addressing.py` drives the full-scope
`scan_ioc_strings` entry point and the console projection.

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

- `--hunt-addr` and `--size` are required together in both directions for
  `--hunt`: `--hunt-addr` needs `--size` because a targeted scan never infers an
  extent, and `--size` needs `--hunt-addr` because accepting it alone would run
  an unbounded whole-dump hunt while discarding the option that asked for a
  bounded one. Both failures are argument errors.
- `--size` keeps its existing meaning for `--extract` and `--strings`, which are
  separate commands and unaffected.
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

Each capability also declares the hunt options a targeted invocation of it
actually reads (`TargetedCapability.consumed_options`, a subset of that
analyzer's own `option_names`):

| Hunter | Consumed by a targeted rescan | Declared but full-scope only |
|---|---|---|
| `pipe` | — | — |
| `stomping` | — | `ref_dir` |
| `cs-beacon` | — | — |
| `yara` | `rules_dir` | — |
| `obfuscation` | — | — |

An option outside that set is refused by the command surface rather than
accepted and recorded in `meta.execution.options`, where a directory nothing
read would suggest the source it feeds was evaluated. The same set is what
observation identity is keyed on in targeted mode: an option a run never
consulted cannot split two otherwise identical observations, while one it did
still isolates them. Full scope keeps identifying by the whole `option_names`.

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

One invocation produces one closure for stomping, YARA, and CS Beacon, two for
pipe (`pipe_name` and `c2_context`, both under `pipe_name_scan`), and three
layer closures for obfuscation. Identity always uses the requested base and
size, regardless of capture outcome.

Per-closure status is derived from two independent gates, which are two
different facts and never collapse into one:

1. the source applies to the target at all — its eligibility gate accepts the
   containing descriptor, and the requested extent is one the algorithm can be
   applied to; and
2. prerequisites are ready and the captured bytes actually reach that source's
   algorithm.

Failing gate 1 is `not_applicable`: the source does not apply to this target,
so there is nothing here it could have missed, and no re-collection or larger
budget would change that — only a different request would. Failing gate 2 is
`not_evaluated`: the source would have applied and did not get to run, which is
a coverage failure a fuller capture or a larger budget could close. If both
hold and any read, short-read, boundary, timeout, hit-cap, candidate-cap, or
retained-budget gap applies, the closure is `partial`; otherwise it is
`complete`.

The source-specific gates are below. Gate 1 has two independent parts, both
properties of the target: the descriptor containing the requested base, and the
requested extent itself. Gate 2 is one number, and it is about the capture.

| Source | Descriptor gate (gate 1) | Minimum requested extent (gate 1) | Minimum captured input (gate 2) |
|---|---|---|---|
| `pipe_name_scan` | `State == MEM_COMMIT` | — | 1 byte |
| `ioc_string_scan` | committed `MEM_IMAGE` with executable protection | — | 1 byte |
| YARA `segment_scan` | selected captured segment; no extra region filter | — | 1 byte |
| CS Beacon `segment_scan` | selected captured segment; no extra region filter | — | 1 byte |
| `encoding_scan/sleep_mask` | committed unbacked `MEM_PRIVATE` `PAGE_READWRITE` | `SLEEP_MASK_KEY_SIZE * SLEEP_MASK_MIN_REPEAT` | 1 byte |
| `encoding_scan/entropy` | committed unbacked `MEM_PRIVATE` | `ENTROPY_MIN_INPUT` (256 bytes) | 256 bytes |
| `encoding_scan/decode` | committed private/image, excluding system-DLL image regions | — | 1 byte |

Only entropy carries a number in both columns, and they are the same number
answering two questions: a 200-byte request is declined for its extent, while a
0x2000-byte request the dump backs 200 bytes of is not evaluated.

YARA and CS Beacon have no descriptor eligibility filter at all, so neither
ever produces `not_applicable`.

A `not_applicable` closure carries an `applicability_reason` naming the exact
gate, from a closed vocabulary: `region_not_committed`,
`region_type_ineligible`, `region_protection_ineligible`,
`region_module_backed`, `region_system_module`, `range_below_source_minimum`.
"Does not apply" without the gate is not actionable, so the reason is required
for that status and forbidden for every other. Widening an analyzer's
eligibility merely to make it run is not an option: the boundary is the answer.

A minimum input splits across both gates, and which side it falls on is decided
by WHAT is short:

* the requested range, clipped to its containing descriptor, is itself shorter
  than the algorithm can be applied to — `not_applicable`, with
  `range_below_source_minimum`. No capture of that range would produce a
  result, so it is a property of the target. Only a different, larger request
  changes it.
* the range clears the minimum but the dump backs fewer bytes of it than the
  minimum — `not_evaluated`. A fuller collection closes exactly this, which is
  what makes it a coverage failure rather than a boundary.

Both are reachable for one source over one dump, so neither may stand in for
the other: an analyst told "does not apply" reaches for a different address,
and one told "not evaluated" reaches for a better capture.

Full scope never makes this distinction, and does not need to: it walks whole
regions rather than a range anybody asked for, so a region under the minimum is
an eligible item with a not-applicable disposition on its own ledger. That
accounting is unchanged — the extent check that produces
`range_below_source_minimum` belongs to the targeted executor, where the extent
is the investigator's own request.

Candidate-pattern minimums inside an algorithm make the closure neither: an
eligible input in which no candidate legitimately appears is still evaluation.

Across closures, `HunterRecord.coverage.status` reduces over the closures that
APPLY: `complete` only when every applicable closure is complete,
`not_evaluated` when every applicable closure is not evaluated — or when no
closure applies at all — and `partial` otherwise. A `not_applicable` closure
takes no part. One layer whose gate declined the target must not turn its
completed siblings into a coverage failure, because nothing about the target
changes what those siblings established; a rescan whose every closure is
inapplicable evaluated no bytes and reports `not_evaluated`, which is a real
answer about the target and not a completeness claim about it.

Each obfuscation layer attributes shared-budget exhaustion only when that layer
observed or was prevented by the exhaustion, and never when its own gate
declined the target — blaming a budget for an inapplicable layer would imply a
bigger-budget rerun could help where it never could. One layer must not inherit
another layer's limitation blindly.

### Retained measurements

A closure that completed without a hit still records what it did. Without that
a targeted result reduces to an unexplained negative: the same card is printed
whether the scan read eight megabytes and measured them or read nothing at all.

Each closure carries bounded `measurements` — a name, a value, its unit, and
optionally the address and extent it was measured at. They are observations
only: they create no finding, move no score, and say nothing about any source
other than the closure carrying them. A `None` value means the closure did not
measure that quantity and is never a measured zero.

Two groups sit in one list. **Structural context** describes where the
requested range sits — `containing_region` (or `containing_segment`),
`containing_allocation_base`, `containing_region_state` / `_type` /
`_protection`, `containing_segment_file_offset`, `containing_module`,
`evaluated_extent`, `captured_bytes`, `capture_file_offset`. Naming a module or
an allocation here is attribution, never a claim that any hunter evaluated it,
and it never imports another hunter's verdict or coverage. Every closure of one
invocation carries identical values for these, so a closure read on its own is
still self-explanatory. **Per-closure work** is everything else, and is the
closure's own.

A closure that never reached its algorithm carries `bytes_evaluated` and the
structural context, and nothing else. Every remaining measurement describes an
execution, and an inapplicable layer reporting an exhaustive window search and
a complete candidate list would describe a search that never ran, contradicting
the closure standing beside it.

Obfuscation's per-layer names are:

| Layer | Names |
|---|---|
| `sleep_mask` | `sleep_mask_keys_recovered`, `sleep_mask_window_coverage`, `sleep_mask_candidate_list` |
| `entropy` | `whole_range_entropy`, `entropy_threshold`, `entropy_window_size`, `entropy_windows_total`, `entropy_windows_evaluated`, `entropy_windows_above_threshold`, `entropy_window_coverage`, `entropy_top_window` (repeated), `entropy_ranges_retained` |
| `decode` | `base64_candidates`, `base64_attempts`, `xor_keys_scored`, `xor_text_candidates`, `xor_structural_candidates`, `xor_attempts`, `compressed_candidates`, `compressed_attempts`, `base64_retained`, `xor_retained`, `compressed_retained`, `xor_sublayer` |

The decode sub-layers count candidates and attempts separately from what they
retained, because a retained count of zero has two causes an analyst acts on
differently: nothing in the range resembled a candidate, or many were decoded
and every one was rejected. The shared budget's attempt total cannot stand in
for them — it is spent by sleep-mask and all three sub-layers together, so it
answers a question about the invocation, not about Base64, XOR, or compression.
`*_candidates` is what the sub-layer's own pre-filter accepted for trying;
`*_attempts` is how many of those actually spent an attempt, which is smaller
whenever a budget or a dedup cut the run short. `xor_keys_scored` is the fixed
255-key text sweep, which spends no attempt at all and is therefore invisible
in any budget number.

A layer that draws on the shared budget also reports, for each of its four
independent resources, what THIS layer spent and that resource's limit:
`budget_attempts_spent` / `_limit`, `budget_decoded_bytes_spent` / `_limit`,
`budget_retained_bytes_spent` / `_limit`, `budget_hits_spent` / `_limit`, plus
`budget_exhausted_reason`. Every `_spent` value is the difference between
immutable snapshots taken immediately before and after that layer's own call.
The budget is one mutable object all three layers spend from in turn, so a
value read off it after they have all run would attribute the whole
invocation's consumption — and the last layer's exhaustion — to every layer
alike. `budget_exhausted_reason` is likewise the reason attributed to that
layer alone, and stays `None` for a layer that finished inside the allowance
even when a later layer went on to exhaust the same budget. All four resources
are reported, the decoded-output cap included: when that is what a run stops
for, a reason with no consumption or ceiling beside it leaves an analyst unable
to size a rerun.

A name is not unique within a closure: a bounded top-N list is N entries
sharing one name, in the order the closure ranked them.

### Windowed targeted entropy

Bypassing the entropy size cap and computing one Shannon value over an
investigator-supplied range does not, on its own, recover what the cap hid. A
single value over a sparse oversized allocation is an average dominated by its
zero-filled majority: a bounded encrypted payload inside it measures far below
the threshold as one number and far above it as its own window. Recovering the
evidence from the whole-range value alone would require the analyst to already
know which sub-window matters, while the skipped-target queue supplies only the
containing target.

A targeted entropy pass therefore measures the range twice. The whole-range
average is still computed and still decides a whole-range hit, so a range that
would flag full-scope flags here too. In addition the range is measured in
fixed, non-overlapping `ENTROPY_WINDOW_SIZE` windows from its base; a trailing
remainder shorter than the 256-byte minimum input is not measured. Past
`ENTROPY_MAX_WINDOWS` the offsets are strided by a deterministic step rather
than truncated, so a sampled pass still spans the whole range — and reports
itself as sampled, which makes the closure `partial` through
`SCAN_REGION_SEARCH_INCOMPLETE` with detail `entropy_window_sampled`, because a
window between two measured ones could hold a payload nobody looked at.

`ENTROPY_TOP_WINDOWS` windows are retained, ordered by descending entropy then
ascending address, so the same bytes always produce the same list and its first
entry is the range's maximum with its location. The window summary is retained
whether or not any window crossed the threshold: "measured 512 windows, highest
3.1" and "did not measure" are different answers to the same question.

Hits stay observation-only, exactly as full scope: when the whole-range average
clears the threshold the range itself is the hit, and only when it does not do
the above-threshold windows become hits instead. The two are mutually
exclusive, so one high-entropy range never reports both itself and its own
parts. A window hit's `EntropyHit.size` is the window extent — `None` means the
whole region — and its JSON carries a `window` object with that extent's base
address and size. A whole-region value omits the key entirely.

`aggregate.build_report` is shared with full scope and stays that way. Its
entropy observation words itself from the evidence it is handed, not from how
the scan was invoked: a hit list containing a windowed value says so and adds
the caveat that a window describes only itself, while a list of whole-region
values — every full-scope result — renders exactly the sentence and the single
limitation it always has.

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

When a granted closure would have applied and did not run, add
`TARGETED_SOURCE_NOT_EVALUATED` sourced to `targeted_scan`, with the closure's
scope when it has one. It is absent-capable (not caller-buildable) and renders
a reason without claiming one particular cause. Prerequisite limitations remain
present alongside it.

When a granted closure's own eligibility gate declined the target, add
`TARGETED_SOURCE_NOT_APPLICABLE` instead — same source, same scope, plus the
gate as `detail`. The two never accompany each other: a source that never
applied to the target did not fail to evaluate it.

The same code, sourced to a real coverage source instead, states the boundary
of the whole invocation: the sources a targeted rescan of that analyzer never
evaluates. That set is declared per analyzer, never inferred from which sources
produced a limitation -- an inference that marks a source unevaluated exactly
when it succeeded. YARA declares none: its rule compilation and match-context
verification are retained completeness checks, which is where the verdict comes
from. CS Beacon declares none either: it reads MemoryInfo and the thread
contexts into scored corroboration.

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

That is stated in the record, not left to omission. A targeted record's
`coverage.sources` carries the analyzer's whole published source vocabulary:
the granted source is `present`, and every source outside the grant is `absent`
with its own `TARGETED_SOURCE_NOT_EVALUATED` sourced to that source name. So a
targeted record is the one place `coverage.status` may be `complete` while
`limitations` is non-empty -- those entries bound what the result is ABOUT and
are not gaps in the scan. Letting them force `partial` instead would make every
targeted rescan exit 3 and destroy the exit-code mapping below.

A source one of the closures' own limitations already speaks about (YARA's
`yara_rules` compile gap) is not additionally marked out of scope; the rescan
reported on it.

### YARA match-context anchoring

Targeted and full-scope judge a hit's memory context at different addresses,
and this changes which hits are reported, not merely how they are labelled.

A full-scope scan anchors the `PE_In_Private_Memory` / `dumpex_scope =
"private_or_unbacked"` suppression at the scanned segment's base, which is the
address it reports the hit against. A targeted rescan anchors it at the string
instances behind the match instead: a requested range can span several
`MemoryInfo` regions, and a rule matching inside a private one must not be
discarded because the range happens to begin in a loaded module. A match is
suppressed only when every instance examined is module-backed; one surviving
instance keeps the match, and the backing-module lookup is anchored at that
same address, so a hit never reports private memory and a containing module at
once.

At most `YARA_MAX_STRINGS_PER_MATCH` instances are examined -- instance count
is attacker-controlled. When that cap truncates the list, suppression (the one
conclusion needing every instance) is downgraded to context-unverified rather
than discarding the match on evidence never fully examined, which makes the
closure partial through the existing match-context rule.

A targeted rescan can therefore report a hit the equivalent full-scope scan
suppressed. That is the intended direction: the finer anchor is the more
precise one, and the rescan exists to examine a range an investigator named.

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
  "coverage_status": "partial",
  "applicability_reason": null,
  "measurements": [
    {"name": "containing_region", "value": 4194304, "unit": "bytes",
     "base_address": "0x0000000010000000", "size": 4194304},
    {"name": "whole_range_entropy", "value": 0.45, "unit": "bits_per_byte",
     "base_address": null, "size": null},
    {"name": "entropy_top_window", "value": 8.0, "unit": "bits_per_byte",
     "base_address": "0x0000000010140000", "size": 65536}
  ]
}
```

The item is closed and deterministic:

- `source`: granted public coverage source.
- `scope`: layer name or `null` for an unscoped source.
- `base_address`: fixed-width normalized requested address.
- `size`: requested positive byte count.
- `captured_size`: actual available bytes, or `null` only when availability was
  never measured. A closure that never reached its algorithm still reports the
  real captured prefix -- that is the number a re-collection or a chunked
  rescan is sized from.
- `capture_state`: `none`, `partial`, or `complete`.
- `coverage_status`: `not_applicable`, `not_evaluated`, `partial`, or
  `complete`.
- `applicability_reason`: the eligibility gate that declined the target,
  non-null exactly when `coverage_status` is `not_applicable`.
- `measurements`: bounded neutral observations, possibly empty. Each is
  `{name, value, unit, base_address, size}`; `unit` is one of `bytes`, `count`,
  `bits_per_byte`, `seconds`, `text`, `flag`, and its type follows from that.
  `value` is `null` only when the quantity was not measured. `base_address` and
  `size` locate a measurement inside the requested range when it has a
  location, and `size` is never set without one.

`captured_size` measures byte availability, not a byte-precise “algorithm
examined through here” offset. Coverage status carries honest algorithm-level
completion where scanners are candidate-, window-, hit-, or deadline-bounded.

A consumer must not count `not_applicable` as a coverage failure. The record's
own `coverage.status` does not, and a rescan whose closures are all
inapplicable reports `not_evaluated` rather than `complete`.

`targeted_scope` is added only for targeted results. Full-scope detail records
omit the key completely; they do not emit `targeted_scope: null`. The field is
optional in v2.14 and is never added retroactively to v2.13 or any historical
schema. Full-scope JSON and golden
fixtures therefore remain byte-for-byte unaffected by this design.

Console output labels the normalized range and prints each closure in the fixed
order above, clearly separating capture from evaluation and retaining ordinary
limitations/diagnostics. A closure reading `not applicable` prints the gate that
declined it, and a complete rescan's closing scope statement names the closures
that did not apply, so "evaluated that range completely" is never readable as
"every layer looked". It does not print a clean banner when coverage is partial
or not evaluated. JSON uses the typed record conversion; no raw parser object is
serialized.

Each closure also prints what it measured, from the same `measurements` the
document carries, so console and JSON cannot disagree. The default card shows
the closure's own work and, for a ranked list, its first entry plus how many
more there are. `--verbose` adds material evidence rather than reprinting the
default card: the structural context the range sits in — one repeated fact
across closures, which is why it is verbose-only — and every entry of a bounded
ranked list.

Every gap has exactly one owning closure. An adapter raises a budget's
exhaustion on the closure that owns that budget; a closure the same budget also
constrains reports the dependency through its own `partial` status and its own
diagnostic, never through a second copy of the limitation. A consumer therefore
counts a gap once whether it reads the `ObservationResult`'s closures directly
or the flattened `HunterRecord.coverage.limitations`. The record's own
flattening additionally collapses entries equal in full structure, first
occurrence winning — a backstop against an adapter that breaks the rule above,
not a routine step, and one that never merges two gaps differing in `detail`,
`targets`, or `affected_count`.

`summary.scan_scope` is checkable, not merely present. The current schema pins
a `targeted` tag's `hunter` to `summary.selected` — which already pins the
single record and its own `hunter` — and pins `source` and `scopes` to that
analyzer's registered targeted capability. `scopes` is pinned as an exact
array, not by membership: a subset claims fewer closures ran than did, and
another order is a different document for a consumer diffing two results.

A `targeted` tag requires `details.targeted_scope` on the record and a `full`
tag forbids it. The entries themselves are pinned per analyzer with
`prefixItems` — one entry per closure, in the adapter's own fixed order, each
naming that closure's `source` and `scope` — with `minItems`/`maxItems` and
`items: false`, so a dropped closure, an extra one, a reordering, and an
invented `source`/`scope` are all rejected rather than merely well-formed.

Note the two orders differ and each is pinned as it is produced:
`scan_scope.scopes` is the sorted, deduplicated set, while
`details.targeted_scope` follows the adapter's fixed closure order
(`sleep_mask`, `entropy`, `decode` for obfuscation; `pipe_name`, `c2_context`
for pipe).

The schema's per-analyzer table is a copy of the registry's grants and of each
adapter's real closure scopes (never `TargetedGrant.scopes`, which is unscoped
for pipe while its invocation closes `pipe_name` and `c2_context`
independently), and is pinned to both by test.

There is currently no Hunt CSV exporter. A future exporter must derive from the
same `HunterRecord`, coverage, and targeted-scope facts rather than inventing a
parallel result model.

## Diagnostics, ordering, and exit codes

The new limitation codes are:

| Code | Construction | Allowed fields | Meaning |
|---|---|---|---|
| `TARGETED_SOURCE_NOT_EVALUATED` | absent-capable | `scope` | two shapes, told apart by `source`: `targeted_scan` means a required targeted closure would have applied and did not run (`scope` names the closure); any other source means one of that analyzer's coverage sources a targeted invocation structurally never evaluates |
| `TARGETED_SOURCE_NOT_APPLICABLE` | caller-buildable | `scope`, `detail` | source fixed to `targeted_scan`: a granted closure whose own descriptor-eligibility gate declined the target, so nothing here was missed. `detail` is REQUIRED and names the gate from the closed applicability vocabulary. Not a coverage failure, and never paired with `TARGETED_SOURCE_NOT_EVALUATED` on the same closure |
| `SCAN_REGION_EVALUATION_TRUNCATED` | caller-buildable | `scope`, `targets` | evaluation stopped at the first descriptor boundary while capture continued |
| `SCAN_REGION_SEARCH_INCOMPLETE` | caller-buildable | `scope`, `detail`, `affected_count` | the scan reached the requested bytes but a bounded internal sample (`window_sampled`, `candidate_list_truncated`), a per-target quota that dropped an occurrence (`match_cap_reached`, `context_only_cap_reached`), a deliberately narrowed pattern set (`pattern_set_withheld`), or an ambiguous overlapping capture (`overlapping_capture`) means its negative is not a full-search negative |

`SCAN_REGION_SEARCH_INCOMPLETE` covers conditions the cap-bypass makes reachable
in targeted mode that the frozen contract predated: obfuscation's
`SLEEP_MASK_MAX_WINDOWS` / `SLEEP_MASK_MAX_CANDIDATES` sampling, a targeted
entropy pass strided past `ENTROPY_MAX_WINDOWS` (`entropy_window_sampled`), a
`CapturedSlice.overlapping` segment table, pipe's per-region
`PIPE_MAX_MATCHES_PER_REGION` / `PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION` quotas,
and stomping's whitelist withholding the whole network IOC pattern set. It is
distinct from `SCAN_BUDGET_EXHAUSTED`, which specifically names a shared
`ScanBudget` limit: every reason here is a bound the scan imposed on its own
search, not a resource that ran out.

The per-region quotas matter here in a way they do not full-scope. Full scope
never hands one region more than the per-target cap (8 MiB for pipe), so a
50-match or 5-record quota is rarely reached; targeted mode hands a single
synthetic region up to the request ceiling, so a rescan of exactly the
oversized region this feature exists for is where they start dropping
occurrences. Each is recorded at the site that dropped one -- never inferred
from a final count -- so a range whose quota was reached but that lost nothing
stays `complete`.
All other failure and budget conditions reuse current codes. The two registries
must stay complete and fail closed; no new code is a diagnostic-only value.

Targeted mode names exactly one hunter. Obfuscation closure order is always
`sleep_mask`, `entropy`, `decode`; evidence, limitations, and diagnostics keep
their existing deterministic ordering.

Argument-shape and range failures use `parser.error()` and exit 2. Unknown,
`all`, and known-but-unsupported hunter capability failures use the established
user-facing Hunt error path and exit 1. A successfully executed targeted command
uses the existing `exit_code_for(coverage.status)` mapping: complete 0, partial
3, not evaluated 4. Detection status does not introduce another exit mapping.

## Compatibility invariants

- `--hunt-addr` landed atomically with its range, capability, executor, CLI,
  record, and schema support, in schema v2.14. Applicability, retained
  measurements, and windowed targeted entropy are same-version additions to
  those still-unreleased shapes.
- v2.13 and older schemas remain frozen.
- Current `--hunt <identity>` and `--hunt all` retain their selection,
  detection, scoring, ordering, console/JSON shape, diagnostics, and exit codes.
- Full-scope details omit `targeted_scope`; existing golden fixtures are not
  regenerated for this feature.
- Targeted execution reuses the same report/evidence architecture and the same
  built-in registry boundary; it does not dynamically inject analyzers.
