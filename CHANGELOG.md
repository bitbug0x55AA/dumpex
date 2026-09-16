# Changelog

User-facing changes are grouped by dumpex release. Internal refactors, test-only
changes, and field-by-field design rationale are intentionally omitted.

For the current JSON contract, see
[Output and Evidence Schema](docs/user/OUTPUT_SCHEMA.md). For compatibility history,
see [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md).

## 3.8.1 — Unreleased

### Fixed

- The console/`--txt` static-analysis lead now recognizes an in-place memory
  transform written across a register rather than only one that a single
  arithmetic instruction performs on memory. A load, a non-identity transform
  of the loaded value, and a store back to the same proven effective address
  are read as one transform loop, so the common `mov`-load / `xor` / `mov`-store
  shape is no longer invisible. An ordinary copy loop, a store to a different
  address, a value clobbered or replaced before the store, and an address whose
  base or index register changed in between are all still reported as nothing.
- A loop closed by an unconditional backward jump is no longer treated as
  falling through to whatever bytes follow it. The edge that leaves such a loop
  is a conditional branch inside the loop body, and a register-indirect
  `call`/`jmp` now counts as supporting context only when it is actually
  reachable from an edge that leaves the loop.
- A `call`/`pop` sequence elsewhere in the same decode window no longer
  contributes to the stronger `self_decoding_stub` lead unless the popped value
  is followed to the very address register the proven transform uses. A
  register that only supplied an address to a load (`add rcx, qword ptr [rbp]`
  takes the data at the code's own address, not the address) no longer carries
  that address onward, and a `call` between the `pop` and the loop now ends the
  carry — a callee's register writes are not in the decoded window.
- A loop whose entry nothing in the decoded window reaches no longer produces a
  lead. Zero padding and data tables decode to instructions like any other
  bytes, and a backward branch decoded from data could previously close a
  "loop" around bytes no execution arrives at.
- A loop that writes back exactly what it read is reported as nothing in every
  spelling: the `or reg, reg` / `and reg, reg` flag-test idioms and `sbb reg,
  reg` join the already-rejected `xor reg, reg`. The one-instruction form now
  gets the same identity check as the three-instruction one, so `add dword ptr
  [rax], 0` is no longer a transform and `and dword ptr [rax], 0` — a scrub —
  is no longer named as one.
- A `push`, `int3`, `int n` or `int1` between a load and its store now ends the
  analysis like any other memory write — each pushes a stack frame it names no
  operand for — and a `call` out of a loop body is no longer treated as an exit
  from it, since control returns below the call.
- A transform-loop shape that is found and then declined is now reported as
  such on the console and in `--txt`, instead of reading as a window that had no
  shape in it. Two declines qualify, both because the instruction rows do not
  reveal them: the loop lies in bytes no decoded branch reaches from the anchor
  (a thread start that is a jump thunk, a `--report-addr` landing on a `ret` or
  inside an instruction, a card anchored in data), or the load, transform and
  same-address store are all present and the value between them could not be
  proven to survive. A decline the rows do show — a copy loop, a store at a
  different address — stays silent. Neither note names an address, neither is a
  lead, neither changes any status, and like the leads themselves neither
  reaches `--json`.
- A run of zero bytes no longer reads as a transform loop. Zero padding decodes
  to `add byte ptr [rax], al`, a read-modify-write whose source is part of its
  own address; writing an address into the bytes at that address is not a
  transform, and is now rejected.
- `pause`, `lfence`, `mfence` and `sfence` in a loop body no longer withhold a
  lead: each is provably inert for this analysis.
- A backward direct `call` is no longer read as a loop-closing branch. capstone
  reports a relative `call` in its jump group as well as its call group; a
  backward one is recursion, not a loop, and recursion around a memory write no
  longer produces a transform-loop lead.
- A `call`/`pop` pair whose `call` nothing in the window reaches — a `jmp` over
  the `call`, straight onto the `pop` — no longer promotes a lead to
  `self_decoding_stub`. A get-PC value reaching the address's *index* register
  (`[rax + rbp]`) now correlates as one reaching its base always did.
- Any instruction that cannot be shown not to write memory now ends the
  analysis between a load and its store, since such a write may land on the
  address under analysis. The decoder answers that question in one place, and
  it does not trust a memory operand's reported direction: capstone describes
  the operands of `movnti`, `stmxcsr` and `cmpxchg16b` as read-only, and each
  of them writes. Instructions that write memory while naming no operand at
  all — a stack push, `maskmov*`, `clzero` — are covered by name, and a string
  instruction's implied destination (`insb` through `[rdi]`) by its operand.
  A read the decoder can place — a `mov`/`movzx`/`movsx` load into a register,
  or a `lea`, which never dereferences at all — is exempt, so a loop that reads
  its key from a table mid-body is still recognised. A read in any other form
  is treated as a possible write and under-reported rather than asserted.
- A `call`/`pop` pair whose widths disagree no longer promotes a lead. `pop bp`
  after a 64-bit `call` recovers sixteen bits of a sixty-four-bit return
  address, and a 32-bit `callw` pushes two bytes a `pop eax` cannot have come
  from; the pushed width, the popped width, and the architecture's address
  width now have to be one number.
- A write to the segment register an address resolves through — named, as in
  `fs:[eax]`, or implied, as the DS of a 32-bit `[eax]` and the SS of `[ebp]` —
  now ends the analysis between a load and its store. Two operands with
  identical text either side of one are two addresses.
- Anything that hands control to code outside the decode window now ends both
  the value flow and the address carry, as an ordinary `call` already did: an
  `int`, `int3` or `syscall` into a handler or the kernel, a `vmcall`,
  `vmmcall`, `vmlaunch`, `vmresume`, `vmfunc` or `vmrun` into a hypervisor,
  `getsec`, and `enclu`, whose enclave-entry and enclave-exit forms are
  selected by a register. Most of these continue at the next instruction and
  report no register or memory effect at all, so nothing else in the decode
  said that other code had run.
- An instruction whose decoded effects contradict the architecture now ends the
  analysis too. `enter` overwrites the frame and stack pointers, a
  segment-register `push`/`pop` moves the stack pointer, and `aam`/`aad` change
  the accumulator, while the decoder reports none of it; a report short in one
  place is no longer relied on in another. This is a consistency check rather
  than a list of instructions to distrust, so an ordinary `push rbp` — which
  the decoder does account for — still carries an address through.
- The all-register push no longer slips past the memory-write rule. It is
  spelled `pushal`/`pushaw`, never `pusha`, so a rule written against the
  spelling matched neither and let eight stack writes through; these sets are
  now keyed on instruction identity instead of on disassembler text.
- An instruction the decoder reports nothing about now ends the analysis
  instead of being treated as harmless. Reporting nothing is not the same as
  doing nothing: `aaa` and `das` change AL, `xlatb` reads memory and writes AL,
  `rdpkru` writes two registers, and the SGX and virtualisation leaf
  instructions (`encls`, `enclv`, `pconfig`) pick what they do — including
  writing memory through a register — from a value this analysis does not
  track. Only instructions positively known to be inert are now carried
  through, so an unrecognised one costs a lead rather than the truth of one.
- A loop whose transforms cancel (`xor` twice, `not` twice, `add 1` then
  `sub 1`) writes back exactly what it read and is no longer reported as a
  transform. Only one transform is proven per loop, so a genuine composite
  transform is now under-reported rather than asserted.
- The rule that a get-PC value must arrive as *one whole copy* of the code's
  own address is now applied to the memory operand the loop actually touches,
  not only to the instructions that led to it. `[rax + rbp*4]` is four times
  where the code sits and `[rbp + rcx]` after `mov rcx, rbp` is twice it;
  neither names a location inside the code, so neither promotes a lead to
  `self_decoding_stub`. An unscaled `[rax + rbp]`, and a scaled index that
  carries nothing (`[rbp + rax*4]`), are unaffected.
- A get-PC address truncated on its way to the access no longer promotes a
  lead. `[ebp]` under a 64-bit address-size override resolves through the low
  half of the popped return address, `[bp]` in 32-bit code through the low
  quarter, and `lea rcx, [ebp]` computes from the same truncated half — none of
  them is the address the `pop` recovered, though the register family is the
  same in each case.
- An operation that changes nothing no longer ends the value flow. `or reg,
  reg`, `and reg, reg`, `add reg, 0`, `and reg, -1` and a zero shift count write
  back the bytes they read, so a transform below one of them transforms the
  value that was *loaded*, and the loop is recognized. Such an operation is
  still not itself the transform, so a loop containing only these is still a
  copy loop and still reported as nothing; operations that replace the value
  with a constant (`and reg, 0`, `or reg, -1`, `xor reg, reg`) still end the
  flow.
- `adc` and `sbb` against zero or against all-ones are no longer read as
  transforms. Both read the carry flag — `adc x, i` is `x + i + CF` and
  `sbb x, i` is `x - i - CF` — so either writes back exactly what it read
  whenever `i + CF` is zero at the operand's width, which the carry being zero
  or one makes those two immediates and no others. A loop spelled `stc` /
  `adc edx, -1`, or `stc` / `adc edx, 0` / `sub edx, 1`, could previously be
  reported as a transform loop that in fact changed nothing, and a `call`/`pop`
  above it could raise that to `self_decoding_stub`. Both spellings are covered
  at every operand width, in the register-mediated and the single-instruction
  form alike. `adc reg, 5`, `adc reg, -2` and `adc reg, reg` are unaffected:
  none is the identity under either value of the flag.
- A withheld-shape note is no longer produced when one copy of the loaded value
  is transformed and a *different* copy — one the instruction rows show being
  overwritten — is what the store reads. The relaxation the note rests on is
  now decided for each tracked value separately, so a transformed register no
  longer keeps its untransformed siblings alive.
- A segment-base write now ends the address proof only for addresses that
  resolve through the segment it moves. `wrfsbase` relocates every FS-relative
  address and leaves a `gs:` access — or a plain `[rbp]` in 64-bit code — where
  it was; `wrgsbase` and `swapgs` move GS alone. `wrmsr` still gives up both,
  because the MSR it writes is selected at run time.
- A withheld-shape note is no longer produced for a value the instruction rows
  show being discarded. `mov edx, [rbp]` followed by `mov edx, eax` and then a
  transform transforms what replaced the loaded value, which is a clean
  negative rather than a proof that was declined for an invisible reason. The
  note's survival relaxation now begins at the first transform rather than at
  the load.
- A load into a register its own address expression uses (`mov eax, dword ptr
  [rax]`, `mov ecx, dword ptr [rax + rcx*4]`) no longer anchors a transform
  loop. The load consumes the register version it destroys, so a later store
  with identical text reaches a different address.
- Two registers that provably hold one value are now treated as one.
  `mov ecx, edx` followed by `xor edx, ecx` leaves zero exactly as
  `xor edx, edx` does, and `sub`, `and`, `or` and `sbb` in the same shape are
  likewise no longer read as transforms of what was loaded.
- A conditional branch between a load and its store now ends the analysis. Its
  taken edge can carry the untransformed value straight to the store, so the
  store has more than one reaching definition and the value that arrives is not
  the one the proof would name.
- A code address that cancels against itself is no longer followed as one.
  `sub rcx, rbp` after `mov rcx, rbp` leaves zero and after
  `lea rcx, [rbp + 0x20]` leaves the constant `0x20`; neither names a location
  in the code, so a transform through such a register is no longer promoted to
  `self_decoding_stub`.
- The `register_transfer_after_loop` signal no longer fires on a transfer
  inside the loop. An exit edge that leaves the loop's address span and falls
  straight back into the body has not left the loop, and the reachability walk
  now stops when it re-enters.
- The withheld-shape note no longer fires on a plain copy loop that happens to
  sit beside unrelated arithmetic, or whose store writes a register the loaded
  value never reached. A transform has to have been attempted on the loaded
  value for the analysis to say it declined to prove one.
- A lead's verbose evidence now names the instructions that carried the proof's
  values as well as its endpoints: the copy that moved a transformed value to
  the store's source register, the `mov`/`lea`/`add` that moved a `call`/`pop`
  address to the loop's address register, and the branches on the path from the
  loop's exit to a register-indirect transfer. When a proof names more
  instructions than the evidence cap holds, the printed list is now marked as a
  cut one.
- An address whose base, index, scale, displacement or segment the decoder
  named and could not resolve is no longer compared as though those parts were
  known. Such an operand now matches no other operand, itself included, instead
  of a defaulted component reading as a real `[base + 0]`.
- A code address that arrives multiplied is no longer followed as one.
  `add rbp, rbp`, `lea rbp, [rbp + rbp]` and `lea rbp, [rbp*2|4|8]` each leave a
  multiple of where the code sits rather than a place in it, as does an `lea`
  whose base and index both carry the same `call`/`pop` value. The carried
  address must now arrive with a coefficient of exactly one, counted over all of
  an instruction's inputs including an index register's scale, so these shapes
  keep the base `memory_transform_loop` name and are no longer promoted to
  `self_decoding_stub`.
- The withheld-shape note no longer fires on a loop whose own instructions say
  the result stopped deriving from what was read. `xor edx, edx`, `add edx, 0`,
  `and edx, 0`, `and edx, -1`, a shift by zero, an operation between two
  registers a `mov` made equal, and a transform of one copy when a different
  copy is what reaches memory are each a negative the instruction rows show, not
  a shortfall of evidence. The note's non-identity rules are now the proof's own
  and the transform state is bound to the derived value rather than to the
  window.
- The withheld-shape note no longer calls two accesses a same-address candidate
  when the address version provably changed between them. A write to the base or
  index register at any width, a write to the segment selector the address
  resolves through (named, or the DS/SS a 32-bit address implies), and
  `wrfsbase`/`wrgsbase`/`swapgs`/`wrmsr`, which move a segment base without
  touching the selector, each end the candidate as they already ended the proof.

### Changed

- A lead's supporting instruction addresses now print once, beside the
  instruction rows they refer to, and only under `--verbose`; the assessment
  block carries the lead's sentence. Neither block repeats the other's half.

Leads remain investigative context: no finding, score, confidence, verdict,
indicator count, coverage status, exit code, public JSON/CSV field, or output
schema changes.

## 3.8.0 — 2026-09-10

### Changed

- Console and `--txt` reports now put the title, assessment, next step, and
  coverage summary first, followed by anchor context, key evidence,
  correlation, and background. Section names are no longer numbered.
- Default detail keeps high-priority evidence concise: it previews up to five
  IOC matches with network-pattern hits first, keeps routine notable and
  proximity-only strings for `--verbose`, coalesces overlapping network-hit
  byte windows, and avoids printing the same retained string in more than one
  section. Omission notices point to `--verbose` and JSON where applicable.
- Evidence gaps, retention limits, and provenance are presented consistently:
  routine complete counts are suppressed, detailed scope/provenance moves to a
  trailing verbose table, and multi-card reports merge genuinely identical
  causes while preserving region-specific gaps. Every collected section still
  names its evidence sources.
- Capstone is now a base dependency and is bundled with the official Windows
  executable, so every supported installation can decode report instruction
  windows. The empty `disasm` extra remains as a compatibility alias for older
  installation commands; a missing or unloadable decoder is reported as a
  broken installation or build.

### Added

- `--report` now correlates each triage-card anchor with its owning PE image,
  including main-image identity and structural consistency, anchor placement
  and memory protection, a bounded x86/x64 instruction window with resolved
  branch targets, and relevant IAT slots. Every section distinguishes missing,
  incomplete, completed-empty, and truncated evidence without changing report
  findings, verdicts, or exit status.
- The console and `--txt` assessment adds qualified static-analysis leads for
  possible in-place memory-transform loops and position-independent
  self-decoding stubs found in the decoded instruction window. Leads are
  investigative context only: they do not change JSON, findings, verdict,
  coverage, or exit status.
- `dumpex --self-check` verifies that the installed instruction decoder works
  for both x86 and x64 and returns a failing exit status with a safe diagnostic
  when the decoder is missing or cannot load.
- Published output schema v2.18 for the new report correlation fields. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the structured
  compatibility details.

### Fixed

- Instruction output now distinguishes a byte-cap stop from an undecodable or
  cut-short tail, reports where linear decoding ended, labels captured
  unregistered branch targets and register-indirect destinations accurately,
  and makes clear that the listing is byte-order analysis rather than an
  executed path.
- `--report-string` no longer prints process-wide and main-image PE context
  before the report's own title, and no longer hides a partial or
  not-evaluated coverage state behind an early "not found" or
  "all hits are in known system modules" return.
- Coverage summaries now include optional-enrichment gaps and completely
  untriaged hit regions, distinguish unavailable evidence from retention cuts,
  merge duplicate causes and shared multi-region gaps, bound repeated
  per-region variants, and state each untriaged-region or short-read fact only
  once. A completed negative such as a module declaring no import directory is
  no longer presented as an evidence gap.
- String-context preview limits are applied after deduplication, preventing a
  duplicate from hiding a unique retained entry. Routine notable strings and
  proximity-only background no longer crowd analyst-significant evidence at
  default detail; query and IOC matches remain visible.
- Anchor placement now shows declared-versus-live protection only when an
  owning PE section provides declared permissions; private and otherwise
  unmapped memory shows only its live protection.

## 3.7.1 — 2026-09-08

### Changed

- Default `--report` console output now summarizes routine enrichment, while
  `--verbose` expands all retained process and per-card context. `--txt` follows
  the requested detail level; structured records and analysis results are
  unchanged.

### Fixed

- Report output now distinguishes console previews from retention caps and
  marks truncated dump-derived values, so omitted or shortened evidence is not
  presented as complete.
- Report process summaries now state when captured module data cannot verify
  whether the process image base is registered.

## 3.7.0 — 2026-09-06

### Added

- `--report` now includes bounded process and session context plus per-card
  exception, allocation-neighborhood, correlated-handle, and nearby-string
  context. Each section distinguishes unavailable, incomplete, completed-empty,
  and truncated evidence without changing report findings or verdicts.
- `--report-string` now limits multi-card generation to 32 cards and a 256 MB
  cumulative card-read budget. Shared-region hits are consolidated, while hits
  left untriaged by the budget are counted explicitly and make the run partial.
- Published output schema v2.17 for the new report context and accounting fields.
  See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the structured
  compatibility details.

## 3.6.2 — 2026-09-05

### Fixed

- `--hunt all` no longer treats several scanners failing to read the same
  uncaptured memory range as corroborating evidence. Skipped-target actions now
  also prefer targets that can be investigated from the current dump over
  targets that require a new collection.
- `--hunt obfuscation --verbose` now shows bounded, terminal-safe previews of
  retained Base64 strings and their decoded content. Text is escaped for safe
  display, while binary and PE content is shown as hex with a SHA-256 when
  appropriate.
- Hunt console `Coverage` rows now distinguish completed byte scanning from
  missing contextual evidence, explain partial coverage without contradictory
  zero-gap wording, and wrap cleanly within the terminal width.

## 3.6.1 — 2026-09-03

### Added

- Coverage now says how much memory a partial hunt actually missed, not only
  that it was partial. Schema v2.15 adds `coverage.missed_bytes` to every result
  and hunter record, including the missed range count and whether the byte
  figure is exact, a lower bound, or unknown. The console reports the figure,
  and scan targets expose their examined and unexamined sizes.
- Schema v2.16 adds `eligible_bytes`, `unscanned_pass_bytes`, and
  `unscanned_fraction` to show the share of each hunter's scanning work that did
  not happen. The console reports the share alongside missed bytes without
  changing coverage status, verdicts, scores, confidence, or exit codes.

### Changed

- `--hunt pipe` now reports a truncated `HandleDataStream`. A dump whose
  descriptor array declares more handles than it delivers now carries a
  `HANDLE_STREAM_TRUNCATED` limitation with the dropped-descriptor count and
  reports partial coverage instead of silently omitting the missing tail.
- `--hunt pipe` now distinguishes a HandleDataStream that was never captured
  from one that was captured but could not be parsed. Parse failures now report
  the parser error as a failed source and prevent that stream's handles from
  being scored, matching `--handles`. See
  [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) for the consumer
  impact.

## 3.6.0 — 2026-09-02

### Added

- Added `--hunt-addr ADDR`, which rescans one virtual-address range with the
  selected hunter instead of the whole dump. It requires `--hunt <TTP>` and
  `--size SIZE`, supports `stomping`, `pipe`, `cs-beacon`, `yara`, and
  `obfuscation`, and reuses each hunter's own detection rules, scores, and
  coverage vocabulary. Only the selected scanner's per-region or per-segment
  size cap is bypassed; every other budget stays enforced. Conclusions apply to
  the requested range only.
- Targeted rescans distinguish a source that does not apply to the requested
  range (`not_applicable`) from one that could not evaluate it
  (`not_evaluated`). They also report per-source measurements and, with
  `--verbose`, the range's structural context.
- A targeted `obfuscation` rescan now measures entropy in bounded windows as
  well as over the whole range, reporting the highest-entropy sub-ranges and
  whether window coverage was exhaustive or sampled.
- The `--hunt all` skipped-target queue now prints the targeted rescan to run
  next for each capable hunter. Targets that require recollection or an
  unsupported hunter are labelled instead, and unsafe-to-render paths receive
  arguments rather than a misleading command line. `--redact-paths` also
  reduces paths in rendered commands to basenames.

### Changed

- `investigation_actions[].recommended_actions` now includes a
  `targeted_hunter_rescan` entry only when a hunter that skipped the target can
  actually run one over it, and only when this dump holds bytes to rescan; its
  `hunters` names that subset rather than every skipping hunter. `skipped_by`
  is unchanged and still names all of them. Schema v2.14 is unchanged: every
  archived document stays valid.
- `--size` now requires `--hunt-addr` when used with `--hunt`, and is rejected
  with a usage error otherwise. Hunt options that the selected targeted scanner
  does not use are also rejected instead of being silently ignored. `--size`
  is unchanged for `--extract` and `--strings`.
- Published schema v2.14. Every hunt summary now carries a `scan_scope` tag
  naming what the invocation covered, and targeted hunter details carry
  per-source applicability, measurements, and coverage in `targeted_scope`.
  Sources outside the targeted grant remain explicit, and schema validation
  rejects inconsistent full/targeted scope combinations. Schema v2.13 and older
  remain frozen.

### Fixed

- A targeted `pipe` rescan whose pipe-name budget ran out attributed that one
  exhaustion to both coverage closures. The gap is now reported once by its
  owning `pipe_name` closure while `c2_context` still reports partial coverage.
- Corrected the reported address of a UTF-16LE IOC token in module-stomping
  output. Matching, classification, and scoring are unchanged.

## 3.5.2 — 2026-08-27

### Changed

- Temporarily disabled `--triage-skipped` pending analyzer-aware recovery
  orchestration.
- Standardized empty memory reads as failed reads across all hunters.

### Fixed

- Made hunt coverage fail closed when eligible scan items are left unaccounted
  for, reporting `SCAN_ITEMS_UNACCOUNTED` instead of complete coverage.
- Preserved exact named-pipe rescan targets when scan budgets are exhausted.
- Prevented zero-length committed regions or captured segments from aborting
  hunt execution.
- Standardized virtual-address formatting across CS Beacon, obfuscation,
  hollowing, named-pipe, and module-stomping output. This may regenerate
  affected deterministic `Finding.id` values once after upgrading.

## 3.4.0 — 2026-08-23

### Added

- Added `--profile`, which reports the dump's stream inventory, memory-capture
  facts, and availability of six analysis capabilities without issuing a
  malicious/clean verdict.
- Added readable, object-type-aware access-right decoding to `--handles` while
  preserving the original `granted_access` integer in JSON.
- Added `--handles --verbose`; default output folds routine anonymous handles
  into exact per-type counts while keeping cross-process-relevant and unreadable
  rows visible.

### Changed

- Completed the breaking schema v2.13 cutover. `--process`, `--handles`, and
  `--profile` replace the retired `--pid`/`--peb` commands and result kinds.
- Improved verbose `--process` output with an explained IAT address pair,
  identity verification states, and safely escaped dump-derived text.

### Fixed

- Corrected dump-time extraction so `--sysinfo` no longer reports a fabricated
  1970 timestamp when time data cannot be recovered.

## 3.3.2 — 2026-08-17

### Added

- Added the first standalone `--handles` inventory over captured
  `HandleDataStream` descriptors.

### Security

- Escaped untrusted dump-derived strings in recon console renderers so captured
  text cannot forge terminal layout or dumpex labels.

## 3.3.1 — 2026-08-16

### Added

- Added consolidated `--process` identity and bounded IAT parsing.
- Moved captured environment context into `--sysinfo`.

### Fixed

- Constrained the supported `minidump` dependency range and hardened handle
  descriptor-size validation against upstream layout drift.

## 3.3.0 — 2026-08-13

### Changed

- Schema v2.11 records exact hidden-PE candidate addresses and file/region
  offsets after injection scanning expanded beyond region-base probes.
- Schema v2.12 preserves target identity, capture state, skip cause, and budget
  facts for read, short-read, and truncated hunter coverage gaps.

### Fixed

- Cobalt Strike verbose output now wraps complete binary TLV values instead of
  silently truncating them.
- Injection finding facts now render virtual addresses at a consistent width.
- Obfuscation, pipe, and cross-hunter investigation queues retain evidence and
  coverage identity correctly when budgets or partial captures intervene.

## 3.2.1 — 2026-08-09

### Added

- Added `--hunt all --triage-skipped`, an opt-in, budgeted deep-content pass
  over the skipped-target queue (schema v2.10).
- Added the metadata-only `result.summary.investigation_actions` queue for
  `--hunt all` (schema v2.9).

### Fixed

- Truncated SHA-256 values are now labelled as prefixes rather than complete
  hashes.
- Module stomping no longer reports a clean IOC scan when memory was unreadable
  or only partially scanned.

## 3.2.0 — 2026-08-08

### Added

- Coverage limitations now identify skipped memory regions/segments with
  structured `targets[]` entries (schema v2.8).

### Fixed

- Corrected obfuscation coverage counting when the same region is skipped by
  multiple scan layers.

## 3.1.3 — 2026-08-08

### Added

- Added console/`--txt` correlation of evidence from different hunters that
  resolves to the same memory region.

### Changed

- Removed `--csv`; JSON is the structured automation format and `--txt` is the
  human transcript.
- Cobalt Strike config output dropped redundant raw hex values (schema v2.6)
  and re-keyed fields by their names (schema v2.7).

## 3.1.2 — 2026-08-06

### Added

- Hunt findings gained deterministic IDs, derived severity, ATT&CK mappings,
  evidence references, IOC values, and rule provenance (schema v2.5).

### Changed

- Standardized normal/verbose hunt finding presentation across hunters.

## 3.1.1 — 2026-08-04

### Changed

- `--diff` now treats the positional dump as the target and the `--diff`
  argument as the baseline.
- CLI help is grouped by purpose; `--diff-scope` and `--strings-encoding` are
  the documented modifier names. Compatibility aliases remain available.

## 3.1.0 — 2026-08-04

### Changed

- Migrated `--hunt` to the shared v2 envelope (schema v2.4), completing one
  structured-output model across all commands available in that release.
- Migrated `--diff`, `--extract`, `--strings`, and `--report` to typed result
  records with structured coverage, diagnostics, and artifacts.

## 3.0.1 — 2026-07-31

### Fixed

- Corrected doubled CSV line endings on Windows in the then-supported CSV
  exporter.
- Failed evidence sources are no longer rendered as present.

## 3.0.0 — 2026-07-31

### Added

- Introduced the v2 structured-output envelope and first-class coverage,
  provenance, artifacts, and diagnostics for recon commands.

### Changed

- Standardized `complete`/`partial`/`not_evaluated` coverage and corresponding
  exit-code behavior across the migrated commands.

## 2.1.0 — 2026-07-29

### Changed

- Reduced false positives in YARA and injection scoring using clean-corpus
  validation.
- Split hunter implementations into focused modules without changing the public
  command names.

### Fixed

- Prevented duplicate YARA suppression output and improved optional-dependency
  test behavior.

## 2.0.0 — 2026-06-01

### Changed

- Improved console compatibility with older Windows Command Prompt and
  PowerShell terminals.

## Compatibility notes

- Current commands emit schema v2.17.
- Historical schema files remain packaged and frozen for archived evidence.
- Validate a document using its own `meta.schema_version`.
- See [Output Schema Migration](docs/user/OUTPUT_MIGRATION.md) before upgrading a
  parser across schema versions.
