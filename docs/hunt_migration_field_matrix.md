# `--hunt` v2 migration — PR1 field matrix & frozen fixtures

**Status: migration complete.** `--hunt` shipped onto the v2.4 envelope in
PR4 — all eleven commands, including `--hunt`, now produce
`dumpex-output-v2.4.schema.json` (see docs/OUTPUT_SCHEMA.md's "One JSON
contract" section), and no command produces the v1.1 contract anymore.
This document is kept as a **historical audit trail**, not a live
reference: it records the pre-migration (v1.1) field inventory frozen
before PR2's work started, and is what each PR2/PR2b/PR4 change was
checked against as it landed. The "Confirmed cross-cutting findings for
PR2+" section at the bottom has been updated in place, after the fact,
where a finding's original prediction turned out to need correction (see
its own "Update" notes) — but the field-by-field inventory above it is
intentionally left as originally frozen, not rewritten to describe the
final shape; read dumpex/output/records.py and
dumpex-output-v2.4.schema.json for that.

Frozen against commit `5c2ef8e87dc17b8eda9f9fe3e2c3af2c6438f7f2` (main), before
any output-shape change. This is an **inventory document**: it records what
each hunter emitted *at that point* (v1.1 JSON via `dumpex/ui/structured.py`,
plain-dict console via `dumpex/hunt/__init__.py`/`presentation.py`),
classified by where each field was expected to land in the v2.4
`HunterRecord` contract. It was the reference PR2+ migration work was
checked against — a field that disappeared without a line in this doc, or a
"hunter-specific detail" that got flattened into the JSON shape instead of
moving into `details`, would have been a regression.

**Revision note**: an earlier version of this PR captured fixtures by
running the CLI against the two real dumps in `tests/corpus/evil/samples/`
and committed the resulting console/JSON/CSV output under `tests/golden/
hunt_v1_1/`. That was wrong and has been removed: `tests/corpus/evil/
samples/` is `.gitignore`d specifically because it is local-only private
corpus material (real process memory strings, real host paths, real file
hashes), and output derived from it must never be committed — confirmed by
inspecting the deleted fixtures' own `meta.evidence` block, which embedded
this machine's real absolute path and a real sample's sha256. Every field
list and every frozen assertion below now comes from either direct source
reading (cited by file/line) or a fully synthetic, checked-in fixture built
from `tests/fixtures/fakes.py` (no real dump, no real memory content) — see
[tests/fixtures/hunt_cases.py](../tests/fixtures/hunt_cases.py) and
[tests/integration/test_hunt_compat_freeze.py](../tests/integration/test_hunt_compat_freeze.py),
which is a real, CI-executed pytest module, not an inert reference file: it
fails the moment a later PR changes a judgment field or console verdict
without updating the corresponding assertion.

## Field classification legend

- **judgment** — one of the 7 common per-hunter judgment fields every
  `HunterRecord` will carry: `score`/`max_score`/`status`/`verdict_level`/
  `confidence`/`lead_count`/`review_priority`. `coverage_status` is
  deliberately NOT in this list — see **coverage** below.
- **finding** — an entry already on the shared `Finding` model
  (`check`/`facts`/`inference`/`confidence`/`rationale`/`limitations`/`tag`)
  → `HunterRecord.findings`. **yara is the one exception**: it has no
  `Finding` list today and none should be synthesized for it — its
  `findings` stays `[]` and its `matches`/`rules_hit` stay in `YaraDetails`
  (typed, but NOT `Finding`-shaped). Do not reclassify yara's `matches` as
  `finding` — that would silently change detection semantics (a YARA rule
  hit is a structural pattern match, not a `check`/`facts`/`inference`/
  `confidence`/`rationale` judgment, and forcing it into that shape would
  require inventing a rationale/confidence the hunter never actually
  computed).
- **detail** — hunter-specific raw evidence with no cross-hunter shape →
  destined for that hunter's typed `*Details` object.
- **coverage** — free-text coverage bookkeeping → destined for the
  structured `CoverageReport` (`sources`/`limitations`), not a hand-rolled
  bool/string. `coverage_status` (a bare string) and `coverage` (a dict of
  per-source booleans, where present) both fall here — **both are
  migration SOURCES, not migration TARGETS**: v2.4 must expose exactly one
  fact, `HunterRecord.coverage.status`, not carry `coverage_status` forward
  as a second field alongside it. PR2's `HunterRecord` schema/dataclass
  must not accidentally keep both (see "Confirmed cross-cutting findings"
  below).
- **provenance/meta** — not part of `result.data.records` at all (rules
  provenance, YARA provenance) → `meta.rules`/`meta.yara_rules`.

## injection

Fields today (`dumpex/hunt/injection/aggregate.py:389-414`): `confidence,
coverage, coverage_reasons, coverage_status, findings,
hidden_pe_unvalidated, hidden_pe_validated, informational_validated_pe_hits,
lead_count, max_score, pe_read_failed, pe_short_reads, review_priority,
rip_full_correlation, rip_hits, rwx, rwx_and_pe_alloc_bases, score,
start_hits, status, suspicious_validated_pe_hits, thread_contexts, threads,
verdict_level`. Frozen scenarios:
`tests/fixtures/hunt_cases.py::injection_detected_full_correlation` (score 3)
and `::injection_inconclusive_no_thread_context`.

| field | class | notes |
|---|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment | unchanged semantics; verdict table `{1:possible,2:likely,3:high}` (`injection/aggregate.py:25`) not touched |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend; `HunterRecord.coverage.status` is the one place this fact lives in v2.4 |
| findings | finding | already `Finding.to_dict()` list — direct `HunterRecord.findings` |
| coverage (dict: memory_info_stream/thread_info_stream/module_list_stream/thread_list_stream/thread_context/threads_total/contexts_parsed/contexts_missing) | coverage | source booleans → `SourceObservation`s; `contexts_missing`/`threads_total` → a new limitation code (context unavailable/partial) |
| coverage_reasons | coverage | free text → must be **rendered from** limitations built at the gap site, never parsed back |
| rwx, hidden_pe_validated, hidden_pe_unvalidated, suspicious_validated_pe_hits, informational_validated_pe_hits, threads, thread_contexts, rwx_and_pe_alloc_bases, rip_hits, rip_full_correlation, start_hits | detail | **confirmed by the frozen test, not assumed**: these are raw `Region`/`ThreadInfo` objects with NO conversion at all before reaching `findings` — `dumpex.ui.structured._json_safe()`'s catch-all is a bare `str(obj)` (see that function's own docstring: "everything else → str(obj)"), which for these fields today produces `"<...MinidumpMemoryInfo object at 0x...>"` — the CPython interpreter's own live heap address, embedded in the JSON, different on every single run. This is worse than "needs a hex-string conversion" — it is a **non-reproducible, effectively meaningless string** in the CURRENT system; `test_injection_detected_full_correlation` pins the SHAPE of this defect via regex specifically so PR2 replacing it with a typed, deterministic `InjectionDetails` conversion is a visible, intentional diff, not a silent behavior change nobody notices. |
| pe_read_failed, pe_short_reads | coverage | counts, not evidence → limitation `affected_count` |

## hollowing

Fields today (`dumpex/hunt/hollowing.py:301-308`): `confidence,
coverage_reasons, coverage_status, findings, lead_count, max_score,
review_priority, score, status, verdict_level` — **confirmed: no raw-detail
fields at all** in the current JSON. Read `hollowing.py` in full (331
lines): the four checks' facts (image base VA/file-offset, memory type at
image base, MZ-header bytes, RWX protection, PEB-vs-module-list name
compare) exist only as `print()` calls and locals (`mem_private`, `mz_wiped`,
`is_rwx`, `name_mismatch`, `base_region`) that never reach the `findings`
dict — today's JSON consumer gets `findings[]` text but none of the
structured facts backing it. `HollowingDetails` is therefore new
JSON-surface, not a pure container move, for this one hunter — worth an
explicit call-out in PR2's own description since "add a details object"
here means promoting console-only facts to the wire, not just relocating
existing ones. Frozen scenarios:
`::hollowing_detected_mem_private_and_rwx` (score 1),
`::hollowing_not_evaluated`.

| field | class |
|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment |
| findings | finding |
| coverage_status, coverage_reasons | coverage | migration SOURCE, not a field to carry forward — see legend |

## stomping

Fields today (`dumpex/hunt/stomping/aggregate.py:50, 342-344`): `confidence,
coverage_counts, coverage_reasons, coverage_status, findings, lead_count,
max_score, protection_leads, review_priority, score, status, verdict_level,
verified_changes`. Frozen scenarios:
`::stomping_detected_tampered_content` (score 1),
`::stomping_clean_matching_reference`, `::stomping_inconclusive_no_ref_dir`.

| field | class | notes |
|---|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment | verdict table `{1:possible,2:high}` — deliberately no "likely" tier (`stomping/aggregate.py:24-30`) |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend |
| findings | finding | |
| protection_leads, verified_changes | detail | `verified_changes[*]` already a flat dict (`module/section/va_start/diff_ranges/ranges_truncated/total_ranges/compared_len/rip_in_changed_range/disk_sha256/mem_sha256`) — closest of the 7 hunters to `StompingDetails`' final shape already; `va_start` is a plain int today and needs hex-string conversion, same defect class as injection's raw objects (just a different manifestation — an int instead of a `str(obj)` repr) |
| coverage_counts (dict: sections_total/sections_compared/reference_missing/reference_mismatch/reference_read_failed/memory_read_failed/short_reads/relocation_failed/headers_parsed) | coverage | maps directly to the user's requested limitation codes: reference not supplied/missing/mismatched/read failed |
| coverage_reasons | coverage | includes the `ref_dir is None` case ("--ref-dir not supplied") — becomes its own limitation code, not folded into generic SOURCE_ABSENT |

## pipe

Fields today (`dumpex/hunt/pipe/aggregate.py:43-50, 285-293`):
`budget_exhausted, c2_context, confidence, coverage_reasons,
coverage_status, findings, framework_pipes, handle_pipes, lead_count,
max_score, private_pipes, review_priority, scan_complete, score, status,
unbacked_in_rgn, verdict_level`. Frozen scenario:
`::pipe_detected_full_corroboration` (score 3).

| field | class | notes |
|---|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment | verdict table `{1:possible,2:likely,3:high}` |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend |
| findings | finding | |
| handle_pipes, private_pipes, c2_context, framework_pipes, unbacked_in_rgn | detail | → `PipeDetails`; `handle_pipes`/`framework_pipes` embed raw `HANDLE` records (`Handle`/`ObjectName`/`GrantedAccess`) with the SAME raw-object/`str(obj)` defect as injection's fields above (not independently verified by a frozen assertion in PR1 — flagged as a follow-up check for PR2, not assumed identical without confirming) |
| budget_exhausted, scan_complete | coverage | booleans → fold into `CoverageReport`/limitation `scan budget exhausted` |
| coverage_reasons | coverage | |

## cs-beacon

Fields today (`dumpex/hunt/cs_beacon/aggregate.py`, confirmed via
`::cs_beacon_detected`): `confidence, config_count, configs, coverage,
coverage_reasons, coverage_status, findings, lead_count, max_score,
review_priority, score, status, verdict_level`.

| field | class | notes |
|---|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment | verdict table `{1:likely,2:high}` |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend |
| findings | finding | |
| config_count | judgment-adjacent | derived count, currently duplicated into the console summary suffix (`dumpex/hunt/__init__.py:150-151`) — keep as a `CsBeaconDetails` field, not a top-level `HunterRecord` field |
| configs | detail | → `CsBeaconDetails.configs`; **confirmed by the frozen test**: `va`/`file_offset` are plain **JSON integers** even after the dispatcher's own sanitization pass, not the fixed-16-hex-string format the v2.4 contract requires — a real shape change, not just a container move. `fields{}`'s int-key→str-key + bytes→hex conversion IS already correct today, but only at the **dispatcher** layer (`dumpex/hunt/__init__.py:59-81`), not inside `_hunt_cs_beacon()` itself — `CsBeaconDetails.__post_init__`/`to_dict()` absorbs that same logic independently for the v2.4 `HunterRecord` path. **Update**: the dispatcher's own hand-rolled sanitization was NOT deleted — `cmd_hunt()`'s bare-dict `results` path (used for console rendering and by other, non-v2 callers) still runs it unchanged; only the separate `_record_from_cs_beacon_report()`/`CsBeaconDetails` path that feeds `--hunt`'s v2.4 JSON/CSV output needed its own, independent conversion. |
| coverage (dict) | coverage | |
| coverage_reasons | coverage | |

## yara — the outlier

Fields today, via the dispatcher (`::yara_not_evaluated`, `::yara_detected`):
`coverage, coverage_status, matches, rules_hit, scan_complete, score,
status, verdict_level` (no `findings`/`confidence`/`lead_count`/
`review_priority`/`max_score` — **confirmed absent** by
`test_yara_not_evaluated`/`test_yara_detected` asserting each key's absence
directly, matching the user's explicit "YARA allowed null" rule).
NOT_EVALUATED shape: just `{matches: [], score: 0, status, coverage_status,
verdict_level}`.

| field | class | notes |
|---|---|---|
| score, status, verdict_level | judgment | present; `max_score`/`confidence`/`lead_count`/`review_priority` **absent** → `HunterRecord` must allow these `null` only for `hunter == "yara"` (schema `if/then`) |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend; **also note yara's key set genuinely differs between NOT_EVALUATED (5 keys) and DETECTED/other (8 keys)** — confirmed by `test_yara_not_evaluated`/`test_yara_detected` each asserting their own distinct key set, unlike every other hunter whose key set is stable across states |
| matches, rules_hit | detail (NOT finding — see legend) | `matches[*].strings[*].data` is dispatcher-sanitized bytes→hex today (`dumpex/hunt/__init__.py:83-88`) — moves into `YaraDetails.to_dict()`, staying its own typed shape rather than being forced onto the `Finding` model |
| coverage (dict: rule_files_compiled/segments_read/segments_short_read/segments_size_ok/matches_completed/hit_cap_not_reached/scan_budget_ok) | coverage | maps directly to requested limitation codes: scan read failed/short read/oversized region skipped/scan budget exhausted/hit cap reached/YARA compile failed all present as booleans already |
| scan_complete | coverage | |
| — (provenance) | provenance/meta | rule file identity/sha256 surfaced only in top-level `meta.yara_rules` (`dumpex/ui/structured.py:227-265`, `dumpex.hunt.yara_hunt.get_yara_provenance()`) at the time this doc was frozen — **since ported** to v2 `envelope.py:build_meta_v2()`'s own `_yara_rules_meta()` helper, so `--hunt`'s v2.4 `meta.yara_rules` carries the same provenance |

## obfuscation

Fields today (`dumpex/hunt/encoding/aggregate.py:123-132, 456-468`):
`base64, budget_exhausted, compressed, confidence, coverage_reasons,
coverage_status, entropy, findings, hidden_pe, hidden_shellcode,
lead_count, max_score, review_priority, score, sleep_mask, status,
verdict_level, xor`. Frozen scenario:
`::obfuscation_detected_validated_pe` (score 1).

| field | class | notes |
|---|---|---|
| score, max_score, status, verdict_level, confidence, lead_count, review_priority | judgment | verdict table `{1:likely,2:high}` |
| coverage_status | coverage | migration SOURCE, not a field to carry forward — see legend |
| findings | finding | |
| sleep_mask, entropy, base64, xor, compressed, hidden_pe, hidden_shellcode | detail | converted via `Hit.to_dict()`/`EntropyHit.to_dict()` (`encoding/models.py`) — region is described BY VALUE (`BaseAddress`/`RegionSize`/... as a plain dict), avoiding `str(obj)` on a raw `Region`, but `State`/`Protect`/`Type` are deliberately left as enum-like objects for `_json_safe()` to reduce to `.name` at serialization time (confirmed: `json.dumps()` on this hunter's raw `findings` dict fails without `_json_safe()` first — it is NOT fully self-sanitizing, only partially, unlike an earlier draft of this doc claimed) → `ObfuscationDetails` should absorb both steps (the by-value region conversion AND the enum→name reduction) so it needs no `_json_safe()` pass at all afterward |
| budget_exhausted | coverage | |
| coverage_reasons | coverage | |

## Confirmed cross-cutting findings for PR2+

1. **`dumpex.ui.structured._json_safe`'s fallback for an unrecognized object
   is `str(obj)` — not an attribute walk, not hex formatting.** For
   injection's `rwx`/`threads`/`rip_hits`/etc. (raw `Region`/`ThreadInfo`
   objects with no `Finding`-style conversion), this means today's JSON
   output embeds the Python interpreter's own live heap address
   (`"<...MinidumpMemoryInfo object at 0x0000020AC1D769D0>"`), which is
   different on every single run — not merely "not yet hex-formatted", but
   actively non-reproducible garbage today. **`pipe`'s raw `Handle`/
   `Region`/`ThreadInfo` records (`handle_pipes`/`private_pipes`/
   `c2_context`/`unbacked_in_rgn`) confirmed to have the same defect** by
   `test_pipe_detected_full_corroboration` in the compat-freeze suite.
   `obfuscation` avoids it via `Hit.to_dict()`'s
   by-value region conversion (still needs `_json_safe()` once more for the
   enum fields, see obfuscation's notes) and `cs-beacon` avoids it via the
   dispatcher's hand-rolled sanitization. PR2 needs an explicit, per-hunter,
   typed conversion for every raw-object field — never assume "the JSON
   already looks fine" without checking, and never simply relocate the
   existing (broken) value into `details`.
2. **`coverage_status` (a bare string) and, where present, `coverage` (a
   dict of booleans/counts) are today's two per-hunter migration SOURCES,
   not two fields to carry forward.** v2.4's `HunterRecord.coverage` is a
   single structured `CoverageReport` built FROM these — PR2 must not ship
   a `HunterRecord` that has both a `coverage_status` string field and a
   `coverage.status` field saying the same thing twice (a two-sources-of-
   truth regression `dumpex/output/coverage.py`'s own module docstring
   explicitly says this migration exists to avoid for every other command).
3. **`--hunt all` had no coverage-based process exit code, as of this
   doc's frozen baseline.**
   `tests/integration/test_hunt_cli_compat_freeze.py::
   test_hunt_all_all_not_evaluated` runs a real `cli.main()` end to end
   with every hunter NOT_EVALUATED and confirms `exit_code == 0` at that
   baseline — `dumpex/cli.py`'s `args.hunt` branch never called
   `exit_code_for()` the way the other ten migrated commands did. **This
   has since shipped**: `--hunt` is now in `_V2_STRUCTURED_MODES`, its
   `args.hunt` branch builds a `CommandResult` and runs it through
   `_apply_command_result()`/`exit_code_for()` like every other v2-routed
   command, and the exit code is coverage-based (`0`/`3`/`4`) instead of
   an unconditional `0` — the release-notes callout this finding asked
   for.
4. **States frozen**: per-hunter judgment/detail dicts, all synthetic, in
   `tests/integration/test_hunt_compat_freeze.py` (13 scenarios, each
   asserting its FULL key set via `assert set(f) == {...}`, not just a
   handful of fields) plus the CLI-layer JSON/CSV/exit-code/full-console
   envelope in `tests/integration/test_hunt_cli_compat_freeze.py` (2
   scenarios: a single `--hunt injection` DETECTED run with byte-exact
   frozen console text, and `--hunt all` all-NOT_EVALUATED with structural
   assertions only — see that file's own docstring for why `--hunt all`
   can't get a byte-exact console freeze: it always attempts to load
   YARA's packaged rules directory and prints that directory's own
   absolute host path). Hunter-level states covered: DETECTED for all 7
   hunters (injection score 3, hollowing score 1, stomping score 1, pipe
   score 3, cs-beacon score 2, yara score 1, obfuscation score 1);
   INCONCLUSIVE for injection/stomping; NOT_EVALUATED for hollowing/yara;
   NOT_DETECTED_IN_SCANNED_SCOPE/clean-complete for stomping; and a
   dispatcher-level "all NOT_EVALUATED, exactly 7 entries, fixed key order"
   sanity check. **Not yet covered**: the full 7×5 hunter×state cross
   product (e.g. pipe/cs-beacon/obfuscation each only have a DETECTED
   scenario frozen so far, no INCONCLUSIVE/NOT_EVALUATED/clean variant) —
   `tests/fixtures/hunt_cases.py` is the place to add more scenarios if
   PR2 needs finer-grained coverage before it starts; this doc flags the
   gap rather than fabricating fixtures to look more complete than they are.
