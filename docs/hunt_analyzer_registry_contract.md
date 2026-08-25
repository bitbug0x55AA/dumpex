# Hunt analyzer-registry contract (issue #70)

**Status: frozen decision record — self-contained.**

Parent: #69 (analyzer registry and registry-driven hunt orchestration).
Blocked by: #44. Blocks #71 (immutable `AnalyzerSpec`/`AnalyzerRegistry`
implementation) and, transitively, #72 (routing `collect_hunt()`/
`cmd_hunt()` through the registry) and #73 (full-scope compatibility
freeze). This document **adds no production registry code** — it is the
matrix and the rule set #71 implements against and #72/#73 verify against,
exactly as `docs/recon_profile_contract.md` was for #43. Every fact below
is read off the current tree (`dumpex/output/records.py`,
`dumpex/hunt/__init__.py`, and each hunter package), not invented — where
a decision genuinely belongs to a later issue (#59/#60's targeted-scan
primitives, #61's request/context/observation types), this document says
so explicitly instead of guessing at their shape.

---

## Table of contents

- §0 Scope, non-goals, and dependency order
- §1 Vocabulary
- §2 Public identity and fixed order: `HUNTERS` vs `AnalyzerRegistry`
- §3 The seven-row analyzer matrix
- §4 `all` is a selection mode, never a registered analyzer
- §5 `AnalyzerSpec` — closed fields and immutability
- §6 `AnalyzerRegistry` — lookup and selection semantics
- §7 Failure behavior
- §8 Late-binding and monkeypatchability
- §9 Registry vs `HuntRequest` vs `HuntExecutionContext` vs `ObservationRegistry`
- §10 Extension rules for a future analyzer
- §11 First-release prohibition on dynamic/third-party analyzer loading
- §12 Compatibility fixtures and architecture tests
- §13 Acceptance gate

---

## §0 Scope, non-goals, and dependency order

### 0.1 What this contract covers

1. The exact public analyzer identities and fixed execution order, and the
   relationship between `HUNTERS` (wire/schema contract) and
   `AnalyzerRegistry` (operational catalog) — §2.
2. One matrix row per analyzer: identity, package/facade, report type,
   builder adapter, renderer, record projector, accepted options,
   provenance hook, full-scope support, targeted source/layer declaration
   — §3.
3. `all` as a selection mode, never a registry entry — §4.
4. `AnalyzerSpec`'s closed field set and immutable-construction rule — §5.
5. `AnalyzerRegistry`'s closed lookup/selection behavior — §6.
6. Every construction-time and call-time failure mode and its fail-closed
   outcome — §7.
7. The late-binding/dependency-injection rule that preserves facade
   monkeypatchability and the existing call-count guarantees — §8.
8. The boundary between static `AnalyzerRegistry`, immutable `HuntRequest`,
   request-scoped `HuntExecutionContext`, and invocation-local
   `ObservationRegistry` — §9.
9. The checklist a future analyzer addition must satisfy — §10.
10. The first release's explicit prohibition on dynamic entry-point
    discovery and third-party analyzer loading — §11.
11. The compatibility fixtures and architecture tests #71/#72/#73 must
    keep green — §12.

### 0.2 Non-goals (frozen)

- No production registry code. `AnalyzerSpec`/`AnalyzerRegistry` are
  designed here in field/behavior terms only; #71 writes the actual
  dataclass and module.
- No change to `collect_hunt()`/`cmd_hunt()` — both keep dispatching
  through their current hard-coded branches until #72.
- No `HuntRequest`, `HuntExecutionContext`, or `ObservationRegistry`
  implementation — #61 owns those; §9 only draws the boundary line so #61
  does not have to re-derive it or invent a second capability map.
- No targeted-scan address/capture-range primitive, no exact
  `--hunt-addr`/`--size` wiring, no *populated* per-check targeted-scan
  grant (e.g. which literal public source name(s) go in stomping's
  `TargetedCapability.grants`, §1) — #59 decides that matrix (structurally
  the same kind of decision this document's own §3 matrix makes), #60
  designs the underlying range/capture primitives, and #61 is the one
  that actually writes the decided grant into `AnalyzerSpec` (§0.2 below,
  §1, §9). This contract *does* freeze two small, closed things in this
  space, both owned by #70/#71, not waited on from #59/#60/#61 (§1, §5
  field 10): `TargetedScanUnit`, a three-value tag (region/segment/
  region+layer) naming which existing gap vocabulary an analyzer already
  reports in — a fact already true of the shipped code today, not a new
  design decision — and `TargetedCapability`/`TargetedGrant`, the small
  frozen value objects (`scan_unit` + `grants: frozenset[TargetedGrant]`,
  each grant a `source`/`scopes` pair) that give #61 a single, typed,
  already-declared field to write that per-check grant into, instead of
  inventing a second capability map. #59 decides the grant's contents,
  #60 designs the range/capture primitives, #61 writes the decided grant
  into the registry; none of the three rename or replace either type.
- No CLI, schema, output, score, Finding ID, coverage, diagnostic, or
  exit-code change. No renaming of `cs-beacon`/`obfuscation` or their
  differently-named packages (`cs_beacon`/`encoding`) — those mismatches
  are recorded as frozen facts in §3, not defects to fix here.
- No dynamic entry-point discovery or third-party analyzer loading in this
  release — §11.

### 0.3 Dependency order

```text
Recon QA #44
  |-> #70 (this contract) -> #71 (AnalyzerSpec/AnalyzerRegistry)
        -> #72 (route collect_hunt()/cmd_hunt() through it)
        -> #73 (full-scope compatibility/extension freeze)
  |-> #59 -> #60 (targeted-rescan contract + range primitives)
        -----------------------------------------------|-> #61 (HuntRequest/
                                                             HuntExecutionContext/
                                                             ObservationRegistry)
```

#70–#73 form the static-registry branch; #59–#60 form the targeted-rescan
branch. Both must converge before #61. This document is written so #61 can
read §9 alone to know exactly what it is *not* allowed to duplicate.

---

## §1 Vocabulary

- **Identity** — the exact public string an investigator passes to
  `--hunt`: one of `HUNTERS` (`dumpex/output/records.py:1282`) or the
  reserved selection word `"all"`. Never a package name.
- **Package/facade** — the dotted module path of the hunter's
  `dumpex/hunt/<pkg>/__init__.py`, e.g. `dumpex.hunt.cs_beacon`. Recorded
  separately from identity because three of the seven package names do
  not equal their public identity (§3).
- **Builder adapter** — that package's `_build_<pkg>_report(mf, **opts)`
  function: the one place a `Report` is constructed, called exactly once
  per selected analyzer per invocation (§8).
- **Renderer** — that package's `_render_<pkg>_console(report, verbose)`
  function. **Not a pure projector**: every one of the seven (confirmed
  by direct read, e.g. `dumpex/hunt/injection/__init__.py:167-175`) calls
  a `report_console.print_console(report, verbose)` side effect and only
  *then* returns `report_legacy.project_legacy_dict(report)`. It is a
  `Report -> dict` function with a console-printing side effect, and is
  therefore only ever safe to call from the printing (`cmd_hunt()`)
  console path — never from `collect_hunt()`'s silent JSON-only path
  (§8, §12).
- **Record projector** — that package's `report_record.py:
  project_hunter_record(report) -> HunterRecord`, the pure `Report ->`
  wire-shape projector every hunter now shares by name (confirmed by
  direct read of all seven `report_record.py` files).
- **Options** — the closed set of extra keyword arguments (beyond `mf`)
  a builder accepts, e.g. stomping's `ref_dir`.
- **Provenance hook** — an optional `Report -> dict | None` accessor
  surfacing rule/build provenance for `meta.*`, distinct from any
  analyzer's own findings (only YARA has one today). Always returns an
  already-`to_dict()`-normalized `dict | None` — never the raw
  provenance dataclass (§3, §5 field 8).
- **Compat wrapper** — that package's `collect.py:
  collect_<identity>_record(mf, **opts) -> HunterRecord` thin public
  function, named after the **public identity** (with `-` folded to `_`),
  not the package: `collect_obfuscation_record`
  (`dumpex/hunt/encoding/collect.py:30`), `collect_yara_record`
  (`dumpex/hunt/yara_hunt/collect.py:13`), `collect_cs_beacon_record`
  (`dumpex/hunt/cs_beacon/collect.py:16`), and
  `collect_injection_record`/`collect_hollowing_record`/
  `collect_stomping_record`/`collect_pipe_record` for the four analyzers
  where identity and package already agree.
- **Roster artifact** — one of the non-registry places the `HUNTERS` set
  is *also* written down by hand today, each independently verified by
  `tests/unit/test_hunter_roster_alignment.py` and each a place an eighth
  analyzer can be silently forgotten (§3, §10, §12) — **all ten are CI-
  enforced by that one test module**, none is left to manual review:
  the four schema enums (`hunterRecord.hunter`, `skipRelationship.hunter`,
  `recommendedAction.hunters.items`, `huntSummary.selected`), the two
  console display maps (`summary_presentation._DISPLAY_NAME`,
  `summary_presentation._EVIDENCE_HUNTER_LABEL`), the region-correlation
  collector table (`region_correlation._COLLECTORS`,
  `dumpex/hunt/region_correlation.py:682-690`), and three human-facing
  artifacts the same test file's own "human-facing artifacts" section
  (`tests/unit/test_hunter_roster_alignment.py:111-157`) checks by
  actually running `cli.main()`/parsing the files: `--hunt`'s own CLI
  help text (`test_cli_hunt_help_lists_exactly_the_roster_in_order`),
  `docs/CLI_REFERENCE.md`'s `--hunt TTP` table row
  (`test_cli_reference_doc_lists_exactly_the_roster_in_order`), and
  `README.md`'s "Hunt overview" table
  (`test_readme_hunt_overview_table_covers_exactly_the_roster_in_order`,
  which additionally requires every row to carry a real, non-empty
  description). None of these ten is derived from `HUNTERS` at runtime —
  that is exactly why each needs its own CI assertion instead.
- **Full-scope support** — whether the analyzer participates in
  `--hunt <identity>` / `--hunt all` today. All seven do.
- **Targeted scan unit** (`TargetedScanUnit`) — a small, closed tag this
  contract itself defines and #71 owns (deliberately **not** a type
  #59/#60 hand this contract, and not blocked on either landing first):
  **region** (a `MemoryInfo` range), **segment** (a contiguous scanned
  byte run, YARA's/CS Beacon's own vocabulary — see
  `coverage.rule_files_compiled`/`segments_read` in
  `docs/hunt_migration_field_matrix.md`'s yara section and
  `scanner.scan_segments` in `dumpex/hunt/cs_beacon/domain.py:294`), or
  **region+layer** (obfuscation's own three-tier decode model, see its
  `report_console.py` verbose-only `_scan_layers_lines()`).
- **`TargetedGrant`**/**`TargetedCapability`** — the actual value
  `AnalyzerSpec.targeted_capability` (§5 field 10) holds when non-`None`:
  not the bare `TargetedScanUnit` tag alone, and (correcting an earlier
  draft of this contract) **not bound to `CoverageSnapshot`'s internal
  field names either** —

  ```
  @dataclass(frozen=True)
  class TargetedGrant:
      source: str
      scopes: frozenset[str]

  @dataclass(frozen=True)
  class TargetedCapability:
      scan_unit: TargetedScanUnit
      grants: frozenset[TargetedGrant]
  ```

  `scan_unit` is the tag above. Each `TargetedGrant.source` names one
  entry in that analyzer's own **public coverage-source vocabulary** —
  the `sources` dict keys each hunter's `report_facts.py` already builds
  via `observe_source(...)` and feeds to `build_coverage_report()`, the
  same vocabulary `CoverageLimitation.source` and (via
  `CoverageReport.sources`) every investigation-action consumer already
  reads. This is a **different, and correct, namespace** from
  `CoverageSnapshot`'s own dataclass field names, which an earlier draft
  of this contract used instead: `CoverageSnapshot` fields
  (`memory_info_stream`, `ref_dir_supplied`, …) are internal facts an
  aggregate consults to *derive* a source's presence — they are never
  themselves the string a `CoverageLimitation`/investigation action
  names. Concretely, for stomping (`dumpex/hunt/stomping/
  report_facts.py:241-255`): `sources = {"memory_info": …, "modules": …,
  "module_headers": …, "reference_files": …, "section_content_diff": …,
  "ioc_string_scan": …}` — the targeted-relevant one is `"ioc_string_scan"`,
  a public source key, **not** `"memory_info_stream"`, the internal
  `CoverageSnapshot` field that source happens to be gated on; an earlier
  draft of this contract would have accepted the latter and rejected the
  former, exactly backwards. Verified per analyzer: pipe's targeted
  source is `"pipe_name_scan"` (`pipe/report_facts.py:228`); yara's and
  cs-beacon's are each `"segment_scan"` (`yara_hunt/report_facts.py:97`,
  `cs_beacon/report_facts.py:171`); obfuscation's is `"encoding_scan"`
  (`encoding/report_facts.py:174`).

  `TargetedGrant.scopes` exists because a source is not always the finest
  targetable unit — obfuscation's own `CoverageLimitation`s already carry
  a `scope` distinct from `source` (`encoding/report_facts.py:182-188`:
  `source="encoding_scan", scope=layer`), and that `layer` is one of a
  real, closed, already-defined constant, `OVERSIZE_SCAN_LAYERS =
  ("sleep_mask", "entropy", "decode")` (`dumpex/hunt/encoding/domain.py:57`)
  — a bare `source="encoding_scan"` with no `scopes` could not express
  "targeted rescan may run the `sleep_mask` decode layer but not
  `entropy`." For the other four targeted-capable analyzers, `scopes` is
  expected to stay empty — **not**, as an earlier draft of this bullet
  claimed, because "no sub-source distinction exists in their own
  `report_facts.py` today" (false: `pipe`/`yara`/`cs-beacon` each already
  emit a non-`None` `scope` on some `CoverageLimitation`, see §7.1 failure
  #5's own revision note for the direct-read evidence and the corrected,
  narrower true claim) — but because none of the three has a *closed,
  statically-importable* scope vocabulary the way `obfuscation`'s
  `OVERSIZE_SCAN_LAYERS` already is, so `AnalyzerSpec` has nothing yet to
  validate a populated `TargetedGrant.scopes` value against for any of
  them. `TargetedGrant.scopes = frozenset()` is a normal, legal, "this
  grant has no finer subdivision" state, not the same "ungranted" meaning
  `TargetedCapability.grants = frozenset()` carries at the outer level
  (§7.2 failure #12).

  **This release does not populate any analyzer's `grants`** — deciding
  which public source(s)/scope(s) each of the five may legitimately be
  narrowed to is #59's own capability-matrix decision (structurally the
  same kind of decision this contract's own §3 matrix makes for full-scope
  execution), not invented here — but the *typed field it belongs in* is
  frozen now, giving #61 (per #58's own delivery structure, "converge …
  analyzer capabilities" — §0.2) a single, legal home to write that
  decision into `AnalyzerSpec` itself, rather than being forced to invent
  a second, parallel capability map (exactly what #69's own Compatibility
  considerations forbid: "adapters … must not introduce parallel dispatch
  maps"). Both `TargetedGrant` and `TargetedCapability`, like
  `AnalyzerSpec`, are frozen dataclasses with their own field-validating
  construction (§5's own pattern) — neither is a nested concern outside
  this contract's immutability rules.
- **Targeted capability** — whether the analyzer is on #58's approved
  first-release targeted-rescan list (`pipe`, `stomping`, `cs-beacon`,
  `yara`, `obfuscation`; `injection` and `hollowing` have none), holding
  its `TargetedCapability` value (`scan_unit` + `grants`) above.

---

## §2 Public identity and fixed order: `HUNTERS` vs `AnalyzerRegistry`

`HUNTERS = ("injection", "hollowing", "stomping", "pipe", "cs-beacon",
"yara", "obfuscation")` (`dumpex/output/records.py:1282`) is, and remains,
the **wire/schema contract**: the exact closed vocabulary and order every
`HunterRecord.hunter` (`records.py:1728-1729`), every
`SkipRelationship.hunter`/`RecommendedAction.hunters`
(`dumpex/hunt/_investigation.py:422-423,618-620`), every region-correlation
ordering (`dumpex/hunt/region_correlation.py:740,744`), and every summary
ordering (`dumpex/hunt/summary.py`, `summary_presentation.py:151`) is
already validated and sorted against. `AnalyzerRegistry` (#71) is the
**operational catalog** built to satisfy that same order — it does not
introduce a second, independent notion of order; it is validated against
`HUNTERS` at construction time (§7, failure #4) and can never disagree
with it. Concretely, since §6 already defines `select("all")` as
returning only the `full_scope_capable` registrations: the filter belongs
on the `HUNTERS` side of the comparison, not the `select("all")` side —

```
tuple(spec.identity for spec in registry.select("all")) \
    == tuple(h for h in HUNTERS if registry.get(h).full_scope_capable)
```

— always, by construction. (An earlier draft of this invariant filtered
`select("all")`'s own output a second time — `if spec.full_scope_capable`
applied to a result §6 already filtered — which is a no-op on the left
side while the right side stayed the unfiltered `HUNTERS`; that version
is false the day any `full_scope_capable=False` analyzer is registered,
exactly the case it claimed to future-proof. Corrected here.) This
release's seven specs are all `full_scope_capable=True` (§3), so today
the right-hand side is already exactly `HUNTERS` and the un-filtered
`registry.select("all")` form holds too — the filtered form above is the
one that keeps holding once a targeted-only analyzer with
`full_scope_capable=False` is registered (§7.1 failure #5, §10 item 4).
Failures #2 (missing) and #4 (reordered) still apply to the full
registration sequence, not to `select("all")`'s filtered result — order
and completeness are checked against every registered spec, never only
the full-scope subset.

`HunterRuntime` (`dumpex/hunt/_runtime.py`) remains what it already is — a
per-call dependency snapshot threaded into a single hunter's submodules —
and is not superseded or duplicated by `AnalyzerRegistry`, which is a
cross-hunter catalog, not a dependency-injection container for one
hunter's internals.

---

## §3 The seven-row analyzer matrix

| Identity | Package/facade | Report type | Builder adapter | Renderer | Record projector | Accepted options | Provenance hook | Full-scope | Targeted `scan_unit`¹ |
|---|---|---|---|---|---|---|---|---|---|
| `injection` | `dumpex.hunt.injection` | `injection.domain.InjectionReport` | `_build_injection_report(mf)` | `_render_injection_console(report, verbose)` | `injection.report_record.project_hunter_record` | none | none | yes | **none** |
| `hollowing` | `dumpex.hunt.hollowing` | `hollowing.domain.HollowingReport` | `_build_hollowing_report(mf)` | `_render_hollowing_console(report, verbose)` | `hollowing.report_record.project_hunter_record` | none | none | yes | **none** |
| `stomping` | `dumpex.hunt.stomping` | `stomping.domain.StompingReport` | `_build_stomping_report(mf, ref_dir=None)` | `_render_stomping_console(report, verbose)` | `stomping.report_record.project_hunter_record` | `ref_dir: str \| None` | none | yes | region (IOC scan only — §1) |
| `pipe` | `dumpex.hunt.pipe` | `pipe.domain.PipeReport` | `_build_pipe_report(mf)` | `_render_pipe_console(report, verbose)` | `pipe.report_record.project_hunter_record` | none | none | yes | region |
| `cs-beacon` | `dumpex.hunt.cs_beacon` | `cs_beacon.domain.CSBeaconReport` | `_build_cs_beacon_report(mf)` | `_render_cs_beacon_console(report, verbose)` | `cs_beacon.report_record.project_hunter_record` | none | none | yes | segment |
| `yara` | `dumpex.hunt.yara_hunt` | `yara_hunt.domain.YaraReport` | `_build_yara_report(mf, rules_dir=None)` | `_render_yara_console(report, verbose)` | `yara_hunt.report_record.project_hunter_record` | `rules_dir: str \| None` | `lambda r: (r.coverage.rules.provenance.to_dict() if r.coverage.rules.provenance is not None else None)` (§5 field 8) | yes | segment |
| `obfuscation` | `dumpex.hunt.encoding` | `encoding.domain.EncodingReport` | `_build_encoding_report(mf)` | `_render_encoding_console(report, verbose)` | `encoding.report_record.project_hunter_record` | none | none | yes | region+layer |

¹ This column shows each analyzer's `TargetedCapability.scan_unit` only
(§1, §5 field 10) — the `scan_unit` half is frozen by this contract for
all five now; the `grants` half of the same `TargetedCapability` value is
left empty this release (#59 decides the contents, #61 writes them), and
is not shown here since it has no contents yet to show.

Confirmed by direct read of every `dumpex/hunt/<pkg>/__init__.py` and
`report_record.py` in the tree — not sampled. Package/identity mismatches
are frozen facts, not defects: `cs-beacon` (identity, hyphen) vs
`cs_beacon` (package, underscore — Python cannot import a hyphenated
module name); `obfuscation` (identity) vs `encoding` (package — a naming
choice predating this contract, per #70's own current workflow note);
`yara` (identity) vs `yara_hunt` (package, disambiguating
from the `yara-python` third-party import). `injection`, `hollowing`,
`stomping`, `pipe` have identity == package. **This contract does not
authorize changing any of the three mismatches** (#70's own Compatibility
considerations: "does not authorize renaming packages or user-facing
terminology").

Every record projector is reached today through a same-named alias
(`_record_from_<identity>_report`) created at the `collect.py` boundary —
either a bare assignment (`injection`, `hollowing`, `stomping`, `pipe`,
`encoding`: `_record_from_X_report = project_hunter_record`) or an import
alias (`cs_beacon`, `yara_hunt`: `from ...report_record import
project_hunter_record as _record_from_X_report`), and the *dispatcher*
(`dumpex/hunt/__init__.py`) re-imports that same alias a second time (`from
dumpex.hunt.injection.collect import _record_from_injection_report`, etc.),
exactly the "operational wiring encoded through imports" #70 names as a
problem. `AnalyzerSpec.record_projector` (§5) is late-bound to the
identical name currently exposed on `dumpex.hunt` (§8) — **not** a direct
reference to `report_record.project_hunter_record` resolved once at
registry-construction time. #71 collapses the two-hop alias chain
(`report_record.py` → `collect.py` → `dumpex/hunt/__init__.py`) down to
one hop (`report_record.py` → registry, late-bound), but it does not, and
must not, remove the late-binding seam itself — see §8 for why removing it
would break `test_collect_hunt_single_scan.py`. The same statement applies
to `builder` and `renderer` (§5 fields 4–6): all three are late-bound, none
is a plain captured reference, and this paragraph is corrected accordingly
from an earlier draft that described `record_projector` as a direct,
non-late-bound reference — that draft contradicted §8's own rule and is
not what #71 should build.

Every renderer has the identical `(report, verbose=False) -> dict`
signature and the identical print-then-return-dict shape (§1); every
builder takes `mf` positionally and, for stomping/yara only, one closed
keyword option. No builder accepts `**kwargs` — the "generic stringly
kwargs bag" #70's own Alternatives Considered section rejects does not
exist today and `AnalyzerSpec.option_names` (§5) must stay closed for the
same reason.

One piece of existing per-identity wiring this matrix does **not**
capture, flagged rather than silently dropped: `cmd_hunt()`'s own
`ttp == "all"` branch backfills `results["yara"]`/`results["obfuscation"]`
with a hand-written NOT_EVALUATED dict when either key is absent
(`dumpex/hunt/__init__.py:283-287`) — a special case for exactly two of
the seven identities, in the legacy `results` dict, not in `records`/
`summary`. Since `run_yara = ttp in ("yara", "all")` and
`run_obfuscation = ttp in ("obfuscation", "all")`
(`dumpex/hunt/__init__.py:205-211`) are both `True` whenever `ttp ==
"all"`, both backfill conditions are unreachable today and this is very
likely dead code — but #72 must make an explicit
call on it (delete it, or explain why the registry-driven path still
needs it) rather than silently carry or silently drop it while
rewriting this function.

Beyond this seven-row matrix, `HUNTERS` is also written down by hand in
ten other places (§1's "roster artifact" entry, §10 item 2) that a
registry-only view of the codebase does not cover: four JSON-schema
enums, two console display maps, `region_correlation._COLLECTORS`,
`--hunt`'s own CLI help text, and two docs tables — all ten already
CI-enforced by `tests/unit/test_hunter_roster_alignment.py`.
`AnalyzerRegistry` does not replace any of these — #71 registers the
seven specs above; §10/§12 require the same test module to gain the
registry itself as an eleventh cross-check once an eighth analyzer is
proposed.

---

## §4 `all` is a selection mode, never a registered analyzer

`"all"` is not, and must never become, an `AnalyzerSpec.identity`. It is
exclusively a value `AnalyzerRegistry.select()` accepts (§6) meaning "the
full frozen order," mirroring exactly what `collect_hunt()`'s and
`cmd_hunt()`'s own `valid = set(HUNTERS) | {"all"}` checks already encode
(`dumpex/hunt/__init__.py:109,200`). A registration attempt with
`identity="all"` is a construction-time failure (§7, failure #3) — treated
identically to registering an identity outside `HUNTERS` (an "extra"
analyzer), since `"all"` is not a member of `HUNTERS` either.

---

## §5 `AnalyzerSpec` — closed fields and immutability

`AnalyzerSpec` is a frozen, validated value object — the same
"`@dataclass(frozen=True)` + a hand-written `__post_init__` that validates
every field" shape already established by `SkipRelationship`
(`dumpex/hunt/_investigation.py:384-385`) and `RecommendedAction`
(`:609-610`), both genuinely `@dataclass(frozen=True)` with their own
field-validating `__post_init__`. (`HunterRecord`
(`dumpex/output/records.py:1702-1703`) is a useful second reference for
the *validation* half of this pattern only — it has a thorough
`__post_init__` — but it is a bare `@dataclass`, not `frozen=True`, so it
is not itself an example of the immutability half; an earlier draft of
this contract cited it as a frozen example, which was wrong.) **It does
*not* reuse
`dumpex.hunt._domain.require_recursively_immutable`**: that helper's own
`_IMMUTABLE_LEAF_TYPES` closes over `NoneType`/`bool`/`int`/`float`/
`complex`/`str`/`bytes` plus tuples/frozensets of those, and its own
docstring explicitly rejects "any other object" — a `type` (field 3) and
four `Callable`s (fields 4–6, 8) are exactly the kind of object it exists
to reject, since a callable cannot be recursively proven immutable the way
a value object can. `AnalyzerSpec.__post_init__` instead validates each
field's own shape directly (`isinstance(x, type)`, `callable(x)`,
`isinstance(option_names, frozenset)`, …) — a frozen dataclass whose
fields are individually validated, not a recursively-immutable value
graph. This is a real distinction, not a wording nuance: it is what makes
fields 4–6/8 (all callables) legal on an otherwise-frozen spec.

Its field set is **exactly** the ten matrix columns of §3, no more:

1. `identity: str` — one `HUNTERS` member, never `"all"`.
2. `package: str` — the dotted facade module path (§1); may differ from
   `identity` (§3).
3. `report_type: type` — that package's own frozen domain `Report` class.
4. `builder: Callable[..., Report]` — late-bound (§8), never a plain
   captured function reference.
5. `renderer: Callable[[Report, bool], dict]` — late-bound; a
   printing-and-returning function, not a pure one (§1, §8).
6. `record_projector: Callable[[Report], HunterRecord]` — late-bound (§8).
7. `option_names: frozenset[str]` — the closed set of extra keyword names
   the builder accepts (empty for five of seven), validated **both
   directions** against the builder's own signature (§7.1 failure #7):
   every name in `option_names` must be a real builder keyword, and every
   non-`mf` builder keyword must be in `option_names`.
8. `provenance_hook: Callable[[Report], dict | None] | None` — `None` for
   six of seven. `yara`'s is
   `lambda r: (r.coverage.rules.provenance.to_dict() if r.coverage.rules.provenance is not None else None)`
   (§3) — the hook itself owns the `RulesProvenance -> dict` conversion
   `dumpex/hunt/__init__.py:258-259` performs today, so every caller of
   `provenance_hook` (e.g. the future `V2Output.set_yara_provenance()`
   wiring) always receives an already-JSON-safe `dict | None`, never the
   raw `RulesProvenance` dataclass.
9. `full_scope_capable: bool` — `True` for every analyzer this release
   (§7.1 failure #5 forbids the one combination that is genuinely
   nonsensical: `full_scope_capable=False` **and**
   `targeted_capability=None` together, i.e. an analyzer that can run in
   neither mode).
10. `targeted_capability: TargetedCapability | None` — `None` for
    `injection`/`hollowing`; otherwise a `TargetedCapability` value (§1 —
    `scan_unit` plus `grants: frozenset[TargetedGrant]`, not the bare
    `TargetedScanUnit` tag alone) for the five analyzers on #58's
    first-release list. `TargetedCapability`/`TargetedGrant`/
    `TargetedScanUnit` are this contract's own closed types, owned by
    #70/#71 — not types #71 waits on #59/#60/#61 to deliver first (§0.2).
    This release freezes the *shape* only: every one of the five gets a
    real `scan_unit` (§3's matrix), but `grants` is empty — #59 decides
    its contents, #61 writes them (§0.2, §1).

**Deliberately not a field**: execution order. A spec's position is its
index in the registry's own frozen registration sequence, validated
against `HUNTERS.index(identity)` at construction (§7, failure #4) — never
a second, independently-settable ordinal, for the same reason
`coverage_status` was retired rather than kept alongside
`coverage.status` (`docs/hunt_migration_field_matrix.md`'s cross-cutting
finding #2): one fact, one place, never two sources of truth that could
silently disagree.

**Deliberately never a field value**: a dump handle, a raw scan buffer, or
any other mutable parser object. This is #69's own Resource and safety
constraint ("Do not retain raw scan buffers or mutable parser objects in
global registry entries"), and is also why `builder`/`renderer`/
`record_projector`/`provenance_hook` are typed as *callables that accept
a `Report`/`mf` argument*, never as already-invoked results — a spec
holding a live result instead of a way to produce one would violate this
rule by construction. §7.1 gains a construction-time failure mode for a
spec field that holds such an object (failure #8 below).

---

## §6 `AnalyzerRegistry` — lookup and selection semantics

`AnalyzerRegistry` is a single, module-level, import-time-constructed
catalog (mirroring how `HUNTERS` and the current dispatcher's own imports
are already wired at import time) — closed over exactly the seven
registrations #71 declares in one place, with no runtime `register()`
method exposed to any caller. It exposes exactly three **production**
operations — two for this release's full-scope path, one reserved for the
targeted-scan call path #61 introduces — plus one internal,
underscore-prefixed introspection method that is deliberately **not**
counted among them:

- **`_all_specs() -> tuple[AnalyzerSpec, ...]`** — the complete
  registration sequence, **unfiltered** by `full_scope_capable` or any
  other field, in registration order (which §7.1 failure #4 already
  guarantees equals `HUNTERS` order). The leading underscore is load-
  bearing, not cosmetic (the same `_`-prefixed-internal convention §6's
  own "Module layout" note already cites for `_runtime.py`/`_domain.py`/
  etc.): this method returns every spec **regardless of capability**, so
  a production call site that reached for it instead of `select()` would
  silently bypass every capability gate §7.2 failures #10/#11 exist to
  enforce — exactly the fail-open outcome those two failures were added
  to close, just re-opened through a different door. It exists **only**
  for the registry module's own construction-time tests and for §12's
  roster cross-check to assert completeness/order (`tuple(spec.identity
  for spec in registry._all_specs()) == HUNTERS`, always, by
  construction) independently of `select("all")`'s own capability
  filtering (§2) — never for `collect_hunt()`/`cmd_hunt()`, which must go
  through `select()`/`select_targeted()` only. Conflating `_all_specs()`
  with `select("all")` — asserting the latter's output equals the
  *unfiltered* `HUNTERS` — is exactly the mistake §2's own invariant was
  corrected to avoid (below); conflating the reverse — reaching for
  `_all_specs()` from inside `collect_hunt()`/`cmd_hunt()` because it's
  the more obvious "give me everything" call — is the mistake §12 now
  adds an architecture test to catch (below), since the underscore alone
  is a convention, not an enforcement mechanism. This method exists
  precisely to give the "is the full roster present and ordered" question
  its own unfiltered answer,
  separate from "what does a full-scope run actually execute."
- **`get(identity: str) -> AnalyzerSpec`** — exact-match single lookup.
  `identity` must be a real `HUNTERS` member; `"all"` is rejected (§4);
  no prefix/fuzzy/case-insensitive matching, and the package name is
  never an accepted key (precisely because `cs-beacon`/`cs_beacon` and
  `obfuscation`/`encoding` already diverge — accepting either would make
  "is this a wire identity or a package name" ambiguous at the one call
  site meant to resolve it).
- **`select(selected: str) -> tuple[AnalyzerSpec, ...]`** — the one
  full-scope entry point `collect_hunt()`/`cmd_hunt()` call (after #72).
  `selected == "all"` returns every `full_scope_capable` registration in
  `HUNTERS` order, always — never re-sorted (§2's filtered invariant; this
  release's seven are all `full_scope_capable=True`, so today this is
  exactly `HUNTERS` order with nothing filtered out). A single identity
  is gated the same way, not merely returned as a 1-tuple unconditionally:
  if the resolved spec's `full_scope_capable` is `False`, `select()` fails
  exactly as described in §7.2 failure #11 — this is the single-identity
  mirror of the `"all"` branch's own filtering, and closes the gap an
  earlier draft of this contract left open (that draft filtered
  `"all"`'s aggregate result but left `select(<single identity>)`
  ungated, so a future targeted-only analyzer — `full_scope_capable=False`
  — could still be requested and fully executed through the single-
  identity path even though it is excluded from `"all"`). Only once a
  spec is confirmed both real (not failure #9) and `full_scope_capable`
  (not failure #11) does `select()` return its 1-tuple. Any unknown
  value fails as described in §7.2 failure #9 — `select()` itself raises
  one canonical, unformatted `UnknownAnalyzerIdentity` exception;
  `collect_hunt()`/`cmd_hunt()` are responsible for turning it into their
  own already-frozen caller-facing text (§7.2).
- **`select_targeted(identity: str, source: str, scope: str | None = None)
  -> AnalyzerSpec`** — the one entry point a future targeted-scan call
  site (#61, after #59/#60) uses. `identity`/`"all"`/`targeted_capability
  is None` are checked exactly as before (failures #9/#10, below) — this
  section only adds what changed: **`select_targeted()` answers "is
  `source`/`scope` granted," not merely "does this analyzer have any
  grant at all."** An earlier draft of this contract gave it only
  `identity`, so it could not express the actual question a targeted
  request needs answered — "is `injection`'s existing `targeted_capability
  is not None` enough to authorize *this* request" was never the right
  test even for a fully-populated grant; whether the *specific* requested
  `source` (and, for `obfuscation`, `scope`) is one of the ones actually
  granted is. Once `identity`/`targeted_capability` pass (failures #9/#10)
  and `grants` is non-empty (failure #12 does not fire), matching proceeds
  against `TargetedCapability.grants` (§1):

  ```
  matching = [g for g in capability.grants if g.source == source]
  if not matching:
      raise UnsupportedTargetedSource(identity, source)   # §7.2 failure #13
  authorized = any(
      (not g.scopes and scope is None)
      or (g.scopes and scope is not None and scope in g.scopes)
      for g in matching
  )
  if not authorized:
      raise UnsupportedTargetedScope(identity, source, scope)   # §7.2 failure #14
  ```

  The match is **symmetric** between `grant.scopes` and the requested
  `scope` — neither side gets a free pass when the other is present or
  absent. An earlier draft of this contract used an asymmetric check
  (`not g.scopes or scope in g.scopes`, gated behind `if scope is not
  None`) that fails open in both directions: (1) a scope-less grant
  (`pipe`'s, `scopes=frozenset()`) would satisfy *any* non-`None`
  `scope` the caller passed — `select_targeted("pipe", "pipe_name_scan",
  scope="arbitrary-invalid-scope")` would have succeeded, despite `pipe`
  having no scope granularity to select from at all; (2) because the
  whole check was gated behind `if scope is not None`, a caller could
  omit `scope` entirely against `obfuscation` (`scopes={"sleep_mask",
  "entropy", "decode"}`) and skip scope validation altogether —
  `select_targeted("obfuscation", "encoding_scan", scope=None)` would
  have succeeded despite obfuscation requiring an explicit layer choice.
  The symmetric form above closes both: a `None` `scope` is authorized
  only against a grant with empty `scopes` (`pipe`/`stomping`/`yara`/
  `cs-beacon`, §1), and a non-`None` `scope` is authorized only when it
  names a member of some matching grant's non-empty `scopes`
  (`obfuscation`, whose grant(s) are expected to name specific members of
  `OVERSIZE_SCAN_LAYERS`, §1/§7.1 failure #5) — an empty `scopes` never
  "falls through" to authorize an arbitrary requested scope, and a
  non-empty `scopes` never authorizes an *absent* one. `identity`
  must be a real `HUNTERS` member with a non-`None` `targeted_capability`
  (§5 field 10); `"all"` is always rejected here, independent of any
  single identity's own capability (#58's own rule: "rejects `--hunt
  all` … without an explicit targeted-scan capability"). Any identity
  whose `targeted_capability` is `None` — `injection`, `hollowing`, or
  a future analyzer that never opted in (§10 item 5) — fails exactly as
  described in §7.2 failure #10, before any analyzer work begins. A
  `targeted_capability` that is non-`None` but whose `grants` is empty
  fails as §7.2 failure #12 instead — a declared-but-unpopulated grant
  is not a usable one; today this is all five of #58's targeted-capable
  identities (§3, §10 item 5), so `select_targeted()` cannot succeed for
  anything, for anyone, until #59 decides and #61 writes a real grant.
  The `source`/`scope` matching above is the single capability-gating
  checkpoint for a specific request; §9's `HuntRequest` construction-time
  validation calls through it rather than re-implementing the same check
  a second time.

**Module layout and import timing.** §7.1's own failure list is only
meaningful if the registry module reliably finishes constructing (or
reliably crashes import) the same way regardless of which entry point
starts the process — and that depends on exactly where the registry
module lives and when it runs relative to `dumpex/hunt/__init__.py`'s own
facade imports, which this contract fixes rather than leaves to whichever
layout #71 happens to reach for:

- The registry module (suggested location: `dumpex/hunt/_registry.py`,
  following the existing `_`-prefixed-internal-module convention already
  used by `_runtime.py`/`_domain.py`/`_coverage.py`/`_finding.py`/
  `_location.py`) is imported by `dumpex/hunt/__init__.py` **after**
  every facade builder/renderer/collect import already in that file
  (`dumpex/hunt/__init__.py:9-23`) — never before, and never from a
  package `dumpex/hunt/__init__.py` itself imports before those lines.
  This guarantees every dispatcher-facing name (`dumpex.hunt.
  _build_injection_report`, etc. — §8) already exists as a `dumpex.hunt`
  module attribute by the time the registry module's own top-level code
  runs, so any construction-time validation that resolves one of those
  names (§7.1 failure #7) sees the real, fully-defined function, not a
  partially initialized module. Failure #6's `EXPECTED_REPORT_TYPES`
  comparison does not depend on this particular ordering guarantee — see
  its own bullet below, which needs a different (and simpler) one.
- The registry module itself **must not** `import dumpex.hunt` at its own
  top level. Combined with the previous point, a top-level `import
  dumpex.hunt` inside a module `dumpex/hunt/__init__.py` is still in the
  middle of importing is exactly how a circular-import `ImportError`
  happens — and per §7.1's own blast-radius note, a construction-time
  failure here takes down the entire CLI, not just `--hunt`, so this is
  not a hazard to leave to be discovered by trial and error. §8's
  late-binding seam already requires resolving dispatcher names at *call*
  time, not at registry-module-import time (`getattr(sys.modules[
  "dumpex.hunt"], "_build_injection_report")`, not a module-level `import
  dumpex.hunt` followed by attribute access) — the same rule that makes
  monkeypatching work (§8) also happens to be the one that avoids this
  import cycle, and #71 must not weaken it to a top-level import for
  convenience.
- §7.1 failure #6's `EXPECTED_REPORT_TYPES` mapping needs the seven real
  domain `Report` classes as ordinary top-level imports inside the
  registry module itself (`from dumpex.hunt.injection.domain import
  InjectionReport`, and so on) — the same kind of production import
  `dumpex/hunt/__init__.py`'s own facade already does for the same seven
  packages (`:9-23`), not a dynamic-discovery mechanism, so it does not
  raise the "does this count as the loading §11 forbids" question:
  `EXPECTED_REPORT_TYPES` is a closed, hard-coded dict of names this
  contract's own §3 matrix already lists, imported the ordinary way,
  never resolved from a string at runtime.

---

## §7 Failure behavior

### 7.1 Construction-time (registry-module import; before any dump is opened)

Every one of these is a **hard failure that crashes import** — never a
warning, never a partial registry — matching #70's own Resource and
safety constraints ("closed registry has deterministic bounded size and
ordering") and its Evidence/coverage semantics section ("Unsupported
capability requests fail before analyzer work begins"). Because
`dumpex.cli` imports `dumpex.hunt` at module scope, a construction-time
failure here means the **entire CLI** (`--recon`, `--strings`, every
subcommand, not only `--hunt`) fails to start, not only `--hunt` itself —
an acceptable and deliberate blast radius, since every state below can
only come from a developer's own in-tree edit to the registry module,
never from investigator input, dump content, or any other runtime value:

1. **Duplicate** — the same `identity` registered twice.
2. **Missing** — a `HUNTERS` member with no registration.
3. **Extra** — a registration whose `identity` is not in `HUNTERS`
   (this is also how a registration attempting `identity="all"` is
   rejected — §4).
4. **Reordered** — a registration's sequence position does not equal
   `HUNTERS.index(identity)` (order drift — the exact risk #69 names).
5. **Invalid capability** — `full_scope_capable` is `False` **and**
   `targeted_capability` is `None` together (an analyzer that could run
   in *neither* mode — the actual "nothing to run" state); or
   `targeted_capability` is non-`None` but its `scan_unit` is unset, or
   its `grants` is not a `frozenset[TargetedGrant]`, or any
   `TargetedGrant.source`/`.scopes` fails its own type check (`source` a
   non-empty `str`, `scopes` a `frozenset[str]`) — §1's `TargetedCapability`
   shape. An *empty* `grants` is legal this release (#59 has not yet
   decided any analyzer's public source/scope grant, and §7.2 failure #12
   already fails closed on that emptiness at call time), but a
   wrong-typed `TargetedGrant` is a construction-time failure regardless.

   **`.scopes` is validated against a real vocabulary today; `.source` is
   not yet, and this contract requires that gap to be closed before, not
   after, #61 writes the first real grant — not merely "considered."**

   `OVERSIZE_SCAN_LAYERS = ("sleep_mask", "entropy", "decode")`
   (`dumpex/hunt/encoding/domain.py:57`) already is a real, importable,
   module-level constant — no production code needs to change to check
   against it. Construction-time validation therefore requires, for every
   `TargetedGrant` whose owning spec's `identity == "obfuscation"`:
   `set(grant.scopes) <= set(OVERSIZE_SCAN_LAYERS)`; for the other four
   targeted-capable identities (`pipe`/`stomping`/`yara`/`cs-beacon`,
   none of which emit a `scope` on their own `CoverageLimitation`s, §1),
   `grant.scopes == frozenset()` is required, not merely expected — a
   non-empty `scopes` on any of those four is a construction-time failure.
   **This rule has an explicit extension path, the same shape as §10 item
   5's "approved five" equality**: it is derived from the current tree
   (only `obfuscation` emits a `scope` on any `CoverageLimitation` today),
   not a permanent one-analyzer-only restriction — the day any other
   hunter's `report_facts.py` starts emitting `scope` on a
   `CoverageLimitation` (a production change to that hunter, made and
   reviewed on its own merits, never silently), this rule's "only
   `obfuscation`" clause must be extended in the same reviewed change to
   include that hunter, exactly as §10 item 5 requires for the
   approved-five identity set. It is not a violation of this rule to
   extend it that way; it would be a violation to add scoped emission to
   a hunter's `report_facts.py` without updating this rule in the same
   change.

   `.source` is different: no equivalent static constant exists yet.
   Each analyzer's public source names (`"ioc_string_scan"`,
   `"pipe_name_scan"`, `"segment_scan"`, `"encoding_scan"`, §1) are today
   `sources = {...}` dict-literal keys built inline inside each
   `report_facts.py`'s own coverage-projection function — not exposed as
   a static, importable, enumerable constant the way `OVERSIZE_SCAN_LAYERS`
   already is (an earlier draft of this check validated against
   `CoverageSnapshot`'s dataclass fields instead, precisely because that
   *was* statically enumerable — but, per §1's correction, that check
   validated the wrong namespace entirely). **This gap is real, and this
   contract requires it closed as a precondition of #61's first real
   grant, not left as an unenforced code-review obligation indefinitely**:
   each targeted-capable analyzer's `report_facts.py` must expose its
   `sources` dict's keys as a real module-level constant (e.g.
   `COVERAGE_SOURCE_NAMES = frozenset(sources)`, or the `sources` dict
   built from iterating a constant key-tuple instead of a literal, so
   there is one source of truth rather than two), mirroring
   `OVERSIZE_SCAN_LAYERS`'s own existing shape — extracting an already-
   present set of literals into a named constant, not new detection logic
   or a schema/output change, so it does not conflict with §0.2's non-goals
   any more than §12's own required test-fixture work does. Once that
   constant exists, `TargetedGrant.source` gets the identical
   `set(g.source for g in cap.grants) <= COVERAGE_SOURCE_NAMES`
   construction-time check `.scopes` already gets above, and a
   `set(build_coverage_report(...).sources) == COVERAGE_SOURCE_NAMES`
   test per hunter guards against the constant and the literal drifting
   apart. Until that constant lands, `.source` correctness remains a
   code-review-time obligation for whoever writes the first real grant —
   but landing it is now a stated precondition of that work, not an
   optional nicety left to "consider."

   **Revision note (closed by #71):** all five `COVERAGE_SOURCE_NAMES`
   constants landed with #71's own registry module
   (`dumpex/hunt/{pipe,stomping,cs_beacon,yara_hunt,encoding}/
   report_facts.py`), each imported into `dumpex/hunt/_registry.py` and
   checked against every `TargetedGrant.source` at `AnalyzerSpec`
   construction time — the gap this paragraph describes is closed, not
   merely planned. A future reader should not re-derive it as still open.

   **Revision note (`.scope` premise corrected by #71):** the "for the
   other four targeted-capable identities (`pipe`/`stomping`/`yara`/
   `cs-beacon`, none of which emit a `scope` on their own
   `CoverageLimitation`s, §1)" clause above (and the earlier "only
   `obfuscation` emits a `scope` on any `CoverageLimitation` today"
   restatement of it, also above), plus the parallel claim in §1's own
   `TargetedGrant`/`TargetedCapability` bullet ("For the other four
   targeted-capable analyzers, `scopes` is expected to stay empty (no
   sub-source distinction exists in their own `report_facts.py` today)"),
   are **both false as written** — a direct read of the tree #71 actually
   did (not merely "considered") shows `pipe` (`pipe_name_scan`,
   `scope="c2_context"`/`"pipe_name"`), `yara` (`segment_scan`,
   `scope="max_total_hits"`/a budget-exhaustion kind), and `cs-beacon`
   (`segment_scan`, `scope=`a budget-exhaustion kind) each already emit a
   non-`None` `scope` on some `CoverageLimitation` today. What both
   clauses were actually reaching for, and what remains true, is narrower:
   only `obfuscation`'s `encoding_scan` source has a **closed,
   statically-importable** scope vocabulary (`OVERSIZE_SCAN_LAYERS`) —
   the other three's `scope` values are dynamic budget-kind/sub-signal
   tags with no fixed constant to validate a `TargetedGrant.scopes` value
   against yet, not an absence of `scope` altogether. `dumpex/hunt/
   _registry.py`'s own `_SCOPED_TARGETED_SOURCES` mapping (each entry
   carrying its own `(source, scopes)` pair, not merely a source name
   validated against a shared hard-wired constant — a second, later
   correction within the same #71 change) and its five
   `test_*_scope_emitting_branches_*` tests in
   `tests/unit/test_analyzer_registry.py` are the corrected, CI-enforced
   statement of this fact — extending that mapping to `pipe`'s own
   `"c2_context"`/`"pipe_name"` distinction (a real, reasonable future
   candidate) is a `#59` capability-matrix decision, exactly as this
   document's own extension rule (§7.1 failure #5, above) already
   describes for any such addition, not a forgotten update to either
   clause above.

   **Not** a failure: `full_scope_capable=False` paired
   with a non-`None` `targeted_capability` — that combination is a
   legitimate targeted-only analyzer, exactly what §10 item 4 requires
   this contract to allow a future analyzer to declare.

   Separately, and independent of the two rules above, **this release's
   seven registrations must satisfy exact-set equality against #58's
   approved list**:

   ```
   {spec.identity for spec in registrations if spec.targeted_capability is not None} \
       == {"pipe", "stomping", "cs-beacon", "yara", "obfuscation"}
   ```

   checked once, over the full registration set, not per-spec — so both
   directions fail construction: `injection` or `hollowing` declaring a
   non-`None` `targeted_capability` (over-grant), and any of the five
   approved identities declaring `None` (under-grant, which would
   silently make a real targeted-capable analyzer unreachable through
   `select_targeted()` — §6). An earlier draft of this contract phrased
   this rule as "targeted_capability set on an identity outside the
   approved five is rejected only for this release's own registrations,"
   which is vacuous by construction (every registration this release
   makes *is* one of "this release's own registrations," so the clause
   excluded its own subject and enforced nothing) — corrected here to a
   concrete, checkable equality. This exact-set check binds **only this
   release's seven registrations**; when `HUNTERS` grows (§10), the
   right-hand side of the equality is exactly what §10 item 5's extension
   checklist updates in the same reviewed change — it is not a separate,
   independent whitelist a future analyzer must somehow also satisfy.
6. **Wrong report type** — `report_type` is not the **exact** class §3's
   matrix names for that identity, checked by identity comparison against
   a closed, hard-coded mapping the registry module itself owns —

   ```
   EXPECTED_REPORT_TYPES = {
       "injection":   InjectionReport,
       "hollowing":   HollowingReport,
       "stomping":    StompingReport,
       "pipe":        PipeReport,
       "cs-beacon":   CSBeaconReport,
       "yara":        YaraReport,
       "obfuscation": EncodingReport,
   }
   assert set(EXPECTED_REPORT_TYPES) == set(HUNTERS)   # itself checked once, not per-spec
   if spec.identity not in EXPECTED_REPORT_TYPES:
       raise InvalidAnalyzerSpec(f"{spec.identity}: no expected report_type on file")   # failure #6
   if spec.report_type is not EXPECTED_REPORT_TYPES[spec.identity]:
       raise InvalidAnalyzerSpec(f"{spec.identity}: wrong report_type")   # failure #6
   ```

   `EXPECTED_REPORT_TYPES` is itself a **roster artifact** (§1, §10 item
   2) — a twelfth place `HUNTERS`' membership is written down by hand,
   alongside `_all_specs()` (§6, the eleventh) — and `set(EXPECTED_REPORT_TYPES)
   == set(HUNTERS)` is its own construction-time assertion, checked once
   (not per-spec, since it doesn't vary per spec), so a future analyzer
   whose author added it to `HUNTERS` but forgot the corresponding
   `EXPECTED_REPORT_TYPES` entry gets a named `InvalidAnalyzerSpec`
   failure identifying the missing identity — never a bare `KeyError`
   from `EXPECTED_REPORT_TYPES[spec.identity]` with no diagnostic
   information about *which* roster artifact was forgotten, which is what
   an earlier draft of this check would have raised.

   — **not** `isinstance(report_type, type)`, which every one of the
   seven domain `Report` classes would trivially satisfy regardless of
   which one was actually assigned to which spec. **An earlier draft of
   this check compared `report_type.__module__` against
   `spec.package + ".domain"` instead of exact identity, and that check
   is insufficient, not merely weaker**: every `<pkg>/domain.py` module
   defines more than one class (confirmed: `dumpex/hunt/injection/
   domain.py` alone defines `CoverageSnapshot`, `InjectionEvidence`, and
   `InjectionReport`), so a same-module mis-registration —
   `AnalyzerSpec(identity="injection", package="dumpex.hunt.injection",
   report_type=InjectionEvidence, ...)` — has the same `__module__` as the
   correct assignment and would have passed a `__module__`-only check.
   The exact-identity comparison above closes that gap directly, at
   construction time, with no runtime call and no `mf`/dump involved —
   `EXPECTED_REPORT_TYPES`' values are the same seven classes the
   registry module already imports to build `builder`/`renderer`/
   `record_projector` bindings for (§8), so this requires no import
   beyond what #71's own module already needs, and stays inside §11's
   "no imports merely to enumerate capabilities" rule (these are the
   registry's own compile-time imports, not a discovery mechanism). This
   check does **not** additionally compare against a `builder` return-type
   annotation: none of the seven current builders carries one — e.g.
   `_build_yara_report(mf: MinidumpFile, rules_dir: str = None):`, no
   `->` at all — so an annotation-based cross-check would be a silent
   no-op today.

   A **second**, defense-in-depth check remains valuable even with the
   construction-time comparison above, and #71 should still add it
   (§12): `isinstance(spec.builder(mf), spec.report_type)`, run against
   the real returned object — this catches the different bug the
   exact-identity check *cannot*: a `builder` that is correctly wired but
   whose own implementation constructs the wrong type at runtime (a typo
   inside `_build_injection_report()` itself, say), which no static
   comparison of declared fields can see. Construction-time exact-identity
   comparison and this runtime instance check catch two different bugs,
   at two different times, and this contract requires both — the runtime
   check is a genuine belt-and-suspenders addition now, not (as an earlier
   draft implied) the *only* thing standing between an invalid `report_type`
   and a passing construction.
7. **Incompatible adapter** — `builder`/`renderer`/`record_projector` is
   missing or not callable; or `option_names` and `builder`'s own
   non-`mf` keyword parameters disagree **in either direction** — a name
   in `option_names` that `builder` doesn't accept, or a keyword
   `builder` accepts that isn't in `option_names`, both fail construction.

   **What gets `inspect.signature()`'d is not `spec.builder`.** §5/§8
   require `spec.builder` itself to be a late-bound seam (e.g.
   `lambda *a, **kw: getattr(sys.modules["dumpex.hunt"],
   "_build_injection_report")(*a, **kw)`) so it re-resolves the
   dispatcher-facing name on every call — and `inspect.signature()` on a
   generic `*a, **kw` wrapper like that yields nothing usable; a check
   written against `spec.builder` directly could never validate a real
   option name and this whole failure mode would be unenforceable as
   written in an earlier draft of this contract. The registration code
   inside the registry module — not `AnalyzerSpec.__post_init__`, and not
   anything stored on the spec — already knows the literal attribute name
   (`"_build_injection_report"`, etc.) as a local value at the moment it
   builds each registration, because it is the code writing that literal
   string into the wrapper in the first place. It resolves the *target*
   once, right there (`target = getattr(sys.modules["dumpex.hunt"],
   "_build_injection_report")`), validates `option_names` against
   `inspect.signature(target).parameters` **before** wrapping it into the
   late-bound `builder` closure, and only then constructs the
   `AnalyzerSpec`. This validates the real function's real signature — at
   registration/construction time, when facade imports are already
   complete (§6's own import-ordering guarantee) so `target` is the real,
   final function, not a stub — while leaving `spec.builder` itself free
   to keep re-resolving the name on every subsequent call (§8), so
   monkeypatching after construction is untouched by this check having
   already run once at construction time. No eleventh `AnalyzerSpec`
   field is needed for this — the attribute-name string is local to the
   registration call, never part of the spec's own closed field set (§5).
   A one-directional check (rejecting only "target accepts more than
   declared") would let an over-declared `option_names` pass construction
   and only fail with a `TypeError` mid-invocation, after `mf` is already
   open — exactly the "before any analyzer work begins" guarantee this
   section exists to provide.

   **`renderer` and `record_projector` get the identical resolve-then-
   inspect treatment `builder` does above — `callable(...)` alone is not
   enough.** A `bad_renderer(report)` missing the `verbose` parameter, a
   `bad_renderer(report, verbose, config)` with an unexpected required
   third parameter, a `bad_renderer(report, verbose)` where `verbose`
   has no default (so a caller invoking `renderer(report, verbose=True)`
   works but `renderer(report)`-style call sites elsewhere in the
   codebase would not), or a `record_projector` accepting any parameter
   beyond `report` — all of these are `callable`, so a shape check that
   stops at `callable(renderer)`/`callable(record_projector)` accepts
   every one of them, deferring the failure to a `TypeError` at whatever
   later moment something actually calls the adapter with real
   arguments, which can be well after `mf` is open and a scan has run.
   The same registration-time resolve-then-inspect pattern used for
   `builder`/`option_names` above closes this: resolve each target
   (`getattr(sys.modules["dumpex.hunt"], "_render_injection_console")`,
   `getattr(dumpex.hunt.injection.report_record, "project_hunter_record")`
   or equivalent — §3's own two-hop-alias discussion) and validate its
   `inspect.signature(...).parameters` accepts exactly `(report,
   verbose=<default>)` for the renderer and exactly `(report)` for the
   projector, before wrapping either into its own late-bound closure —
   never against the wrapper itself, for the same reason given above for
   `builder`.

   What this construction-time signature check cannot see is *return*
   type — a `renderer` that accepts the right parameters but returns
   something other than a `dict`, or a `record_projector` that returns
   something other than a `HunterRecord`, both pass every check above and
   can only be caught by actually calling them. This contract requires
   that as a **runtime** check, not a construction-time one (§12): once a
   `Report` is built for any compat-freeze/architecture fixture already
   in this contract's scope, assert `isinstance(spec.renderer(report,
   False), dict)` and `isinstance(spec.record_projector(report),
   HunterRecord)` against the *same already-built* `Report` those
   fixtures already construct — this adds no second scan (§8's
   same-instance invariant already requires one `Report` per fixture
   scenario) and needs no new `mf`/dump beyond what those fixtures
   already build.
8. **Retained mutable state** — any field holds a dump handle, a raw scan
   buffer, or any other mutable/live parser object rather than a callable
   or an immutable value (#69's own Resource and safety constraint: "Do
   not retain raw scan buffers or mutable parser objects in global
   registry entries" — §5's own closing paragraph).

### 7.2 Call-time (per invocation)

9. **Unknown identity** — `identity`/`selected` is not a real `HUNTERS`
   member, passed to **any** of the three identity-accepting *production*
   operations §6 exposes (`_all_specs()` takes no identity argument and
   cannot trigger this failure — it is excluded from this count, §6):
   `get(identity)` and `select_targeted(identity, source, scope=None)`
   where `identity` is
   not in `HUNTERS` (this includes `identity="all"` — `"all"` is a valid
   `select()` argument but never a valid `get()`/`select_targeted()`
   argument, since it is not a registered spec, §4), and
   `select(selected)` where `selected` is not in `HUNTERS ∪ {"all"}`. All
   three raise the **same** canonical, unformatted exception (e.g.
   `UnknownAnalyzerIdentity`, carrying the offending value and the valid
   set for that operation) — one exception type, three call sites, so
   `HuntRequest` construction (§9) can catch one thing regardless of
   which registry operation it went through. For `select()` specifically,
   this exception does **not** attempt to
   reproduce either caller's own message text, because the two existing
   callers' texts are not the same string and no single `select()` return
   value can equal both: `collect_hunt()` raises `ValueError(f"collect_
   hunt() got unknown selected={selected!r} -- must be 'all' or one of
   {HUNTERS}")` (`dumpex/hunt/__init__.py:109-113`), while `cmd_hunt()`
   prints `RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(
   valid))}")` and calls `sys.exit(1)` (`:200-203`) — different wording,
   different sort order (`cmd_hunt()` sorts, `collect_hunt()` doesn't),
   different failure mechanism (exception vs. print-and-exit) entirely.
   #72's compatibility obligation is: each caller catches `select()`'s one
   canonical exception and re-emits **its own existing, unchanged** text
   from it — `collect_hunt()` keeps raising its own `ValueError` text,
   `cmd_hunt()` keeps printing its own `RED(...)` text and exiting 1 — so
   the byte-identical guarantee lives at the two call sites (§12), not
   inside `select()` itself.
10. **Unsupported capability** (`AnalyzerRegistry.select_targeted(identity,
    source, scope=None)`, §6) — `identity` is a **real, registered**
    `HUNTERS` member (already
    past failure #9) whose `targeted_capability` is `None` (`injection`,
    `hollowing`, or any future analyzer that didn't opt in per §10 item
    5). Distinct from failure #9: the identity is valid, the requested
    *mode* is not. `select_targeted("all")` is failure #9, not this one —
    `"all"` is rejected because it is never a registered identity to
    begin with (§4), before capability is even consulted; failure #10 is
    reached only once identity resolution has already succeeded. Fails
    closed before any analyzer work begins, matching #58's own explicit
    rule: "rejects `--hunt all`, `injection`, `hollowing`, and future
    hunters without an explicit targeted-scan capability" — the `all`
    half of that rule is enforced by failure #9, the `injection`/
    `hollowing`/future-analyzer half by this one.
11. **Unsupported full-scope request** (`AnalyzerRegistry.select(identity)`,
    single-identity branch, §6) — `identity` is a real, registered
    `HUNTERS` member whose `full_scope_capable` is `False`. This release's
    seven are all `full_scope_capable=True` (§3), so failure #11 is
    unreachable *today* — it exists for the day §10 item 4's targeted-only
    analyzer is registered, at which point its identity is a legal
    `--hunt` argument (it is in `HUNTERS`, and therefore in the CLI help
    text and `test_hunter_roster_alignment.py`'s own `list(HUNTERS) +
    ["all"]` assertion — §1) but must still be rejected the moment
    `select()` resolves it, before `mf` is touched. This is the
    single-identity mirror of failure #10: #10 gates the targeted path
    against an analyzer with no targeted capability, #11 gates the
    full-scope path against an analyzer with no full-scope capability —
    the two together are what make `full_scope_capable`/
    `targeted_capability` actual enforcement points rather than
    descriptive-only fields (§5 fields 9–10).
12. **Unpopulated targeted grant** (`AnalyzerRegistry.select_targeted(identity,
    source, scope=None)`, §6) — `identity` is real and `targeted_capability`
    is non-`None` (past failure #10), but `targeted_capability.grants` is
    empty.
    **`frozenset()` means "no source-level grant has been declared
    yet" — never "no restriction, everything is targeted-capable."** This
    is the fail-closed reading §1's own `TargetedCapability` bullet
    requires, stated here as the actual enforcement point rather than left
    as prose alone: the whole reason `grants` exists is to stop
    a bare `scan_unit` tag from implying "every check this analyzer owns
    is targeted-capable" (§1 — `stomping`'s IOC-scan-only distinction is
    the concrete case this was added to express); shipping five specs
    with `targeted_capability` non-`None` but `grants` empty,
    with `select_targeted()` treating that the same as a real grant, would
    reproduce exactly the fail-open outcome the field was introduced to
    prevent — and exactly the alternative #70 itself rejects: "Treat
    every analyzer as targeted-capable by default: fails open and can
    overstate scan scope." This release's five targeted-capable specs
    (§3) all have `grants = frozenset()` (§10 item 5 — #59 decides its
    contents, #61 writes it, §0.2), so failure #12 fires for **all five**
    of them today, unconditionally — this is expected and correct, not a
    defect: there is no targeted-scan CLI entry point in this release at
    all (#59–#65 add one), so nothing today calls `select_targeted()` for
    a real invocation; the failure exists so that the day something does —
    prematurely, by a bug, or via #61 before #59's grant decision and
    #61's own population land — it fails closed instead of silently
    authorizing an unscoped scan. Once #61 writes a real, non-empty
    `grants` for a given identity (from #59's own decision), failure #12
    stops firing for that identity specifically; populating it is exactly
    the act that turns the grant "on."
13. **Unsupported targeted source** (`AnalyzerRegistry.select_targeted
    (identity, source, scope=None)`, §6) — `identity` has a real, populated
    grant (past failure #12), but no `TargetedGrant` in
    `targeted_capability.grants` has `.source == source`. E.g. requesting
    `source="reference_files"` against `stomping`, whose only granted
    source is `"ioc_string_scan"` (§1) — `"reference_files"` is
    deliberately a **real** entry in stomping's own public `sources` dict
    (`report_facts.py:241-255`): whether a reference directory was
    supplied at all, gated on `ref_dir_supplied`. Its sibling
    `"section_content_diff"` is the disk-reference comparison itself
    (`present=True`, unconditional) and is likewise ungranted, making
    either name a valid choice for this test — naming both here rather
    than conflating them keeps §1's own point precise: the test that
    exercises this failure must reject a source that genuinely exists and
    genuinely runs but was never granted — rejecting a merely-unknown/
    misspelled string
    would pass under a weaker implementation that treats every *real*
    source name as implicitly authorized and only rejects garbage input,
    which is exactly the failure mode `TargetedGrant` exists to prevent
    (§1: stomping's disk-reference comparison must never be treated as
    targeted-capable merely because its IOC scan is).
14. **Unsupported targeted scope** (same call) — `source` matches at
    least one `TargetedGrant` (past failure #13), but no matching grant
    satisfies §6's own symmetric `authorized` test: `(grant.scopes is
    empty and scope is None)` **or** `(grant.scopes is non-empty and
    scope is a member of it)`. Stated as the three ways this fails,
    matching §12's own required fixture (a)–(c) exactly — §12's (d) is the
    positive control (a legal, named scope, which must succeed), not a
    fourth failure way, so it has no counterpart here by design — an
    earlier draft of this failure entry described only the third:
    1. `grant.scopes` is empty but the requested `scope` is not `None`
       (e.g. `select_targeted("pipe", "pipe_name_scan", scope=
       "arbitrary-invalid-scope")`) — an empty `scopes` means "this
       source has no finer subdivision, only a scope-less request is
       satisfied," **never** "unrestricted, any scope is accepted." An
       earlier draft of both this failure entry and §6's own matching
       code read empty `scopes` as the latter, which is itself a fail-open
       bug §6's own text now documents and rejects — restated here so
       the two sections describe the same corrected rule, not two
       different ones.
    2. `grant.scopes` is non-empty but the requested `scope` is `None`
       (e.g. `select_targeted("obfuscation", "encoding_scan", scope=
       None)`) — a source with named scopes requires the caller to pick
       one; omitting `scope` is not itself a wildcard.
    3. `grant.scopes` is non-empty and `scope` is not `None`, but `scope`
       is not among the named members (e.g. `scope="unpack"` against
       `obfuscation`'s `{"sleep_mask", "entropy", "decode"}`) — the case
       an earlier draft of this entry described in full and the other two
       omitted.

---

## §8 Late-binding and monkeypatchability

`tests/integration/test_collect_hunt_single_scan.py:46-66`
(`_patch_counters()`) proves the exact seam that must survive #72's
cutover: it patches `_build_<pkg>_report` **on `dumpex.hunt` itself**
(`hunt_pkg = dumpex.hunt`, the dispatcher module) — the *second* binding
created by `dumpex/hunt/__init__.py`'s own `from dumpex.hunt.injection
import _build_injection_report`-style imports — not the origin binding on
`dumpex.hunt.injection`. This is the same "second binding" hazard
`dumpex/hunt/_runtime.py`'s own module docstring already documents for a
single hunter's internal submodules, now true one level up, at the
dispatcher/registry boundary.

Therefore: `AnalyzerSpec.builder`/`.renderer`/`.record_projector` must
**not** be plain function references captured once when the registry
module is imported. #71 must resolve each through a late-bound seam that
reads the current value of the dispatcher-facing name at **call** time —
e.g. `getattr(sys.modules["dumpex.hunt"], "_build_injection_report")`
(deliberately via `sys.modules`, not a module-level `import dumpex.hunt`
inside the registry module itself — see §6's own "Module layout and
import timing" note on why a top-level `import dumpex.hunt` there risks a
circular import) — so `monkeypatch.setattr(hunt_pkg, "_build_injection_
report", fake)` keeps working, unchanged, after #72. A registry that
resolves these once at import time would silently break this test and
every fixture built the same way, without any visible error — the single
most important compatibility hazard this contract names.

The corollary call-count invariant — every selected analyzer's builder
invoked **exactly once** per invocation, an unselected analyzer's builder
**never** invoked — must hold through `AnalyzerRegistry.select()` exactly
as it holds through today's `if _wanted(hunter):` branches
(`dumpex/hunt/__init__.py:119-132`) and `if run_<hunter>:` branches
(`:229-263`). This is not a new rule; it is `test_collect_hunt_single_scan.
py`'s own guarantee, named as a compatibility fixture in §12.

**Same seam, all three adapters.** §5 fields 4–6 (`builder`, `renderer`,
`record_projector`) are late-bound identically — none is a plain captured
reference, all three resolve through whatever name the dispatcher module
currently exposes at call time. §3's discussion of `record_projector`'s
two-hop alias chain is the same hazard as this section's `builder`
example, not a different one.

**Same-instance invariant.** #70's own Evidence and coverage semantics
section states, as a hard requirement, "Renderer and projector must
consume the same report instance" — not merely "call the builder once."
Today this holds by construction: `cmd_hunt()` binds `report =
_build_injection_report(mf)` to a local and passes that *same* Python
object to both `_render_injection_console(report, verbose)` and
`_record_from_injection_report(report)` (`dumpex/hunt/__init__.py:230-232`
and the six analogous blocks through `:263`). A registry-driven call path
that instead did `spec.renderer(spec.builder(mf))` followed by
`spec.record_projector(spec.builder(mf))` would still satisfy the
call-count invariant above (each *symbol* still called once per
statement) while silently building **two separate `Report` instances**
from two separate scans — the call-count fixture would not catch this,
because it counts invocations of the builder symbol, not distinctness of
the object handed to the other two adapters. #71/#72 must thread one
already-built `Report` into both `renderer` and `record_projector`
explicitly (§12 needs a fixture asserting `id(report)` identity across
both consumers, since none of today's fixtures asserts this directly —
they only prove single-build via call count, which is necessary but not
sufficient for this stronger guarantee).

**`collect_hunt()` never calls `renderer`.** Because `renderer` prints
(§1), and `collect_hunt()`'s own silence guarantee
(`tests/integration/test_collect_hunt_is_silent.py`, §12) must survive
#72's cutover unchanged, the registry-driven `collect_hunt()` path must
call only `spec.builder` and `spec.record_projector` for each selected
analyzer — never `spec.renderer` — exactly mirroring today's
`collect_hunt()`, which already never calls any `_render_*_console`
function (`dumpex/hunt/__init__.py:88-137`). Only `cmd_hunt()`'s console
path calls `spec.renderer`.

---

## §9 Registry vs `HuntRequest` vs `HuntExecutionContext` vs `ObservationRegistry`

Each of the four types answers one question, at one scope, and never
answers another's:

| Type | Owner | Scope | Question it answers | Never holds |
|---|---|---|---|---|
| `AnalyzerRegistry` | #71 (this contract) | process-wide, one instance, import-time | "What analyzers exist, and what can each one do?" | a dump handle, a per-call option *value*, scan results, budgets already consumed |
| `HuntRequest` | #61 | one `--hunt` invocation, immutable once built | "What was asked for, this call?" — the single selected identity or the `"all"` selection word (§6; no multi-identity selection exists in the CLI today, so `HuntRequest` should not invent one), option values keyed by **builder** parameter name (`ref_dir`, `rules_dir` — `rules_dir` is `cmd_hunt`/`cli.py`'s own `yara_dir` CLI parameter renamed at the builder boundary, `dumpex/cli.py:437-438` → `_build_yara_report(mf, rules_dir=...)`; #72 must keep `cmd_hunt(..., yara_dir=...)`'s own external parameter name, only the internal `HuntRequest`/builder-facing key is `rules_dir`), and (post-#59/#60) an optional targeted range | scan results, mutable execution state |
| `HuntExecutionContext` | #61 | one invocation, mutable during execution | "What's available while this call is running?" — the `mf` handle, budgets in play, `HunterRuntime`-style late-bound dependency snapshots | a second capability map, identity/order validation (already done at `HuntRequest` construction) |
| `ObservationRegistry` | #61 (keyed/scoped under #61, per #70's own Evidence and coverage semantics section: "Observation reuse is keyed and scoped under #61; it is not a property of global analyzer registration") | one invocation, accumulates during execution | "What has already been read, this call?" — memoized already-scanned content for reuse by a later targeted rescan or PEB analyzer | capability metadata, identity validation, anything true beyond one invocation |

Concretely: `HuntRequest` is validated against `AnalyzerRegistry` exactly
once, at construction (an invalid identity/option/capability never
reaches `HuntExecutionContext`); `AnalyzerRegistry` itself is never
consulted again mid-execution, and never stores per-invocation state.
`ObservationRegistry` is not a second analyzer catalog and must not grow
its own capability flags — a source or segment being "already observed"
is an execution-time fact, not a registration-time one. This split is the
one #61 must build against without inventing an alternative boundary or a
second capability map, per #69's own explicit instruction.

Two more of #70's own hard requirements bind across this whole boundary,
not just one type, and are recorded here so #61/#62–#64 don't have to
re-derive them: **"Capability metadata cannot disable analyzer budgets or
authorize unbounded work"** — `targeted_capability`/`full_scope_capable`
(§5 fields 9–10) are declarations that a code path *exists*, never a lever
that widens `dumpex.hunt._budget`'s existing byte/time/candidate/match/
decode/evidence-retention limits (#58's own rule that a targeted scan
bypasses only the per-region/per-segment size cap, "total-byte, time,
candidate, match, decode-output, and retained-evidence budgets remain
enforced" applies with equal force at the registry layer); and
**"Registration metadata may declare capabilities but cannot manufacture,
transform, or upgrade evidence/coverage"** — no `AnalyzerSpec` field or
`AnalyzerRegistry` method may construct, edit, or promote a finding,
score, or `CoverageReport` value; every one of those stays owned by the
analyzer's own `aggregate.py`/`domain.py`, exactly as `HuntExecutionContext`
and `ObservationRegistry` (this table's other two rows) already keep
scan results out of their own "Never holds" column.

---

## §10 Extension rules for a future analyzer

A later issue proposing an eighth analyzer (or a ninth, for future PEB
work per #53) must satisfy every item below before `AnalyzerRegistry`
accepts it — none are optional, and none are inferred from an existing
analyzer's shape by default:

1. **Identity and order are a reviewed decision, not an append.** State
   the new identity's exact position in `HUNTERS`' order and justify it
   (cost, a dependency on another analyzer's output, console grouping) —
   never "wherever it was written," since §7 failure #4 rejects any
   registration whose position disagrees with the reviewed `HUNTERS`
   order.
2. **Every roster artifact, not just the schema.** `HUNTERS` is written
   down by hand in **ten** other places today (§1's "roster artifact"
   entry), and `tests/unit/test_hunter_roster_alignment.py` enforces
   **all ten already** — including the three human-facing ones (`--hunt`'s
   CLI help text, `docs/CLI_REFERENCE.md`'s `--hunt TTP` row, and
   `README.md`'s "Hunt overview" table), each checked by that test module
   actually running `cli.main()` or parsing the file, not merely by
   convention. The four schema enums (`hunterRecord.hunter`,
   `skipRelationship.hunter`, `recommendedAction.hunters.items`,
   `huntSummary.selected` — bump `CURRENT_SCHEMA` in the same change),
   the two console display maps (`summary_presentation._DISPLAY_NAME`,
   `summary_presentation._EVIDENCE_HUNTER_LABEL`), and
   `region_correlation._COLLECTORS` all need the new identity's key in
   the same change that adds it to `HUNTERS` — never inside a
   registry-only edit — but in every one of these ten cases, forgetting
   it is now a **CI failure**, not a silent gap for a human reviewer to
   catch. `_COLLECTORS` is nonetheless worth calling out specially: unlike
   the other nine, its *production* failure mode (independent of the test
   that catches the regression pre-merge) is silent — `build_region_
   correlations()`'s own lookup is `collector = _COLLECTORS.get(record.
   hunter); if collector is None: continue` (`dumpex/hunt/
   region_correlation.py:730-733`) — a missing entry does not raise, it
   silently drops that analyzer's signals from `--hunt all`'s CORRELATED
   REGIONS section while the command still reports `complete` coverage,
   in the hypothetical world where the CI check was itself skipped or
   weakened.

   #71's own `AnalyzerRegistry` module adds two **more** roster artifacts
   beyond these ten, both internal to the registry itself rather than
   pre-existing elsewhere in the tree, and both already self-checking
   (§6, §7.1 failure #6): the eleventh is the registry's own registration
   sequence (`_all_specs()`, checked against `HUNTERS` by §7.1 failures
   #2/#4 at construction time); the twelfth is `EXPECTED_REPORT_TYPES`
   (§7.1 failure #6's own `set(EXPECTED_REPORT_TYPES) == set(HUNTERS)`
   assertion). A new analyzer's own registration item (item 3, below)
   already requires touching both — this note exists only so an
   implementer scanning this checklist for "which files change" does not
   read "ten" and stop one file short inside `dumpex/hunt/`'s own
   registry module.
3. **One complete `AnalyzerSpec` registration** — every field in §5,
   with no partial/placeholder capability.
4. **`full_scope_capable` stated explicitly.** This release's seven are
   all `True`; a future analyzer that is genuinely full-scope-incapable
   (targeted-only, `full_scope_capable=False` with a non-`None`
   `targeted_capability` — §7.1 failure #5 permits exactly this
   combination) must say so, never default to `True` by omission.
   `select()` fails closed on it via §7.2 failure #11 the moment an
   investigator requests it through the single-identity `--hunt`
   path — but that identity is still a member of `HUNTERS`, and
   therefore still a legal CLI argument and still listed in `--hunt`'s
   own help text and `test_hunter_roster_alignment.py`'s `list(HUNTERS) +
   ["all"]` assertion (§1). The issue proposing a targeted-only analyzer
   must make an explicit choice about this, not leave it implicit: either
   (a, recommended) keep it listed and let `--hunt <identity>` fail with a
   clear "this analyzer is targeted-scan only" message (failure #11's own
   job), or (b) special-case the CLI help text and that roster assertion
   to exclude it from the full-scope argument list while still accepting
   it elsewhere (a materially larger change, since `HUNTERS` today has no
   notion of "listed but not directly selectable"). This contract does
   not choose between (a) and (b) — it requires the future issue to.

   **The same decision has an `--hunt all` side this contract also does
   not resolve on the future issue's behalf, but does require it to
   address explicitly.** §6's `select("all")` already excludes any
   `full_scope_capable=False` spec from a full-scope run (§2's corrected
   invariant) — so a targeted-only analyzer's registration, by itself,
   silently changes nothing about `--hunt all`'s *record count*. But that
   silence is exactly the problem: a registered, schema-listed,
   `HUNTERS`-listed analyzer that never appears in a "complete"
   `--hunt all` run, with nothing in `records`, `summary`, or console
   output saying why, is an undisclosed coverage gap — indistinguishable
   from that analyzer having simply been forgotten. This contract
   requires, but does not itself design, a disclosure mechanism: the
   future issue registering the first `full_scope_capable=False` analyzer
   must make `select("all")` excluding a spec **visible** somewhere in
   `--hunt all`'s own output (a `CoverageReport` limitation, a
   `Diagnostic`, a dedicated `summary` field — the concrete carrier is
   that issue's to choose, "must be visible" is what this contract
   freezes). That same issue must also explicitly update every fixture
   §12/item 7 name — item 7's own full-scope-vs-targeted-only fixture
   table is the single, authoritative list of exactly what changes for
   this case (not repeated or re-derived here, to avoid the "one fact,
   two places" problem §5 itself warns against for `coverage_status`) —
   as part of the same review, not as a follow-up discovered by a failing
   test.
5. **`targeted_capability` defaults to `None` (unsupported) and must be
   actively opted into** with a real `TargetedCapability` value — never
   inherited "because it's similar to an existing targeted-capable
   analyzer." This release's five targeted-capable specs ship with
   `grants = frozenset()`, real content pending #59's own capability-
   matrix decision and #61's own write of it into the registry (§0.2, §7.2
   failure #12 — the *entire point* being that emptiness means "not
   grantable yet," never "unrestricted," so it fails closed rather than
   open in the meantime). **A future analyzer opting in through this
   checklist item does not get the same grace period**: by the time an
   eighth analyzer's own frozen-contract issue (item 8) is proposed, #59
   and #61 are expected to have already landed (§0.3's dependency order),
   so that issue must give `grants` real, non-empty content at
   registration time — leaving it empty here would not be "this release's
   temporary state," it would be a new analyzer shipping permanently
   unable to pass §7.2 failure #12, unable to ever actually be
   targeted-scanned despite declaring `targeted_capability` non-`None`.
   This mirrors #70's own rejected alternative: "Treat every
   analyzer as targeted-capable by default: fails open and can overstate
   scan scope." §7.1 failure #5's exact-set equality check binds only
   this release's own seven registrations — growing `HUNTERS` means
   growing that equality's right-hand side in the same reviewed change,
   which is what this checklist item requires; it is the sanctioned
   extension path for that check, not a violation of it.
6. **Builder/renderer/record_projector use the same late-bound,
   monkeypatchable seam** as every existing analyzer (§8) — an analyzer
   whose dependencies are imported and called without that seam does not
   satisfy this contract regardless of what it detects.
7. **New compat-freeze fixtures**, matching §12's existing set — and the
   shape of these fixtures **depends on item 4's `full_scope_capable`
   decision**, not one fixed template for every future analyzer:

   - **Full-scope (`full_scope_capable=True`)**: a synthetic scenario
     builder in `tests/fixtures/hunt_cases.py`; a full key-set freeze
     entry in `tests/integration/test_hunt_compat_freeze.py`; new golden
     files under `tests/fixtures/hunt_cli_golden/` for a `--hunt
     <identity>` run (normal and verbose console, plus JSON); an updated
     `all_console.txt`/`all_hunt_dict.json` golden and an updated
     `build_hunt_summary(records, selected="all")` count expectation
     (record count +1, since `--hunt all` genuinely includes it); both
     hard-coded seven-call lists in `test_hunt_all_seven_collectors.py`
     extended to eight (§12 — both call sites, not one); an added row in
     `test_collect_hunt_single_scan.py`'s `_BUILDER_ATTR` table; that
     file's two `@pytest.mark.parametrize("selected", HUNTERS)` cases
     (`test_collect_hunt_single_hunter_calls_only_that_builder_once`,
     `test_cmd_hunt_collect_records_single_hunter_calls_only_that_builder_
     once` — §12) continue to exercise this identity's normal, successful
     single-analyzer path unchanged; and that file's two `"all"` cases
     (`test_collect_hunt_all_calls_each_builder_exactly_once`,
     `test_cmd_hunt_collect_records_all_calls_each_builder_exactly_once`
     — §12) need no change at all, since a full-scope addition is exactly
     what their `== HUNTERS`/per-hunter `len(counts[hunter]) == 1`
     assertions already expect once `HUNTERS` grows.
   - **Targeted-only (`full_scope_capable=False`)**: **no** `--hunt
     <identity>` console/JSON golden — that path is a `select()` capability
     failure (§7.2 failure #11) by design, so the correct fixture is a
     negative assertion (the specific exception/exit behavior, not a
     successful-run golden); `all_console.txt`/`all_hunt_dict.json` may
     still change, but only because of item 4's own disclosure
     requirement (a visible "excluded, targeted-only" signal), never
     because of a record-count change — `--hunt all`'s record count is
     unaffected by a `full_scope_capable=False` registration (§6's
     `select("all")` filtering, §2). `test_hunt_all_seven_collectors.py`'s
     **two hard-coded lists ARE still extended to eight, `== HUNTERS`
     unchanged** — an earlier draft of this item said otherwise ("that
     file proves the full-scope collector set, which this identity is not
     a member of"), which was wrong: that file calls each
     `collect_<identity>_record(mf)` compat wrapper directly (§12) and
     never goes through `select()`/`select_targeted()` at all, so
     `full_scope_capable`/§7.2 failure #11 do not apply to it — its own
     `collect_<identity>_record()` produces a normal `HunterRecord`
     regardless of full-scope capability, and its assertion is literally
     `== HUNTERS` (`tuple(r.hunter for r in records) == HUNTERS`, §12),
     which becomes false the moment `HUNTERS` grows to eight members and
     the call list does not — leaving it at seven calls is what would
     break this fixture, not what keeps it correct; §12's own description
     of this file is the authoritative one, not this item's earlier text.
     `test_collect_hunt_single_scan.py`'s `_BUILDER_ATTR` row is still
     added (its builder is still real and still called exactly once when
     validly invoked), and — because it calls each identity's
     `collect_<identity>_record()`/`_build_*_report()` compat path
     directly, not `select()` — `tests/fixtures/hunt_cases.py` still needs
     a synthetic scenario for it and `test_hunt_compat_freeze.py` still
     needs its key-set freeze entry, same as the full-scope branch above,
     for exactly the same reason `test_hunt_all_seven_collectors.py`'s two
     call-lists still get extended above: none of these fixtures route
     through `select()`, so none of them are exempted by
     `full_scope_capable=False`. What genuinely differs for this identity
     is only the **`select()`/`select_targeted()`-routed** surfaces:
     - Both `HUNTERS`-parametrized *single-selection* cases in
       `test_collect_hunt_single_scan.py` (§12) must branch on
       `full_scope_capable` — this identity's parametrized case in each
       asserts the §7.2 failure #11 capability failure, not a successful
       `records == (selected,)`/per-hunter call-count outcome, since
       `collect_hunt(mf, selected)`/`cmd_hunt(mf, selected, ...)` **do**
       route through `select()`.
     - Both `HUNTERS`-coupled `"all"` cases in the same file
       (`test_collect_hunt_all_calls_each_builder_exactly_once`,
       `test_cmd_hunt_collect_records_all_calls_each_builder_exactly_once`)
       also route through `select("all")`, and must be updated the same
       way `test_hunt_all_seven_collectors.py` is *not*: their
       `== HUNTERS`/`sorted(HUNTERS)`/per-hunter `len(counts[hunter]) ==
       1` assertions become false the moment `HUNTERS` grows to eight
       while `select("all")` still filters this identity out (§2, §6) —
       they must be rewritten against the filtered set (`tuple(h for h in
       HUNTERS if registry.get(h).full_scope_capable)`, the same form §2's
       own corrected invariant uses), not left asserting the raw,
       unfiltered `HUNTERS` tuple. An earlier draft of this item omitted
       both of these two files' four `HUNTERS`-coupled tests entirely,
       leaving two of them (the `"all"` cases) primed to break on the
       registration this item exists to describe, with nothing in this
       checklist predicting it.

   An earlier draft of this item described one universal template
   ("`all_console.txt` also changes, since `--hunt all` now includes one
   more record") that is simply false for the targeted-only case §7.1
   failure #5/§10 item 4 explicitly permit — corrected here.
8. **A new analyzer is never automatically a compatibility-preserving
   change, even when no existing record's identity/order/shape changes —
   for either capability shape above.** For a full-scope analyzer,
   `--hunt all`'s output *as a whole* — record count, `HunterRecord`
   array length/positions, `summary` counts, overall verdict/status,
   possibly the process exit code, the CORRELATED REGIONS section,
   investigation-action counts, and the console summary card — changes by
   construction the moment it is registered. For a targeted-only
   analyzer, the record set is unaffected, but item 4's disclosure
   requirement still changes `--hunt all`'s own output (a new visible
   exclusion signal) and `--hunt <identity>` gains an entirely new
   failure mode (§7.2 failure #11) where none existed before — "the
   record count didn't change" is not the same claim as "nothing
   observable changed." Either way, every new analyzer therefore requires
   its **own** frozen-contract issue, following this document's own
   template, that explicitly evaluates schema/summary/console/exit-code/
   correlation impact before registration — item 1–7 above are this
   checklist's necessary conditions for that issue to satisfy, not a
   substitute for writing it.

---

## §11 First-release prohibition on dynamic/third-party analyzer loading

`AnalyzerRegistry` construction must not use `importlib.metadata.
entry_points()`, `pkgutil.iter_modules()` plugin-directory scanning, or
any other mechanism that discovers or imports analyzer code not already
reviewed inside `dumpex/hunt/` at the time #71's registry module is
written. Every `AnalyzerSpec` this release registers is defined, in one
place, inside the tree — no out-of-tree or third-party analyzer
registration path exists, and none may be added under this contract.

This is not "not yet implemented" scaffolding to fill in later — it is a
direct consequence of #70's own Resource and safety constraints:
"Catalog enumeration performs no dump reads, rule
compilation, imports with scan side effects, or buffer allocation." A
dynamic-discovery mechanism that imports arbitrary code at catalog-build
time cannot make that guarantee (an imported module can execute arbitrary
top-level code), so it is out of scope for the registry's design, not
merely deferred.

---

## §12 Compatibility fixtures and architecture tests

Later issues (#71 first, then #72/#73) must keep every one of these green
throughout the cutover — none may be weakened, skipped, or have its
target function silently re-pointed without re-verifying the guarantee it
names:

- **`tests/integration/test_collect_hunt_single_scan.py`** — the
  call-count/one-build proof (§8): every selected analyzer's builder runs
  exactly once, an unselected one never runs, for both `collect_hunt()`
  and `cmd_hunt(..., collect_records=True)`.
- **`tests/integration/test_collect_hunt_is_silent.py`** — `collect_hunt()`
  and every `collect_<identity>_record()` compat wrapper (§1 — named by
  public identity, e.g. `collect_obfuscation_record`, not by package)
  print nothing, even on a cold rules cache.
- **`tests/integration/test_hunt_all_summary_source.py`** — the `--hunt
  all` HUNT SUMMARY card reads only real `HunterRecord`s, never the
  legacy per-hunter `results` dict — proof a poisoned `results` value
  cannot leak into it.
- **`tests/integration/test_hunt_compat_freeze.py`** — full key-set
  freezes (`assert set(f) == {...}`) for every hunter across its detected/
  inconclusive/not-evaluated/clean states.
- **`tests/integration/test_hunt_cli_compat_freeze.py`** — the CLI-layer
  JSON/CSV/exit-code/full-console envelope. **Not** only `injection`:
  `tests/fixtures/hunt_cli_golden/` holds 29 golden files covering
  normal- and verbose-console text plus `hunt_dict.json` for **all seven**
  analyzers (`injection`, `hollowing`, `stomping` and
  `stomping_ioc_hit`, `pipe`, `cs-beacon` and `cs-beacon_multi`, `yara`,
  `obfuscation`), plus `all_console.txt`/`all_hunt_dict.json` for `--hunt
  all`'s complete summary card — every one of these is a byte-exact
  freeze #72 must reproduce exactly, not only `injection`'s. #72 must not
  resolve a golden diff by regenerating the golden file
  (`scripts/update_hunt_cli_goldens.py`) without a corresponding review of
  *why* the byte output changed — regenerating goldens to make a diff
  disappear is exactly how a real output-drift regression gets silently
  approved.
- **`tests/integration/test_hunt_dispatcher.py`** — narrower than it
  sounds: today it holds exactly one real test,
  `test_cs_beacon_config_fields_survive_dispatcher()`, which calls only
  `cmd_hunt(mf, "cs-beacon", verbose=False)` (never `collect_hunt()`) and
  guards specifically against the historical defect where `cmd_hunt()`'s
  own hand-rolled CS Beacon sanitization silently dropped a config field
  the hunter had added but the dispatcher didn't yet know about. It does
  **not** cover the other six analyzers today. #72 should extend this
  file to a `HUNTERS`-parametrized field-survives-the-dispatcher check
  (covering both `cmd_hunt()` and `collect_hunt()`) as part of the
  cutover — registry-driven dispatch removes the per-hunter hand-rolled
  reconstruction this test exists to guard against, which is exactly what
  makes a general version of it cheap to add and valuable to have before
  #72 lands, not only for `cs-beacon`.
- **`tests/integration/test_yara_provenance_attribution.py`** — proves
  `meta.yara_rules` reflects *this* run's own `RulesProvenance`, never
  `dumpex.hunt.yara_hunt.get_yara_provenance()`'s process-wide "last
  build" global. `AnalyzerSpec.provenance_hook` (§5 field 8) must keep
  reading `report.coverage.rules.provenance` off the `Report` instance
  passed to it — never falling back to that module-level global — or this
  fixture starts failing (or worse, silently passes while attributing a
  prior run's rules file to the current one).
- **`tests/hunt/test_output_source_architecture.py`** — the
  aggregate-returns-immutable-Report / Findings-stored-once /
  aggregate-consumes-evidence-not-dump / presentation-consumes-only-Report
  contracts every analyzer's own `aggregate.py`/`domain.py`/
  `report_console.py` boundary already satisfies. Note what this suite
  does **not** prove (§7.1 failure #6): it parametrizes over `REPORT_TYPES`
  as bare class objects and asserts properties of `aggregate.
  build_report()`'s own signature — it never calls any `_build_*_report()`
  facade function, so it does not confirm that calling `spec.builder(mf)`
  actually returns an instance of `spec.report_type`. This gap needs a new
  fixture (below) — it does not belong in this file, since it needs
  `AnalyzerRegistry` itself, which doesn't exist yet when this file's
  existing tests run.
- **(new, #71-owned)** `#71`'s own registry test module (e.g.
  `tests/unit/test_analyzer_registry.py`) must add, alongside its
  construction/call-time failure-mode tests (§7), a fixture parametrized
  over all seven identities asserting `isinstance(spec.builder(
  empty_mf()), spec.report_type)` — the check §7.1 failure #6 names as
  currently unproven. Use an empty-segments `FakeMF` (every hunter's
  NOT_EVALUATED early-exit path, so this is cheap and needs no realistic
  dump). This exact `memory_segments_64 = None` / `memory_segments =
  None` `FakeMF` subclass is independently duplicated **six** times
  already, not two: `tests/integration/test_collect_hunt_single_scan.py:
  41-42`, `tests/integration/test_hunt_all_seven_collectors.py:48-49`,
  `tests/integration/test_collect_hunt_is_silent.py:47-48`,
  `tests/hunt/test_cs_beacon.py:27-28`,
  `tests/hunt/test_cs_beacon_collect.py:53-54`, and
  `tests/hunt/test_yara_hunt.py:71-72`. #71 should promote at least the
  three `tests/integration/` copies (the ones this contract's own fixture
  work already touches) to a shared `empty_mf()` in `tests/fixtures/
  fakes.py`, with those three files importing it from there — adding a
  seventh independent copy for this new fixture instead would make the
  duplication worse, not better. The three `tests/hunt/`-package copies
  are out of this contract's scope to migrate (they predate it and aren't
  otherwise touched by #71/#72), but are recorded here so a future
  cleanup doesn't have to rediscover the full count.
- **(new, #71-owned)** §7.2 failures #12/#13/#14 each need their own test
  — `select_targeted(identity, source, scope=None)` takes `source` as a
  **required** positional argument (§6), so every one of these calls must
  pass a real one; a bare `registry.select_targeted(identity)` raises
  `TypeError` before any capability logic runs at all, proving nothing
  about any of the three failure modes and must not appear in this
  fixture. A table of (identity, real public source name, real scope or
  `None`) grounds every case in an actual value rather than a
  placeholder, e.g.:

  ```
  TARGETED_CASES = (
      ("pipe",        "pipe_name_scan",  None),
      ("stomping",    "ioc_string_scan", None),
      ("yara",        "segment_scan",    None),
      ("cs-beacon",   "segment_scan",    None),
      ("obfuscation", "encoding_scan",   "sleep_mask"),
  )
  ```

  Required cases, each asserting the **specific named exception** for its
  failure number (never a bare `Exception`/`pytest.raises(Exception)`,
  which would pass just as well if the wrong failure — or a `TypeError`
  from a malformed call — fired instead, proving nothing about which gate
  actually caught it):
  - **Failure #12**: parametrized over `TARGETED_CASES`, `registry.
    select_targeted(identity, source, scope)` (this release's real,
    unpopulated registry) raises the failure-#12 exception for every
    entry — this release's actual shipped state (§3/§10 item 5).
  - **Failure #12, positive case**: a synthetic spec built directly (not
    via the real registry) with a non-empty `grants` whose one
    `TargetedGrant` matches the call's `source`/`scope` exactly —
    `select_targeted()` against that spec succeeds and returns it,
    proving the gate reads the field rather than always failing.
  - **Failure #13**: a `source` not present in any grant, using a **real**
    stomping source that is deliberately not the granted one (e.g.
    `select_targeted("stomping", "reference_files")` against a synthetic
    spec whose only grant is `ioc_string_scan` — `"reference_files"`
    (whether a reference directory was supplied, gated on
    `ref_dir_supplied`) and its sibling `"section_content_diff"` (the
    disk-reference comparison itself) are both confirmed to exist in
    stomping's own `sources` dict, `report_facts.py:241-255`, and either
    is a valid choice here — not an invented string) raises the
    failure-#13 exception — the exact distinction `TargetedGrant` exists
    to enforce (§1: stomping's disk-reference comparison must never be
    targeted-capable merely because its IOC scan is). Using a genuinely
    unknown string
    instead would only prove "rejects garbage input," not "rejects a
    real, running, but ungranted source" — the actual claim this failure
    makes; add an unknown-string case too if useful, but it must not be
    the *only* one, and this contract requires the real-source case as
    the primary one. An assertion that `"reference_files"` is actually a
    member of stomping's real `sources` (rather than assumed from this
    document's own prose) keeps the case from silently degenerating into
    the weaker unknown-string test if that source is ever renamed.
  - **Failure #14, four ways**, against synthetic specs (real grants
    still being empty this release): (a) a scope-less grant
    (`scopes=frozenset()`) with a non-`None` requested `scope` (the
    `pipe`/"arbitrary-invalid-scope" case §6 now documents as the bug an
    earlier draft's asymmetric match let through); (b) a scoped grant
    (`obfuscation`-shaped, `scopes={"sleep_mask", "entropy", "decode"}`)
    with `scope=None` (the second bug that same draft let through); (c) a
    scoped grant with a `scope` not among its named members (e.g.
    `"unpack"` against the `obfuscation`-shaped grant above); (d) a
    scoped grant with a legal, named `scope` (`"sleep_mask"`) — this one
    must **succeed**, not raise, proving the positive path isn't
    collateral damage from closing (a)–(c).

  Alongside these, one positive assertion **about the real registry's
  current shipped state**, worth pinning explicitly rather than leaving
  as an inference from other tests:
  `sum(1 for spec in registry._all_specs() if spec.targeted_capability is
  not None and spec.targeted_capability.grants) == 0` — this
  release genuinely has zero populated grants, and the assertion is
  written so it starts failing (loudly, as a test update needed, not
  silently) the exact day #61 writes the first real one (from #59's own
  decision) — **that same issue** (#61, or whichever of #62–#64 first
  populates a given identity's grant, per §0.2's ownership split) is the
  one expected to update this assertion, not #59/#60, which never touch
  `AnalyzerSpec` — rather than relying on this document's own prose to be
  remembered.
- **(new, #71-owned)** An architecture-boundary test asserting
  `AnalyzerRegistry._all_specs()` (§6) is referenced **only** from inside
  the registry module itself and from test files — never from
  `dumpex/hunt/__init__.py` or any other production module. `_all_specs()`
  returns every registered spec unfiltered by capability, and the leading
  underscore alone (§6) is a naming convention, not an enforcement
  mechanism — a future edit to `collect_hunt()`/`cmd_hunt()` that reached
  for it instead of `select()`/`select_targeted()` would silently bypass
  every capability gate §7.2 failures #10/#11 exist to enforce, with
  nothing in §7's own failure list positioned to catch it (those failures
  all fire *inside* `select()`/`select_targeted()`, which such a call
  would never go through). This is the same class of boundary check
  `tests/hunt/test_output_source_architecture.py` already runs for other
  layering rules — a grep/AST-based "no production import of
  `_all_specs`" assertion, not a runtime behavioral test, is sufficient
  and cheap.
- **`tests/integration/test_hunt_all_seven_collectors.py`** — **not**
  actually a `--hunt all` invocation (an earlier draft of this contract
  described it as one; corrected here): it directly calls all seven
  `collect_<identity>_record(mf)` compat wrappers itself, and asserts
  `tuple(r.hunter for r in records) == HUNTERS`, then validates the
  result against the packaged JSON schema — independently of `cli.py`,
  `cmd_hunt()`, `collect_hunt()`, and (once #71 lands) `AnalyzerRegistry`
  entirely. The seven-call list is hard-coded **twice**, not once — once
  in `test_all_seven_collectors_agree_with_hunters_own_fixed_order()`
  (`:53-63`) and again, independently, in
  `test_all_seven_collectors_feed_the_real_summary_reducer_and_validate()`
  (`:68-78`) — a new analyzer's manual extension (below) must edit both,
  since editing only one leaves the other silently covering one fewer
  analyzer than it appears to. This same file also `pytest.importorskip
  ("jsonschema")`s at **module** level (`:31`), so in an environment
  without `jsonschema` installed, both tests are skipped entirely —
  including the first one, which asserts only ordering and never actually
  needs `jsonschema` itself. #72 should not treat that skip as "the
  roster/order proof still ran" without checking; moving the
  `importorskip` into the second test function only (or a fixture scoped
  to it) would let the first, `jsonschema`-independent assertion keep
  running unconditionally — a low-cost fix worth making alongside the
  `_empty_mf()` promotion below, though not one this contract mandates.
  The list's hard-coded, `HUNTERS`-independent nature means it needs
  **manual extension** (both call sites, above) the same way
  `test_collect_hunt_single_scan.py`'s `_BUILDER_ATTR` table does (§10
  item 7) whenever a new analyzer is registered — full-scope or
  targeted-only alike, since this test's own list is not filtered by
  `full_scope_capable` at all (it simply doesn't know that concept). This
  is a fixture-maintenance fact, not a consequence of §6's `select("all")`
  filtering — it would need the same manual update even if
  `AnalyzerRegistry` didn't exist.
- **`tests/unit/test_hunter_roster_alignment.py`** — the ten-of-ten
  roster-artifact alignment suite (§1, §10 item 2): the four schema
  enums, `summary_presentation._DISPLAY_NAME`/`_EVIDENCE_HUNTER_LABEL`,
  `region_correlation._COLLECTORS`, and the three human-facing artifacts
  (CLI help, `CLI_REFERENCE.md`, `README.md`), each asserted against
  `HUNTERS` independently of `AnalyzerRegistry`. This module's own
  docstring explicitly delegates two *other* checks it does not attempt
  itself — "membership/order against the runtime dispatcher" — to
  `tests/integration/test_hunt_all_seven_collectors.py` (above) and
  `test_collect_hunt_single_scan.py` (already listed above); #71/#72 keep
  all three modules green, not only this one. #71 does not replace any of
  them — `AnalyzerRegistry` becomes the eleventh and twelfth places the
  roster is recorded (`_all_specs()` and `EXPECTED_REPORT_TYPES`, §10
  item 2), not a substitute for the other ten, and #71 should add two
  matching assertions here, both against the **unfiltered** full
  registration set (§6's new `_all_specs()`, never `select("all")` — using
  `select("all")` here would reproduce the exact mistake §2's own
  invariant was corrected to avoid, since `select("all")` is deliberately
  *not* the full roster once a targeted-only analyzer exists):
  `set(spec.identity for spec in registry._all_specs()) == set(HUNTERS)`,
  plus the reverse — every `_COLLECTORS`/display-map key has a matching
  spec in `registry._all_specs()` — so a future analyzer registered in
  `AnalyzerRegistry` but forgotten in
  `_COLLECTORS` fails CI instead of silently dropping correlation signals
  (§10 item 2).

  **Revision note:** #71 added the first (unfiltered) assertion exactly as
  specified, but deliberately did NOT add a second, separate `<=`
  assertion for the reverse direction: with `test_region_correlation_
  collectors_cover_exactly_hunters`/`test_summary_presentation_maps_
  cover_exactly_hunters` (both already `== set(HUNTERS)`) and the new
  `test_analyzer_registry_all_specs_covers_exactly_hunters` (also `==
  set(HUNTERS)`) all three already asserted as equalities against the
  same `set(HUNTERS)`, a fourth `_COLLECTORS <= registry._all_specs()`
  assertion is implied by transitivity of the three `==`s and cannot fail
  independently of them — it is a test with no way to catch a regression
  the other three would not already catch, not a second, independent
  guard. `tests/unit/test_hunter_roster_alignment.py`'s own
  `test_analyzer_registry_all_specs_covers_exactly_hunters` docstring
  records this reasoning inline rather than duplicating a
  cannot-fail-alone assertion.
- **`tests/fixtures/hunt_cases.py`** — the synthetic, `FakeMF`-backed
  fixture source every scenario above is built from; never real
  corpus-derived output (see `docs/hunt_migration_field_matrix.md`'s own
  revision note on why `tests/corpus/` output must never be committed).

#71 extends this set (adds registry-level unit tests for §5–§7's
construction/call-time failure modes, plus the roster cross-check above)
rather than replacing any of it; #72 re-points these fixtures' target
call path at `AnalyzerRegistry.select()` only once it can prove
byte-identical behavior against every one of them, golden files included.

---

## §13 Acceptance gate

This contract is complete when every item below holds, matching #70's own
suggested acceptance criteria:

- The seven-row matrix in §3 is reviewed and complete — confirmed here by
  direct read of all seven `dumpex/hunt/<pkg>/__init__.py` and
  `report_record.py` files, not sampled.
- Identity, order, option, provenance, report-type, and capability
  ownership are each stated exactly once (§2, §5) — never duplicated
  across two fields that could disagree, and `select()`/`select_targeted()`
  (§6) are the only two capability-gating checkpoints, never re-implemented
  ad hoc at a call site.
- `AnalyzerRegistry`, `HuntRequest`, `HuntExecutionContext`, and
  `ObservationRegistry` responsibilities do not overlap (§9's table), and
  neither budgets nor evidence/coverage can be widened or fabricated by
  registration metadata alone (§9's two closing invariants).
- Every invalid registry/capability state (§7) has a named, deterministic,
  fail-closed outcome — construction-time failures crash import;
  call-time failures fail before any analyzer runs; the two-directional
  option-name check (§7.1 failure #7), the corrected, non-contradictory
  capability check with its `TargetedGrant` shape validation bound to the
  correct public source vocabulary rather than `CoverageSnapshot`'s
  internal fields (§7.1 failure #5), the single-identity full-scope gate
  (§7.2 failure #11, symmetric with failure #10's targeted-scan gate), and
  the fail-closed-on-empty-grant gate (§7.2 failure #12 — `grants =
  frozenset()` means "not yet granted," never "unrestricted") close the
  gaps earlier drafts of this contract left open.
- The existing monkeypatchability seam, extended uniformly to all three
  adapters (§8), the one-build/two-consumer call-count invariant, and the
  same-report-instance invariant between `renderer` and `record_projector`
  are named, explicit compatibility requirements — not assumed to survive
  #72 by accident.
- A future analyzer addition has an explicit, testable checklist (§10)
  that also covers every roster artifact beyond the schema (§10 item 2),
  and is never automatically classified as compatibility-preserving (§10
  item 8) — not implicit package discovery (§11 forecloses that path
  entirely).

`dumpex/output/records.py`'s `HUNTERS` tuple remains the sole runtime
source of truth for identity and order until #71 lands — this document
adds no code, only the contract #71's registry module and tests are
checked against, and #72/#73 verify compatibility against.
