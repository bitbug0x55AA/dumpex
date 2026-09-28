"""
The complete limitation-rendering corpus and coverage registry baseline.

`capture_coverage_corpus()` returns, in registry order:

* ``code_specs``   -- every `_CODE_SPECS` entry's non-callable fields and
                      the qualified name of each callable it wires in;
* ``derived``      -- the ordered collections derived from the registry;
* ``limitations``  -- per code, a set of construction cases and their
                      outcome: rendered text, card summary, the `to_dict()`
                      values that differ from an unset limitation (the full
                      key order is ``derived.limitation_to_dict_keys``), the
                      missed-bytes projection for codes that claim a memory
                      gap, or the exact rejection;
* ``vocabularies`` -- the members of every renderer and validator
                      vocabulary the cases are generated from;
* ``reports``      -- `build_coverage_report()` and
                      `combine_coverage_reports()` over source states,
                      requirements and prebuilt limitations: status, exit
                      code, reasons, sources, limitations and missed bytes,
                      or the exact rejection;
* ``capability_limitations`` -- `render_capability_limitation()` over every
                      capability code and display source;
* ``formatting``   -- the shared coverage formatting helpers over fixed
                      inputs.

Construction cases are derived from each code's own spec (its fixed
source and allowed fields), from every member of each vocabulary in
`VOCABULARIES` and every oversized-skip source contract, and from the
explicit cases in `_EXTRA_CASES` wherever a renderer has a branch the
generated cases do not reach. Every code must end up with at least one
rendered case, and every vocabulary member with a rendered case of its own.
"""
from dumpex.output import coverage as cov
from dumpex.output import records as rec
from dumpex.output.coverage import CoverageLimitation, ScanTarget, ScanTargetKind

from tests.fixtures.decomposition_baseline.stable import qualname, stable
from tests.fixtures.decomposition_baseline.surface import baseline_object


def _p(name: str):
    """A private name of dumpex.output.coverage, wherever it is defined now."""
    return baseline_object("dumpex.output.coverage", name)

_REGION = dict(kind=ScanTargetKind.MEMORY_REGION, file_offset=0x400, state="MEM_COMMIT",
               type="MEM_PRIVATE", protection="PAGE_EXECUTE_READWRITE")


def _region(i, *, size=0x2000, size_limit=None, captured_size=None):
    base = 0x10000 + i * 0x10000
    return ScanTarget(base_address=base, size=size, size_limit=size_limit,
                      allocation_base=base, captured_size=captured_size, **_REGION)


def _segment(i, *, size=0x2000, size_limit=None):
    return ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=0x7F0000 + i * 0x10000,
                      size=size, size_limit=size_limit, file_offset=0x9000 + i * 0x2000)


# Generic values for every structured field a code allows.
_FILL = {
    "scope": "dump",
    "affected_count": 1,
    "unavailable_fields": ("start_address", "create_time"),
    "available_fields": ("tid",),
    "counterpart_source": "threads",
    "related_sources": ("misc_info", "threads"),
    "related_tids": (4660, 4664),
    "thread_id": 4660,
    "detail": "synthetic detail",
    "targets": (_region(0),),
    "budget_limit": 64,
    "budget_consumed": 64,
}

_FOUR_REGIONS = tuple(_region(i) for i in range(4))
_FOUR_OVERSIZED_REGIONS = tuple(_region(i, size=0x300000, size_limit=0x200000) for i in range(4))
_TWO_SEGMENTS = tuple(_segment(i) for i in range(2))

# (case id, code, kwargs besides code) -- the explicit construction cases.
_EXTRA_CASES = (
    ("counterpart", "SOURCE_ABSENT",
     dict(source="thread_info", scope="thread", affected_count=3, counterpart_source="threads",
          unavailable_fields=("start_address",))),
    ("fields", "SOURCE_ABSENT",
     dict(source="thread_info", scope="thread", unavailable_fields=("start_address", "create_time"),
          available_fields=("tid",))),
    ("detail", "SOURCE_FAILED",
     dict(source="handles", detail="HandleStreamFramingError: synthetic", scope="dump")),
    ("three_sources", "SOURCE_GROUP_ABSENT",
     dict(source="misc_info", related_sources=("misc_info", "threads", "exception"))),
    ("valid", "PID_THREAD_LIST_FALLBACK",
     dict(source="misc_info", counterpart_source="threads", related_tids=(4660, 4664, 4668, 4672))),
    ("plural", "REPORT_STRING_SCAN_INCOMPLETE", dict(source="string_search", affected_count=3)),
    ("budget", "PE_HEADER_SCAN_TRUNCATED",
     dict(source="hidden_pe_scan", affected_count=4, targets=_FOUR_REGIONS, scope="total_bytes",
          budget_limit=4096, budget_consumed=4100)),
    ("budget", "PE_HEADER_SCAN_NOT_STARTED",
     dict(source="hidden_pe_scan", affected_count=1, targets=(_region(0),),
          scope="validations_total", budget_limit=10, budget_consumed=10)),
    ("pipe", "SCAN_REGION_OVERSIZED_SKIPPED",
     dict(source="pipe_name_scan", affected_count=4, targets=_FOUR_OVERSIZED_REGIONS)),
    ("encoding", "SCAN_REGION_OVERSIZED_SKIPPED",
     dict(source="encoding_scan", scope="entropy", affected_count=1,
          targets=(_region(0, size=0x300000, size_limit=0x200000),))),
    ("segments", "SCAN_REGION_OVERSIZED_SKIPPED",
     dict(source="segment_scan", affected_count=2,
          targets=tuple(_segment(i, size=0x300000, size_limit=0x200000) for i in range(2)))),
    ("wrong_kind", "SCAN_REGION_OVERSIZED_SKIPPED",
     dict(source="segment_scan", affected_count=1,
          targets=(_region(0, size=0x300000, size_limit=0x200000),))),
    ("short_read", "SCAN_REGION_SHORT_READ",
     dict(source="pipe_name_scan", affected_count=1,
          targets=(_region(0, captured_size=0x800),))),
    ("sampled", "SCAN_REGION_SEARCH_INCOMPLETE",
     dict(source="segment_scan", affected_count=2, detail="window_sampled", scope="sleep_mask")),
    ("free_text", "SCAN_REGION_SEARCH_INCOMPLETE",
     dict(source="segment_scan", affected_count=1, detail="not a known reason")),
    ("module_backed", "TARGETED_SOURCE_NOT_APPLICABLE",
     dict(source="targeted_scan", detail="region_module_backed", scope="injection")),
    ("wrong_source", "TARGETED_SOURCE_NOT_APPLICABLE",
     dict(source="pipe_name_scan", detail="region_module_backed")),
    ("deadline", "SCAN_BUDGET_EXHAUSTED",
     dict(source="pipe_name_scan", detail="deadline", scope="pipe", affected_count=2,
          targets=tuple(_region(i) for i in range(2)))),
    ("bare", "SCAN_BUDGET_EXHAUSTED", dict(source="pipe_name_scan", detail="max_hits")),
    ("budget", "CS_BEACON_SCAN_BUDGET_EXHAUSTED",
     dict(source="segment_scan", detail="scan deadline reached", scope="max_candidates",
          budget_limit=256, budget_consumed=257, affected_count=2, targets=_TWO_SEGMENTS)),
    ("bare", "CS_BEACON_SCAN_BUDGET_EXHAUSTED",
     dict(source="segment_scan", detail="scan deadline reached")),
    ("budget", "YARA_HIT_CAP_REACHED",
     dict(source="segment_scan", affected_count=1, scope="max_total_hits", budget_limit=100,
          budget_consumed=100, targets=(_segment(0),))),
    ("budget", "YARA_SCAN_BUDGET_EXHAUSTED",
     dict(source="segment_scan", affected_count=2, scope="scan_deadline_seconds",
          budget_limit=30, budget_consumed=31, targets=_TWO_SEGMENTS)),
    ("entries", "IAT_ENTRIES_TRUNCATED",
     dict(source="iat", scope="iat_total_entries", budget_limit=4096, budget_consumed=4096)),
    ("bytes", "ENVIRONMENT_BLOCK_TRUNCATED",
     dict(source="environment_block", affected_count=1, scope="environment_bytes",
          budget_limit=65536, budget_consumed=65536)),
    ("segment", "ENVIRONMENT_BLOCK_TRUNCATED",
     dict(source="environment_block", affected_count=2, scope="captured_segment")),
    ("alternate", "THREAD_INFO_STREAM_TRUNCATED",
     dict(source="baseline.thread_info", affected_count=2)),
    ("alternate", "HANDLE_STREAM_TRUNCATED", dict(source="handle_data", affected_count=5)),
    ("wrong_source", "MODULE_CLASSIFICATION_UNAVAILABLE", dict(source="threads")),
    ("negative_count", "THREAD_CONTEXT_PARTIAL", dict(source="thread_context", affected_count=-1)),
    ("budget_half", "SCAN_REGION_READ_FAILED",
     dict(source="pipe_name_scan", affected_count=1, targets=(_region(0),), budget_limit=5)),
)


def _generic_cases(code, spec):
    source = spec.fixed_source or "synthetic_source"
    base = {"source": source}
    if spec.fixed_related_sources is not None:
        base["related_sources"] = spec.fixed_related_sources
    full = dict(base)
    for name in sorted(spec.allowed_fields):
        full.setdefault(name, _FILL[name])
    yield "min", base
    if full != base:
        yield "full", full


# CoverageLimitation.to_dict() always emits this key set in this order;
# each case records only the values that differ from an unset limitation.
_TO_DICT_UNSET = CoverageLimitation(code=cov.LimitationCode.SOURCE_ABSENT, source="x").to_dict()


def _to_dict_delta(limitation) -> dict:
    wire = limitation.to_dict()
    if list(wire) != list(_TO_DICT_UNSET):
        return {"__full__": wire}
    return {k: v for k, v in wire.items() if v != _TO_DICT_UNSET[k] or k in ("code", "source")}


def _build(code, kwargs):
    try:
        limitation = CoverageLimitation(code=code, **kwargs)
    except Exception as exc:   # noqa: BLE001 -- the rejection IS the characterized outcome
        return None, {"outcome": "rejected", "error": f"{type(exc).__name__}: {exc}"}
    out = {
        "outcome": "rendered",
        "render": cov.render_limitation(limitation),
        "summary": cov.summarize_limitation(limitation),
        "to_dict": _to_dict_delta(limitation),
    }
    if _p("_CODE_SPECS")[limitation.code].memory_gap is not None:
        missed = cov.summarize_missed_bytes([limitation])
        out["missed_bytes"] = stable(missed)
        out["missed_bytes_clause"] = cov.format_missed_bytes_clause(missed)
    return limitation, out


def _disallowed_probe(code, spec, kwargs):
    """The first structured field this code does NOT allow, set on top of a
    rendered case -- the generic allowed-fields guard's rejection."""
    for name, default in _p("_STRUCTURED_FIELD_DEFAULTS").items():
        if name in spec.allowed_fields:
            continue
        value = _FILL[name]
        if name == "affected_count" and "targets" in kwargs:
            value = len(kwargs["targets"])
        probe = dict(kwargs, **{name: value})
        return _build(code, probe)[1] | {"field": name}
    return None


def _limitation_cases():
    extra = {}
    for case_id, code_name, kwargs in _EXTRA_CASES:
        extra.setdefault(code_name, []).append((case_id, kwargs))
    for generated in (_vocabulary_cases(), _oversized_contract_cases()):
        for code_name, cases in generated.items():
            extra.setdefault(code_name, []).extend(cases)
    out = []
    for code, spec in _p("_CODE_SPECS").items():
        cases, rendered_kwargs = [], None
        for case_id, kwargs in [*_generic_cases(code, spec), *extra.get(code.name, [])]:
            limitation, outcome = _build(code, kwargs)
            cases.append({"case": case_id, "kwargs": stable(kwargs), **outcome})
            if limitation is not None and rendered_kwargs is None:
                rendered_kwargs = kwargs
        entry = {"code": code.value, "cases": cases}
        if rendered_kwargs is not None:
            probe = _disallowed_probe(code, spec, rendered_kwargs)
            if probe is not None:
                entry["disallowed_field_probe"] = probe
        out.append(entry)
    return out


def _spec_table():
    rows = []
    for code, spec in _p("_CODE_SPECS").items():
        rows.append({
            "code": code.value,
            "render": qualname(spec.render),
            "fixed_source": spec.fixed_source,
            "alternate_sources": sorted(spec.alternate_sources),
            "fixed_related_sources": stable(spec.fixed_related_sources),
            "min_related_sources": spec.min_related_sources,
            "absent_capable": spec.absent_capable,
            "group_capable": spec.group_capable,
            "caller_buildable": spec.caller_buildable,
            "validate_fields": qualname(spec.validate_fields) if spec.validate_fields else None,
            "validate_against_sources": (qualname(spec.validate_against_sources)
                                         if spec.validate_against_sources else None),
            "allowed_fields": sorted(spec.allowed_fields),
            "memory_gap": spec.memory_gap.value if spec.memory_gap is not None else None,
            "summary": qualname(spec.summary) if spec.summary else None,
        })
    return rows


def _derived():
    return {
        "limitation_code_order": [c.value for c in cov.LimitationCode],
        "code_specs_order": [c.value for c in _p("_CODE_SPECS")],
        "fixed_source_codes": [[c.value, s] for c, s in _p("_FIXED_SOURCE_CODES").items()],
        "absent_capable_codes": [c.value for c in _p("_ABSENT_CAPABLE_CODES")],
        "group_evaluation_codes": [c.value for c in _p("_GROUP_EVALUATION_CODES")],
        "caller_buildable_codes": [c.value for c in _p("_CALLER_BUILDABLE_COMPLETENESS_CODES")],
        "single_source_evaluation_codes": [c.value for c in _p("_SINGLE_SOURCE_EVALUATION_CODES")],
        "single_source_is_absent_capable":
            _p("_SINGLE_SOURCE_EVALUATION_CODES") is _p("_ABSENT_CAPABLE_CODES"),
        "structured_field_defaults": stable(_p("_STRUCTURED_FIELD_DEFAULTS")),
        "source_display_names": stable(_p("_SOURCE_DISPLAY_NAMES")),
        "limitation_to_dict_keys": list(_TO_DICT_UNSET),
        "exit_codes": {status.value: cov.exit_code_for(status.value)
                       for status in cov.CoverageStatus},
    }


def _capability_limitations():
    sources = [*rec.CAPABILITY_SOURCE_DISPLAY_NAMES, "unregistered_source"]
    out = []
    for code in rec.CapabilityLimitationCode:
        out.append({"code": code.value,
                    "rendered": {s: rec.render_capability_limitation(code.value, s) for s in sources}})
    return out


def _formatting():
    display_names = [*_p("_SOURCE_DISPLAY_NAMES"), "unregistered_source"]
    fractions = [0.0, 1e-9, 0.00004, 0.0001, 0.0049, 0.005, 0.0999, 0.1, 0.5, 0.994, 0.9999, 1.0]
    previews = {}
    for count in range(1, 6):
        targets = tuple(_region(i) for i in range(count))
        previews[str(count)] = {"noun": cov.scan_target_noun(targets),
                                "preview": cov.format_scan_target_preview(targets)}
    previews["segments"] = {"noun": cov.scan_target_noun(_TWO_SEGMENTS),
                            "preview": cov.format_scan_target_preview(_TWO_SEGMENTS)}
    previews["mixed"] = {"noun": cov.scan_target_noun((_region(0), _segment(0))),
                         "preview": cov.format_scan_target_preview((_region(0), _segment(0)))}
    describe = {
        "region": _region(0).describe(),
        "oversized": _region(1, size=0x300000, size_limit=0x200000).describe(),
        "short": _region(2, captured_size=0x800).describe(),
        "segment": _segment(0).describe(),
    }
    return {
        "display_source_name": {name: cov.display_source_name(name) for name in display_names},
        "unscanned_percent": [[f, cov.format_unscanned_percent(f)] for f in fractions],
        "scan_target_previews": previews,
        "scan_target_describe": describe,
    }


# ── Renderer and validator vocabularies ───────────────────────────────────
# Every private collection a renderer or field validator of
# `dumpex.output.coverage` keys on, with the code and field it feeds and a
# builder for one construction case per member. The cases are generated
# from the live collection, so an added, removed or reworded member shows
# up as a corpus difference, and `vocabulary_coverage` must report every
# member rendered.


def _budget(v):
    return dict(scope=v, budget_limit=64, budget_consumed=65)


def _env_truncated(v):
    kwargs = dict(source="environment_block", affected_count=1, scope=v)
    if v in _p("_ENV_TRUNCATION_BUDGET_SCOPES"):
        kwargs.update(budget_limit=0x10000, budget_consumed=0x10000)
    return kwargs


VOCABULARIES = (
    ("_SCAN_REGION_SEARCH_INCOMPLETE_REASONS", "SCAN_REGION_SEARCH_INCOMPLETE",
     lambda v: dict(source="segment_scan", affected_count=1, detail=v)),
    ("_TARGETED_SOURCE_NOT_APPLICABLE_REASONS", "TARGETED_SOURCE_NOT_APPLICABLE",
     lambda v: dict(source="targeted_scan", detail=v)),
    ("_SCAN_BUDGET_EXHAUSTED_REASONS", "SCAN_BUDGET_EXHAUSTED",
     lambda v: dict(source="pipe_name_scan", detail=v)),
    ("_PE_SCAN_BUDGET_KINDS", "PE_HEADER_SCAN_TRUNCATED",
     lambda v: dict(source="hidden_pe_scan", affected_count=1, targets=(_region(0),), **_budget(v))),
    ("_PE_SCAN_BUDGET_KINDS", "PE_HEADER_SCAN_NOT_STARTED",
     lambda v: dict(source="hidden_pe_scan", affected_count=1, targets=(_region(0),), **_budget(v))),
    ("_YARA_BUDGET_KINDS", "YARA_HIT_CAP_REACHED",
     lambda v: dict(source="segment_scan", affected_count=1, targets=(_segment(0),), **_budget(v))),
    ("_YARA_BUDGET_KINDS", "YARA_SCAN_BUDGET_EXHAUSTED",
     lambda v: dict(source="segment_scan", affected_count=1, targets=(_segment(0),), **_budget(v))),
    ("_CS_BEACON_BUDGET_KINDS", "CS_BEACON_SCAN_BUDGET_EXHAUSTED",
     lambda v: dict(source="segment_scan", detail="budget reached", **_budget(v))),
    ("_IAT_TRUNCATION_SCOPES", "IAT_ENTRIES_TRUNCATED",
     lambda v: dict(source="iat", **_budget(v))),
    ("_ENV_TRUNCATION_SCOPES", "ENVIRONMENT_BLOCK_TRUNCATED", _env_truncated),
)

# Collections a renderer or validator reads that other sections of this
# corpus exercise member by member, and where.
VOCABULARIES_CAPTURED_ELSEWHERE = {
    "_SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS": "oversized_source_contracts",
    "_ENV_TRUNCATION_BUDGET_SCOPES": "vocabulary _ENV_TRUNCATION_SCOPES",
    "_PID_SOURCES_ABSENT_SOURCES": "limitations PID_SOURCES_ABSENT (fixed related sources)",
    "_SOURCE_DISPLAY_NAMES": "formatting.display_source_name",
    "_STRUCTURED_FIELD_DEFAULTS": "derived.structured_field_defaults",
    "_CODE_SPECS": "code_specs",
    "_FIXED_SOURCE_CODES": "derived.fixed_source_codes",
    "_ABSENT_CAPABLE_CODES": "derived.absent_capable_codes",
    "_GROUP_EVALUATION_CODES": "derived.group_evaluation_codes",
    "_CALLER_BUILDABLE_COMPLETENESS_CODES": "derived.caller_buildable_codes",
    "_SINGLE_SOURCE_EVALUATION_CODES": "derived.single_source_evaluation_codes",
}


def _members(collection) -> list:
    return sorted(collection, key=lambda v: (v is None, str(v)))


def _vocabulary_cases() -> dict:
    """{code name: [(case id, kwargs)]} generated from VOCABULARIES."""
    out = {}
    for attribute, code_name, builder in VOCABULARIES:
        for member in _members(_p(attribute)):
            out.setdefault(code_name, []).append((f"{attribute}:{member}", builder(member)))
    return out


def _oversized_contract_cases() -> dict:
    """For every source with a fixed SCAN_REGION_OVERSIZED_SKIPPED contract:
    one case per allowed scope with a target of the required kind, one with
    a target of the other kind, and one with a scope outside the contract."""
    cases = []
    contracts = _p("_SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS")
    for source in sorted(contracts):
        kind, scopes = contracts[source]
        good = (_segment(0, size=0x300000, size_limit=0x200000)
                if kind == ScanTargetKind.MEMORY_SEGMENT
                else _region(0, size=0x300000, size_limit=0x200000))
        wrong = (_region(0, size=0x300000, size_limit=0x200000)
                 if kind == ScanTargetKind.MEMORY_SEGMENT
                 else _segment(0, size=0x300000, size_limit=0x200000))
        for scope in _members(scopes):
            cases.append((f"contract:{source}:{scope}",
                          dict(source=source, scope=scope, affected_count=1, targets=(good,))))
        cases.append((f"contract:{source}:wrong_kind",
                      dict(source=source, scope=_members(scopes)[0], affected_count=1,
                           targets=(wrong,))))
        cases.append((f"contract:{source}:unlisted_scope",
                      dict(source=source, scope="unlisted_scope", affected_count=1,
                           targets=(good,))))
    return {"SCAN_REGION_OVERSIZED_SKIPPED": cases}


def vocabulary_coverage(corpus: dict) -> dict:
    """{vocabulary: [members with no rendered case]} for every entry of
    VOCABULARIES and every oversized source contract scope."""
    rendered = {case["case"] for entry in corpus["limitations"] for case in entry["cases"]
                if case["outcome"] == "rendered"}
    out = {}
    for attribute, _code, _builder in VOCABULARIES:
        out[attribute] = sorted(str(m) for m in _members(_p(attribute))
                                if f"{attribute}:{m}" not in rendered)
    contracts = _p("_SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS")
    out["_SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS"] = sorted(
        f"{source}:{scope}" for source, (_kind, scopes) in contracts.items()
        for scope in _members(scopes) if f"contract:{source}:{scope}" not in rendered)
    return out


def unaccounted_vocabularies() -> list:
    """Private module-level collections that a function or method of
    `dumpex.output.coverage`'s family reads -- the legacy module, its owner
    modules, its submodules and every module its definitions are imported
    from (see surface.Locator) -- and that neither VOCABULARIES nor
    VOCABULARIES_CAPTURED_ELSEWHERE accounts for."""
    import dis
    import inspect
    import types
    from tests.fixtures.decomposition_baseline.surface import baseline_locator
    locator = baseline_locator("dumpex.output.coverage")
    accounted = {a for a, _c, _b in VOCABULARIES} | set(VOCABULARIES_CAPTURED_ELSEWHERE)
    collections, loaded = set(), set()

    def walk(code):
        for ins in dis.get_instructions(code):
            if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME"):
                loaded.add(ins.argval)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                walk(const)

    for module in locator.family():
        bindings = locator.bindings(module)
        for name, how in bindings["defined"]:
            value = getattr(module, name, None)
            if how == "value" and name.startswith("_") and not name.startswith("__") \
                    and isinstance(value, (dict, frozenset, set, tuple)):
                collections.add(name)
            elif how == "def" and inspect.isfunction(value):
                walk(value.__code__)
            elif how == "class" and inspect.isclass(value):
                for member in bindings["class_members"].get(name, ()):
                    raw = value.__dict__.get(member)
                    raw = getattr(raw, "__func__", None) or getattr(raw, "fget", None) or raw
                    if inspect.isfunction(raw):
                        walk(raw.__code__)
    return sorted((collections & loaded) - accounted)


# ── Coverage report assembly ──────────────────────────────────────────────


def _obs(name, state, count=None, detail=None):
    return cov.SourceObservation(name=name, state=cov.SourceState(state), record_count=count,
                                 detail=detail)


def _sources(*observations):
    return {o.name: o for o in observations}


_P3 = ("present", 3)
_TID_FALLBACK = dict(code="PID_THREAD_LIST_FALLBACK", source="misc_info",
                     counterpart_source="threads", related_tids=(4, 8, 12))


def _report_cases():
    """(case id, callable returning a CoverageReport) for build_coverage_report
    over source states, requirements and prebuilt limitations, then
    combine_coverage_reports over the reports."""
    L, SR, ER = cov.CoverageLimitation, cov.SourceRequirement, cov.EvaluationRequirement
    b = cov.build_coverage_report
    return (
        ("complete", lambda: b(_sources(_obs("modules", *_P3)),
                               evaluation_sources=("modules",), completeness_checks=["modules"])),
        ("single_source_absent", lambda: b(_sources(_obs("modules", "absent")),
                                           evaluation_sources=("modules",),
                                           completeness_checks=["modules"])),
        ("group_absent", lambda: b(_sources(_obs("threads", "absent"), _obs("thread_info", "absent")),
                                   evaluation_sources=("threads", "thread_info"))),
        ("three_group_absent", lambda: b(
            _sources(_obs("a", "absent"), _obs("b", "absent"), _obs("c", "absent")),
            evaluation_sources=("a", "b", "c"))),
        ("group_partly_absent", lambda: b(
            _sources(_obs("threads", *_P3), _obs("thread_info", "absent")),
            evaluation_sources=("threads", "thread_info"),
            completeness_checks=["threads", "thread_info"])),
        ("failed_source", lambda: b(
            _sources(_obs("handles", "failed", detail="HandleStreamFramingError: synthetic")),
            completeness_checks=["handles"])),
        ("present_empty_is_complete", lambda: b(_sources(_obs("modules", "present_empty", 0)),
                                                completeness_checks=["modules"])),
        ("requirement_counterpart", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", *_P3)),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads",
                                    scope="thread", unavailable_fields=("start_address",))])),
        ("requirement_counterpart_present_empty", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", "present_empty", 0)),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads")])),
        ("requirement_counterpart_empty_with_count", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", "present_empty", 0)),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads",
                                    affected_count=2)])),
        ("requirement_zero_count_counterpart_present", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", *_P3)),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads",
                                    affected_count=0)])),
        ("requirement_count_disagrees_with_counterpart", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", *_P3)),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads",
                                    affected_count=5)])),
        ("requirement_counterpart_failed", lambda: b(
            _sources(_obs("thread_info", "absent"), _obs("threads", "failed", detail="boom")),
            completeness_checks=[SR(source="thread_info", counterpart_source="threads")])),
        ("requirement_dedicated_absent_code", lambda: b(
            _sources(_obs("modules", "absent")),
            completeness_checks=[SR(source="modules",
                                    absent_code="MODULE_CLASSIFICATION_UNAVAILABLE")])),
        ("prebuilt_key_mismatch", lambda: b(
            _sources(_obs("threads", *_P3), _obs("thread_info", *_P3)),
            completeness_checks=[L(code="SOURCE_KEY_MISMATCH", source="thread_info",
                                   counterpart_source="threads", affected_count=1,
                                   scope="thread")])),
        ("prebuilt_key_mismatch_counterpart_absent", lambda: b(
            _sources(_obs("threads", "absent"), _obs("thread_info", *_P3)),
            completeness_checks=[L(code="SOURCE_KEY_MISMATCH", source="thread_info",
                                   counterpart_source="threads", affected_count=1)])),
        ("prebuilt_thread_list_fallback", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", *_P3)),
            completeness_checks=[L(**_TID_FALLBACK)])),
        ("prebuilt_thread_list_fallback_count_mismatch", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", "present", 2)),
            completeness_checks=[L(**_TID_FALLBACK)])),
        ("prebuilt_thread_list_fallback_threads_absent", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", "absent")),
            completeness_checks=[L(**_TID_FALLBACK)])),
        ("prebuilt_exception_tid_fallback_exception_absent", lambda: b(
            _sources(_obs("exception", "absent")),
            completeness_checks=[L(code="PID_EXCEPTION_TID_FALLBACK", source="exception",
                                   thread_id=4)])),
        ("prebuilt_code_not_caller_buildable", lambda: b(
            _sources(_obs("modules", "absent")),
            completeness_checks=[L(code="SOURCE_ABSENT", source="modules")])),
        ("unknown_source_referenced", lambda: b(
            _sources(_obs("modules", *_P3)), completeness_checks=["threads"])),
        ("source_key_name_mismatch", lambda: b(
            {"modules": _obs("threads", *_P3)}, completeness_checks=["modules"])),
        ("both_evaluation_forms", lambda: b(
            _sources(_obs("modules", *_P3)), evaluation_sources=("modules",),
            evaluation_groups=[ER(sources=("modules",))])),
        ("evaluation_groups_one_absent", lambda: b(
            _sources(_obs("baseline.modules", "absent"), _obs("target.modules", *_P3)),
            evaluation_groups=[ER(sources=("baseline.modules",)),
                               ER(sources=("target.modules",))])),
        ("dedicated_group_code", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", "absent"),
                     _obs("exception", "absent")),
            evaluation_sources=ER(sources=("misc_info", "threads", "exception"),
                                  all_absent_code="PID_SOURCES_ABSENT"))),
        ("not_evaluated_retains_prebuilt_and_failed", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", *_P3),
                     _obs("handles", "failed", detail="boom")),
            evaluation_sources=("misc_info",),
            completeness_checks=[L(**_TID_FALLBACK), "handles"],
            retain_completeness_checks_when_not_evaluated=True)),
        ("not_evaluated_drops_prebuilt_by_default", lambda: b(
            _sources(_obs("misc_info", "absent"), _obs("threads", *_P3),
                     _obs("handles", "failed", detail="boom")),
            evaluation_sources=("misc_info",),
            completeness_checks=[L(**_TID_FALLBACK), "handles"])),
        ("eligible_bytes_and_pass_scopes", lambda: b(
            _sources(_obs("encoding_scan", *_P3)),
            completeness_checks=[L(code="SCAN_REGION_OVERSIZED_SKIPPED", source="encoding_scan",
                                   scope="entropy", affected_count=1,
                                   targets=(_region(0, size=0x300000, size_limit=0x200000),))],
            eligible_bytes=0x1000000, pass_scopes=("entropy",))),
        ("invalid_evaluation_requirement_code", lambda: ER(
            sources=("a", "b"), all_absent_code="SOURCE_ABSENT")),
        ("invalid_evaluation_requirement_duplicates", lambda: ER(sources=("a", "a"))),
        ("invalid_source_requirement_code", lambda: SR(
            source="modules", absent_code="SOURCE_FAILED")),
        ("invalid_source_requirement_fixed_source", lambda: SR(
            source="threads", absent_code="MODULE_CLASSIFICATION_UNAVAILABLE")),
    )


def _report_projection(report) -> dict:
    if not isinstance(report, cov.CoverageReport):
        return {"outcome": "constructed", "value": stable(report)}
    return {
        "outcome": "built",
        "status": report.status.value,
        "exit_code": cov.exit_code_for(report.status.value),
        "reasons": list(report.reasons),
        "sources": {name: obs.to_dict() for name, obs in report.sources.items()},
        "limitations": [lim.to_dict() for lim in report.limitations],
        "missed_bytes": report.missed_bytes.to_dict(),
    }


def _run_report_case(fn) -> dict:
    try:
        return _report_projection(fn())
    except Exception as exc:   # noqa: BLE001 -- the rejection IS the characterized outcome
        return {"outcome": "rejected", "error": f"{type(exc).__name__}: {exc}"}


def _combine_cases(built: dict):
    c = cov.combine_coverage_reports
    b = cov.build_coverage_report
    threads_complete = lambda: b(_sources(_obs("threads", *_P3)), completeness_checks=["threads"])
    located_gap = lambda: b(
        _sources(_obs("pipe_name_scan", *_P3)),
        completeness_checks=[cov.CoverageLimitation(
            code="SCAN_REGION_OVERSIZED_SKIPPED", source="pipe_name_scan", affected_count=1,
            targets=(_region(0, size=0x300000, size_limit=0x200000),))])
    return (
        ("complete_and_partial", lambda: c([built["complete"], built["failed_source"]])),
        ("all_not_evaluated", lambda: c([built["single_source_absent"], built["group_absent"]])),
        ("all_complete", lambda: c([built["complete"], threads_complete()])),
        ("not_evaluated_and_complete", lambda: c([built["group_absent"], built["complete"]])),
        ("duplicate_limitation_once", lambda: c([built["failed_source"], built["failed_source"]])),
        ("same_source_agreeing", lambda: c([built["complete"], built["complete"]])),
        ("conflicting_sources", lambda: c([built["complete"],
                                           b(_sources(_obs("modules", "absent")),
                                             completeness_checks=["modules"])])),
        ("eligible_bytes_refused", lambda: c([built["eligible_bytes_and_pass_scopes"]])),
        ("located_memory_gap_refused", lambda: c([located_gap()])),
        ("empty_refused", lambda: c([])),
    )


def _report_corpus() -> dict:
    cases = _report_cases()
    built = {}
    out = {"build": {}, "combine": {}}
    for case_id, fn in cases:
        out["build"][case_id] = _run_report_case(fn)
        try:
            built[case_id] = fn()
        except Exception:   # noqa: BLE001 -- recorded above
            pass
    for case_id, fn in _combine_cases(built):
        out["combine"][case_id] = _run_report_case(fn)
    return out


def capture_coverage_corpus() -> dict:
    return {
        "code_specs": _spec_table(),
        "derived": _derived(),
        "limitations": _limitation_cases(),
        "vocabularies": {a: {"code": c, "members": [str(m) for m in _members(_p(a))]}
                         for a, c, _b in VOCABULARIES},
        "reports": _report_corpus(),
        "capability_limitations": _capability_limitations(),
        "formatting": _formatting(),
    }
