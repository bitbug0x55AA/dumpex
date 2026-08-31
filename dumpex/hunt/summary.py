"""Reduce hunter records into one deterministic hunt summary.

Overall status follows explicit detection and coverage precedence rather than
console wording. Counts, correlations, investigation actions, and findings are
derived from existing records without rescanning or changing hunter results.
"""
from dumpex.output.records import HUNTERS, HunterRecord, _require_hex_address

# ── Scan scope (`summary.scan_scope`) ───────────────────────────────────
# A closed, tagged shape naming what one hunt invocation actually covered:
# `{"kind": "full"}` for a whole-dump hunt, or a `targeted` variant carrying
# the analyzer, its granted coverage source, the scopes its closures were
# attributed under, and the requested range. It is present in every hunt
# summary, in both modes, so a consumer never has to infer scope from the
# presence or absence of another field -- an absent tag would make "full" and
# "an older producer" the same document.
_SCAN_SCOPE_FULL_KEYS = frozenset({"kind"})
_SCAN_SCOPE_TARGETED_KEYS = frozenset({
    "kind", "hunter", "source", "scopes", "base_address", "size"})


def full_scan_scope() -> dict:
    """The `full` variant. A fresh dict per call: the summary it lands in is
    a mutable document a caller still adds to."""
    return {"kind": "full"}


def validate_scan_scope(scan_scope: dict) -> dict:
    """`scan_scope`, checked against the closed shape for its own tag. Both
    variants are exact key sets -- a targeted tag missing its range, or a full
    tag carrying one, is a producer bug that must not reach the wire."""
    if not isinstance(scan_scope, dict):
        raise TypeError(
            f"build_hunt_summary() scan_scope must be a dict, got {scan_scope!r}")
    kind = scan_scope.get("kind")
    if kind == "full":
        expected = _SCAN_SCOPE_FULL_KEYS
    elif kind == "targeted":
        expected = _SCAN_SCOPE_TARGETED_KEYS
    else:
        raise ValueError(
            f"build_hunt_summary() scan_scope kind must be 'full' or 'targeted', "
            f"got {kind!r}")
    if frozenset(scan_scope) != expected:
        raise ValueError(
            f"build_hunt_summary() scan_scope kind={kind!r} must carry exactly "
            f"{sorted(expected)}, got {sorted(scan_scope)}")
    if kind != "targeted":
        return dict(scan_scope)

    if scan_scope["hunter"] not in HUNTERS:
        raise ValueError(
            f"build_hunt_summary() scan_scope hunter must be one of {HUNTERS}, "
            f"got {scan_scope['hunter']!r}")
    if not isinstance(scan_scope["source"], str) or not scan_scope["source"]:
        raise ValueError(
            f"build_hunt_summary() scan_scope source must be a non-empty str, "
            f"got {scan_scope['source']!r}")
    scopes = scan_scope["scopes"]
    if not isinstance(scopes, list) or any(
            not isinstance(scope, str) or not scope for scope in scopes):
        raise ValueError(
            f"build_hunt_summary() scan_scope scopes must be a list of non-empty str, "
            f"got {scopes!r}")
    if list(scopes) != sorted(set(scopes)):
        raise ValueError(
            f"build_hunt_summary() scan_scope scopes must be sorted and free of "
            f"duplicates, got {scopes!r}")
    _require_hex_address(scan_scope["base_address"],
                         "build_hunt_summary() scan_scope base_address")
    size = scan_scope["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError(
            f"build_hunt_summary() scan_scope size must be a positive plain int, "
            f"got {size!r}")
    # A real copy, not a shallow one: `scopes` is the only nested value, and a
    # caller mutating its own list afterwards must not reach into the summary
    # this returns.
    return {**scan_scope, "scopes": list(scopes)}


# Relative severity among the three verdict levels a DETECTED hunter can
# report -- deliberately its own tuple, not reused from
# dumpex.output.records._HUNT_VERDICT_LEVELS (whose ordering also
# includes "clean"/"inconclusive"/"not_evaluated" interleaved for an
# unrelated reason and must not be assumed to double as a severity rank).
_DETECTED_VERDICT_ORDER = ("possible", "likely", "high")


def build_hunt_summary(records: "list[HunterRecord]", selected: str, *,
                        full_scope_hunters: "tuple | None" = None,
                        scan_scope: "dict | None" = None) -> dict:
    """
    `selected` is the `--hunt` argument: `"all"` or one of `HUNTERS`.

    `records` must be exactly:
      - one `HunterRecord` per hunter in `full_scope_hunters`' own fixed
        order, when `selected == "all"`; or
      - exactly one `HunterRecord` whose `.hunter == selected`, otherwise.

    `full_scope_hunters` (keyword-only) is the exact, capability-filtered
    identity set a `selected == "all"` call's own `records` must match --
    defaults to the full, unfiltered `HUNTERS` tuple when omitted (every
    existing caller before this parameter existed, and every one of this
    module's own historical tests, get the identical behavior they always
    had, since every registered analyzer stays `full_scope_capable=True`
    today; see dumpex.hunt.full_scope_hunters(), which callers that DO
    know the real, capability-filtered roster -- dumpex/hunt/__init__.py,
    dumpex/cli.py -- pass explicitly). Finding, #73: an earlier version
    of this function hard-coded the unfiltered `HUNTERS` unconditionally,
    which crashed every `--hunt all` invocation with a `ValueError` the
    moment a `full_scope_capable=False` analyzer was ever registered
    (contract `docs/developer/hunt_analyzer_registry_contract.md` §2's own "the
    filter belongs on the `HUNTERS` side" invariant governed `AnalyzerRegistry.
    select("all")`'s own return value correctly, but this function never
    read it) -- this parameter is what makes that invariant actually
    reach `--hunt all`'s real output, not merely `select("all")`'s own.

    Raises `ValueError`/`TypeError` on any shape violation -- the same
    "fail loudly on a shape the caller got wrong" precedent every other
    cross-record reducer in this codebase follows (see e.g.
    dumpex.output.coverage.combine_coverage_reports).

    Status-to-overall-status reduction (ordering is part of public behavior):

        any hunter DETECTED                                  -> DETECTED
        no DETECTED, any INCONCLUSIVE or some-but-not-all
            NOT_EVALUATED                                     -> INCONCLUSIVE
        no DETECTED, no INCONCLUSIVE, ALL NOT_EVALUATED       -> NOT_EVALUATED
        no DETECTED, no INCONCLUSIVE, none NOT_EVALUATED      -> NOT_DETECTED_IN_SCANNED_SCOPE

    "some-but-not-all NOT_EVALUATED" (e.g. 3 of 7 hunters never got the
    data source they needed, the other 4 ran clean) is deliberately
    INCONCLUSIVE, not NOT_DETECTED_IN_SCANNED_SCOPE -- a scope that was
    only PARTLY looked at has not earned "clean", the same reasoning
    dumpex.hunt._finding.verdict_level()'s own docstring gives for why
    NOT_EVALUATED/INCONCLUSIVE take priority over a score<=0 "clean"
    default at the single-hunter level.

    `highest_verdict_level` is picked from the DETECTED hunters' own
    verdict_level values (never re-derived from score) when any exist;
    otherwise it's "inconclusive"/"not_evaluated"/"clean" matching
    `overall_status` exactly.

    `scan_scope` (keyword-only) is the closed tagged shape naming what this
    invocation covered -- see `validate_scan_scope`. It defaults to the `full`
    variant, which is the only correct answer for a summary built without a
    targeted request; a targeted caller passes its own variant explicitly.
    """
    if selected == "all":
        expected_hunters = tuple(full_scope_hunters) if full_scope_hunters is not None else tuple(HUNTERS)
    elif selected in HUNTERS:
        expected_hunters = (selected,)
    else:
        raise ValueError(
            f"build_hunt_summary() got unknown selected={selected!r} -- must be 'all' or "
            f"one of {HUNTERS}")

    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("build_hunt_summary() records must be a list of HunterRecord")

    actual_hunters = tuple(r.hunter for r in records)
    if actual_hunters != expected_hunters:
        raise ValueError(
            f"build_hunt_summary(selected={selected!r}) expected records for hunters "
            f"{expected_hunters!r} in that exact order, got {actual_hunters!r}")

    detected = [r for r in records if r.status == "DETECTED"]
    inconclusive = [r for r in records if r.status == "INCONCLUSIVE"]
    not_evaluated = [r for r in records if r.status == "NOT_EVALUATED"]
    lead_count = sum((r.lead_count or 0) for r in records)

    if detected:
        overall_status = "DETECTED"
        highest_verdict_level = max(
            (r.verdict_level for r in detected), key=_DETECTED_VERDICT_ORDER.index)
    elif inconclusive or (not_evaluated and len(not_evaluated) < len(records)):
        overall_status = "INCONCLUSIVE"
        highest_verdict_level = "inconclusive"
    elif len(not_evaluated) == len(records):
        overall_status = "NOT_EVALUATED"
        highest_verdict_level = "not_evaluated"
    else:
        overall_status = "NOT_DETECTED_IN_SCANNED_SCOPE"
        highest_verdict_level = "clean"

    return {
        "selected": selected,
        "scan_scope": validate_scan_scope(
            scan_scope if scan_scope is not None else full_scan_scope()),
        "hunter_count": len(records),
        "detected_count": len(detected),
        "inconclusive_count": len(inconclusive),
        "not_evaluated_count": len(not_evaluated),
        "overall_status": overall_status,
        "highest_verdict_level": highest_verdict_level,
        "lead_count": lead_count,
    }
