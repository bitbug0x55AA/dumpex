"""`CSBeaconReport` -> console lines pure projector -- the ONE console
renderer for the CS Beacon hunter, replacing the pre-migration
`presentation.render(report, verbose)` (which printed a per-config header
table, then that config's Finding narrative, then a large ad-hoc field
breakdown -- C2/Identity/Transport, Process Injection, Malleable C2/GET/
POST transforms, SSH transport, DNS transport, and, under --verbose, the
full field table -- BEFORE the verdict, with progress lines printed
separately in `dumpex/hunt/cs_beacon/__init__.py` around the scan itself).

This module never prints (returns the exact lines a caller would print),
and never receives `mf`: every VA, file offset, region protection, and
field value it renders was resolved once, at scan time, onto
`report.evidence` (dumpex.hunt.cs_beacon.models.ConfigEvidence).

Implements the verdict-first structure approved in issue #1 (verdict block
-> KEY SIGNALS -> WHY THIS VERDICT (normal only) -> bounded evidence detail
-> unified COVERAGE -> verbose hint), mirroring
`dumpex.hunt.hollowing.report_console`/`dumpex.hunt.stomping.report_console`/
`dumpex.hunt.pipe.report_console`/`dumpex.hunt.injection.report_console`/
`dumpex.hunt.encoding.report_console` (the five completed reference
pilots). Legacy console byte parity is intentionally NOT preserved (see
issue #9's own console scope).

What moved, and where (issue #9's console scope, point by point):

  * the hunt header is emitted HERE, via
    `dumpex.hunt._report_console.header_lines()`, instead of by a separate
    pre-build console function. The normal-mode "Scanning N segment(s)
    ..."/"Scan complete..." progress lines are gone entirely -- they
    carried console-progress STATE on the Report itself (`scan_note`,
    issue #9's own "confirmed current gap"), and nothing prints before the
    Report exists any more, the same resolution every other migrated
    hunter applied;
  * the verdict, confidence, score, coverage status, and review priority
    are the FIRST thing rendered, as a key/value block;
  * each structurally-valid config becomes ONE compact KEY SIGNAL entry
    (context-corroborated configs sorted first for display -- a DISPLAY
    reorder only; `report.results`/`report.evidence.hits` construction
    order, and therefore the frozen v1.1/typed-record `configs[]` array
    order, is never touched);
  * WHY THIS VERDICT explains the single driving config only -- the first
    corroborated hit if any, else the first hit;
  * the large per-config field breakdown is now BEACON CONFIGS, a bounded
    (issue #9: "explicit truncation counts"), VERBOSE-mostly section:
    normal mode shows each shown config's resolved location, estimated
    version, and BeaconType/core transport identity; verbose additionally
    expands the complete field table, Malleable C2, and Process Injection
    transforms;
  * coverage reasons/impacts render exactly once, in the unified COVERAGE
    section, instead of a separate "[~] ..." progress-style line.
"""
import dataclasses

from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import DETECTED, NOT_EVALUATED, INCONCLUSIVE, _status_text
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_OBSERVATION,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    header_lines, render_why_this_verdict, render_coverage, with_verbose_facts, wrap_block,
)
from dumpex.hunt.cs_beacon.domain import CSBeaconReport
from dumpex.hunt.cs_beacon.models import ConfigEvidence
from dumpex.hunt.cs_beacon.parser import _cs_decode_instructions, _cs_decode_type3_value
from dumpex.hunt.cs_beacon.report_facts import (
    finding_from_check_result, project_coverage_v1,
)
from dumpex.hunt.cs_beacon.schema import (
    CS_BEACON_TYPES, CS_FIELD_TYPE_NAMES, CS_INJECT_PERMS, CS_PROXY_TYPES,
)


_STRUCTURAL_CONFIG    = "cs_beacon.structural_config"
_NO_STRUCTURAL_CONFIG = "cs_beacon.no_structural_config"

# How many configs BEACON CONFIGS expands in full -- bounded so a dump
# stuffed with dozens of hits cannot make the console transcript unbounded.
# `--json`/the typed record always carry every hit regardless.
MAX_DISPLAYED_CONFIGS = 10

_INJECT_FIELD_IDS = (0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0033, 0x0034, 0x0035)

# Substrings identifying a per-hit `CheckResult.limitation` that restates a
# whole-report COVERAGE gap (`report_facts.project_coverage_v1`'s own
# reason text for that same gap) rather than a genuinely per-hit caveat.
# `finding.limitations` keeps this text for --json/the typed record (the
# current-contract freeze) -- this module's own --verbose KEY SIGNALS
# rendering is the ONE place it is filtered out, so a report with several
# uncorroborated hits doesn't restate the same MemoryInfoListStream/
# ThreadListStream gap once per hit AND once more in COVERAGE (issue #9:
# "Render coverage reasons/impacts exactly once").
_COVERAGE_LIMITATION_MARKERS = (
    "MemoryInfoListStream missing from this dump",
    "ThreadListStream missing from this dump",
    "thread(s) had no parsed CONTEXT",
)


def _without_coverage_limitations(finding):
    kept = tuple(l for l in finding.limitations
                 if not any(marker in l for marker in _COVERAGE_LIMITATION_MARKERS))
    if kept == finding.limitations:
        return finding
    return dataclasses.replace(finding, limitations=list(kept))


def _file_offset_text(file_offset) -> str:
    return f"0x{file_offset:x}" if file_offset is not None else "(not captured)"


def _hit_for(result) -> "ConfigEvidence | None":
    for item in result.evidence:
        if isinstance(item, ConfigEvidence):
            return item
    return None


def _display_value(f) -> str:
    """One TLV field's value for console display -- the ONE place both
    the Process Injection section and the Full Config Field Table decide
    how to show a type-3 (bytes) field, mirroring the pre-migration
    `_field_display_value()` exactly (see that function's own docstring
    for the printable/binary rule this reproduces)."""
    if f.type != 3:
        return str(f.value)
    _, is_text = _cs_decode_type3_value(f.raw)
    if is_text:
        return repr(f.value)
    hexs = f.raw.hex()
    return f"{hexs[:64]}{'...' if len(hexs) > 64 else ''}"


# ── KEY SIGNALS ────────────────────────────────────────────────────────

def _key_signal_title(result, hit: "ConfigEvidence | None") -> str:
    if hit is None:
        return "No structurally-valid config found"
    return f"Beacon config @ 0x{hit.hit_va:x}"


def _render_key_signal_compact(finding, hit, width: int) -> list:
    icon = RED("[!]") if finding.tag == TAG_DETECTION else DIM("[i]")
    label = "DETECTION" if finding.tag == TAG_DETECTION else "CONTEXT"
    title = _key_signal_title(None, hit) if hit is not None else "No structurally-valid config found"
    lines = [f"  {icon} {label:<9}  {title}"]
    lines.extend(wrap_block(finding.inference, width, 6))
    return lines


def _ordered_for_display(report: CSBeaconReport, findings: list) -> list:
    """`(result, finding)` pairs -- one per `report.results` entry, same
    order -- reordered so a context-corroborated config's KEY SIGNAL sorts
    before an uncorroborated one -- a DISPLAY-only reorder (issue #9's
    console scope); `report.results`/the frozen `configs[]` array order is
    never touched. Ties keep construction order."""
    def _rank(pair):
        index, (result, _finding) = pair
        hit = _hit_for(result)
        if hit is None:
            return (2, index)
        corroborated = report.evidence.corroboration_for(hit) is not None
        return (0 if corroborated else 1, index)
    pairs = list(zip(report.results, findings))
    ranked = sorted(enumerate(pairs), key=_rank)
    return [pair for _, pair in ranked]


# ── BEACON CONFIGS (bounded) ──────────────────────────────────────────

def _location_lines(hit: ConfigEvidence, w: int) -> list:
    region = hit.region
    lines = wrap_block(
        f"VA 0x{hit.hit_va:016x}  File offset {_file_offset_text(hit.hit_fo)}", w, 6)
    if region is not None:
        lines.extend(wrap_block(
            f"Region 0x{region.base_address:016x}  size 0x{region.size:x}  "
            f"protect {region.protect}", w, 6))
    else:
        lines.extend(wrap_block(
            "Region: not covered by MemoryInfoListStream", w, 6))
    return lines


def _core_transport_identity(hit: ConfigEvidence, w: int) -> list:
    """BeaconType/core transport identity -- issue #9's own normal-mode
    scope. Deliberately a short, fixed set (BeaconType, C2 host/URI, port,
    UserAgent) rather than every field this config carries -- the complete
    field table is a VERBOSE-only expansion (see `_field_table_lines`)."""
    lines = []
    beacon_type = hit.field(0x0001)
    if beacon_type is not None:
        text = CS_BEACON_TYPES.get(beacon_type.value, f"unknown ({beacon_type.value})")
        color = RED if beacon_type.value in (1, 2) else YELLOW   # DNS/SMB = more covert
        lines.extend(wrap_block(f"BeaconType: {color(text)}", w, 6))
    c2 = hit.field(0x0008)
    if c2 is not None:
        raw = (c2.value or "").strip("\x00") if isinstance(c2.value, str) else ""
        if "," in raw:
            host, uri = raw.split(",", 1)
            lines.extend(wrap_block(f"C2 Host: {host.strip()}   GET URI: {uri.strip()}", w, 6))
        elif raw:
            lines.extend(wrap_block(f"C2 Server: {raw}", w, 6))
    port = hit.field(0x0002)
    if port is not None:
        lines.extend(wrap_block(f"Port: {port.value}", w, 6))
    ua = hit.field(0x0009)
    if ua is not None:
        text = (ua.value or "").strip("\x00") if isinstance(ua.value, str) else ""
        if text:
            lines.extend(wrap_block(f"UserAgent: {text}", w, 6))
    return lines


def _corroboration_line(report: CSBeaconReport, hit: ConfigEvidence, w: int) -> list:
    corroboration = report.evidence.corroboration_for(hit)
    if corroboration is not None:
        return wrap_block(f"Context corroboration: YES — {'; '.join(corroboration.reasons)}", w, 6)
    return wrap_block("Context corroboration: none — structural validity only", w, 6)


def _field_table_lines(hit: ConfigEvidence, w: int) -> list:
    if not hit.fields:
        return []
    name_w = max(len(f.name) for f in hit.fields)
    type_w = max(len(CS_FIELD_TYPE_NAMES.get(f.type, str(f.type))) for f in hit.fields)
    lines = [f"      {BOLD('Full Config Field Table')}", "",
             f"        {'Field':<{name_w}}  {'Type':<{type_w}}  Value"]
    for f in sorted(hit.fields, key=lambda item: item.field_id):
        type_name = CS_FIELD_TYPE_NAMES.get(f.type, str(f.type))
        lines.append(f"        {f.name:<{name_w}}  {type_name:<{type_w}}  {_display_value(f)}")
    lines.append("")
    return lines


def _malleable_c2_lines(hit: ConfigEvidence, w: int) -> list:
    lines = []
    for field_id, label, itype in (
        (0x000b, "Malleable C2 (server→client transform)", 1),
        (0x000c, "HTTP GET header transforms", 2),
        (0x000d, "HTTP POST header transforms", 3),
    ):
        f = hit.field(field_id)
        if f is None or not f.raw:
            continue
        try:
            instructions = _cs_decode_instructions(f.raw, itype)
        except Exception:
            instructions = []
        if not instructions:
            continue
        lines.append(f"      {BOLD(label)}")
        for step in instructions:
            lines.extend(wrap_block(f"› {step}", w, 8))
        lines.append("")
    return lines


def _process_injection_lines(hit: ConfigEvidence, w: int) -> list:
    present = [hit.field(fid) for fid in _INJECT_FIELD_IDS]
    present = [f for f in present if f is not None]
    if not present:
        return []
    name_w = max(len(f.name) for f in present)
    lines = [f"      {BOLD('Process Injection')}", ""]
    for f in sorted(present, key=lambda item: item.field_id):
        value = (CS_INJECT_PERMS.get(f.value, str(f.value)) if f.field_id in (0x002b, 0x002c)
                 else _display_value(f))
        lines.extend(wrap_block(f"{f.name:<{name_w}}  {value}", w, 8))
    lines.append("")
    return lines


def _beacon_config_block(report: CSBeaconReport, hit: ConfigEvidence, index: int, w: int,
                          verbose: bool) -> list:
    lines = [f"  {BOLD(f'Beacon config #{index}')}", ""]
    lines.extend(_location_lines(hit, w))
    lines.extend(wrap_block(f"Version: {hit.cs_version} (estimated)", w, 6))
    lines.extend(_core_transport_identity(hit, w))
    lines.extend(_corroboration_line(report, hit, w))
    lines.append("")
    if verbose:
        lines.extend(_field_table_lines(hit, w))
        lines.extend(_process_injection_lines(hit, w))
        lines.extend(_malleable_c2_lines(hit, w))
    return lines


def _beacon_configs_lines(report: CSBeaconReport, w: int, verbose: bool) -> list:
    """The bounded BEACON CONFIGS section (issue #9's own console scope) --
    nothing rendered when no config was found at all."""
    hits = report.evidence.hits
    if not hits:
        return []
    lines = [f"  {BOLD('BEACON CONFIGS')}", ""]
    shown = hits[:MAX_DISPLAYED_CONFIGS]
    for index, hit in enumerate(shown, 1):
        lines.extend(_beacon_config_block(report, hit, index, w, verbose))
    remaining = len(hits) - len(shown)
    if remaining > 0:
        # `MAX_DISPLAYED_CONFIGS` bounds this section in BOTH normal and
        # --verbose mode (verbose only expands the DETAIL shown for each
        # already-displayed config, not how many configs are shown) -- the
        # hint must say --json, never --verbose, or it promises a fuller
        # list --verbose does not actually produce.
        lines.extend(wrap_block(
            f"... and {remaining} more config(s) not shown here — see --json for the full "
            f"list.", w, 2))
        lines.append("")
    return lines


# ── Verdict block / coverage impacts ──────────────────────────────────

def _render_verdict_block(report: CSBeaconReport, coverage_status: str, findings: list) -> list:
    status, score = report.status, report.score
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "Memory64ListStream missing from this dump")
    elif status == DETECTED:
        verdict_text = (
            RED(f"COBALT STRIKE — {report.config_count} beacon config(s) found in memory "
                f"(context-corroborated)")
            if report.any_corroborated else
            YELLOW(f"COBALT STRIKE — {report.config_count} beacon config(s) found in memory "
                   f"(structural validity only)"))
    elif status == INCONCLUSIVE:
        verdict_text = YELLOW("INCONCLUSIVE — partial coverage" + leads_suffix(findings))
    else:
        verdict_text = GREEN("CLEAN — no beacon config found in memory" + leads_suffix(findings))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", report.confidence),
        ("Score",      f"{score}/{report.max_score}"),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     report.review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _coverage_impacts(report: CSBeaconReport, coverage_status: str) -> list:
    coverage = report.coverage
    impacts = []
    if not coverage.evaluated:
        impacts.append("No memory segments were captured in this dump at all — nothing was "
                       "examined, so a score of 0 here is not a clean result.")
    elif not coverage.mem_info_available:
        impacts.append("MemoryInfoListStream missing — region/execution-context "
                       "corroboration could not be verified for any config hit found here.")
    if report.status == DETECTED and coverage_status == "partial":
        impacts.append("Coverage incomplete despite a detection — the segment(s)/check(s) "
                       "that could not fully run may hold further corroboration.")
    return impacts


def _driving_finding(report: CSBeaconReport, findings: list):
    """The single config that actually justified the verdict -- the first
    context-corroborated hit if any, else the first hit. `None` when no
    hit exists at all (score 0): a lone CONTEXT observation explains
    nothing about a CLEAN/INCONCLUSIVE verdict, matching every other
    migrated hunter's own `_driving_finding` guard."""
    structural = [(r, f) for r, f in zip(report.results, findings) if r.check == _STRUCTURAL_CONFIG]
    if not structural:
        return None
    for result, finding in structural:
        hit = _hit_for(result)
        if hit is not None and report.evidence.corroboration_for(hit) is not None:
            return finding
    return structural[0][1]


def render_console_lines(report: CSBeaconReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `CSBeaconReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, and no
    `mf`."""
    findings = [finding_from_check_result(r, report) for r in report.results]
    has_hits = bool(report.evidence.hits)
    coverage_status, coverage_reasons = project_coverage_v1(
        report.coverage, has_hits=has_hits, any_corroborated=report.any_corroborated)
    w = resolve_width(width)

    lines = list(header_lines("Cobalt Strike Beacon Config"))
    lines.extend(_render_verdict_block(report, coverage_status, findings))
    lines.append("")

    ordered = _ordered_for_display(report, findings)
    if ordered:
        lines.append(f"  {BOLD('KEY SIGNALS')}")
        lines.append("")
        for result, finding in ordered:
            hit = _hit_for(result)
            if verbose:
                title = _key_signal_title(result, hit)
                lines.extend(render_finding_lines(_without_coverage_limitations(finding),
                                                   level=DetailLevel.VERBOSE, indent=2,
                                                   width=w, title=title))
            else:
                lines.extend(_render_key_signal_compact(finding, hit, w))
                lines.append("")

    if not verbose and report.status != NOT_EVALUATED:
        driving = _driving_finding(report, findings)
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    lines.extend(_beacon_configs_lines(report, w, verbose))

    if coverage_reasons:
        lines.extend(render_coverage(coverage_status, coverage_reasons, w,
                                      _coverage_impacts(report, coverage_status)))

    if not verbose and has_hits:
        lines.append(DIM("  Use --verbose for the complete field table, Malleable C2, and "
                          "Process Injection transforms.\n"))

    return lines


def print_console(report: CSBeaconReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
