"""Render a ``CSBeaconReport`` as verdict-first console lines.

Resolved locations and decoded fields come from immutable config evidence.
Display ordering may prioritize corroborated hits without changing record order.
"""
import dataclasses

from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import DETECTED, NOT_EVALUATED, INCONCLUSIVE, _status_text
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_OBSERVATION,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    coverage_kv_value, header_lines, render_why_this_verdict, render_coverage,
    with_verbose_facts, wrap_block,
)
from dumpex.hunt.cs_beacon.domain import CSBeaconReport
from dumpex.hunt.cs_beacon.models import ConfigEvidence
from dumpex.hunt.cs_beacon.parser import _cs_decode_instructions, _cs_decode_type3_value
from dumpex.hunt.cs_beacon.report_facts import (
    finding_from_check_result, project_coverage_report, project_coverage_v1,
)
from dumpex.output.records import hex_address
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
    """One TLV field's value for console display when it fits inline as
    a single wrapped run of text -- `str(value)` for a non-bytes field,
    `repr(value)` for a printable type-3 field. A BINARY type-3 field's
    value never reaches this function: `_value_lines()` routes it
    straight to `_wrap_hex_value()` with the field's FULL raw bytes as
    hex instead, so the complete value can be wrapped across lines
    without ever being sliced short (issue #46: a fixed 64-hex-char slice
    here used to silently discard the tail of any field over 32 bytes,
    even under --verbose's own "complete field table")."""
    if f.type != 3:
        return str(f.value)
    return repr(f.value)


def _wrap_hex_value(hexs: str, prefix: str, w: int) -> list:
    """`hexs` (a complete, never-truncated hex encoding of a binary TLV
    field) as one or more lines: `prefix` (the field's name/type columns,
    already padded) on the first line, continuation lines indented to
    align under where the hex itself started. Splits only on whole-byte
    (even hex-digit) boundaries -- a byte is never torn across a line
    break -- and always shows every hex digit somewhere, so a value too
    long for one line is wrapped, never shortened."""
    hang = len(prefix)
    avail = max(2, ((w - hang) // 2) * 2)
    if len(hexs) <= avail:
        return [prefix + hexs]
    pad = " " * hang
    chunks = [hexs[i:i + avail] for i in range(0, len(hexs), avail)]
    return [prefix + chunks[0]] + [pad + chunk for chunk in chunks[1:]]


def _is_binary_bytes(f) -> bool:
    """True only for a type-3 field whose raw payload is NOT printable
    text -- the one condition that routes a field's value through
    `_wrap_hex_value()` instead of being shown as-is."""
    return f.type == 3 and not _cs_decode_type3_value(f.raw)[1]


def _value_lines(f, prefix: str, w: int) -> list:
    """`prefix` (a field's already-formatted name/type columns) plus that
    field's display value: a binary field's full hex always wraps with a
    hanging indent (`_wrap_hex_value()`) instead of ever being sliced
    short. A printable/non-bytes value renders on exactly ONE line,
    UNCHANGED from `_display_value()` -- deliberately never passed
    through `wrap_text()`, which re-joins on `text.split()` and would
    silently collapse any run of repeated whitespace already present in
    the field's own text (a lossy transform distinct from, and not
    excused by, the binary-truncation bug this function exists to fix)."""
    if _is_binary_bytes(f):
        return _wrap_hex_value(f.raw.hex(), prefix, w)
    return [prefix + _display_value(f)]


# ── KEY SIGNALS ────────────────────────────────────────────────────────

def _key_signal_title(result, hit: "ConfigEvidence | None") -> str:
    if hit is None:
        return "No structurally-valid config found"
    return f"Beacon config @ {hex_address(hit.hit_va)}"


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
        f"VA {hex_address(hit.hit_va)}  File offset {_file_offset_text(hit.hit_fo)}", w, 6)
    if region is not None:
        lines.extend(wrap_block(
            f"Region {hex_address(region.base_address)}  size 0x{region.size:x}  "
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
        prefix = f"        {f.name:<{name_w}}  {type_name:<{type_w}}  "
        lines.extend(_value_lines(f, prefix, w))
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
        if f.field_id in (0x002b, 0x002c):
            # A synthetic, dumpex-generated enum label (never raw evidence
            # bytes) -- ordinary word-wrap is fine here.
            value = CS_INJECT_PERMS.get(f.value, str(f.value))
            lines.extend(wrap_block(f"{f.name:<{name_w}}  {value}", w, 8))
        else:
            prefix = " " * 8 + f"{f.name:<{name_w}}  "
            lines.extend(_value_lines(f, prefix, w))
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

def _render_verdict_block(report: CSBeaconReport, coverage_status: str, findings: list,
                           coverage_report) -> list:
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
        ("Coverage",   coverage_kv_value(coverage_status, coverage_report)),
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
    lines.extend(_render_verdict_block(report, coverage_status, findings,
                                        project_coverage_report(
                                            report.coverage, has_hits=has_hits,
                                            any_corroborated=report.any_corroborated)))
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
