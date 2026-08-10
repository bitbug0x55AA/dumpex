"""`EncodingReport` -> console lines pure projector -- the ONE console
renderer for the encoding (obfuscation) hunter, replacing the pre-
migration `dumpex.hunt.encoding.presentation.render()` (which printed a
long per-layer CLEAN/OBSERVATION/LEAD/DETECTION inventory with the
verdict last). This module never prints (returns the exact lines a
caller would print) and never returns a legacy-dict projection (see
`report_legacy.py` for that, an independent pure function of the SAME
`EncodingReport`).

Implements the verdict-first structure approved in issue #1 (verdict
block -> KEY SIGNALS -> WHY THIS VERDICT (normal only) -> unified
COVERAGE -> verbose hint), mirroring `dumpex.hunt.injection.
report_console` (the completed reference pilot). Legacy console byte
parity is intentionally NOT preserved (see this hunter's own migration
issue) -- reviewed goldens in tests/fixtures/hunt_cli_golden/
obfuscation_console.txt/obfuscation_verbose_console.txt are the new
target.

This is also the one place this hunter's normal/verbose CONSOLE detail
POLICY lives: `report_facts.finding_from_check_result` builds a compat
`Finding` carrying only wire-shaped `facts` (never `verbose_facts`);
`_console_finding` below is what augments it with `verbose_facts`,
entirely locally, so `report_legacy.py`/`report_record.py` never execute
this policy at all.
"""
import dataclasses

from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text
from dumpex.hunt._finding import (
    DetailLevel, Finding, leads_suffix, render_finding_lines,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION,
)
from dumpex.hunt._console import resolve_width, wrap_text, render_kv_block
from dumpex.hunt.encoding.domain import EncodingReport
from dumpex.hunt.encoding.report_facts import finding_from_check_result, project_coverage_v1


# ── Verbose-only evidence-item fact rendering (console policy only) ──────
# Richer than report_facts.py's capped, wire-shaped facts: includes file
# offset and a couple of fields --json never carried, byte-identical to
# the pre-migration aggregate.py's own _*_verbose_fact() functions.

def _sleep_mask_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA=0x{h.location.va:016x} File_offset={fo_str} Region_size=0x{h.region.size:x} "
            f"XOR_key={h.key.hex()} rotation_offset={h.key_offset} "
            f"Decoded_type={h.classification.kind.upper()}")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:4])}"
    return fact


def _entropy_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    rwx = " [RWX]" if h.region.is_rwx else ""
    return (f"VA=0x{h.location.va:016x}{rwx} File_offset={fo_str} Size=0x{h.region.size:x} "
            f"Entropy={h.entropy:.3f}bits threshold={h.threshold} Protection={h.region.protect}")


def _base64_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA=0x{h.location.va:016x} File_offset={fo_str} "
            f"Decoded_type={h.classification.kind.upper()} "
            f"Decoded_size={len(h.decoded)}bytes B64_length={len(h.raw)}chars")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


def _xor_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA=0x{h.location.va:016x} File_offset={fo_str} XOR_key=0x{h.key:02x} "
            f"Decoded_type={h.classification.kind.upper()}")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


def _compressed_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA=0x{h.location.va:016x} File_offset={fo_str} Algorithm={h.layer.upper()} "
            f"Decoded_type={h.classification.kind.upper()} Decoded_size={len(h.decoded)}bytes")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


def _structural_pe_verbose_fact(h) -> str:
    reg_str = "registered" if h.known_module else "UNREGISTERED"
    return (f"type=PE encoding={h.layer} container_VA=0x{h.location.va:x} "
            f"module_status={reg_str} decoded_size={len(h.decoded)}"
            + ("" if h.complete else " decode=incomplete(output-cap)"))


def _shellcode_verbose_fact(h, report: EncodingReport) -> str:
    in_context = h in report.evidence.shellcode_context_hits
    return (f"type=shellcode_bootstrap encoding={h.layer} container_VA=0x{h.location.va:x} "
            f"decoded_size={len(h.decoded)} prefix={h.decoded[:6].hex()}"
            + (f" container_protect={h.region.protect} (executable+private)" if in_context else ""))


_VERBOSE_ITEM_RENDERERS = {
    "obfuscation.sleep_mask_confirmed":    _sleep_mask_verbose_fact,
    "obfuscation.entropy_observation":     _entropy_verbose_fact,
    "obfuscation.base64_observation":      _base64_verbose_fact,
    "obfuscation.xor_observation":         _xor_verbose_fact,
    "obfuscation.compressed_observation":  _compressed_verbose_fact,
}

# structural_payload/shellcode_bootstrap_lead's verbose rendering is the
# SAME text as their wire-shaped facts (report_facts.py's own
# _structural_pe_item_fact/_shellcode_item_fact, duplicated here rather
# than imported -- see this module's own docstring) -- only uncapped,
# matching the pre-migration aggregate.py's own `verbose_facts=facts`
# (the full, uncapped list; every field it carries per hit is already
# complete, so the only delta verbose provides is completeness, not new
# fields).

def _verbose_facts_for(result, report: EncodingReport) -> tuple:
    if result.check == "obfuscation.structural_payload":
        return tuple(_structural_pe_verbose_fact(item) for item in result.evidence)
    if result.check == "obfuscation.shellcode_bootstrap_lead":
        return tuple(_shellcode_verbose_fact(item, report) for item in result.evidence)
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        return ()
    return tuple(renderer(item) for item in result.evidence)


def _console_finding(result, report: EncodingReport) -> Finding:
    finding = finding_from_check_result(result, report)
    verbose_facts = _verbose_facts_for(result, report)
    if not verbose_facts:
        return finding
    return dataclasses.replace(finding, verbose_facts=list(verbose_facts))


_TITLES = {
    "obfuscation.sleep_mask_confirmed":    "CS Sleep Mask XOR-encoded beacon memory",
    "obfuscation.entropy_observation":     "High-entropy private memory",
    "obfuscation.base64_observation":      "Base64 encoded payloads",
    "obfuscation.xor_observation":         "XOR single-byte obfuscation",
    "obfuscation.compressed_observation":  "Compressed data (GZIP/ZLIB)",
    "obfuscation.structural_payload":      "Structural PE payload inside encoded data",
    "obfuscation.shellcode_bootstrap_lead": "Shellcode bootstrap pattern inside encoded data",
}

_TAG_ICON  = {TAG_DETECTION: RED("[!]"), TAG_LEAD: YELLOW("[~]"), TAG_OBSERVATION: DIM("[i]")}
_TAG_LABEL = {TAG_DETECTION: "DETECTION", TAG_LEAD: "LEAD", TAG_OBSERVATION: "CONTEXT"}
_TAG_RANK  = {TAG_DETECTION: 0, TAG_LEAD: 1, TAG_OBSERVATION: 2}
_LABEL_WIDTH = max(len(label) for label in _TAG_LABEL.values())

_COVERAGE_ICON = {"complete": GREEN("[✓]"), "partial": YELLOW("[~]"), "not_evaluated": DIM("[-]")}


def _header_lines(title: str) -> list:
    bar = BOLD("══════════════════════════════════════════")
    return ["", bar, BOLD(f"  HUNT: {title}"), bar, ""]


def _scan_layers_lines() -> list:
    """Verbose-only scan-detail block replacing the pre-migration
    "Layer 0/1/2-4: ..." pre-scan progress announcements -- this module
    is a pure post-hoc projection (see this module's own docstring), so
    these lines can no longer print DURING the scan; folded into a static
    verbose-only summary instead, per issue's "collapse ... into
    verbose-only scan detail"."""
    return [
        DIM("  Layers scanned:"),
        DIM("    Layer 0: CS Sleep Mask XOR scan (frequency analysis)"),
        DIM("    Layer 1: Shannon entropy scan"),
        DIM("    Layers 2-4: Base64 / XOR / GZIP scan"),
        "",
    ]


def _sorted_for_display(findings: list) -> list:
    return [f for _, f in sorted(enumerate(findings),
                                  key=lambda pair: (_TAG_RANK.get(pair[1].tag, 3), pair[0]))]


def _wrap_block(text: str, width: int, indent: int) -> list:
    pad = " " * indent
    return [pad + line for line in wrap_text(text, max(1, width - indent), hang_indent=0)]


def _render_verdict_block(status: str, verdict_level: str, score: int, max_score: int,
                           confidence: str, coverage_status: str, review_priority: str,
                           findings: list) -> list:
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "no required stream present in this dump")
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict_text = GREEN("CLEAN" + leads_suffix(findings))
    elif score == 0:
        verdict_text = YELLOW("INCONCLUSIVE — partial scan coverage" + leads_suffix(findings))
    else:
        verdict_text = (
            RED("HIGH CONFIDENCE — sleep-mask decode AND a structural PE payload confirmed")
            if verdict_level == "high" else
            YELLOW("LIKELY — one structural indicator (sleep-mask decode or PE payload)"))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", confidence),
        ("Score",      f"{score}/{max_score}"),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _render_key_signal_compact(finding, width: int) -> list:
    title = _TITLES.get(finding.check, finding.check)
    label = _TAG_LABEL.get(finding.tag, finding.tag.upper())
    icon  = _TAG_ICON.get(finding.tag, DIM("[?]"))
    lines = [f"  {icon} {label:<{_LABEL_WIDTH}}  {title}"]
    lines.extend(_wrap_block(finding.inference, width, 6))
    return lines


def _render_why_this_verdict(driving, width: int) -> list:
    lines = [f"  {BOLD('WHY THIS VERDICT')}", ""]
    lines.append("  Inference")
    lines.extend(_wrap_block(driving.inference, width, 4))
    lines.append("")
    lines.append(f"  Confidence: {driving.confidence.upper()}")
    lines.extend(_wrap_block(driving.rationale, width, 4))
    if driving.limitations:
        lines.append("")
        lines.append("  Caveat")
        lines.extend(_wrap_block(driving.limitations[0], width, 4))
    lines.append("")
    return lines


def _render_coverage(coverage_status: str, reasons: list, width: int) -> list:
    icon = _COVERAGE_ICON.get(coverage_status, DIM("[?]"))
    lines = [f"  {BOLD('COVERAGE')}", "", f"  {icon} {coverage_status.replace('_', ' ').upper()}"]
    for reason in reasons:
        lines.extend(_wrap_block(reason, width, 6))
    lines.append("")
    return lines


def render_console_lines(report: EncodingReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `EncodingReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value."""
    findings = [_console_finding(r, report) for r in report.results]
    _, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(_header_lines("Obfuscation Detection"))
    if verbose:
        lines.extend(_scan_layers_lines())

    lines.extend(_render_verdict_block(report.status, report.verdict_level, report.score,
                                        report.max_score, report.confidence, coverage_status,
                                        report.review_priority, findings))
    lines.append("")

    ordered = _sorted_for_display(findings)
    if ordered:
        lines.append(f"  {BOLD('KEY SIGNALS')}")
        lines.append("")
        for f in ordered:
            if verbose:
                title = _TITLES.get(f.check, f.check)
                lines.extend(render_finding_lines(f, level=level, indent=2, width=w, title=title))
            else:
                lines.extend(_render_key_signal_compact(f, w))
                lines.append("")

    if not verbose:
        driving = ordered[0] if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD) else None
        if driving is not None:
            lines.extend(_render_why_this_verdict(driving, w))

    if coverage_reasons:
        lines.extend(_render_coverage(coverage_status, coverage_reasons, w))

    evidence = report.evidence
    has_raw_evidence = bool(evidence.sleep_mask_hits or evidence.entropy_hits
                            or evidence.base64_hits or evidence.xor_hits or evidence.compressed_hits)
    if not verbose and has_raw_evidence:
        lines.append(DIM("  Use --verbose for complete per-region evidence, file offsets, and "
                          "decoded content.\n"))

    return lines


def print_console(report: EncodingReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
