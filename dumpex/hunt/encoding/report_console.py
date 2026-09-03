"""Render an ``EncodingReport`` as verdict-first console lines.

Verbose evidence is a console-only projection; wire-shaped facts remain
stable for legacy and structured output.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_LEAD,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    coverage_kv_value, header_lines, sorted_for_display, render_key_signal_compact,
    render_why_this_verdict, render_coverage, with_verbose_facts,
)
from dumpex.hunt.encoding.domain import EncodingReport
from dumpex.hunt.encoding.report_facts import (
    _shellcode_item_fact, _structural_pe_item_fact, finding_from_check_result,
    project_coverage_report, project_coverage_v1,
)
from dumpex.output.records import hex_address


# ── Verbose-only evidence-item fact rendering (console policy only) ──────
# Richer than report_facts.py's capped, wire-shaped facts: includes file
# offset and a couple of fields --json never carried. Every address-typed
# field (`VA`, `container_VA`) goes through the shared `hex_address()`
# helper, so a verbose line renders an address in the same fixed-width,
# zero-padded 16-hex-digit form as the wire fact, the structured record,
# and `--json` `details`.

def _sleep_mask_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA={hex_address(h.location.va)} File_offset={fo_str} Region_size=0x{h.region.size:x} "
            f"XOR_key={h.key.hex()} rotation_offset={h.key_offset} "
            f"Decoded_type={h.classification.kind.upper()}")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:4])}"
    return fact


def _entropy_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    rwx = " [RWX]" if h.region.is_rwx else ""
    size_label = "Window_size" if h.size is not None else "Size"
    return (f"VA={hex_address(h.location.va)}{rwx} File_offset={fo_str} "
            f"{size_label}=0x{h.measured_size:x} "
            f"Entropy={h.entropy:.3f}bits threshold={h.threshold} Protection={h.region.protect}")


def _base64_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA={hex_address(h.location.va)} File_offset={fo_str} "
            f"Decoded_type={h.classification.kind.upper()} "
            f"Decoded_size={len(h.decoded)}bytes B64_length={len(h.raw)}chars")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


def _xor_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA={hex_address(h.location.va)} File_offset={fo_str} XOR_key=0x{h.key:02x} "
            f"Decoded_type={h.classification.kind.upper()}")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


def _compressed_verbose_fact(h) -> str:
    fo = h.location.file_offset
    fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
    fact = (f"VA={hex_address(h.location.va)} File_offset={fo_str} Algorithm={h.layer.upper()} "
            f"Decoded_type={h.classification.kind.upper()} Decoded_size={len(h.decoded)}bytes")
    if h.classification.ioc_strings:
        fact += f" IOC_strings={', '.join(h.classification.ioc_strings[:3])}"
    return fact


_VERBOSE_ITEM_RENDERERS = {
    "obfuscation.sleep_mask_confirmed":    _sleep_mask_verbose_fact,
    "obfuscation.entropy_observation":     _entropy_verbose_fact,
    "obfuscation.base64_observation":      _base64_verbose_fact,
    "obfuscation.xor_observation":         _xor_verbose_fact,
    "obfuscation.compressed_observation":  _compressed_verbose_fact,
}

# structural_payload/shellcode_bootstrap_lead's verbose rendering is the
# SAME text as their wire-shaped facts, only uncapped: the check already
# carries every field it knows about its own evidence item, so the only
# delta --verbose provides is completeness. The wire renderers in
# report_facts.py are the single source for that text (and, through
# `hex_address()`, for its address formatting) rather than a second copy
# kept in step by hand.

def _verbose_facts_for(result, report: EncodingReport) -> tuple:
    if result.check == "obfuscation.structural_payload":
        return tuple(_structural_pe_item_fact(item, report) for item in result.evidence)
    if result.check == "obfuscation.shellcode_bootstrap_lead":
        return tuple(_shellcode_item_fact(item, report) for item in result.evidence)
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        return ()
    return tuple(renderer(item) for item in result.evidence)


def _console_finding(result, report: EncodingReport):
    finding = finding_from_check_result(result, report)
    return with_verbose_facts(finding, _verbose_facts_for(result, report))


_TITLES = {
    "obfuscation.sleep_mask_confirmed":    "CS Sleep Mask XOR-encoded beacon memory",
    "obfuscation.entropy_observation":     "High-entropy private memory",
    "obfuscation.base64_observation":      "Base64 encoded payloads",
    "obfuscation.xor_observation":         "XOR single-byte obfuscation",
    "obfuscation.compressed_observation":  "Compressed data (GZIP/ZLIB)",
    "obfuscation.structural_payload":      "Structural PE payload inside encoded data",
    "obfuscation.shellcode_bootstrap_lead": "Shellcode bootstrap pattern inside encoded data",
}

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


def _render_verdict_block(status: str, verdict_level: str, score: int, max_score: int,
                           confidence: str, coverage_status: str, review_priority: str,
                           findings: list, coverage_report) -> list:
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
        ("Coverage",   coverage_kv_value(coverage_status, coverage_report)),
        ("Review",     review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def render_console_lines(report: EncodingReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `EncodingReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value."""
    findings = [_console_finding(r, report) for r in report.results]
    _, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(header_lines("Obfuscation Detection"))
    if verbose:
        lines.extend(_scan_layers_lines())

    lines.extend(_render_verdict_block(report.status, report.verdict_level, report.score,
                                        report.max_score, report.confidence, coverage_status,
                                        report.review_priority, findings,
                                        project_coverage_report(report.coverage)))
    lines.append("")

    ordered = sorted_for_display(findings)
    if ordered:
        lines.append(f"  {BOLD('KEY SIGNALS')}")
        lines.append("")
        for f in ordered:
            if verbose:
                title = _TITLES.get(f.check, f.check)
                lines.extend(render_finding_lines(f, level=level, indent=2, width=w, title=title))
            else:
                lines.extend(render_key_signal_compact(f, w, _TITLES))
                lines.append("")

    if not verbose:
        driving = ordered[0] if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD) else None
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    if coverage_reasons:
        lines.extend(render_coverage(coverage_status, coverage_reasons, w))

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
