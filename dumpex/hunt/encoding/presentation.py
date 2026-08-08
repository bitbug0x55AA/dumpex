"""
Console rendering for dumpex.hunt.encoding. Pure formatting: every
tag/score/confidence/note decision was already made by
dumpex/hunt/encoding/aggregate.py (see EncodingReport) -- this module
only turns that decision into text and prints it. No hunter logic lives
here, and no raw hit list (report.sleep_mask_hits, report.entropy_hits,
...) is read for --verbose detail -- every Finding in report.findings_list
already carries everything Finding.print() can show for it (see
aggregate.py's five *_verbose_fact() functions, where that detail --
including file offset and a few other fields --json never carried --
is built once, at Finding-construction time). The raw lists are still read
here for the short CLEAN/OBSERVATION/LEAD/DETECTION status lines below
(report.sleep_mask_hits, etc. -- just a truthiness/count check, not a
source of rendered detail).
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import _print_check, _status_text, INCONCLUSIVE, NOT_EVALUATED
from dumpex.hunt._finding import DetailLevel, TAG_OBSERVATION, leads_suffix
from dumpex.hunt.encoding.aggregate import EncodingReport, oversized_layer_reasons


def _print_sleep_mask(sleep_mask_hits):
    if sleep_mask_hits:
        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            RED("SUSPICIOUS — beacon memory decoded via sleep mask key recovery"),
            f"{len(sleep_mask_hits)} region(s) with confirmed CS Sleep Mask encoding",
        )
    else:
        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            GREEN("CLEAN — no sleep mask XOR encoding detected"),
        )


def _print_entropy(entropy_hits):
    if entropy_hits:
        _print_check("High-entropy private memory (observation)",
                     YELLOW("OBSERVATION — not scored, see rationale"),
                     f"{len(entropy_hits)} high-entropy MEM_PRIVATE region(s)")
    else:
        _print_check("High-entropy private memory",
                     GREEN("CLEAN — no anomalous entropy in private regions"))


def _print_base64(base64_unique, tag, note):
    if base64_unique:
        _print_check("Base64 encoded payloads (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(base64_unique)} region(s) with Base64-decodable data")
    else:
        _print_check("Base64 encoded payloads",
                     GREEN("CLEAN — no significant Base64 payloads found"))


def _print_xor(xor_unique, tag, note):
    if xor_unique:
        _print_check("XOR single-byte obfuscation (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(xor_unique)} region(s) with single-byte XOR obfuscation")
    else:
        _print_check("XOR single-byte obfuscation",
                     GREEN("CLEAN — no single-byte XOR payloads identified"))


def _print_compressed(compressed_unique, tag, note):
    if compressed_unique:
        _print_check("Compressed data (GZIP/ZLIB) (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(compressed_unique)} region(s) with compressed data (GZIP/ZLIB)")
    else:
        _print_check("Compressed data (GZIP/ZLIB)",
                     GREEN("CLEAN — no compressed payloads found"))


def _print_structural_pe(all_pe_hits):
    if not all_pe_hits:
        return
    _print_check("Structural PE payload inside encoded data",
                 RED("DETECTION — executable payload concealed by encoding"),
                 f"{len(all_pe_hits)} PE payload(s) found inside encoded/compressed data")


def _print_shellcode(all_shellcode_hits):
    if not all_shellcode_hits:
        return
    _print_check("Shellcode bootstrap pattern inside encoded data (lead)",
                 YELLOW("LEAD — not scored, see rationale"),
                 f"{len(all_shellcode_hits)} shellcode-bootstrap-pattern match(es) inside encoded/compressed data")


def render(report: EncodingReport, verbose: bool = False):
    """Print the whole hunt's console RESULT output, in the same order the
    monolithic _hunt_encoding used to interleave it in. Decides nothing;
    every tag/note/score/status value is read off `report`. The "Layer N
    scanning..." progress announcements are NOT here -- they print from
    dumpex/hunt/encoding/__init__.py, immediately before each layer is
    actually called, so the CLI shows progress DURING a slow scan instead
    of only after every layer has already finished (see that module's own
    comment on why)."""
    _print_sleep_mask(report.sleep_mask_hits)
    _print_entropy(report.entropy_hits)
    _print_base64(report.base64_hits, report.base64_tag, report.base64_note)
    _print_xor(report.xor_hits, report.xor_tag, report.xor_note)
    _print_compressed(report.compressed_hits, report.compressed_tag, report.compressed_note)
    _print_structural_pe(report.all_pe_hits)
    _print_shellcode(report.all_shellcode_hits)

    # Every Finding this hunter built, one print() each -- the CLEAN/
    # OBSERVATION/LEAD/DETECTION lines above are a short per-layer status
    # summary only; this is where the narrative (inference/confidence/
    # rationale/limitations) that used to be --json-only becomes visible
    # on console too. See Finding.print()'s own docstring for how `level`
    # gates fact-list expansion.
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL
    for f in report.findings_list:
        f.print(level=level)

    score = report.score
    if not report.mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif report.fully_skipped:
        # The total-gap case is the one most worth naming addresses for --
        # nothing at all was scanned, so every finding below is a
        # non-result until these regions are looked at some other way.
        oversized = "; ".join(oversized_layer_reasons(report.oversized_by_layer))
        verdict = _status_text(INCONCLUSIVE,
            f"all {report.regions_count} region(s) filtered out by every layer's size/type limits "
            f"— nothing was actually scanned" + (f" ({oversized})" if oversized else ""))
    elif report.status == INCONCLUSIVE:
        # Per SCAN LAYER, with the actual VA/size of each skipped region --
        # never one summed "N oversized region(s)" count, which would
        # report the same physical region up to three times as three
        # separate regions (see aggregate.oversized_layer_reasons).
        reason = ", ".join(filter(None, [
            *oversized_layer_reasons(report.oversized_by_layer),
            f"{report.total_read_failed} region(s) failed to read" if report.total_read_failed else "",
            f"{report.total_short_reads} region(s) short-read" if report.total_short_reads else "",
            f"decode budget exhausted ({report.exhausted_reason})" if report.budget_exhausted else "",
        ]))
        verdict = _status_text(INCONCLUSIVE, reason + leads_suffix(report.findings_list))
    else:
        # Branches on report.verdict_level -- the SAME value aggregate.py
        # already computed for findings['verdict_level'] via
        # _VERDICT_LEVEL_BY_SCORE -- rather than re-deriving a tier from
        # `score` here independently. Two independent score->tier mappings
        # (one here, one in aggregate.py) is exactly how JSON and console
        # verdict text could silently drift apart the next time the
        # scoring contract changes; there must be only one.
        verdict = (RED("HIGH CONFIDENCE — sleep-mask decode AND a structural PE payload confirmed") if report.verdict_level == "high" else
                   YELLOW("LIKELY — one structural indicator (sleep-mask decode or PE payload)")     if report.verdict_level == "likely" else
                   GREEN("CLEAN — no structurally-confirmed payload; raw observations/leads "
                         "above (entropy/Base64/GZIP/XOR/string/shellcode-prefix) are "
                         "informational only" + leads_suffix(report.findings_list)))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 — structural detections only; "
          f"entropy/Base64/GZIP/shellcode-prefix are observations/leads, never a verdict "
          f"by themselves)\n")

    if not verbose and any([report.sleep_mask_hits, report.base64_hits, report.xor_hits,
                            report.compressed_hits, report.entropy_hits]):
        print(DIM("  Use --verbose to expand region addresses, decoded content, and IOC strings.\n"))
