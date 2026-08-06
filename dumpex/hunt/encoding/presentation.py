"""
Console rendering for dumpex.hunt.encoding. Pure formatting: every
tag/score/confidence/note decision was already made by
dumpex/hunt/encoding/aggregate.py (see EncodingReport) -- this module
only turns that decision into text and prints it. No hunter logic lives
here.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import va_to_file_offset, prot_str, addr_to_module
from dumpex.hunt._ui import _print_check, _status_text, INCONCLUSIVE, NOT_EVALUATED
from dumpex.hunt._finding import TAG_OBSERVATION, leads_suffix
from dumpex.hunt.encoding.aggregate import EncodingReport

# Every one of these seven checks gets a separate, uncapped --verbose-only
# raw-evidence block below (matching what presentation.py showed before
# rendering was centralized on Finding.print()), so they're rendered with
# facts_mode="omit"/"notice" in render() below rather than "full" --
# printing both would show the same VA twice under --verbose. See
# Finding.print()'s own docstring for what those modes mean.
#
# obfuscation.structural_payload/shellcode_bootstrap_lead were originally
# left off this set on the theory that their Finding.facts already carried
# every field the pre-existing console detail did -- true of the FIELDS,
# but not the CAP: aggregate.py truncates both at facts[:20] + "... and N
# more" (see check="obfuscation.structural_payload"/
# "obfuscation.shellcode_bootstrap_lead" there), while the pre-
# centralization console printed every hit, always, uncapped, unconditional
# on --verbose. A dump with >20 hits of either kind silently lost hit #21
# onward from --verbose the moment rendering moved to facts_mode="full".
_SUPPLEMENTED_CHECKS = frozenset({
    "obfuscation.sleep_mask_confirmed", "obfuscation.entropy_observation",
    "obfuscation.base64_observation", "obfuscation.xor_observation",
    "obfuscation.compressed_observation", "obfuscation.structural_payload",
    "obfuscation.shellcode_bootstrap_lead",
})


def _print_sleep_mask_detail(mf, sleep_mask_hits):
    print(DIM("      CS Sleep Mask XOR-encoded beacon memory — full detail:"))
    for h in sleep_mask_hits:
        r = h.region
        fo = va_to_file_offset(mf, r.BaseAddress)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        ctype = h.cls['type'].upper()
        color_fn = RED if h.cls['is_pe'] or h.cls['is_shellcode'] else YELLOW
        print(DIM(f"          VA (process)   0x{r.BaseAddress:016x}"))
        print(DIM(f"          File offset    {fo_str}"))
        print(DIM(f"          Region size    0x{r.RegionSize:x}  ({r.RegionSize // 1024} KB)"))
        print(DIM(f"          XOR key        {h.key.hex()}  (rotation offset {h.key_offset})"))
        print(f"          Decoded type   {color_fn(ctype)}")
        if h.cls['ioc_strings']:
            print(DIM(f"          IOC strings    {', '.join(h.cls['ioc_strings'][:4])}"))
    print()


def _print_entropy_detail(mf, entropy_hits, susp_prots):
    print(DIM("      High-entropy private memory — full detail:"))
    for h in entropy_hits:
        r = h.region
        p = prot_str(r.Protect)
        fo = va_to_file_offset(mf, r.BaseAddress)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        rwx = RED(" [RWX]") if any(s in p for s in susp_prots) else ""
        print(f"          VA (process)   0x{r.BaseAddress:016x}{rwx}")
        print(DIM(f"          File offset    {fo_str}"))
        print(DIM(f"          Size           0x{r.RegionSize:x}"))
        print(DIM(f"          Entropy        {h.entropy:.3f} bits  (threshold: {h.threshold})"))
        print(DIM(f"          Protection     {p}"))
    print()


def _print_base64_detail(mf, base64_unique):
    print(DIM("      Base64 encoded payloads — full detail:"))
    for h in base64_unique:
        abs_va = h.region.BaseAddress + h.offset
        fo = va_to_file_offset(mf, abs_va)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        ctype = h.cls['type'].upper()
        print(DIM(f"          VA (process)   0x{abs_va:016x}"))
        print(DIM(f"          File offset    {fo_str}"))
        print(DIM(f"          Decoded type   {ctype}"))
        print(DIM(f"          Decoded size   {len(h.decoded)} bytes"))
        print(DIM(f"          B64 length     {len(h.raw)} chars"))
        if h.cls['ioc_strings']:
            print(DIM(f"          IOC strings    {', '.join(h.cls['ioc_strings'][:3])}"))
    print()


def _print_xor_detail(mf, xor_unique):
    print(DIM("      XOR single-byte obfuscation — full detail:"))
    for h in xor_unique:
        r = h.region
        fo = va_to_file_offset(mf, r.BaseAddress)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        ctype = h.cls['type'].upper()
        print(DIM(f"          VA (process)   0x{r.BaseAddress:016x}"))
        print(DIM(f"          File offset    {fo_str}"))
        print(DIM(f"          XOR key        0x{h.key:02x}"))
        print(DIM(f"          Decoded type   {ctype}"))
        if h.cls['ioc_strings']:
            print(DIM(f"          IOC strings    {', '.join(h.cls['ioc_strings'][:3])}"))
    print()


def _print_compressed_detail(mf, compressed_unique):
    print(DIM("      Compressed data (GZIP/ZLIB) — full detail:"))
    for h in compressed_unique:
        abs_va = h.region.BaseAddress + h.offset
        fo = va_to_file_offset(mf, abs_va)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        print(DIM(f"          VA (process)   0x{abs_va:016x}"))
        print(DIM(f"          File offset    {fo_str}"))
        print(DIM(f"          Algorithm      {h.layer.upper()}"))
        print(DIM(f"          Decoded type   {h.cls['type'].upper()}"))
        print(DIM(f"          Decoded size   {len(h.decoded)} bytes"))
        if h.cls['ioc_strings']:
            print(DIM(f"          IOC strings    {', '.join(h.cls['ioc_strings'][:3])}"))
    print()


def _print_structural_pe_detail(all_pe_hits, modules):
    print(DIM("      Structural PE payload inside encoded data — full detail:"))
    for h in all_pe_hits:
        abs_va = h.region.BaseAddress + h.offset
        known = addr_to_module(abs_va, modules)
        print(DIM(f"          Encoding       {h.layer.upper()}"))
        print(DIM(f"          Container VA   0x{abs_va:016x}"))
        print(f"          Module status  {DIM('registered') if known else RED('UNREGISTERED — hidden PE')}")
        line = f"          Decoded PE     {len(h.decoded)} bytes"
        if not h.complete:
            line += "  (decompression hit the output cap — not end-to-end verified)"
        print(DIM(line))
    print()


def _print_shellcode_detail(all_shellcode_hits, context_hits):
    print(DIM("      Shellcode bootstrap pattern inside encoded data — full detail:"))
    for h in all_shellcode_hits:
        abs_va = h.region.BaseAddress + h.offset
        in_context = h in context_hits
        print(DIM(f"          Encoding       {h.layer.upper()}"))
        print(DIM(f"          Container VA   0x{abs_va:016x}"))
        print(DIM(f"          Decoded size   {len(h.decoded)} bytes (call-$+5 bootstrap prefix)"))
        if in_context:
            print(DIM(f"          Container prot {prot_str(h.region.Protect)}  (executable+private — elevated lead)"))
    print()


def _print_sleep_mask(mf, verbose, sleep_mask_hits):
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


def _print_entropy(mf, verbose, entropy_hits, susp_prots):
    if entropy_hits:
        _print_check("High-entropy private memory (observation)",
                     YELLOW("OBSERVATION — not scored, see rationale"),
                     f"{len(entropy_hits)} high-entropy MEM_PRIVATE region(s)")
    else:
        _print_check("High-entropy private memory",
                     GREEN("CLEAN — no anomalous entropy in private regions"))


def _print_base64(mf, verbose, base64_unique, tag, note):
    if base64_unique:
        _print_check("Base64 encoded payloads (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(base64_unique)} region(s) with Base64-decodable data")
    else:
        _print_check("Base64 encoded payloads",
                     GREEN("CLEAN — no significant Base64 payloads found"))


def _print_xor(mf, verbose, xor_unique, tag, note):
    if xor_unique:
        _print_check("XOR single-byte obfuscation (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(xor_unique)} region(s) with single-byte XOR obfuscation")
    else:
        _print_check("XOR single-byte obfuscation",
                     GREEN("CLEAN — no single-byte XOR payloads identified"))


def _print_compressed(mf, verbose, compressed_unique, tag, note):
    if compressed_unique:
        _print_check("Compressed data (GZIP/ZLIB) (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}",
                     f"{len(compressed_unique)} region(s) with compressed data (GZIP/ZLIB)")
    else:
        _print_check("Compressed data (GZIP/ZLIB)",
                     GREEN("CLEAN — no compressed payloads found"))


def _print_structural_pe(mf, all_pe_hits, modules):
    if not all_pe_hits:
        return
    _print_check("Structural PE payload inside encoded data",
                 RED("DETECTION — executable payload concealed by encoding"),
                 f"{len(all_pe_hits)} PE payload(s) found inside encoded/compressed data")


def _print_shellcode(all_shellcode_hits, context_hits):
    if not all_shellcode_hits:
        return
    _print_check("Shellcode bootstrap pattern inside encoded data (lead)",
                 YELLOW("LEAD — not scored, see rationale"),
                 f"{len(all_shellcode_hits)} shellcode-bootstrap-pattern match(es) inside encoded/compressed data")


def render(mf, verbose: bool, report: EncodingReport, susp_prots, modules):
    """Print the whole hunt's console RESULT output, in the same order the
    monolithic _hunt_encoding used to interleave it in. Decides nothing;
    every tag/note/score/status value is read off `report`. The "Layer N
    scanning..." progress announcements are NOT here -- they print from
    dumpex/hunt/encoding/__init__.py, immediately before each layer is
    actually called, so the CLI shows progress DURING a slow scan instead
    of only after every layer has already finished (see that module's own
    comment on why)."""
    _print_sleep_mask(mf, verbose, report.sleep_mask_hits)

    _print_entropy(mf, verbose, report.entropy_hits, susp_prots)

    _print_base64(mf, verbose, report.base64_hits, report.base64_tag, report.base64_note)
    _print_xor(mf, verbose, report.xor_hits, report.xor_tag, report.xor_note)
    _print_compressed(mf, verbose, report.compressed_hits, report.compressed_tag, report.compressed_note)

    _print_structural_pe(mf, report.all_pe_hits, modules)
    _print_shellcode(report.all_shellcode_hits, report.shellcode_context_hits)

    # Every Finding this hunter built, one print() each -- the CLEAN/
    # OBSERVATION/LEAD/DETECTION lines above are a short per-layer status
    # summary only; this is where the narrative (inference/confidence/
    # rationale/limitations) that used to be --json-only becomes visible
    # on console too. See Finding.print()'s own docstring for how
    # `verbose` gates fact-list expansion.
    for f in report.findings_list:
        if f.check in _SUPPLEMENTED_CHECKS:
            f.print(verbose=verbose, facts_mode="omit" if verbose else "notice")
        else:
            f.print(verbose=verbose)

    if verbose:
        if report.sleep_mask_hits:
            _print_sleep_mask_detail(mf, report.sleep_mask_hits)
        if report.entropy_hits:
            _print_entropy_detail(mf, report.entropy_hits, susp_prots)
        if report.base64_hits:
            _print_base64_detail(mf, report.base64_hits)
        if report.xor_hits:
            _print_xor_detail(mf, report.xor_hits)
        if report.compressed_hits:
            _print_compressed_detail(mf, report.compressed_hits)
        if report.all_pe_hits:
            _print_structural_pe_detail(report.all_pe_hits, modules)
        if report.all_shellcode_hits:
            _print_shellcode_detail(report.all_shellcode_hits, report.shellcode_context_hits)

    score = report.score
    if not report.mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif report.fully_skipped:
        verdict = _status_text(INCONCLUSIVE,
            f"all {report.regions_count} region(s) filtered out by every layer's size/type limits "
            f"— nothing was actually scanned")
    elif report.status == INCONCLUSIVE:
        reason = ", ".join(filter(None, [
            f"{report.total_size_skipped} oversized region(s) skipped" if report.total_size_skipped else "",
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
