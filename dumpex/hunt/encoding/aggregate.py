"""
Aggregation layer for dumpex.hunt.encoding: the ONLY place score, status,
coverage_status, verdict_level, confidence, lead_count, and
review_priority are computed for this hunter. Takes the raw LayerResult/
DecodeResult objects the scan layers (sleep_mask, entropy, decoding)
produced and turns them into Finding objects plus the final `findings`
JSON dict — and, since presentation.py must render exactly what was
decided here (not recompute it), also returns an EncodingReport bundling
everything the console renderer needs (deduped hit lists, tags, notes).

Nothing here prints. Nothing in dumpex/hunt/encoding/presentation.py
decides tag/score/confidence — it only formats what this module already
decided.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority)
from dumpex.hunt.encoding.classification import _structural_note

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
# No "3": this hunter's max score is 2 (confirmed sleep-mask decode and/or
# a validated PE payload — no third independent structural signal).
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}


@dataclass
class EncodingReport:
    """Everything dumpex/hunt/encoding/presentation.py needs to render the
    console output, precomputed here so presentation.py makes no
    tag/score/confidence decisions of its own -- only formatting."""
    findings: dict                # the full JSON-facing result dict
    findings_list: list            # list[Finding] (for the verdict line's leads_suffix)

    sleep_mask_hits: list = field(default_factory=list)   # list[Hit]
    entropy_hits: list = field(default_factory=list)       # list[EntropyHit]

    base64_hits: list = field(default_factory=list)        # deduped list[Hit]
    base64_tag: str = None
    base64_note: str = None
    xor_hits: list = field(default_factory=list)
    xor_tag: str = None
    xor_note: str = None
    compressed_hits: list = field(default_factory=list)
    compressed_tag: str = None
    compressed_note: str = None

    all_pe_hits: list = field(default_factory=list)         # list[Hit]
    pe_any_incomplete: bool = False
    pe_all_incomplete: bool = False

    all_shellcode_hits: list = field(default_factory=list)  # list[Hit]
    shellcode_context_hits: list = field(default_factory=list)
    shellcode_confidence: str = None

    mem_info_available: bool = True
    fully_skipped: bool = False
    regions_count: int = 0
    total_size_skipped: int = 0
    total_read_failed: int = 0
    total_short_reads: int = 0
    budget_exhausted: bool = False
    exhausted_reason: str = ""

    score: int = 0
    status: str = None
    verdict_level: str = None   # SAME value as findings['verdict_level'] -- presentation.py
                                 # must branch on this, not re-derive its own score->tier
                                 # mapping, so a scoring-contract change can't make JSON and
                                 # console verdict text silently disagree.


def _dedup_by_region(hits: list) -> list:
    """First hit per distinct region.BaseAddress, preserving order --
    matches the original per-layer console/JSON reporting, which counts
    "N region(s) with X" rather than every individual candidate string
    match within the same region."""
    seen = set()
    unique = []
    for h in hits:
        if h.region.BaseAddress not in seen:
            seen.add(h.region.BaseAddress)
            unique.append(h)
    return unique


def _classify_section(hits: list, ioc_only_note="IOC-style string(s) found — treated as a lead",
                       no_content_note="no structural or IOC content found"):
    """Shared has_pe/has_shellcode/ioc_only/tag/note derivation for the
    three decode-layer observation sections (base64/xor/compressed) --
    identical decision logic previously duplicated three times inline.
    base64's note wording is more verbose than xor/compressed's in the
    original console output (an existing inconsistency, not something
    this refactor should quietly erase), hence the overridable defaults."""
    has_pe        = any(h.cls['is_pe'] for h in hits)
    has_shellcode = any(h.cls['is_shellcode'] for h in hits)
    structural = has_pe or has_shellcode
    ioc_only   = [h for h in hits if h.cls['ioc_strings'] and not (h.cls['is_pe'] or h.cls['is_shellcode'])]
    tag  = TAG_LEAD if ioc_only and not structural else TAG_OBSERVATION
    note = (_structural_note(has_pe, has_shellcode) if structural else
            ioc_only_note if ioc_only else
            no_content_note)
    return has_pe, has_shellcode, ioc_only, tag, note


def build_report(mf, verbose, sleep_mask_result, entropy_result, decode_result,
                  modules, regions, susp_prots, mem_info_available, decode_budget) -> EncodingReport:
    """
    Turn the three scan layers' raw results into the final findings dict
    plus an EncodingReport for presentation.py. This is the ONLY place
    score/status/coverage_status/verdict_level/confidence/lead_count/
    review_priority are computed for this hunter.
    """
    sleep_mask_hits = sleep_mask_result.hits
    sleep_mask_coverage = sleep_mask_result.coverage
    entropy_hits = entropy_result.hits
    entropy_coverage = entropy_result.coverage
    decode_coverage = decode_result.coverage

    findings = {
        'sleep_mask': [],
        'entropy':    [],
        'base64':     [],
        'xor':        [],
        'compressed': [],
        'hidden_pe':       [],
        'hidden_shellcode': [],
        'score': 0,
    }
    findings_list = []

    report = EncodingReport(findings=findings, findings_list=findings_list,
                             sleep_mask_hits=sleep_mask_hits, entropy_hits=entropy_hits)

    pe_hits, shellcode_hits = [], []

    # ── Sleep Mask ──────────────────────────────────────────────────────
    if sleep_mask_hits:
        for h in sleep_mask_hits:
            if h.cls['is_pe']:
                findings['hidden_pe'].append(h)
            elif h.cls['is_shellcode']:
                findings['hidden_shellcode'].append(h)
        findings['sleep_mask'] = sleep_mask_hits
        findings_list.append(Finding(
            check="obfuscation.sleep_mask_confirmed",
            facts=[f"VA=0x{h.region.BaseAddress:x} key={h.key.hex()} "
                   f"rotation_offset={h.key_offset} decoded_type={h.cls['type']}"
                   for h in sleep_mask_hits[:10]],
            inference=f"{len(sleep_mask_hits)} region(s) decode cleanly under a recovered "
                       f"repeating-key XOR AND contain the literal 'sha256\\x00' marker "
                       f"that Cobalt Strike's sleep-mask-encoded beacon memory always "
                       f"carries once decoded.",
            confidence=CONFIDENCE_HIGH,
            rationale="This is not a raw statistical signal (unlike entropy/Base64/GZIP "
                       "below): key recovery is validated against a specific, known-content "
                       "marker before being accepted — a coincidental match is not "
                       "plausible for a repeating XOR key long enough to pass the "
                       "frequency-analysis candidate filters.",
            limitations=["Specific to Cobalt Strike's sleep-mask XOR scheme; does not "
                         "generalize to other frameworks' memory-encryption-at-rest."],
            tag=TAG_DETECTION,
        ))

    # ── Entropy ───────────────────────────────────────────────────────────
    if entropy_hits:
        findings['entropy'] = entropy_hits
        findings_list.append(Finding(
            check="obfuscation.entropy_observation",
            facts=[f"VA=0x{h.region.BaseAddress:x} entropy={h.entropy:.3f} threshold={h.threshold} "
                   f"protect={prot_str(h.region.Protect)}" for h in entropy_hits[:15]],
            inference=f"{len(entropy_hits)} MEM_PRIVATE region(s) exceed the Shannon-entropy "
                       f"threshold typical of encrypted/compressed/packed content.",
            confidence=CONFIDENCE_LOW,
            rationale="Shannon entropy is a purely statistical property shared by "
                       "encryption, compression, packed code, media buffers, crypto key "
                       "material, and plenty of ordinary high-randomness data — it carries "
                       "no information about WHAT the content is. Reported as an "
                       "observation only; never contributes to the obfuscation score on "
                       "its own.",
            limitations=["Cannot distinguish malicious encoding from benign "
                         "high-randomness content (e.g. session keys, compressed media, "
                         "GUIDs/hashes in bulk)."],
            tag=TAG_OBSERVATION,
        ))

    # ── Base64 / XOR / Compressed (decode layers) ──────────────────────────
    for h in decode_result.base64:
        if h.cls['is_pe']:
            pe_hits.append(h)
        elif h.cls['is_shellcode']:
            shellcode_hits.append(h)
    for h in decode_result.xor:
        if h.cls['is_pe']:
            pe_hits.append(h)
        elif h.cls['is_shellcode']:
            shellcode_hits.append(h)
    for h in decode_result.compressed:
        if h.cls['is_pe']:
            pe_hits.append(h)
        elif h.cls['is_shellcode']:
            shellcode_hits.append(h)

    base64_unique = _dedup_by_region(decode_result.base64)
    if base64_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(
            base64_unique,
            ioc_only_note="IOC-style string(s) found inside decoded content — treated "
                          "as a lead, not a detection",
            no_content_note="no structural or IOC content found in decoded data")
        report.base64_tag, report.base64_note = tag, note
        findings['base64'] = base64_unique
        findings_list.append(Finding(
            check="obfuscation.base64_observation",
            facts=[f"VA=0x{h.region.BaseAddress+h.offset:x} decoded_type={h.cls['type']} "
                   f"decoded_size={len(h.decoded)}" for h in base64_unique[:15]],
            inference=f"{len(base64_unique)} region(s) contain data that decodes cleanly as "
                       f"Base64.",
            confidence=CONFIDENCE_LOW,
            rationale="Base64 is a generic, ubiquitous encoding used constantly by benign "
                       "software (certificates, config blobs, telemetry, embedded assets) — "
                       "its mere presence carries no information about intent. Reported as "
                       "an observation and never drives the obfuscation score by itself; "
                       "only a decoded PE header or shellcode bootstrap pattern (see "
                       "obfuscation.structural_payload) does.",
            limitations=["IOC-style strings inside decoded content are a lead, not proof — "
                         "see obfuscation.base64_observation facts / stomping-style string "
                         "caveats."],
            tag=tag,
        ))

    xor_unique = _dedup_by_region(decode_result.xor)
    if xor_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(xor_unique)
        report.xor_tag, report.xor_note = tag, note
        findings['xor'] = xor_unique
        findings_list.append(Finding(
            check="obfuscation.xor_observation",
            facts=[f"VA=0x{h.region.BaseAddress:x} key=0x{h.key:02x} decoded_type={h.cls['type']}"
                   for h in xor_unique[:15]],
            inference=f"{len(xor_unique)} region(s) decode plausibly under a brute-forced "
                       f"single-byte XOR key (already filtered to require IOC content or a "
                       f"structural PE/shellcode match before being surfaced at all).",
            confidence=CONFIDENCE_LOW,
            rationale="A single-byte XOR key is trivial to satisfy by chance on any "
                       "sufficiently long buffer scored only by printable-ratio — reported "
                       "as an observation/lead; only a decoded PE header or shellcode "
                       "bootstrap counts toward the score (see obfuscation.structural_payload).",
            limitations=["255-key brute force with a printable-ratio heuristic; a "
                         "coincidental key that happens to look plausible cannot be ruled "
                         "out for short samples."],
            tag=tag,
        ))

    compressed_unique = _dedup_by_region(decode_result.compressed)
    if compressed_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(compressed_unique)
        report.compressed_tag, report.compressed_note = tag, note
        findings['compressed'] = compressed_unique
        findings_list.append(Finding(
            check="obfuscation.compressed_observation",
            facts=[f"VA=0x{h.region.BaseAddress+h.offset:x} algo={h.layer} decoded_type={h.cls['type']} "
                   f"decoded_size={len(h.decoded)}" for h in compressed_unique[:15]],
            inference=f"{len(compressed_unique)} region(s) contain data that decompresses cleanly "
                       f"as GZIP/ZLIB.",
            confidence=CONFIDENCE_LOW,
            rationale="GZIP/ZLIB is a general-purpose compression format used throughout "
                       "ordinary software (updates, resources, network payloads) — its "
                       "presence alone carries no information about intent. Reported as an "
                       "observation; only a decompressed PE header or shellcode bootstrap "
                       "(see obfuscation.structural_payload) contributes to the score.",
            limitations=["IOC-style strings inside decompressed content are a lead, not "
                         "proof, on their own."],
            tag=tag,
        ))
    report.base64_hits, report.xor_hits, report.compressed_hits = base64_unique, xor_unique, compressed_unique

    # ── Structural PE payload (drives score, together with sleep-mask) ─────
    # A PE header that passes full structural validation
    # (dumpex.core.pe_utils.parse_pe_header — DOS/COFF/optional header/
    # complete section table, not just an 'MZ' prefix), found via ANY layer
    # (Base64, XOR, GZIP/ZLIB; sleep mask is scored separately above). This
    # — not "an encoding scheme was merely detected" — is what can move the
    # obfuscation verdict, per phase-two policy.
    all_pe_hits = list(findings['hidden_pe']) + pe_hits
    if all_pe_hits:
        # A gzip/zlib hit whose decompression stopped at the output cap
        # before reaching end-of-stream (complete=False) was never verified
        # end-to-end — the visible PE structure is real, but truncation/
        # corruption beyond the cap can't be ruled out the way it can for a
        # fully-decoded stream. That's disclosed as a limitation whenever
        # ANY hit is incomplete, but only pulls confidence down to MEDIUM
        # when EVERY hit in this batch is incomplete -- one fully
        # end-to-end-verified PE in the batch is itself enough to justify
        # HIGH, regardless of what else showed up alongside it; a single
        # unverified extra hit must not drag a genuinely confirmed
        # detection down.
        any_incomplete = any(not h.complete for h in all_pe_hits)
        all_incomplete = all(not h.complete for h in all_pe_hits)
        report.pe_any_incomplete, report.pe_all_incomplete = any_incomplete, all_incomplete
        facts = []
        for h in all_pe_hits:
            abs_va = h.region.BaseAddress + h.offset
            known  = addr_to_module(abs_va, modules)
            reg_str = "registered" if known else "UNREGISTERED"
            facts.append(f"type=PE encoding={h.layer} container_VA=0x{abs_va:x} "
                         f"module_status={reg_str} decoded_size={len(h.decoded)}"
                         + ("" if h.complete else " decode=incomplete(output-cap)"))
        findings['hidden_pe'] = all_pe_hits
        findings_list.append(Finding(
            check="obfuscation.structural_payload",
            facts=facts[:20] + ([f"... and {len(facts)-20} more"] if len(facts) > 20 else []),
            inference="Decoded/decompressed content from one or more obfuscation layers "
                       "structurally validates as a PE image.",
            confidence=CONFIDENCE_MEDIUM if all_incomplete else CONFIDENCE_HIGH,
            rationale="Unlike raw entropy/Base64/GZIP presence, this checks WHAT the "
                       "decoded bytes actually are: full PE structural validation (DOS/"
                       "COFF/optional header + complete section table). Encoding was only "
                       "the delivery mechanism here — the payload itself is the evidence.",
            limitations=(["Structural validation reduces but does not eliminate false "
                          "positives from adversarially-crafted or coincidental byte "
                          "sequences in high-entropy data."]
                         + (["One or more hits came from a gzip/zlib stream that hit the "
                             "decompression output cap before end-of-stream/checksum was "
                             "reached — the decoded PE structure is real as far as examined, "
                             "but the source stream was never verified end-to-end."]
                            if any_incomplete else [])),
            tag=TAG_DETECTION,
        ))
    report.all_pe_hits = all_pe_hits

    # ── Shellcode bootstrap pattern — LEAD ONLY, never scored ──────────────
    # A 6-byte "call $+5; pop reg" prefix is a real, commonly-seen shellcode
    # idiom, but 6 bytes is far too little evidence to score on its own —
    # it has no structural validation comparable to a full PE header (no
    # section table, no plausible entry point, no instruction-stream
    # corroboration), and can occur by chance in high-entropy or
    # adversarially-crafted data. It is reported as an investigative lead
    # and explicitly does NOT contribute to the obfuscation score.
    all_shellcode_hits = list(findings['hidden_shellcode']) + shellcode_hits
    if all_shellcode_hits:
        # A bare 6-byte prefix match is weak on its own, but one sitting
        # inside a region that's ALSO executable+private (the same
        # combination injection.py/hollowing.py treat as suspicious) is a
        # meaningfully stronger combination than either signal alone —
        # still not structural proof (no section table, no entry-point
        # check), so this stays tag=LEAD and never touches score, but the
        # combo is worth flagging above a bare "6 bytes matched somewhere".
        context_hits = [h for h in all_shellcode_hits
                        if prot_str(h.region.Type) == 'MEM_PRIVATE'
                        and any(s in prot_str(h.region.Protect) for s in susp_prots)]
        report.shellcode_context_hits = context_hits
        facts = []
        for h in all_shellcode_hits:
            abs_va = h.region.BaseAddress + h.offset
            in_context = h in context_hits
            facts.append(f"type=shellcode_bootstrap encoding={h.layer} container_VA=0x{abs_va:x} "
                         f"decoded_size={len(h.decoded)} prefix={h.decoded[:6].hex()}"
                         + (f" container_protect={prot_str(h.region.Protect)} (executable+private)"
                            if in_context else ""))
        findings['hidden_shellcode'] = all_shellcode_hits
        confidence = CONFIDENCE_MEDIUM if context_hits else CONFIDENCE_LOW
        report.shellcode_confidence = confidence
        rationale = ("A 6-byte prefix match has no structural validation behind it "
                     "(no section table, no entry-point plausibility check, no "
                     "instruction-stream/control-flow corroboration) — nowhere near the "
                     "rigor of the PE structural check above, so this never contributes "
                     "to the obfuscation score regardless of confidence. Would need "
                     "disassembly-based corroboration (e.g. a sustained run of valid "
                     "instructions, a recognizable API-resolution idiom) before being "
                     "treated as a detection.")
        if context_hits:
            rationale += (f" Confidence raised to MEDIUM because {len(context_hits)} of "
                           f"{len(all_shellcode_hits)} match(es) sit inside a region that is "
                           f"ALSO executable+private (MEM_PRIVATE + one of "
                           f"{', '.join(susp_prots)}) — the same combination "
                           f"injection.py/hollowing.py treat as suspicious on its own — worth "
                           f"an analyst's closer look even though it still isn't structural proof.")
        findings_list.append(Finding(
            check="obfuscation.shellcode_bootstrap_lead",
            facts=facts[:20] + ([f"... and {len(facts)-20} more"] if len(facts) > 20 else []),
            inference=f"{len(all_shellcode_hits)} decoded payload(s) begin with a "
                       f"call-$+5-style shellcode bootstrap prefix (6 bytes)"
                       + (f", {len(context_hits)} of them inside an executable+private region"
                          if context_hits else "") + ".",
            confidence=confidence,
            rationale=rationale,
            limitations=["6 bytes is not enough evidence to rule out coincidence, "
                         "especially inside high-entropy or adversarially-crafted data."],
            tag=TAG_LEAD,
        ))
    report.all_shellcode_hits = all_shellcode_hits

    # ── Verdict ───────────────────────────────────────────────────────────
    # Score reflects STRUCTURAL detections only — confirmed sleep-mask
    # decode and/or a validated PE payload, found via any layer. Raw
    # entropy/Base64/GZIP/XOR presence and the shellcode-bootstrap prefix
    # (reported above as observations/leads) never contribute.
    score = int(bool(sleep_mask_hits)) + int(bool(all_pe_hits))
    findings['score'] = score
    findings['max_score'] = 2
    report.score = score
    report.mem_info_available = mem_info_available
    report.regions_count = len(regions)

    # Every layer has its own size/type filters (SLEEP_MASK_REGION_MAX,
    # ENTROPY_SCAN_MAX, DECODE_SCAN_MAX) — regions can exist (mem_info
    # available) while every single one gets filtered out by every layer
    # (e.g. a dump with only huge regions), meaning nothing was actually
    # read despite MemoryInfoListStream being present. A negative result
    # in that case is not the same claim as "scanned and clean". This must
    # catch partial gaps too, not just the all-skipped extreme: one region
    # scanned fine and a second one skipped/unreadable is still an
    # incomplete scope, even though *something* got scanned.
    any_region_scanned = bool(sleep_mask_coverage.scanned or entropy_coverage.scanned
                               or decode_coverage.scanned)
    fully_skipped = mem_info_available and bool(regions) and not any_region_scanned
    report.fully_skipped = fully_skipped
    total_size_skipped = (sleep_mask_coverage.skipped_oversize + entropy_coverage.skipped_oversize
                           + decode_coverage.skipped_oversize)
    total_read_failed  = (sleep_mask_coverage.read_failed + entropy_coverage.read_failed
                           + decode_coverage.read_failed)
    total_short_reads  = (sleep_mask_coverage.short_reads + entropy_coverage.short_reads
                           + decode_coverage.short_reads)
    budget_exhausted = decode_budget.exhausted()
    findings['budget_exhausted'] = budget_exhausted
    report.total_size_skipped, report.total_read_failed, report.total_short_reads = (
        total_size_skipped, total_read_failed, total_short_reads)
    report.budget_exhausted = budget_exhausted
    report.exhausted_reason = decode_budget.exhausted_reason
    coverage_gap = bool(total_size_skipped or total_read_failed or total_short_reads or budget_exhausted)

    # Coverage tracked independently of status/score — see stomping.py /
    # pipe.py for why: a nonzero score must not silently imply every
    # region was scanned.
    coverage_reasons = []
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if fully_skipped:
        coverage_reasons.append(f"all {len(regions)} region(s) filtered out by every layer's "
                                 f"size/type limits — nothing was actually scanned")
    if total_size_skipped:
        coverage_reasons.append(f"{total_size_skipped} oversized region(s) skipped")
    if total_read_failed:
        coverage_reasons.append(f"{total_read_failed} region(s) failed to read")
    if total_short_reads:
        coverage_reasons.append(f"{total_short_reads} region(s) returned fewer bytes than "
                                 f"declared (short read) — not fully scanned")
    if budget_exhausted:
        coverage_reasons.append(f"decode budget exhausted ({decode_budget.exhausted_reason})")

    complete = not (fully_skipped or coverage_gap)
    coverage_status = derive_coverage_status(mem_info_available, complete)
    findings['coverage_status']  = coverage_status
    findings['coverage_reasons'] = coverage_reasons

    status = derive_status(mem_info_available, score > 0, complete)
    findings['status'] = status
    report.status = status
    findings['verdict_level'] = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    report.verdict_level = findings['verdict_level']
    findings['confidence'] = overall_confidence(findings_list, score)
    findings['findings'] = [f.to_dict() for f in findings_list]
    findings['lead_count'] = lead_count(findings_list)
    findings['review_priority'] = review_priority(findings_list, score, status)

    # `findings` (returned to the caller, and from there straight into
    # dumpex.ui.structured.StructuredOutput's --json output) must hold
    # JSON-safe data, never the raw Hit/EntropyHit objects `report` above
    # keeps for presentation.py to render console detail from.
    # dumpex.ui.structured._json_safe has no dataclass case and falls back
    # to str(obj) for anything it doesn't recognize -- for a Hit, that
    # means the region object's live memory address AND the full raw
    # `decoded` bytes end up embedded in a single opaque JSON string
    # instead of a clean, reproducible structure. Converting HERE, in one
    # place, after every hit list has reached its final form, is safer
    # than converting at each of the seven assignment sites above (harder
    # to accidentally miss one).
    for key in ('sleep_mask', 'entropy', 'base64', 'xor', 'compressed',
                'hidden_pe', 'hidden_shellcode'):
        findings[key] = [h.to_dict() for h in findings[key]]

    return report
