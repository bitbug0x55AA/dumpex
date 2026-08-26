"""Aggregate encoding-layer evidence into one immutable report.

Scoring, findings, and coverage are derived from typed scan results. Per-layer
gaps and evidence caps remain visible; aggregation performs no reads or output.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH, \
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION
from dumpex.hunt.encoding.classification import _structural_note
from dumpex.hunt.encoding.domain import CoverageSnapshot, EncodingEvidence, EncodingReport


def _dedup_by_region(hits: tuple) -> tuple:
    """First hit per distinct region.base_address, preserving order --
    matches the original per-layer console/JSON reporting, which counts
    "N region(s) with X" rather than every individual candidate string
    match within the same region. Returns the SAME hit objects (never
    copies), so the result is a valid subset-by-identity of `hits`."""
    seen = set()
    unique = []
    for h in hits:
        if h.region.base_address not in seen:
            seen.add(h.region.base_address)
            unique.append(h)
    return tuple(unique)


def _classify_section(hits: tuple, ioc_only_note="IOC-style string(s) found — treated as a lead",
                       no_content_note="no structural or IOC content found"):
    """Shared has_pe/has_shellcode/ioc_only/tag/note derivation for the
    three decode-layer observation sections (base64/xor/compressed) --
    identical decision logic previously duplicated three times inline.
    base64's note wording is more verbose than xor/compressed's in the
    original console output (an existing inconsistency, not something
    this refactor should quietly erase), hence the overridable defaults."""
    has_pe        = any(h.classification.is_pe for h in hits)
    has_shellcode = any(h.classification.is_shellcode for h in hits)
    structural = has_pe or has_shellcode
    ioc_only   = [h for h in hits if h.classification.ioc_strings
                  and not (h.classification.is_pe or h.classification.is_shellcode)]
    tag  = TAG_LEAD if ioc_only and not structural else TAG_OBSERVATION
    note = (_structural_note(has_pe, has_shellcode) if structural else
            ioc_only_note if ioc_only else
            no_content_note)
    return has_pe, has_shellcode, ioc_only, tag, note


def build_report(sleep_mask_hits: tuple, entropy_hits: tuple, base64_hits: tuple,
                  xor_hits: tuple, compressed_hits: tuple, *,
                  memory_info_stream: bool, region_count: int, any_region_scanned: bool,
                  sleep_mask_oversized: tuple = (), entropy_oversized: tuple = (),
                  decode_oversized: tuple = (),
                  sleep_mask_read_failed: tuple = (), entropy_read_failed: tuple = (),
                  decode_read_failed: tuple = (),
                  sleep_mask_short_read: tuple = (), entropy_short_read: tuple = (),
                  decode_short_read: tuple = (),
                  budget_exhausted: bool = False, exhausted_reason: str = "") -> EncodingReport:
    """
    Turn the scan layers' typed evidence into the final `EncodingReport`.
    This is the ONLY place score/coverage/the seven CheckResults are
    computed for this hunter.

    `base64_hits`/`xor_hits`/`compressed_hits` are the RAW (undeduped)
    hit tuples the decode scan layer produced -- one entry per candidate
    match, so the SAME region can appear more than once. Deduplication
    (`_dedup_by_region`) happens here, once, and only for the
    base64/xor/compressed OBSERVATION checks' own evidence (and,
    downstream, `report_legacy.py`'s `findings['base64']`/etc, which
    reads that same CheckResult's evidence rather than re-deriving it).
    `structural_payload`/`shellcode_bootstrap_lead` deliberately partition
    the RAW, undeduped lists instead: a region with two decode candidates
    at different offsets -- one structural, one not -- must not have its
    structural hit silently dropped because dedup happened to keep the
    OTHER occurrence first (a real detection-semantics requirement, not
    an implementation detail).
    """
    all_source_hits = sleep_mask_hits + base64_hits + xor_hits + compressed_hits
    pe_hits = tuple(h for h in all_source_hits if h.classification.is_pe)
    shellcode_hits = tuple(h for h in all_source_hits if h.classification.is_shellcode)
    shellcode_context_hits = tuple(
        h for h in shellcode_hits if h.region.type == "MEM_PRIVATE" and h.region.is_rwx)

    results = []

    # ── Sleep Mask ──────────────────────────────────────────────────────
    if sleep_mask_hits:
        results.append(CheckResult(
            check="obfuscation.sleep_mask_confirmed",
            evidence=sleep_mask_hits,
            evidence_limit=10,
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
        results.append(CheckResult(
            check="obfuscation.entropy_observation",
            evidence=entropy_hits,
            evidence_limit=15,
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

    # ── Base64 / XOR / Compressed (decode layers, deduped) ───────────────
    base64_unique = _dedup_by_region(base64_hits)
    if base64_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(
            base64_unique,
            ioc_only_note="IOC-style string(s) found inside decoded content — treated "
                          "as a lead, not a detection",
            no_content_note="no structural or IOC content found in decoded data")
        results.append(CheckResult(
            check="obfuscation.base64_observation",
            evidence=base64_unique,
            evidence_limit=15,
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

    xor_unique = _dedup_by_region(xor_hits)
    if xor_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(xor_unique)
        results.append(CheckResult(
            check="obfuscation.xor_observation",
            evidence=xor_unique,
            evidence_limit=15,
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

    compressed_unique = _dedup_by_region(compressed_hits)
    if compressed_unique:
        has_pe, has_shellcode, ioc_only, tag, note = _classify_section(compressed_unique)
        results.append(CheckResult(
            check="obfuscation.compressed_observation",
            evidence=compressed_unique,
            evidence_limit=15,
            inference=f"{len(compressed_unique)} region(s) contain data that decompresses "
                       f"cleanly as GZIP/ZLIB.",
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

    # ── Structural PE payload (drives score, together with sleep-mask) ─────
    if pe_hits:
        any_incomplete = any(not h.complete for h in pe_hits)
        all_incomplete = all(not h.complete for h in pe_hits)
        results.append(CheckResult(
            check="obfuscation.structural_payload",
            evidence=pe_hits,
            evidence_limit=20,
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

    # ── Shellcode bootstrap pattern — LEAD ONLY, never scored ──────────────
    if shellcode_hits:
        confidence = CONFIDENCE_MEDIUM if shellcode_context_hits else CONFIDENCE_LOW
        rationale = ("A 6-byte prefix match has no structural validation behind it "
                     "(no section table, no entry-point plausibility check, no "
                     "instruction-stream/control-flow corroboration) — nowhere near the "
                     "rigor of the PE structural check above, so this never contributes "
                     "to the obfuscation score regardless of confidence. Would need "
                     "disassembly-based corroboration (e.g. a sustained run of valid "
                     "instructions, a recognizable API-resolution idiom) before being "
                     "treated as a detection.")
        if shellcode_context_hits:
            rationale += (f" Confidence raised to MEDIUM because {len(shellcode_context_hits)} "
                           f"of {len(shellcode_hits)} match(es) sit inside a region that is "
                           f"ALSO executable+private (MEM_PRIVATE + a rules-defined "
                           f"suspicious protection) — the same combination "
                           f"dumpex/hunt/injection/ and hollowing.py treat as suspicious on "
                           f"its own — worth an analyst's closer look even though it still "
                           f"isn't structural proof.")
        results.append(CheckResult(
            check="obfuscation.shellcode_bootstrap_lead",
            evidence=shellcode_hits,
            evidence_limit=20,
            inference=f"{len(shellcode_hits)} decoded payload(s) begin with a "
                       f"call-$+5-style shellcode bootstrap prefix (6 bytes)"
                       + (f", {len(shellcode_context_hits)} of them inside an "
                          f"executable+private region" if shellcode_context_hits else "") + ".",
            confidence=confidence,
            rationale=rationale,
            limitations=["6 bytes is not enough evidence to rule out coincidence, "
                         "especially inside high-entropy or adversarially-crafted data."],
            tag=TAG_LEAD,
        ))

    # ── Verdict ───────────────────────────────────────────────────────────
    # Score reflects STRUCTURAL detections only — confirmed sleep-mask
    # decode and/or a validated PE payload, found via any layer. Raw
    # entropy/Base64/GZIP/XOR presence and the shellcode-bootstrap prefix
    # (reported above as observations/leads) never contribute.
    score = int(bool(sleep_mask_hits)) + int(bool(pe_hits))

    coverage = CoverageSnapshot(
        memory_info_stream=memory_info_stream, region_count=region_count,
        any_region_scanned=any_region_scanned,
        sleep_mask_oversized=sleep_mask_oversized, entropy_oversized=entropy_oversized,
        decode_oversized=decode_oversized,
        sleep_mask_read_failed=sleep_mask_read_failed, entropy_read_failed=entropy_read_failed,
        decode_read_failed=decode_read_failed,
        sleep_mask_short_read=sleep_mask_short_read, entropy_short_read=entropy_short_read,
        decode_short_read=decode_short_read,
        budget_exhausted=budget_exhausted, exhausted_reason=exhausted_reason,
    )
    evidence = EncodingEvidence(
        sleep_mask_hits=sleep_mask_hits, entropy_hits=entropy_hits,
        base64_hits=base64_hits, xor_hits=xor_hits, compressed_hits=compressed_hits,
        pe_hits=pe_hits, shellcode_hits=shellcode_hits,
        shellcode_context_hits=shellcode_context_hits,
    )
    return EncodingReport(score=score, coverage=coverage, results=tuple(results), evidence=evidence)
