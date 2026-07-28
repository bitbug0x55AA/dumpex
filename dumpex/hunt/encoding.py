"""
Encoded / obfuscated payload hunter.

Detection layers (applied per memory region):

  Layer 0: CS Sleep Mask XOR decode  — frequency-analysis key recovery for
                                       Cobalt Strike beacon memory encoded by
                                       the sleep mask (PAGE_READWRITE private
                                       regions). Adapted from cs-analyze-
                                       processdump.py by Didier Stevens
                                       (public domain, https://DidierStevens.com).

  Layer 1: Shannon entropy scan  — catches all encoding schemes including custom
                                   crypto, RC4, AES blobs, multi-byte XOR, etc.

  Layer 2: Base64 detection      — standard + URL-safe; minimum 80 chars (60
                                   decoded bytes) — see B64_MIN_LEN

  Layer 3: XOR single-byte BF    — MEM_PRIVATE regions ≤ 512 KB only;
                                   sample-first heuristic to avoid O(n×255)
                                   full-region cost

  Layer 4: GZIP / ZLIB           — magic-byte scan + decompress attempt

All decoded/decompressed content goes through a shared classifier:
  - MZ + PE\\x00\\x00     → PE payload → _hunt_hidden_pe logic applied
  - call-$+5 bootstrap    → likely shellcode
  - printable > 85 %      → IOC string scan (IP / URL / pipe names)
  - else                  → hex prefix reported

Address semantics: every hit reports VA (process) + .dmp file offset,
consistent with the rest of Dumpex.

This file used to hold all five layers' implementations directly; each
layer's own logic now lives in dumpex/hunt/_encoding/ instead
(classification.py, entropy.py, sleep_mask.py, decoders.py, config.py —
see that package's own __init__.py). No specific line-count comparison
here on purpose — `wc -l` this file and `git log` for the actual before/
after if you need the number; a hardcoded count in a comment just goes
stale the next time either file changes size.

The ONLY stable contract this split preserves is `_hunt_encoding` itself
(the public entry point imported by dumpex/hunt/__init__.py): same
signature, same behavior, same JSON output for the same input. Verified
during development via this file's own regression test suite (see
tests/hunt/test_encoding*.py, tests/integration/test_json_schema.py,
tests/perf/test_benchmarks.py) plus ad hoc before/after output diffing
that was NOT committed as a repo fixture — there is no standing
golden-snapshot test here, only the ordinary regression tests above; if
you need snapshot-style diffing again, treat it as a one-off tool, not an
existing asset. Every constant is still re-exported so
`import dumpex.hunt.encoding as encoding; encoding.X` reads the current
value for any X that lived here before. That is NOT the same claim as
"every private helper's call
signature is unchanged" — it explicitly is not: _scan_sleep_mask and
_scan_entropy, in particular, gained new required parameters
(`read_region`, and both now also take `config`) that a direct call with
the OLD argument list would no longer satisfy. These were never a public
contract (leading underscore, no caller outside this package), so that
break is deliberate and in scope for this split; only _hunt_encoding's
own contract is guaranteed.

Re-exporting a name is NOT enough by itself to keep monkeypatching
working, though: `encoding.B64_MIN_LEN = 999` only rebinds THIS module's
copy of that name -- decoders.py's own separate B64_MIN_LEN binding never
sees it, so _scan_base64's behavior wouldn't actually change (see
dumpex/hunt/_encoding/config.py for the full explanation, and its own
history for why this was initially missed). Every tunable that affects a
layer's actual behavior is therefore threaded through explicitly instead
of read as a bare module constant inside each layer: `read_region` as
its own parameter, and every other tunable (B64_MIN_LEN, XOR_*,
ENTROPY_*, SLEEP_MASK_*, DECOMPRESS_MAX_OUTPUT) bundled into one
`EncodingConfig`, built here from THIS module's own (re-exported, still
monkeypatchable) globals and passed into every layer. `_hunt_encoding`
passes through whatever its OWN module-level values currently are, on
every call -- so `encoding.read_region = ...` / `encoding.B64_MIN_LEN =
...` style overrides set before calling `_hunt_encoding()` still work.
"""

import time
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors   import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (
    get_modules, get_memory_regions, addr_to_module,
    va_to_file_offset, prot_str, read_region,
)
from dumpex.hunt._ui    import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._coverage import derive_status, derive_coverage_status, CoverageTracker
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority, leads_suffix)

# ── Re-exports: every name previously defined directly in this file, now
# implemented in dumpex/hunt/_encoding/*. Kept importable as encoding.X for
# existing callers/tests (import dumpex.hunt.encoding as encoding). ────────
from dumpex.hunt._encoding.config import EncodingConfig
from dumpex.hunt._encoding.classification import (
    _IOC_PAT, _is_plausible_ip, _classify_decoded, _structural_note,
)
from dumpex.hunt._encoding.entropy import (
    ENTROPY_PRIVATE_THRESHOLD, ENTROPY_RWX_THRESHOLD, ENTROPY_SCAN_MAX,
    _shannon_entropy, _scan_entropy,
)
from dumpex.hunt._encoding.sleep_mask import (
    SLEEP_MASK_KEY_SIZE, SLEEP_MASK_MIN_REPEAT, SLEEP_MASK_MAX_BYTE_FREQ,
    SLEEP_MASK_MIN_ACBD, SLEEP_MASK_MAX_CANDIDATES, SLEEP_MASK_REGION_MAX,
    SLEEP_MASK_VALIDATE_SAMPLE, SLEEP_MASK_VALIDATION_MARKER, SLEEP_MASK_MAX_WINDOWS,
    _sm_xor, _sm_key_stats, _sm_normalize_key, _sm_avg_consec_diff,
    _sm_recover_candidates, _sm_validate_and_decode, _scan_sleep_mask,
)
from dumpex.hunt._encoding.decoders import (
    B64_MIN_LEN, XOR_SCAN_MAX, XOR_SAMPLE_SIZE, XOR_SCORE_MIN, DECOMPRESS_MAX_OUTPUT,
    _B64_PAT, _GZIP_SIG, _ZLIB_SIGS,
    _scan_base64, _xor_table, _score_xor_key, _scan_xor,
    _bounded_decompress, _scan_compressed,
)

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
# No "3": this hunter's max score is 2 (confirmed sleep-mask decode and/or
# a validated PE payload — no third independent structural signal).
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

# ── Tunables (kept here: only _hunt_encoding itself reads these, to build
# the shared decode budget below — no submodule needs them) ────────────────
DECODE_SCAN_MAX = 2 * 1024 * 1024   # Base64 / XOR / GZIP: skip > 2 MB

# Layers 2 (Base64) and 4 (GZIP/ZLIB) share ONE ScanBudget across the whole
# hunt (all regions combined) rather than each region getting its own
# independent "≤200 attempts per signature" allowance — a dump with many
# qualifying regions could otherwise turn a per-region cap into unbounded
# total decode attempts and retained memory. See dumpex/hunt/_budget.py.
ENCODING_BUDGET_MAX_ATTEMPTS  = 2000              # total decode/decompress
                                                   # attempts, whole hunt
ENCODING_BUDGET_MAX_RETAINED  = 32 * 1024 * 1024  # cumulative decoded bytes
                                                   # kept in findings, whole hunt
ENCODING_BUDGET_MAX_HITS      = 500               # cumulative hits retained
ENCODING_BUDGET_TIME_SECONDS  = 60.0              # wall-clock cap, layers 0 and 2-4 combined
                                                   # (Layer 0 now shares this deadline too --
                                                   # see decode_budget's construction below)


def _is_system_dll(module) -> bool:
    """True if module is a Microsoft system DLL under System32/SysWOW64/WinSxS."""
    if module is None:
        return False
    path = (module.name or "").replace("\\", "/").lower()
    return (
        "/windows/system32/"  in path or
        "/windows/syswow64/" in path or
        "/windows/winsxs/"   in path
    )


# ══════════════════════════════════════════════════════════════════════════
# MAIN HUNTER
# ══════════════════════════════════════════════════════════════════════════

def _hunt_encoding(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan process memory for encoded / obfuscated payloads.

    Runs five detection layers in sequence:

      Layer 0  CS Sleep Mask  — frequency-analysis XOR key recovery for
                                beacon memory encoded while sleeping
                                (adapted from Didier Stevens cs-analyze-
                                processdump.py, public domain)
      Layer 1  Entropy        — Shannon entropy on MEM_PRIVATE regions
      Layer 2  Base64         — standard + URL-safe alphabet
      Layer 3  XOR 1-byte BF  — brute-force single-byte XOR with IOC check
      Layer 4  GZIP / ZLIB    — magic byte + decompress attempt

    Decoded content from all layers passes through a shared classifier.
    PE payloads trigger a module-list cross-check (same as _hunt_injection).
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    SUSPICIOUS_PROTS = get_rules()["suspicious_protections"]
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    findings = {
        'sleep_mask': [],   # Layer 0: (hit_dict, ...)
        'entropy':    [],   # Layer 1: (region, entropy, threshold) — OBSERVATION ONLY
        'base64':     [],   # Layer 2: (region, offset, cls) — OBSERVATION/LEAD unless PE/shellcode
        'xor':        [],   # Layer 3: (region, key, cls) — OBSERVATION/LEAD unless PE/shellcode
        'compressed': [],   # Layer 4: (region, offset, algo, cls) — OBSERVATION/LEAD unless PE/shellcode
        'hidden_pe':       [],   # structural: decoded content validates as a PE (any layer)
        'hidden_shellcode': [],  # structural: decoded content matches a shellcode bootstrap (any layer)
        'score': 0,
    }
    findings_list = []   # Finding objects — facts/inference/confidence/rationale/limitations

    # config bundles every encoding.* tunable, read from THIS module's own
    # (re-exported, and therefore still monkeypatchable) globals -- see
    # dumpex/hunt/_encoding/config.py for why layers can't just read their
    # own separate copies of these constants directly.
    config = EncodingConfig(
        entropy_private_threshold=ENTROPY_PRIVATE_THRESHOLD, entropy_rwx_threshold=ENTROPY_RWX_THRESHOLD,
        entropy_scan_max=ENTROPY_SCAN_MAX, b64_min_len=B64_MIN_LEN, xor_scan_max=XOR_SCAN_MAX,
        xor_sample_size=XOR_SAMPLE_SIZE, xor_score_min=XOR_SCORE_MIN,
        decompress_max_output=DECOMPRESS_MAX_OUTPUT, sleep_mask_key_size=SLEEP_MASK_KEY_SIZE,
        sleep_mask_min_repeat=SLEEP_MASK_MIN_REPEAT, sleep_mask_max_byte_freq=SLEEP_MASK_MAX_BYTE_FREQ,
        sleep_mask_min_acbd=SLEEP_MASK_MIN_ACBD, sleep_mask_max_candidates=SLEEP_MASK_MAX_CANDIDATES,
        sleep_mask_region_max=SLEEP_MASK_REGION_MAX, sleep_mask_validate_sample=SLEEP_MASK_VALIDATE_SAMPLE,
        sleep_mask_validation_marker=SLEEP_MASK_VALIDATION_MARKER, sleep_mask_max_windows=SLEEP_MASK_MAX_WINDOWS,
    )

    # One budget shared across the WHOLE hunt, layers 0 and 2-4 alike (see
    # dumpex/hunt/_budget.py) — bounds total decode/decompress attempts and
    # retained bytes, but just as importantly bounds sleep-mask's own
    # candidate-recovery/validation cost: unlike entropy's cheap linear
    # per-region scan, sleep-mask's per-region cost is genuinely large (up
    # to ~130 XOR-over-2MB combinations, see _sm_validate_and_decode), so a
    # dump with many qualifying regions could otherwise make Layer 0 run
    # for unbounded total time before this budget previously even existed
    # (it used to only cover layers 2-4). Layer 0 only reads
    # exhausted()/poll() here (deadline), never note_attempt()/take_hit() —
    # those remain specific to what layers 2-4 actually decode/retain.
    decode_budget = ScanBudget(
        max_bytes_read=ENCODING_BUDGET_MAX_RETAINED * 4,
        max_attempts=ENCODING_BUDGET_MAX_ATTEMPTS,
        max_retained_bytes=ENCODING_BUDGET_MAX_RETAINED,
        max_hits=ENCODING_BUDGET_MAX_HITS,
        deadline=time.monotonic() + ENCODING_BUDGET_TIME_SECONDS,
    )

    _print_hunt_header("Obfuscation Detection")

    # ── Layer 0: CS Sleep Mask XOR ────────────────────────────────────────
    print(DIM("  [*] Layer 0: CS Sleep Mask XOR scan (frequency analysis) …"))
    sleep_mask_hits, sleep_mask_coverage = _scan_sleep_mask(regions, modules, mf, read_region,
                                                             config, decode_budget)

    if sleep_mask_hits:
        detail = f"{len(sleep_mask_hits)} region(s) with confirmed CS Sleep Mask encoding"
        for hit in sleep_mask_hits:
            r      = hit['region']
            key    = hit['key']
            offset = hit['offset']
            cls    = hit['cls']
            fo     = va_to_file_offset(mf, r.BaseAddress)
            fo_str = f"0x{fo:x}" if fo else "(not captured)"
            ctype  = cls['type'].upper()
            color_fn = RED if cls['is_pe'] or cls['is_shellcode'] else YELLOW

            detail += (
                f"\n          VA (process)   0x{r.BaseAddress:016x}"
                f"\n          File offset    {fo_str}"
                f"\n          Region size    0x{r.RegionSize:x}  ({r.RegionSize // 1024} KB)"
                f"\n          XOR key        {key.hex()}  (rotation offset {offset})"
                f"\n          Decoded type   {color_fn(ctype)}"
            )
            if cls['ioc_strings']:
                detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:4])}"

            if cls['is_pe']:
                findings['hidden_pe'].append(('sleep_mask', r, 0, hit['decoded'], True))
            elif cls['is_shellcode']:
                findings['hidden_shellcode'].append(('sleep_mask', r, 0, hit['decoded'], True))

        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            RED("SUSPICIOUS — beacon memory decoded via sleep mask key recovery"),
            detail,
        )
        findings['sleep_mask'] = sleep_mask_hits
        findings_list.append(Finding(
            check="obfuscation.sleep_mask_confirmed",
            facts=[f"VA=0x{h['region'].BaseAddress:x} key={h['key'].hex()} "
                   f"rotation_offset={h['offset']} decoded_type={h['cls']['type']}"
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
    else:
        _print_check(
            "CS Sleep Mask XOR-encoded beacon memory",
            GREEN("CLEAN — no sleep mask XOR encoding detected"),
        )

    # ── Layer 1: Entropy ──────────────────────────────────────────────────
    print(DIM("  [*] Layer 1: Shannon entropy scan …"))
    entropy_hits, entropy_coverage = _scan_entropy(regions, modules, mf, SUSPICIOUS_PROTS, read_region, config)

    if entropy_hits:
        detail = f"{len(entropy_hits)} high-entropy MEM_PRIVATE region(s)"
        if verbose:
            for r, ent, threshold in entropy_hits:
                p      = prot_str(r.Protect)
                fo     = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                rwx    = RED(" [RWX]") if any(s in p for s in SUSPICIOUS_PROTS) else ""
                detail += (
                    f"\n          VA (process)   0x{r.BaseAddress:016x}{rwx}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Size           0x{r.RegionSize:x}"
                    f"\n          Entropy        {ent:.3f} bits  (threshold: {threshold})"
                    f"\n          Protection     {p}"
                )
        _print_check("High-entropy private memory (observation)",
                     YELLOW("OBSERVATION — not scored, see rationale"), detail)
        findings['entropy'] = entropy_hits
        findings_list.append(Finding(
            check="obfuscation.entropy_observation",
            facts=[f"VA=0x{r.BaseAddress:x} entropy={ent:.3f} threshold={threshold} "
                   f"protect={prot_str(r.Protect)}" for r, ent, threshold in entropy_hits[:15]],
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
    else:
        _print_check("High-entropy private memory",
                     GREEN("CLEAN — no anomalous entropy in private regions"))

    # ── Layers 2–4: per-region decode ─────────────────────────────────────
    print(DIM("  [*] Layers 2-4: Base64 / XOR / GZIP scan …"))

    b64_hits, xor_hits, cmp_hits, pe_hits, shellcode_hits = [], [], [], [], []
    decode_coverage = CoverageTracker()
    # decode_budget was already constructed above (shared with Layer 0).

    for r in regions:
        if decode_budget.exhausted():
            break
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) not in ('MEM_PRIVATE', 'MEM_IMAGE'):
            continue
        mod = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == 'MEM_IMAGE' and _is_system_dll(mod):
            continue
        if r.RegionSize > DECODE_SCAN_MAX:
            decode_coverage.note_skipped_oversize()
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            decode_coverage.note_read_failed()
            continue
        if len(data) < r.RegionSize:
            decode_coverage.note_short_read()
            if not data:
                continue
        decode_coverage.note_scanned()

        for off, raw, decoded, cls in _scan_base64(data, r.BaseAddress, decode_budget, config):
            # take_hit() is the ONLY gate for whether this candidate is
            # actually kept — its return value MUST be checked (unlike the
            # old note_hit(), whose result could be silently ignored while
            # still appending the item regardless).
            if not decode_budget.take_hit(len(decoded)):
                break
            b64_hits.append((r, off, cls, raw, decoded))
            # Base64 has no output-cap/truncation concern (1:1-ish decode
            # of an already-bounded region) -- always "complete".
            if cls['is_pe']:
                pe_hits.append(('base64', r, off, decoded, True))
            elif cls['is_shellcode']:
                shellcode_hits.append(('base64', r, off, decoded, True))

        if (prot_str(r.Type) == 'MEM_PRIVATE' and r.RegionSize <= config.xor_scan_max):
            for key, decoded, cls in _scan_xor(data, r.BaseAddress, decode_budget, config):
                if not decode_budget.take_hit(len(decoded)):
                    break
                xor_hits.append((r, key, cls, decoded))
                if cls['is_pe']:
                    pe_hits.append(('xor', r, 0, decoded, True))
                elif cls['is_shellcode']:
                    shellcode_hits.append(('xor', r, 0, decoded, True))

        if not decode_budget.exhausted():
            for off, algo, decoded, cls, complete in _scan_compressed(data, r.BaseAddress, decode_budget, config):
                if not decode_budget.take_hit(len(decoded)):
                    break
                cmp_hits.append((r, off, algo, cls, decoded))
                # complete=False means decompression hit the output cap
                # before the stream's own end-of-stream/checksum was
                # reached -- classification is based on a verified-so-far
                # PREFIX, not a fully end-to-end-validated stream (see
                # _bounded_decompress). Downstream confidence must reflect
                # that, not treat it identically to a complete decode.
                if cls['is_pe']:
                    pe_hits.append((algo, r, off, decoded, complete))
                elif cls['is_shellcode']:
                    shellcode_hits.append((algo, r, off, decoded, complete))

    # ── Report Base64 ─────────────────────────────────────────────────────
    seen_b64 = set()
    b64_unique = []
    for item in b64_hits:
        if item[0].BaseAddress not in seen_b64:
            seen_b64.add(item[0].BaseAddress)
            b64_unique.append(item)

    if b64_unique:
        detail = f"{len(b64_unique)} region(s) with Base64-decodable data"
        if verbose:
            for r, off, cls, raw, decoded in b64_unique[:10]:
                abs_va = r.BaseAddress + off
                fo     = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                ctype  = cls['type'].upper()
                detail += (
                    f"\n          VA (process)   0x{abs_va:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Decoded type   {ctype}"
                    f"\n          Decoded size   {len(decoded)} bytes"
                    f"\n          B64 length     {len(raw)} chars"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        has_pe        = any(h[2]['is_pe'] for h in b64_unique)
        has_shellcode = any(h[2]['is_shellcode'] for h in b64_unique)
        structural = has_pe or has_shellcode
        ioc_only   = [h for h in b64_unique if h[2]['ioc_strings'] and not (h[2]['is_pe'] or h[2]['is_shellcode'])]
        tag  = TAG_LEAD if ioc_only and not structural else TAG_OBSERVATION
        note = (_structural_note(has_pe, has_shellcode) if structural else
                "IOC-style string(s) found inside decoded content — treated "
                "as a lead, not a detection" if ioc_only else
                "no structural or IOC content found in decoded data")
        _print_check("Base64 encoded payloads (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}", detail)
        findings['base64'] = b64_unique
        findings_list.append(Finding(
            check="obfuscation.base64_observation",
            facts=[f"VA=0x{r.BaseAddress+off:x} decoded_type={cls['type']} "
                   f"decoded_size={len(decoded)}" for r, off, cls, raw, decoded in b64_unique[:15]],
            inference=f"{len(b64_unique)} region(s) contain data that decodes cleanly as "
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
    else:
        _print_check("Base64 encoded payloads",
                     GREEN("CLEAN — no significant Base64 payloads found"))

    # ── Report XOR ────────────────────────────────────────────────────────
    seen_xor = set()
    xor_unique = []
    for item in xor_hits:
        if item[0].BaseAddress not in seen_xor:
            seen_xor.add(item[0].BaseAddress)
            xor_unique.append(item)

    if xor_unique:
        detail = f"{len(xor_unique)} region(s) with single-byte XOR obfuscation"
        if verbose:
            for r, key, cls, decoded in xor_unique[:10]:
                fo     = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                ctype  = cls['type'].upper()
                detail += (
                    f"\n          VA (process)   0x{r.BaseAddress:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          XOR key        0x{key:02x}"
                    f"\n          Decoded type   {ctype}"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        has_pe        = any(h[2]['is_pe'] for h in xor_unique)
        has_shellcode = any(h[2]['is_shellcode'] for h in xor_unique)
        structural = has_pe or has_shellcode
        ioc_only   = [h for h in xor_unique if h[2]['ioc_strings'] and not (h[2]['is_pe'] or h[2]['is_shellcode'])]
        tag  = TAG_LEAD if ioc_only and not structural else TAG_OBSERVATION
        note = (_structural_note(has_pe, has_shellcode) if structural else
                "IOC-style string(s) found — treated as a lead" if ioc_only else
                "no structural or IOC content found")
        _print_check("XOR single-byte obfuscation (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}", detail)
        findings['xor'] = xor_unique
        findings_list.append(Finding(
            check="obfuscation.xor_observation",
            facts=[f"VA=0x{r.BaseAddress:x} key=0x{key:02x} decoded_type={cls['type']}"
                   for r, key, cls, decoded in xor_unique[:15]],
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
    else:
        _print_check("XOR single-byte obfuscation",
                     GREEN("CLEAN — no single-byte XOR payloads identified"))

    # ── Report GZIP / ZLIB ────────────────────────────────────────────────
    seen_cmp = set()
    cmp_unique = []
    for item in cmp_hits:
        if item[0].BaseAddress not in seen_cmp:
            seen_cmp.add(item[0].BaseAddress)
            cmp_unique.append(item)

    if cmp_unique:
        detail = f"{len(cmp_unique)} region(s) with compressed data (GZIP/ZLIB)"
        if verbose:
            for r, off, algo, cls, decoded in cmp_unique[:10]:
                abs_va = r.BaseAddress + off
                fo     = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo:x}" if fo else "(not captured)"
                detail += (
                    f"\n          VA (process)   0x{abs_va:016x}"
                    f"\n          File offset    {fo_str}"
                    f"\n          Algorithm      {algo.upper()}"
                    f"\n          Decoded type   {cls['type'].upper()}"
                    f"\n          Decoded size   {len(decoded)} bytes"
                )
                if cls['ioc_strings']:
                    detail += f"\n          IOC strings    {', '.join(cls['ioc_strings'][:3])}"
        has_pe        = any(h[3]['is_pe'] for h in cmp_unique)
        has_shellcode = any(h[3]['is_shellcode'] for h in cmp_unique)
        structural = has_pe or has_shellcode
        ioc_only   = [h for h in cmp_unique if h[3]['ioc_strings'] and not (h[3]['is_pe'] or h[3]['is_shellcode'])]
        tag  = TAG_LEAD if ioc_only and not structural else TAG_OBSERVATION
        note = (_structural_note(has_pe, has_shellcode) if structural else
                "IOC-style string(s) found — treated as a lead" if ioc_only else
                "no structural or IOC content found")
        _print_check("Compressed data (GZIP/ZLIB) (observation)",
                     YELLOW("OBSERVATION" if tag == TAG_OBSERVATION else "LEAD") + f" — {note}", detail)
        findings['compressed'] = cmp_unique
        findings_list.append(Finding(
            check="obfuscation.compressed_observation",
            facts=[f"VA=0x{r.BaseAddress+off:x} algo={algo} decoded_type={cls['type']} "
                   f"decoded_size={len(decoded)}" for r, off, algo, cls, decoded in cmp_unique[:15]],
            inference=f"{len(cmp_unique)} region(s) contain data that decompresses cleanly "
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
    else:
        _print_check("Compressed data (GZIP/ZLIB)",
                     GREEN("CLEAN — no compressed payloads found"))

    # ── Structural PE payload check (this is what actually drives the score,
    # together with sleep-mask) ─────────────────────────────────────────────
    # A PE header that passes full structural validation
    # (dumpex.core.pe_utils.parse_pe_header — DOS/COFF/optional header/
    # complete section table, not just an 'MZ' prefix), found via ANY layer
    # (Base64, XOR, GZIP/ZLIB; sleep mask is scored separately above). This
    # — not "an encoding scheme was merely detected" — is what can move the
    # obfuscation verdict, per phase-two policy.
    all_pe_hits = findings['hidden_pe'] + pe_hits
    if all_pe_hits:
        # A gzip/zlib hit whose decompression stopped at the output cap
        # before reaching end-of-stream (complete=False) was never verified
        # end-to-end — the visible PE structure is real, but truncation/
        # corruption beyond the cap can't be ruled out the way it can for a
        # fully-decoded stream (see _bounded_decompress). That's disclosed
        # as a limitation whenever ANY hit is incomplete, but only pulls
        # confidence down to MEDIUM when EVERY hit in this batch is
        # incomplete -- one fully end-to-end-verified PE in the batch is
        # itself enough to justify HIGH, regardless of what else showed up
        # alongside it; a single unverified extra hit must not drag a
        # genuinely confirmed detection down.
        any_incomplete = any(not complete for *_, complete in all_pe_hits)
        all_incomplete = all(not complete for *_, complete in all_pe_hits)
        detail = f"{len(all_pe_hits)} PE payload(s) found inside encoded/compressed data"
        facts = []
        for enc, r, off, decoded, complete in all_pe_hits:
            abs_va = r.BaseAddress + off
            known  = addr_to_module(abs_va, modules)
            reg_str = "registered" if known else "UNREGISTERED"
            facts.append(f"type=PE encoding={enc} container_VA=0x{abs_va:x} "
                         f"module_status={reg_str} decoded_size={len(decoded)}"
                         + ("" if complete else " decode=incomplete(output-cap)"))
            detail += (f"\n          Encoding       {enc.upper()}"
                       f"\n          Container VA   0x{abs_va:016x}"
                       f"\n          Module status  {RED('UNREGISTERED — hidden PE') if not known else 'registered'}"
                       f"\n          Decoded PE     {len(decoded)} bytes"
                       + ("" if complete else "  (decompression hit the output cap — not end-to-end verified)"))
        _print_check("Structural PE payload inside encoded data",
                     RED("DETECTION — executable payload concealed by encoding"),
                     detail)
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

    # ── Shellcode bootstrap pattern — LEAD ONLY, never scored ──────────────
    # A 6-byte "call $+5; pop reg" prefix is a real, commonly-seen shellcode
    # idiom, but 6 bytes is far too little evidence to score on its own —
    # it has no structural validation comparable to a full PE header (no
    # section table, no plausible entry point, no instruction-stream
    # corroboration), and can occur by chance in high-entropy or
    # adversarially-crafted data. It is reported as an investigative lead
    # and explicitly does NOT contribute to the obfuscation score.
    all_shellcode_hits = findings['hidden_shellcode'] + shellcode_hits
    if all_shellcode_hits:
        facts = []
        detail = f"{len(all_shellcode_hits)} shellcode-bootstrap-pattern match(es) inside encoded/compressed data"
        # A bare 6-byte prefix match is weak on its own, but one sitting
        # inside a region that's ALSO executable+private (the same
        # combination injection.py/hollowing.py treat as suspicious) is a
        # meaningfully stronger combination than either signal alone —
        # still not structural proof (no section table, no entry-point
        # check), so this stays tag=LEAD and never touches score, but the
        # combo is worth flagging above a bare "6 bytes matched somewhere".
        context_hits = [(enc, r, off, decoded) for enc, r, off, decoded, _complete in all_shellcode_hits
                         if prot_str(r.Type) == 'MEM_PRIVATE'
                         and any(s in prot_str(r.Protect) for s in SUSPICIOUS_PROTS)]
        for enc, r, off, decoded, _complete in all_shellcode_hits:
            abs_va = r.BaseAddress + off
            in_context = (enc, r, off, decoded) in context_hits
            facts.append(f"type=shellcode_bootstrap encoding={enc} container_VA=0x{abs_va:x} "
                         f"decoded_size={len(decoded)} prefix={decoded[:6].hex()}"
                         + (f" container_protect={prot_str(r.Protect)} (executable+private)"
                            if in_context else ""))
            detail += (f"\n          Encoding       {enc.upper()}"
                       f"\n          Container VA   0x{abs_va:016x}"
                       f"\n          Decoded size   {len(decoded)} bytes (call-$+5 bootstrap prefix)")
            if in_context:
                detail += f"\n          Container prot {prot_str(r.Protect)}  (executable+private — elevated lead)"
        _print_check("Shellcode bootstrap pattern inside encoded data (lead)",
                     YELLOW("LEAD — not scored, see rationale"), detail)
        findings['hidden_shellcode'] = all_shellcode_hits
        confidence = CONFIDENCE_MEDIUM if context_hits else CONFIDENCE_LOW
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
                           f"{', '.join(SUSPICIOUS_PROTS)}) — the same combination "
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

    # ── Verdict ───────────────────────────────────────────────────────────
    # Score reflects STRUCTURAL detections only — confirmed sleep-mask
    # decode and/or a validated PE payload, found via any layer. Raw
    # entropy/Base64/GZIP/XOR presence and the shellcode-bootstrap prefix
    # (reported above as observations/leads) never contribute.
    score = int(bool(sleep_mask_hits)) + int(bool(all_pe_hits))
    findings['score'] = score
    findings['max_score'] = 2
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
    total_size_skipped = (sleep_mask_coverage.skipped_oversize + entropy_coverage.skipped_oversize
                           + decode_coverage.skipped_oversize)
    total_read_failed  = (sleep_mask_coverage.read_failed + entropy_coverage.read_failed
                           + decode_coverage.read_failed)
    total_short_reads  = (sleep_mask_coverage.short_reads + entropy_coverage.short_reads
                           + decode_coverage.short_reads)
    budget_exhausted = decode_budget.exhausted()
    findings['budget_exhausted'] = budget_exhausted
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
    findings['verdict_level'] = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    findings['confidence'] = overall_confidence(findings_list, score)
    findings['findings'] = [f.to_dict() for f in findings_list]
    findings['lead_count'] = lead_count(findings_list)
    findings['review_priority'] = review_priority(findings_list, score, status)

    # Detection-tier findings first, for visibility; observations/leads are
    # already shown inline with each layer's CLEAN/OBSERVATION/LEAD check
    # above and are not repeated here.
    for f in findings_list:
        if f.tag == TAG_DETECTION:
            f.print()

    if not mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif fully_skipped:
        verdict = _status_text(INCONCLUSIVE,
            f"all {len(regions)} region(s) filtered out by every layer's size/type limits "
            f"— nothing was actually scanned")
    elif status == INCONCLUSIVE:
        reason = ", ".join(filter(None, [
            f"{total_size_skipped} oversized region(s) skipped" if total_size_skipped else "",
            f"{total_read_failed} region(s) failed to read" if total_read_failed else "",
            f"{total_short_reads} region(s) short-read" if total_short_reads else "",
            f"decode budget exhausted ({decode_budget.exhausted_reason})" if budget_exhausted else "",
        ]))
        verdict = _status_text(INCONCLUSIVE, reason + leads_suffix(findings_list))
    else:
        verdict = (RED("HIGH CONFIDENCE — sleep-mask decode AND a structural PE payload confirmed") if score >= 2 else
                   YELLOW("LIKELY — one structural indicator (sleep-mask decode or PE payload)")     if score == 1 else
                   GREEN("CLEAN — no structurally-confirmed payload; raw observations/leads "
                         "above (entropy/Base64/GZIP/XOR/string/shellcode-prefix) are "
                         "informational only" + leads_suffix(findings_list)))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 — structural detections only; "
          f"entropy/Base64/GZIP/shellcode-prefix are observations/leads, never a verdict "
          f"by themselves)\n")

    if not verbose and any([sleep_mask_hits, b64_unique, xor_unique,
                            cmp_unique, entropy_hits]):
        print(DIM("  Use --verbose to expand region addresses, decoded content, and IOC strings.\n"))

    return findings
