"""YARA memory scanner."""
import os
import sys
import atexit
import hashlib
import contextlib
import importlib.resources
from pathlib import Path
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.core.memory import (get_modules, get_memory_regions, addr_to_module,
    va_to_file_offset, prot_str, _get_region_at)
from dumpex.core.evidence import sha256_file
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt.cs_beacon import CS_MAX_SEG_SCAN
from dumpex.hunt._context import MemoryContext, classify_memory_context, CONFIRMED_PRIVATE

YARA_MATCH_TIMEOUT      = 30    # seconds, per (segment, rule-file) match() call
YARA_MAX_STRINGS_PER_MATCH = 50 # cap annotated string instances kept per match
YARA_MAX_TOTAL_HITS     = 2000  # hard cap on collected hits across the whole scan

_packaged_yara_ctx_stack = None   # lazily-created; closed at process exit via atexit
_LAST_YARA_PROVENANCE    = None   # set by _load_yara_rules(); see get_yara_provenance()


def get_yara_provenance() -> "dict | None":
    """
    Reproducible content provenance for the YARA rule files actually used
    by the most recent _load_yara_rules() call: {"rules_dir": str,
    "files": [{"name", "sha256", "compiled", "error"}, ...] sorted by
    name, "aggregate_sha256": str, "compiled_ok": int, "compile_failed":
    int}. None if YARA scanning was never invoked this process (e.g.
    --hunt injection alone, which never calls _load_yara_rules).

    A --yara-dir path or directory name alone doesn't tell an analyst
    reviewing a report months later WHICH rules actually produced a
    verdict — rule files get edited in place routinely. The per-file and
    aggregate sha256 let a finding be tied to the exact rule content that
    generated it, the same way meta.rules already does for rules.yaml
    (see dumpex.rules_pkg.loader.get_rules_source_info).
    """
    return _LAST_YARA_PROVENANCE


def _packaged_yara_rules_dir() -> "str | None":
    """
    Return the on-disk directory path of the packaged YARA rules
    (dumpex/rules_pkg/data/yara — the single copy shipped in the wheel, see
    pyproject.toml package-data), or None if not present.

    Resolved via importlib.resources rather than a __file__-relative path,
    so this is what actually keeps YARA scanning working for a `pip
    install dumpex` wheel with no rules/ directory anywhere near the
    invoking script — including a zip-safe/zipapp install, where __file__
    isn't a real filesystem path at all. importlib.resources.as_file() is a
    zero-cost passthrough when the package is already unpacked on disk (the
    normal case), and only materializes to a temp directory when it isn't;
    either way the returned path is real and glob()-able.
    """
    global _packaged_yara_ctx_stack
    try:
        traversable = importlib.resources.files("dumpex.rules_pkg").joinpath("data", "yara")
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        return None
    try:
        if not traversable.is_dir():
            return None
    except Exception:
        return None
    if _packaged_yara_ctx_stack is None:
        _packaged_yara_ctx_stack = contextlib.ExitStack()
        atexit.register(_packaged_yara_ctx_stack.close)
    path = _packaged_yara_ctx_stack.enter_context(importlib.resources.as_file(traversable))
    return str(path)

def _load_yara_rules(rules_dir: str) -> tuple:
    """
    Compile every .yar / .yara file in rules_dir independently.

    Returns (loaded, compile_failed):
      loaded         — list of (filename, compiled_rules)
      compile_failed — count of files that could not be compiled at all

    Compiling per-file means a syntax error in one file doesn't prevent the
    rest from running — but a file that never compiled also never
    contributed any rule to the scan, so it must count against scan
    coverage rather than just print a warning and vanish: a dump that would
    have matched that broken rule file's signatures must not come back
    NOT_DETECTED_IN_SCANNED_SCOPE as if the file's rules had actually run.

    Also records reproducible content provenance for every candidate file
    (compiled or not) — see get_yara_provenance() — as a side effect,
    keyed by sorted filename so the recorded order is deterministic
    regardless of filesystem iteration order.
    """
    import yara, glob
    global _LAST_YARA_PROVENANCE
    loaded = []
    compile_failed = 0
    file_provenance = []
    patterns = [
        os.path.join(rules_dir, "*.yar"),
        os.path.join(rules_dir, "*.yara"),
    ]
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            fname = os.path.basename(path)
            try:
                file_sha256 = sha256_file(path)
            except OSError:
                file_sha256 = None
            try:
                compiled = yara.compile(filepath=path)
                loaded.append((fname, compiled))
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": True, "error": None})
            except yara.SyntaxError as e:
                print(YELLOW(f"  [~] YARA syntax error in {fname}: {e}"))
                compile_failed += 1
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": False, "error": str(e)})
            except Exception as e:
                print(YELLOW(f"  [~] Could not load {fname}: {e}"))
                compile_failed += 1
                file_provenance.append({"name": fname, "sha256": file_sha256,
                                         "compiled": False, "error": str(e)})

    file_provenance.sort(key=lambda f: f["name"])
    aggregate = hashlib.sha256()
    for f in file_provenance:
        aggregate.update(f["name"].encode("utf-8"))
        aggregate.update((f["sha256"] or "").encode("utf-8"))
    _LAST_YARA_PROVENANCE = {
        "rules_dir":        rules_dir,
        "files":            file_provenance,
        "aggregate_sha256": aggregate.hexdigest(),
        "compiled_ok":      len(loaded),
        "compile_failed":   compile_failed,
    }
    return loaded, compile_failed


def _context_unverified_reason(contexts) -> str:
    """
    Build an accurate explanation for a set of MemoryContext values (see
    dumpex/hunt/_context.py) behind one or more context_unverified hits.
    UNKNOWN and OTHER are different findings and must not share one
    message: UNKNOWN means neither ModuleList nor MemoryInfo could
    classify the address at all; OTHER means MemoryInfo WAS available and
    resolved it to some type that's neither MEM_IMAGE nor MEM_PRIVATE
    (e.g. MEM_MAPPED) — that's a materially different situation from
    "no context available".
    """
    contexts = set(contexts)
    parts = []
    if "unknown" in contexts:
        parts.append("no ModuleList/MemoryInfo available to classify")
    if "other" in contexts:
        parts.append("region type is neither MEM_IMAGE nor MEM_PRIVATE, e.g. MEM_MAPPED")
    return "; ".join(parts) if parts else "context could not be verified"


def _hunt_yara(mf: MinidumpFile, rules_dir: str = None,
               verbose: bool = False) -> dict:
    """
    Scan all captured memory segments against every YARA rule in rules_dir.

    For each match reports:
      - Rule name, file, tags, description, MITRE ATT&CK ID
      - Every matched string: VA (process), file offset in .dmp, hex preview
      - Per-region context (protection, memory type, backing module)

    Score = number of *distinct rule names* that matched at least once,
    so finding 50 instances of one rule still counts as 1.

    Address semantics (consistent with the rest of Dumpex):
      VA (process)      — virtual address in the target process
      File offset (.dmp) — byte position inside the .dmp file
      Region base (VA)  — start of the enclosing memory region

    Rules directory resolution (when rules_dir is None — pass --yara-dir
    for an explicit, deliberate override instead of relying on this):
      1. sys._MEIPASS/rules/yara/         Compatibility with older
                                           PyInstaller builds
      2. dumpex.rules_pkg/data/yara/      Canonical package resource used
                                           by wheels and current PyInstaller
                                           builds (see
                                           _packaged_yara_rules_dir())

    There is deliberately no automatic cwd/script-dir scan: a DFIR working
    directory routinely contains untrusted case files, and that scan used
    to sit AFTER the packaged-defaults check anyway — which always
    succeeds now that YARA rules are bundled in the wheel — making it dead
    code that could never actually run. --yara-dir is the explicit,
    auditable way to point at a different rules directory.
    """
    _print_hunt_header("YARA Memory Scan")
    findings = {"matches": [], "score": 0, "status": NOT_EVALUATED}

    def _not_evaluated(reason: str) -> dict:
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(NOT_EVALUATED, reason)}\n")
        return findings

    # ── Locate and import yara-python ─────────────────────────────────
    try:
        import yara
    except ImportError:
        print(YELLOW("  [~] yara-python is not installed."))
        print(DIM ("      Install with: pip install yara-python"))
        print()
        return _not_evaluated("yara-python not installed")

    # ── Resolve rules directory ───────────────────────────────────────
    if rules_dir is None:
        # sys.argv[0] and cwd are dev-environment assumptions — a pip-
        # installed dumpex has no rules/ next to whatever invoked it.
        # Current PyInstaller builds collect dumpex.rules_pkg's package data
        # in its canonical layout; the _MEIPASS/rules path below is retained
        # only for compatibility with older frozen builds.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and (Path(meipass) / "rules" / "yara").is_dir():
            rules_dir = str(Path(meipass) / "rules" / "yara")
        else:
            rules_dir = _packaged_yara_rules_dir()

    if rules_dir is None or not os.path.isdir(rules_dir):
        print(YELLOW(f"  [~] No YARA rules directory found."))
        print(DIM (f"      Expected: ./rules/yara/  (or pass --yara-dir PATH)"))
        print()
        return _not_evaluated("no YARA rules directory found")

    # ── Load rule files ───────────────────────────────────────────────
    rule_files, compile_failed = _load_yara_rules(rules_dir)
    if not rule_files:
        print(YELLOW(f"  [~] No .yar / .yara files found in {rules_dir}"))
        if compile_failed:
            print(YELLOW(f"      ({compile_failed} file(s) present but failed to compile)"))
        print()
        if compile_failed:
            return _not_evaluated(f"all {compile_failed} rule file(s) in {rules_dir} failed to compile")
        return _not_evaluated(f"no .yar/.yara files in {rules_dir}")

    print(DIM(f"  [*] Loaded {len(rule_files)} rule file(s) from {rules_dir}"))
    if compile_failed:
        print(YELLOW(f"  [~] {compile_failed} rule file(s) failed to compile — "
                      f"scan coverage is reduced, not just a warning\n"))

    # ── Collect memory segments ───────────────────────────────────────
    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments

    if not segs:
        print(YELLOW("  [~] No memory segments in dump — cannot scan."))
        print()
        return _not_evaluated("Memory64ListStream missing from this dump")

    # Two independent context sources used to judge whether a
    # PE_In_Private_Memory hit is really in private memory or just a
    # legitimately loaded module: ModuleList (name/base/size per module) and
    # MemoryInfo (per-region Type/Protect/State, including MEM_IMAGE vs
    # MEM_PRIVATE). Either one alone lets us classify a hit; only when BOTH
    # are absent from this dump can the address not be judged at all.
    modules_available  = bool(mf.modules and mf.modules.modules)
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    reader  = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) …\n"))

    # ── Scan ──────────────────────────────────────────────────────────
    # all_hits: list of dicts, one per YARA match instance
    all_hits     = []
    skipped      = 0
    read_failed  = 0
    scanned      = 0
    timed_out    = 0
    match_failed = 0   # non-timeout exception from compiled.match() — the
                       # (segment, rule-file) pair was never actually
                       # evaluated and must not be indistinguishable from
                       # "evaluated, no match"
    truncated    = False   # hit YARA_MAX_TOTAL_HITS before finishing the scan
    suppressed_module_pe = 0   # PE_In_Private_Memory hits suppressed because
                               # the match address resolved to a known module
                               # or a MEM_IMAGE region
    context_unverified   = 0   # PE_In_Private_Memory hits that could not be
                               # classified at all: neither ModuleList nor
                               # MemoryInfo is present in this dump, so there
                               # is no way to tell a legitimate module header
                               # from a genuinely private-memory PE
    triggered_rules  = set()   # rule names with at least one confidently
                                # classified hit — drives score/DETECTED
    unverified_rules = set()   # rule names whose hits were ALL context_unverified

    for seg in segs:
        if truncated:
            break
        if seg.size > CS_MAX_SEG_SCAN:
            skipped += 1
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            # A segment that fails to read was never actually scanned — it
            # must not be silently indistinguishable from "scanned, clean".
            read_failed += 1
            continue
        scanned += 1

        for fname, compiled in rule_files:
            try:
                # timeout bounds a single (segment, rule-file) match() call —
                # a pathological rule/input combination (e.g. rules with
                # heavy regex backtracking) must not be able to hang the scan.
                matches = compiled.match(data=data, timeout=YARA_MATCH_TIMEOUT)
            except Exception as e:
                # yara-python raises yara.TimeoutError specifically; match on
                # the exception class name rather than message text, which
                # isn't a stable contract across yara-python versions. Any
                # OTHER exception (a crafted/corrupt segment tripping a YARA
                # internal error, a module error, etc.) must still be
                # accounted for — silently `continue`-ing here previously
                # left this (segment, rule-file) pair unrepresented in any
                # counter, so a scan that hit nothing else came back CLEAN
                # even though this pair was never actually evaluated.
                if "timeout" in type(e).__name__.lower():
                    timed_out += 1
                else:
                    match_failed += 1
                continue

            for match in matches:
                if len(all_hits) >= YARA_MAX_TOTAL_HITS:
                    truncated = True
                    break

                hit_context_unverified = False
                hit_memory_context = None
                if match.rule == "PE_In_Private_Memory":
                    # PE_In_Private_Memory's own rule description says it's
                    # only meaningful applied to MEM_PRIVATE/unregistered
                    # memory (condition is just "$mz at 0 and $pe" — no
                    # memory-type awareness at all, since YARA matches raw
                    # segment bytes with no such context). Left unfiltered,
                    # it fires on every legitimately loaded module's MZ/PE
                    # header too, since the match is always at the scanned
                    # segment's own base address. classify_memory_context
                    # names every combination of ModuleList/MemoryInfo
                    # availability explicitly (see dumpex/hunt/_context.py)
                    # so there's no silent fall-through case: a MemoryInfo
                    # gap (region not found) with ModuleList missing is
                    # UNKNOWN, not a confirmed PRIVATE hit, and a region of
                    # some other type (e.g. MEM_MAPPED) is OTHER, not
                    # treated as either IMAGE or PRIVATE.
                    addr = seg.start_virtual_address
                    ctx = classify_memory_context(addr, modules, regions,
                                                   modules_available, mem_info_available)
                    hit_memory_context = ctx.value

                    if ctx == MemoryContext.IMAGE:
                        suppressed_module_pe += 1
                        continue

                    if ctx not in CONFIRMED_PRIVATE:
                        # OTHER or UNKNOWN — the address cannot be
                        # confidently classified as private memory. Still
                        # record the hit (an investigator should see it)
                        # but it must not, by itself, stand as a confirmed
                        # detection. Which of the two it is matters for the
                        # message shown later — UNKNOWN means neither
                        # context source could even be consulted, OTHER
                        # means MemoryInfo WAS consulted and resolved to
                        # some type that's neither MEM_IMAGE nor
                        # MEM_PRIVATE (e.g. MEM_MAPPED) — those are
                        # different findings and must not share one
                        # "no ModuleList/MemoryInfo" message.
                        context_unverified += 1
                        hit_context_unverified = True

                if hit_context_unverified:
                    unverified_rules.add(match.rule)
                else:
                    triggered_rules.add(match.rule)

                # Annotate each matched string with its absolute VA + file offset,
                # capped so one match with pathologically many instances can't
                # blow up memory/output.
                annotated_strings = []
                for s in match.strings:
                    if len(annotated_strings) >= YARA_MAX_STRINGS_PER_MATCH:
                        break
                    # yara-python ≥4.3: s is a yara.StringMatch with .instances
                    # yara-python <4.3:  s is a tuple (offset, name, data)
                    if hasattr(s, 'instances'):
                        for inst in s.instances:
                            if len(annotated_strings) >= YARA_MAX_STRINGS_PER_MATCH:
                                break
                            off     = inst.offset
                            matched = inst.matched_data
                            abs_va  = seg.start_virtual_address + off
                            fo      = seg.start_file_address + off
                            annotated_strings.append({
                                "var":       s.identifier,
                                "offset":    off,
                                "va":        abs_va,
                                "fo":        fo,
                                "data":      matched,
                            })
                    else:
                        off, varname, matched = s
                        abs_va = seg.start_virtual_address + off
                        fo     = seg.start_file_address + off
                        annotated_strings.append({
                            "var":    varname,
                            "offset": off,
                            "va":     abs_va,
                            "fo":     fo,
                            "data":   matched,
                        })

                all_hits.append({
                    "rule":     match.rule,
                    "file":     fname,
                    "tags":     match.tags,
                    "meta":     match.meta,
                    "seg_va":   seg.start_virtual_address,
                    "seg_fo":   seg.start_file_address,
                    "seg_size": seg.size,
                    "strings":  annotated_strings,
                    "context_unverified": hit_context_unverified,
                    "memory_context": hit_memory_context,
                })
            if truncated:
                break

    scan_note = f" ({skipped} segment(s) >50 MB skipped)" if skipped else ""
    if read_failed:
        scan_note += f" ({read_failed} segment(s) failed to read)"
    if timed_out:
        scan_note += f" ({timed_out} match() call(s) timed out after {YARA_MATCH_TIMEOUT}s)"
    if match_failed:
        scan_note += f" ({match_failed} match() call(s) failed)"
    if truncated:
        scan_note += f" — TRUNCATED at {YARA_MAX_TOTAL_HITS} hits, scan did not complete"
    print(DIM(f"  [*] Scan complete — {scanned} segment(s) scanned{scan_note}."))
    if suppressed_module_pe:
        print(DIM(f"  [·] {suppressed_module_pe} PE_In_Private_Memory match(es) suppressed — "
                  f"MZ/PE header belonged to a known, legitimately loaded module.\n"))

    coverage = {
        "rule_files_compiled": compile_failed == 0,
        "segments_read":       read_failed == 0,
        "segments_size_ok":    skipped == 0,
        "matches_completed":   match_failed == 0 and timed_out == 0,
        "hit_cap_not_reached": not truncated,
    }
    findings["coverage"] = coverage
    any_gap = not all(coverage.values())

    # ── Nothing found ─────────────────────────────────────────────────
    if not all_hits:
        print()
        if any_gap:
            reason = ", ".join(filter(None, [
                f"{compile_failed} rule file(s) failed to compile" if compile_failed else "",
                f"{skipped} oversized segment(s) skipped" if skipped else "",
                f"{read_failed} segment(s) failed to read" if read_failed else "",
                f"{timed_out} match() call(s) timed out" if timed_out else "",
                f"{match_failed} match() call(s) failed" if match_failed else "",
                f"hit cap reached" if truncated else "",
            ]))
            findings["status"] = INCONCLUSIVE
            findings["scan_complete"] = False
            _print_check("YARA rules", _status_text(INCONCLUSIVE, reason))
        else:
            findings["status"] = NOT_DETECTED_IN_SCANNED_SCOPE
            findings["scan_complete"] = True
            _print_check("YARA rules", GREEN("CLEAN — no rules matched"))
        return findings

    # ── Group hits by rule; build _print_check detail strings ─────────
    from collections import defaultdict
    by_rule = defaultdict(list)
    for hit in all_hits:
        by_rule[hit["rule"]].append(hit)

    has_verbose_overflow = False   # tracks whether any rule has >5 regions when not verbose

    for rule_name, hits in sorted(by_rule.items()):
        meta  = hits[0]["meta"]
        rfile = hits[0]["file"]
        desc  = meta.get("description", "")
        mitre = meta.get("mitre", "")
        ref   = meta.get("reference", "")
        tags  = hits[0]["tags"]

        # Deduplicate by segment base VA
        seen_vas = {}
        for hit in hits:
            if hit["seg_va"] not in seen_vas:
                seen_vas[hit["seg_va"]] = hit

        n_segs    = len(seen_vas)
        n_strings = sum(len(h["strings"]) for h in seen_vas.values())

        # ── Compact detail (always shown) ────────────────────────────
        tag_part   = f"  [{', '.join(tags)}]" if tags else ""
        mitre_part = f"  {mitre}"             if mitre else ""
        desc_part  = f"  {desc[:72]}{'…' if len(desc) > 72 else ''}" if desc else ""
        detail     = (f"{n_segs} region(s), {n_strings} string hit(s)"
                      f"{mitre_part}{tag_part}"
                      f"\n          {DIM(rfile)}{desc_part}")
        if ref:
            detail += f"\n          ref: {ref}"

        # ── Verbose expansion: per-region hit lines ───────────────────
        if verbose:
            for seg_va, hit in sorted(seen_vas.items()):
                mod     = addr_to_module(seg_va, modules)
                backing = os.path.basename(mod.name) if mod else "(private/unbacked)"
                detail += (f"\n\n          Region  VA 0x{seg_va:016x}"
                           f"  size 0x{hit['seg_size']:x}"
                           f"  ← {backing}")

                for sv in hit["strings"]:
                    raw      = sv["data"]
                    is_text  = all(0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)
                                   for b in raw[:64])
                    preview  = (raw[:64].decode("ascii", errors="replace").rstrip()
                                if is_text else raw[:24].hex())
                    detail  += (f"\n            {DIM(sv['var']):<18}"
                                f"  VA 0x{sv['va']:016x}"
                                f"  DMP 0x{sv['fo']:x}"
                                f"  {preview}")
        else:
            # Non-verbose: show first 5 regions as a one-liner summary
            region_list = [f"0x{va:x}" for va in sorted(seen_vas)[:5]]
            overflow    = n_segs - 5
            detail += f"\n          regions: {', '.join(region_list)}"
            if overflow > 0:
                detail    += f"  … +{overflow} more"
                has_verbose_overflow = True

        # A rule whose EVERY hit is context_unverified (PE_In_Private_Memory
        # in a MemoryContext.OTHER or MemoryContext.UNKNOWN region — see
        # dumpex/hunt/_context.py) cannot be reported as a confirmed
        # detection — it's shown for visibility but with a distinct,
        # non-alarming status. The two contexts are different findings
        # (OTHER means MemoryInfo WAS available and resolved to some other
        # type; UNKNOWN means neither context source classified it at
        # all), so the message must say which applies, not always claim
        # "no ModuleList/MemoryInfo".
        rule_is_unverified = all(h.get("context_unverified") for h in hits)
        if rule_is_unverified:
            rule_contexts = {h.get("memory_context") for h in hits}
            status_label = YELLOW(f"CONTEXT UNVERIFIED — {_context_unverified_reason(rule_contexts)}")
        else:
            status_label = RED("SUSPICIOUS")
        _print_check(
            f"Rule: {rule_name}  {DIM('(' + rfile + ')')}",
            status_label,
            detail,
        )

    if suppressed_module_pe:
        print(DIM(f"  [·] {suppressed_module_pe} PE_In_Private_Memory match(es) suppressed — "
                  f"resolved to a known module or a MEM_IMAGE region.\n"))
    if context_unverified:
        all_unverified_contexts = {h.get("memory_context") for h in all_hits
                                   if h.get("context_unverified")}
        print(YELLOW(f"  [~] {context_unverified} PE_In_Private_Memory match(es) could not be "
                      f"classified ({_context_unverified_reason(all_unverified_contexts)}).\n"))

    # ── Verdict ───────────────────────────────────────────────────────
    # score/DETECTED are driven only by confidently classified hits
    # (triggered_rules); rules whose only evidence is context_unverified
    # don't get to unilaterally declare DETECTED — see INCONCLUSIVE branch.
    score = len(triggered_rules)
    findings["matches"]   = all_hits
    findings["score"]     = score
    findings["rules_hit"] = sorted(triggered_rules)

    if triggered_rules:
        findings["status"]        = DETECTED
        findings["scan_complete"] = not any_gap   # keep DETECTED even with
                                                   # partial coverage, but say so
        verdict = (RED(f"HIGH — {score} distinct rule(s) matched")      if score >= 3 else
                   YELLOW(f"MEDIUM — {score} distinct rule(s) matched") if score >= 1 else
                   GREEN("CLEAN"))
        print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score} rule(s))\n")
    else:
        # Only unverified hits (and/or coverage gaps) — a negative can't be
        # trusted and a positive can't be confirmed either.
        findings["status"]        = INCONCLUSIVE
        findings["scan_complete"] = False
        reason = (f"{len(unverified_rules)} rule(s) matched but could not be classified "
                  f"(context_unverified)" if unverified_rules else
                  "coverage incomplete, see above")
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(INCONCLUSIVE, reason)}\n")

    if truncated or timed_out or match_failed or compile_failed:
        print(YELLOW(f"  [~] Scan did not fully complete "
                      f"({'hit result cap' if truncated else ''}"
                      f"{' + ' if truncated and (timed_out or match_failed or compile_failed) else ''}"
                      f"{f'{timed_out} timeout(s)' if timed_out else ''}"
                      f"{' + ' if timed_out and (match_failed or compile_failed) else ''}"
                      f"{f'{match_failed} match failure(s)' if match_failed else ''}"
                      f"{' + ' if match_failed and compile_failed else ''}"
                      f"{f'{compile_failed} rule file(s) failed to compile' if compile_failed else ''}"
                      f") — there may be more matches than shown.\n"))

    if not verbose and has_verbose_overflow:
        print(DIM("  Use --verbose to expand all region and string match details.\n"))

    return findings
