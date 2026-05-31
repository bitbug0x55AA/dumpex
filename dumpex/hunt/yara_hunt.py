"""YARA memory scanner."""
import os
import sys
from pathlib import Path
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.core.memory import get_modules, addr_to_module, va_to_file_offset
from dumpex.hunt._ui import _print_hunt_header, _print_check
from dumpex.hunt.cs_beacon import CS_MAX_SEG_SCAN

def _load_yara_rules(rules_dir: str) -> list:
    """
    Compile every .yar / .yara file in rules_dir independently.

    Returns list of (filename, compiled_rules).
    Compiling per-file means a syntax error in one file doesn't
    prevent the rest from running.
    """
    import yara, glob
    loaded = []
    patterns = [
        os.path.join(rules_dir, "*.yar"),
        os.path.join(rules_dir, "*.yara"),
    ]
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            fname = os.path.basename(path)
            try:
                compiled = yara.compile(filepath=path)
                loaded.append((fname, compiled))
            except yara.SyntaxError as e:
                print(YELLOW(f"  [~] YARA syntax error in {fname}: {e}"))
            except Exception as e:
                print(YELLOW(f"  [~] Could not load {fname}: {e}"))
    return loaded


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

    Rules directory search order (when rules_dir is None):
      1. ./rules/yara/   (canonical — next to the script)
      2. ./rules/yara/   (canonical — cwd)
      3. ./yara-rules/   (legacy layout, backwards compat)
    """
    _print_hunt_header("YARA Memory Scan")
    findings = {"matches": [], "score": 0}

    # ── Locate and import yara-python ─────────────────────────────────
    try:
        import yara
    except ImportError:
        print(YELLOW("  [~] yara-python is not installed."))
        print(DIM ("      Install with: pip install yara-python"))
        print()
        return findings

    # ── Resolve rules directory ───────────────────────────────────────
    if rules_dir is None:
        script_dir = Path(sys.argv[0]).resolve().parent
        for candidate in (
            script_dir / "rules" / "yara",   # canonical
            Path.cwd()  / "rules" / "yara",
            script_dir / "yara-rules",        # legacy
            Path.cwd()  / "yara-rules",
        ):
            if candidate.is_dir():
                rules_dir = str(candidate)
                break

    if rules_dir is None or not os.path.isdir(rules_dir):
        print(YELLOW(f"  [~] No YARA rules directory found."))
        print(DIM (f"      Expected: ./rules/yara/  (or pass --yara-dir PATH)"))
        print()
        return findings

    # ── Load rule files ───────────────────────────────────────────────
    rule_files = _load_yara_rules(rules_dir)
    if not rule_files:
        print(YELLOW(f"  [~] No .yar / .yara files found in {rules_dir}"))
        print()
        return findings

    print(DIM(f"  [*] Loaded {len(rule_files)} rule file(s) from {rules_dir}"))

    # ── Collect memory segments ───────────────────────────────────────
    segs = []
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        segs = mf.memory_segments_64.memory_segments
    elif mf.memory_segments and mf.memory_segments.memory_segments:
        segs = mf.memory_segments.memory_segments

    if not segs:
        print(YELLOW("  [~] No memory segments in dump — cannot scan."))
        print()
        return findings

    modules = get_modules(mf)
    reader  = mf.get_reader()

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) …\n"))

    # ── Scan ──────────────────────────────────────────────────────────
    # all_hits: list of dicts, one per YARA match instance
    all_hits     = []
    skipped      = 0
    scanned      = 0
    triggered_rules = set()   # for deduped score

    for seg in segs:
        if seg.size > CS_MAX_SEG_SCAN:
            skipped += 1
            continue
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            continue
        scanned += 1

        for fname, compiled in rule_files:
            try:
                matches = compiled.match(data=data)
            except Exception:
                continue

            for match in matches:
                triggered_rules.add(match.rule)

                # Annotate each matched string with its absolute VA + file offset
                annotated_strings = []
                for s in match.strings:
                    # yara-python ≥4.3: s is a yara.StringMatch with .instances
                    # yara-python <4.3:  s is a tuple (offset, name, data)
                    if hasattr(s, 'instances'):
                        for inst in s.instances:
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
                })

    scan_note = f" ({skipped} segment(s) >50 MB skipped)" if skipped else ""
    print(DIM(f"  [*] Scan complete — {scanned} segment(s) scanned{scan_note}."))

    # ── Nothing found ─────────────────────────────────────────────────
    if not all_hits:
        print()
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

        _print_check(
            f"Rule: {rule_name}  {DIM('(' + rfile + ')')}",
            RED("SUSPICIOUS"),
            detail,
        )

    # ── Verdict ───────────────────────────────────────────────────────
    score = len(triggered_rules)
    findings["matches"]   = all_hits
    findings["score"]     = score
    findings["rules_hit"] = sorted(triggered_rules)

    verdict = (RED(f"HIGH — {score} distinct rule(s) matched")      if score >= 3 else
               YELLOW(f"MEDIUM — {score} distinct rule(s) matched") if score >= 1 else
               GREEN("CLEAN"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score} rule(s))\n")

    if not verbose and has_verbose_overflow:
        print(DIM("  Use --verbose to expand all region and string match details.\n"))

    return findings

