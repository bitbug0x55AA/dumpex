"""Hunt command dispatcher."""
import os
import sys
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import va_to_file_offset, prot_str
from dumpex.hunt._ui import _status_text, NOT_EVALUATED, INCONCLUSIVE
from dumpex.hunt.injection  import _hunt_injection
from dumpex.hunt.hollowing  import _hunt_hollowing
from dumpex.hunt.stomping   import _hunt_stomping
from dumpex.hunt.pipe       import _hunt_pipe
from dumpex.hunt.cs_beacon  import _hunt_cs_beacon
from dumpex.hunt.yara_hunt  import _hunt_yara
from dumpex.hunt.encoding   import _hunt_encoding

def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False, yara_dir: str = None):
    """Run TTP-specific detection playbooks."""
    valid = {"injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation", "all"}
    if ttp not in valid:
        print(RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(valid))}"))
        sys.exit(1)

    run_injection  = ttp in ("injection",  "all")
    run_hollowing  = ttp in ("hollowing",  "all")
    run_stomping   = ttp in ("stomping",   "all")
    run_pipe       = ttp in ("pipe",       "all")
    run_cs_beacon  = ttp in ("cs-beacon",  "all")
    run_yara       = ttp in ("yara",       "all")
    run_obfuscation   = ttp in ("obfuscation",   "all")

    results = {}

    if run_injection:
        results["injection"]  = _hunt_injection(mf, verbose=verbose)
    if run_hollowing:
        results["hollowing"]  = _hunt_hollowing(mf, verbose=verbose)
    if run_stomping:
        results["stomping"]   = _hunt_stomping(mf,  verbose=verbose)
    if run_pipe:
        results["pipe"]       = _hunt_pipe(mf, verbose=verbose)
    if run_cs_beacon:
        # --hunt all always runs the full memory scan now — skipping it when
        # prior TTPs scored 0 meant a beacon could be present in a dump with
        # no injection/hollowing/stomping/pipe indicators (e.g. a beacon
        # sitting in ordinary-looking memory) and --hunt all would still
        # report "No TTP indicators found" without ever having looked.
        results["cs-beacon"] = _hunt_cs_beacon(mf, verbose=verbose)
    if run_yara:
        results["yara"]       = _hunt_yara(mf, rules_dir=yara_dir, verbose=verbose)
    if run_obfuscation:
        results["obfuscation"]   = _hunt_encoding(mf, verbose=verbose)

    # ── Sanitize for JSON serialization ───────────────────────────────────
    # CS beacon: convert int-keyed field dicts + bytes
    if "cs-beacon" in results:
        safe_cfgs = []
        for cfg in results["cs-beacon"].get("configs", []):
            safe_fields = {}
            for fid, rec in cfg.get("fields", {}).items():
                raw = rec.get("raw", b"")
                safe_fields[str(fid)] = {
                    "name":  rec.get("name", ""),
                    "type":  rec.get("type", ""),
                    "raw":   raw.hex() if isinstance(raw, bytes) else str(raw),
                    "value": (rec["value"].hex()
                              if isinstance(rec.get("value"), bytes)
                              else rec.get("value")),
                }
            safe_cfgs.append({
                "va":              cfg["va"],
                "file_offset":     cfg["file_offset"],
                "region_base":     cfg.get("region_base"),
                "region_size":     cfg.get("region_size"),
                "region_protect":  cfg.get("region_protect"),
                "xor_key":         cfg["xor_key"],
                "cs_version":      cfg["cs_version"],
                "fields":          safe_fields,
            })
        results["cs-beacon"]["configs"] = safe_cfgs

    # YARA: bytes → hex in matched string data
    if "yara" in results:
        for match in results["yara"].get("matches", []):
            for sv in match.get("strings", []):
                if isinstance(sv.get("data"), bytes):
                    sv["data"] = sv["data"].hex()

    # Summary card for --hunt all
    if ttp == "all" and "yara" not in results:
        results["yara"] = {"matches": [], "score": 0, "rules_hit": [], "status": NOT_EVALUATED}
    if ttp == "all" and "obfuscation" not in results:
        results["obfuscation"] = {"score": 0, "status": NOT_EVALUATED}

    if ttp == "all":
        print(BOLD("══════════════════════════════════════════"))
        print(BOLD("  HUNT SUMMARY"))
        print(BOLD("══════════════════════════════════════════"))
        labels = {
            "injection": ("Process Injection",          results["injection"]["score"],  3),
            "hollowing": ("Process Hollowing",          results["hollowing"]["score"],  4),
            "stomping":  ("Module Stomping",            results["stomping"]["score"],   2),
            "pipe":      ("Named Pipe C2 / Lat. Move.", results["pipe"]["score"],       4),
            "cs-beacon": ("Cobalt Strike Beacon",       results["cs-beacon"]["score"],  1),
            "yara":      ("YARA Rules",                 results["yara"]["score"],       3),
            "obfuscation":  ("Obfuscation Detection",       results["obfuscation"]["score"],   5),
        }
        any_hit           = False
        any_not_evaluated = False
        any_inconclusive  = False
        for key, (name, score, max_score) in labels.items():
            status = results.get(key, {}).get("status")
            if status == NOT_EVALUATED:
                verdict = _status_text(NOT_EVALUATED)
                any_not_evaluated = True
            elif status == INCONCLUSIVE:
                verdict = _status_text(INCONCLUSIVE)
                any_inconclusive = True
            elif key == "cs-beacon" and score > 0:
                verdict = RED(f"BEACON CONFIG FOUND ({score} config(s))")
                any_hit = True
            elif key == "yara" and score > 0:
                rules_hit = results["yara"].get("rules_hit", [])
                verdict = RED(f"RULES MATCHED: {', '.join(rules_hit[:4])}{'…' if len(rules_hit) > 4 else ''}")
                any_hit = True
            elif score == 0:
                verdict = GREEN("CLEAN")
            elif score >= max_score - 1:
                verdict = RED("HIGH CONFIDENCE")
                any_hit = True
            else:
                verdict = YELLOW("POSSIBLE")
                any_hit = True
            suffix = (f"  ({score}/{max_score})" if key not in ("cs-beacon", "yara") else "")
            print(f"  {name:<25} {verdict}{suffix}")
        print()
        if any_hit:
            print(YELLOW("  Overall: One or more TTPs detected. Run --report for deep-dive."))
        elif any_not_evaluated or any_inconclusive:
            print(YELLOW("  Overall: No TTPs detected in what was scanned, but coverage is "
                          "incomplete — one or more checks were NOT EVALUATED or INCONCLUSIVE "
                          "(see per-TTP status above). This is not a clean bill of health."))
        else:
            print(GREEN("  Overall: No TTP indicators found in this dump."))
        print()

    return results

