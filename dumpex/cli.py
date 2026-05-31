"""Command-line entry point."""
import sys
import argparse
import datetime
from pathlib import Path
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors import RED, DIM, BOLD
from dumpex.core.memory import open_dump, parse_hex_or_int, _resolve_size
from dumpex.rules_pkg.loader import get_rules
from dumpex.ui.structured import StructuredOutput, _TeeWriter

from dumpex.commands.list_cmd import cmd_list
from dumpex.commands.modules  import cmd_modules
from dumpex.commands.threads  import cmd_threads
from dumpex.commands.extract  import cmd_extract, cmd_strings
from dumpex.commands.peb      import cmd_peb
from dumpex.commands.sysinfo  import cmd_sysinfo, cmd_pid
from dumpex.commands.report   import cmd_report
from dumpex.commands.diff     import cmd_diff
from dumpex.hunt              import cmd_hunt

def main():
    parser = argparse.ArgumentParser(
        prog="dumpex",
        description=BOLD("dumpex — Minidump Memory Extractor & Analyzer"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\n'.join(__doc__.strip().splitlines()[3:]) if __doc__ else None
    )

    parser.add_argument("dumpfile", help="Primary .DMP file")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list",         action="store_true", help="List all memory regions")
    mode.add_argument("--modules",      action="store_true", help="List loaded modules")
    mode.add_argument("--threads",      action="store_true", help="List threads with analysis")
    mode.add_argument("--extract",      metavar="ADDR",      help="Extract raw bytes at address")
    mode.add_argument("--strings",      metavar="ADDR",      help="Extract strings at address")
    mode.add_argument("--peb",          action="store_true", help="Show PEB info")
    mode.add_argument("--pid",          action="store_true", help="Show the Process ID recorded in the dump")
    mode.add_argument("--sysinfo",      action="store_true", help="Show OS, host, process and CPU summary")
    mode.add_argument("--diff",         metavar="DUMP2",     help="Diff against a second .DMP file")
    mode.add_argument("--report",        action="store_true", help="Generate triage report anchored to a TID, address, or string")
    mode.add_argument("--hunt",          metavar="TTP",       help="TTP detection: injection | hollowing | stomping | pipe | cs-beacon | yara | obfuscation | all")

    # Shared
    parser.add_argument("-s", "--size",      metavar="SIZE",   help="Region size in hex")
    parser.add_argument("-o", "--output",    metavar="FILE",   help="Output file for --extract")
    parser.add_argument("--filter",          metavar="PROT",   help="Filter --list by protection name")
    parser.add_argument("--grep",            metavar="REGEX",  help="Regex filter for --strings")
    parser.add_argument("--min-len",         metavar="N", type=int, default=6,
                        help="Minimum string length (default: 6)")
    parser.add_argument("--encoding",        choices=["ascii", "unicode", "both"], default="both",
                        help="String encoding to scan (default: both)")
    parser.add_argument("--diff-mode",       choices=["modules", "threads", "memory", "all"],
                        default="all", help="What to diff (default: all)")

    parser.add_argument('--verbose',    action='store_true', help='Show all regions including routine ones')
    parser.add_argument('--yara-dir',   metavar='DIR',       default=None,
                        help='Directory of .yar rule files for --hunt yara (default: ./rules/yara/)')
    parser.add_argument('--json',       metavar='FILE',      default=None,
                        help='Write structured results to FILE as JSON  (e.g. results.json)')
    parser.add_argument('--csv',        metavar='PATH',      default=None,
                        help='Write CSV output: FILE.csv → single combined file  |  DIR\\ → one file per table')
    parser.add_argument('--txt',        metavar='FILE',      default=None,
                        help='Write plain-text copy of all console output to FILE (ANSI colours stripped)')
    parser.add_argument('--report-tid',  metavar='TID',  help='Anchor report to this Thread ID (hex or decimal)')
    parser.add_argument('--report-addr',   metavar='ADDR',   help='Anchor report to this memory address (hex)')
    parser.add_argument('--report-string', metavar='STRING', help='Search all memory for string, report on each hit region')
    args = parser.parse_args()

    # ── Derive a short label describing the command being run ─────────────
    # Used in auto-generated filenames when the caller passes a directory.
    # Examples:  hunt_all   modules   sysinfo   report_string
    # Must be derived before the --txt tee block so the filename can use it.
    def _cmd_label() -> str:
        if args.hunt:
            return f"hunt_{args.hunt.replace('-', '_')}"
        if args.modules:    return "modules"
        if args.threads:    return "threads"
        if args.pid:        return "pid"
        if args.sysinfo:    return "sysinfo"
        if args.peb:        return "peb"
        if args.list:       return "list"
        if args.report:
            sub = (f"tid_{args.report_tid}"     if args.report_tid else
                   f"addr_{args.report_addr}"   if args.report_addr else
                   "string"                     if args.report_string else "report")
            return sub
        if args.strings:    return f"strings_{args.strings}"
        if args.extract:    return f"extract_{args.extract}"
        if args.diff:       return "diff"
        return "dumpex"
    cmd_label = _cmd_label()

    # ── Plain-text tee ────────────────────────────────────────────────────
    _tee_fh     = None
    _tee_stdout = None
    if args.txt:
        txt_path = Path(args.txt)
        if str(args.txt).endswith(('/', '\\')) or txt_path.is_dir():
            ts       = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
            label    = f"_{cmd_label}" if cmd_label else ""
            txt_path = txt_path / f"dumpex_{ts}{label}.txt"
        txt_path.parent.mkdir(parents=True, exist_ok=True)
        _tee_fh     = open(txt_path, 'w', encoding='utf-8')
        _tee_stdout = sys.stdout
        sys.stdout  = _TeeWriter(_tee_fh, _tee_stdout)

    mf   = open_dump(args.dumpfile)

    # Structured output collector — populated by commands that support it
    need_structured = bool(args.json or args.csv)
    out = StructuredOutput(args.dumpfile, mf) if need_structured else None

    if   args.list:         cmd_list(mf, args.filter)
    elif args.modules:
        data = cmd_modules(mf)
        if out: out.add("modules", data)
    elif args.threads:
        data = cmd_threads(mf)
        if out: out.add("threads", data)
    elif args.peb:          cmd_peb(mf)
    elif args.pid:
        data = cmd_pid(mf)
        if out: out.add("pid", data)
    elif args.sysinfo:
        data = cmd_sysinfo(mf)
        if out: out.add("sysinfo", data)
    elif args.report:
        if not args.report_tid and not args.report_addr and not args.report_string:
            print(RED("[!] --report requires at least one of: --report-tid, --report-addr, --report-string"))
            sys.exit(1)
        cmd_report(mf,
                  report_tid=args.report_tid,
                  report_addr=args.report_addr,
                  report_string=args.report_string,
                  extract_to=args.output,
                  min_len=args.min_len)
    elif args.hunt:
        data = cmd_hunt(mf, args.hunt, verbose=args.verbose, yara_dir=args.yara_dir)
        if out and data: out.add("hunt", data)
    elif args.diff:         cmd_diff(mf, args.diff, args.diff_mode, verbose=args.verbose)

    elif args.extract:
        addr = parse_hex_or_int(args.extract)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_extract(mf, addr, size, args.output, auto_size=_req is None)

    elif args.strings:
        addr = parse_hex_or_int(args.strings)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_strings(mf, addr, size, args.min_len, args.grep, args.encoding, auto_size=_req is None)

    # ── Write structured output ────────────────────────────────────────────
    if out:
        if out._sections:
            if args.json:
                out.write_json(args.json, cmd_label=cmd_label)
            if args.csv:
                out.write_csv(args.csv,  cmd_label=cmd_label)
        else:
            print(DIM("  [~] --json/--csv: this command does not produce structured output."))

    # ── Finalise plain-text output ────────────────────────────────────────
    if _tee_fh is not None:
        sys.stdout = _tee_stdout          # restore real stdout first
        _tee_fh.close()
        print(DIM(f"  [·] TXT  written → {args.txt}"))

