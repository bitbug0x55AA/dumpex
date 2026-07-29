"""Command-line entry point."""
import os
import sys
import argparse
import datetime
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors import RED, DIM, BOLD
from dumpex.core.memory import open_dump, parse_hex_or_int, _resolve_size
from dumpex.rules_pkg.loader import get_rules, configure_rules_source
from dumpex.ui.structured import StructuredOutput, _ANSI_RE
from dumpex.output import V2Output
from dumpex.core.safe_io import check_not_dump_path, AtomicTextTee

from dumpex.commands.list_cmd import cmd_list
from dumpex.commands.modules  import cmd_modules
from dumpex.commands.threads  import cmd_threads
from dumpex.commands.extract  import cmd_extract, cmd_strings
from dumpex.commands.peb      import cmd_peb
from dumpex.commands.sysinfo  import cmd_sysinfo, cmd_pid
from dumpex.commands.report   import cmd_report
from dumpex.commands.diff     import cmd_diff
from dumpex.hunt              import cmd_hunt

# ── v2 structured-output routing ────────────────────────────────────────
# --hunt keeps StructuredOutput/dumpex-output-v1.1.schema.json unchanged.
# These six recon commands are migrated onto the v2 envelope (see
# dumpex/output/ and dumpex-output-v2.0.schema.json); --diff/--report/
# --extract/--strings don't produce structured output yet at all (their
# own canonical records are a later migration) -- requesting --json/--csv
# with one of them is now rejected up front (see the pre-flight check in
# main()) instead of running the full command and only saying so
# afterward.
_V2_STRUCTURED_MODES = frozenset({"list", "modules", "threads", "pid", "sysinfo", "peb"})
_UNSUPPORTED_STRUCTURED_MODES = frozenset({"diff", "report", "extract", "strings"})

# Exit codes for the six v2-routed recon commands, independent of
# --json/--csv having been requested at all: a SOC script checking `$?`
# on a bare `dumpex --threads dump.dmp` should be able to detect
# incomplete coverage without needing to also parse JSON. Every other
# command's exit-code behavior (0 on completion, an uncaught exception's
# default nonzero exit on a fatal error) is unchanged by this PR --
# folding --report/--hunt into this same convention is a later,
# cross-cutting decision, not made here for just these six commands.
EXIT_OK      = 0
EXIT_PARTIAL = 3


def _selected_run_mode(args) -> str:
    """The single mode flag argparse's mutually_exclusive_group(required=True)
    guarantees is set, as a plain string key into _V2_STRUCTURED_MODES /
    _UNSUPPORTED_STRUCTURED_MODES -- kept separate from _cmd_label() below,
    which returns a filename-oriented label (e.g. "hunt_all", "tid_1234"),
    not a bare mode name."""
    if args.list:      return "list"
    if args.modules:   return "modules"
    if args.threads:   return "threads"
    if args.extract:   return "extract"
    if args.strings:   return "strings"
    if args.peb:       return "peb"
    if args.pid:       return "pid"
    if args.sysinfo:   return "sysinfo"
    if args.diff:      return "diff"
    if args.report:    return "report"
    if args.hunt:      return "hunt"
    return ""   # unreachable: the mode group is required=True


def main():
    # Captured before any argument parsing or dump access — the earliest
    # possible point in the run — so --json meta.execution.duration_seconds
    # covers the whole invocation (including open_dump()/MinidumpFile.parse(),
    # which can be non-trivial for a multi-GB dump) rather than only the
    # time from StructuredOutput's own construction, which used to happen
    # AFTER the dump was already open.
    started_at = datetime.datetime.now(datetime.timezone.utc)

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
                        help='Directory of .yar rule files for --hunt yara '
                             '(default: packaged rules; no automatic cwd/script-dir scan)')
    parser.add_argument('--ref-dir',    metavar='DIR',       default=None,
                        help='Directory of analyst-supplied reference module files '
                             '(matched by basename) for --hunt stomping\'s optional '
                             'on-disk-vs-memory section byte diff. Not required — the '
                             'structural section-protection-mismatch check runs without it.')
    parser.add_argument('--rules-file', metavar='FILE',      default=None,
                        help='Explicit rules.yaml/.yml/.json for TTP detection '
                             '(default: packaged rules; no automatic cwd/script-dir scan)')
    parser.add_argument('--json',       metavar='FILE',      default=None,
                        help='Write structured results to FILE as JSON  (e.g. results.json)')
    parser.add_argument('--csv',        metavar='PATH',      default=None,
                        help='Write CSV output: FILE.csv → single combined file  |  DIR\\ → one file per table')
    parser.add_argument('--txt',        metavar='FILE',      default=None,
                        help='Write plain-text copy of all console output to FILE (ANSI colours stripped)')
    parser.add_argument('--report-tid',  metavar='TID',  help='Anchor report to this Thread ID (hex or decimal)')
    parser.add_argument('--report-addr',   metavar='ADDR',   help='Anchor report to this memory address (hex)')
    parser.add_argument('--report-string', metavar='STRING', help='Search all memory for string, report on each hit region')
    parser.add_argument('--force',      action='store_true',
                        help='Allow overwriting an existing output file (--txt/--output/--json/--csv). '
                             'Never allowed for the input dump file itself.')
    parser.add_argument('--case-id',    metavar='ID',        default=None,
                        help='Case/ticket identifier recorded in --json meta.execution.case_id '
                             '(free-form; not validated or used elsewhere)')
    parser.add_argument('--analyst',    metavar='NAME',      default=None,
                        help='Analyst name/handle recorded in --json meta.execution.analyst')
    parser.add_argument('--redact-paths', action='store_true',
                        help='Omit absolute filesystem paths from --json meta (evidence.path and '
                             'any --ref-dir/--yara-dir/--rules-file path in meta.execution.options '
                             'are reduced to their basename) — for sharing JSON output outside the '
                             'analyst\'s own machine without leaking local directory layout')
    args = parser.parse_args()

    run_mode = _selected_run_mode(args)

    # --json/--csv on a command that doesn't produce structured output yet
    # (--diff/--report/--extract/--strings -- see _UNSUPPORTED_STRUCTURED_MODES)
    # is rejected HERE, before the dump is even opened, rather than running
    # the full command and only saying so afterward once nothing was
    # collected to write.
    if (args.json or args.csv) and run_mode in _UNSUPPORTED_STRUCTURED_MODES:
        flag = "--json" if args.json else "--csv"
        parser.error(f"{flag} is not supported for --{run_mode} yet -- structured output "
                     f"currently covers --list/--modules/--threads/--pid/--sysinfo/--peb "
                     f"(v2) and --hunt (v1.1). Rerun without {flag}.")

    # --ref-dir is only meaningful for --hunt stomping, but validated
    # unconditionally and up front — a silently-ignored typo'd/missing
    # path would otherwise make the on-disk content-diff check quietly
    # never run, with no indication why (the tool would just report
    # "no --ref-dir supplied" for a path the user DID supply).
    if args.ref_dir and not os.path.isdir(args.ref_dir):
        parser.error(f"--ref-dir {args.ref_dir!r} is not an existing directory")

    # Explicit rules.yaml override (--rules-file), if any — must be set
    # before anything calls get_rules() (every hunt module that reads TTP
    # rules does, on first use, and caches the result for the rest of the
    # run). See rules_pkg/loader.py for why there's no automatic cwd scan.
    if args.rules_file:
        configure_rules_source(args.rules_file)

    # ── Output-path safety ──────────────────────────────────────────────────
    # Checked before the dump is opened or any output file is touched: a
    # MinidumpFile keeps reading from the file handle on demand for the life
    # of the process (not a one-time upfront slurp), so there is no point in
    # program execution where overwriting the dump path becomes "safe" —
    # this is a hard, unconditional refusal, not something --force can lift.
    for out_arg, label in ((args.txt, "--txt"), (args.output, "--output"),
                            (args.json, "--json"), (args.csv, "--csv")):
        if out_arg:
            check_not_dump_path(out_arg, args.dumpfile, label)

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

    # ── Curated CLI options for --json meta.execution.options ─────────────
    # Deliberately NOT the full argparse Namespace (would include flags
    # irrelevant to whatever mode actually ran) and NEVER raw environment
    # variables (may carry credentials/hostnames unrelated to this run) —
    # just the handful of options that could have influenced this run's
    # output, so a JSON result can be understood/reproduced without also
    # having the original command line.
    def _build_options() -> dict:
        opts = {"verbose": args.verbose}
        if args.hunt:
            opts["hunt"] = args.hunt
            opts["yara_dir"] = args.yara_dir
            opts["ref_dir"] = args.ref_dir
            opts["rules_file"] = args.rules_file
        if args.list:
            opts["filter"] = args.filter
        if args.strings:
            opts["min_len"] = args.min_len
            opts["grep"] = args.grep
            opts["encoding"] = args.encoding
        if args.diff:
            opts["diff_mode"] = args.diff_mode
        return opts

    # ── Plain-text tee ────────────────────────────────────────────────────
    # Streams to a scratch temp file for the whole run; the final filename
    # is only generated and committed in finalize() below, once (and only
    # if) the run completes — nothing is ever created at/near the final
    # --txt path before that point, so a crash, Ctrl-C, or refusal never
    # leaves an empty placeholder behind.
    _tee        = None
    _tee_stdout = None
    if args.txt:
        _tee        = AtomicTextTee(args.txt, cmd_label, args.dumpfile, args.force,
                                     sys.stdout, _ANSI_RE)
        _tee_stdout = sys.stdout
        sys.stdout  = _tee

    exit_code = None
    try:
        mf   = open_dump(args.dumpfile)

        # Structured output collector — populated by commands that support
        # it. The six v2-routed recon commands always get a V2Output (built
        # regardless of --json/--csv, so the exit-code contract below is
        # consistent whether or not structured output was actually
        # written); --hunt keeps constructing StructuredOutput exactly as
        # before, only when --json/--csv was actually requested.
        need_structured = bool(args.json or args.csv)
        if run_mode in _V2_STRUCTURED_MODES:
            out = V2Output(args.dumpfile, mf, command=cmd_label, options=_build_options(),
                            case_id=args.case_id, analyst=args.analyst,
                            redact_paths=args.redact_paths, started_at=started_at)
        elif need_structured:
            out = StructuredOutput(args.dumpfile, mf, command=cmd_label, options=_build_options(),
                                    case_id=args.case_id, analyst=args.analyst,
                                    redact_paths=args.redact_paths,
                                    started_at=started_at)
        else:
            out = None

        # --json/--csv path resolution (existing-file / dump-path / dir-mode
        # collision handling) is owned entirely by StructuredOutput.write_json
        # / write_csv (via commit_output) — not duplicated here. Likewise
        # --output is checked exactly once, inside cmd_extract/cmd_report
        # right before the write.

        exit_code = _run(args, mf, out, cmd_label)
    except BaseException:
        if _tee is not None:
            _tee.abandon()
            sys.stdout = _tee_stdout
        raise
    else:
        if _tee is not None:
            sys.stdout = _tee_stdout
            txt_path, summary = _tee.finalize()
            print(DIM(f"  [·] TXT  written → {txt_path}  ({summary})"))

    if exit_code:
        sys.exit(exit_code)


def _run(args, mf, out, cmd_label) -> "int | None":
    """Returns the process exit code for the six v2-routed recon commands
    (EXIT_OK/EXIT_PARTIAL — see module docstring), or None for every other
    command (unchanged exit-code behavior: 0 on completion, an uncaught
    exception's default nonzero exit on a fatal error)."""
    exit_code = None

    def _apply_v2_result(kind, records, coverage_status, coverage_reasons):
        if out:
            out.set_result(kind, records, coverage_status, coverage_reasons)
        return EXIT_PARTIAL if coverage_status == "partial" else EXIT_OK

    if args.list:
        exit_code = _apply_v2_result("memory_regions", *cmd_list(mf, args.filter))
    elif args.modules:
        exit_code = _apply_v2_result("modules", *cmd_modules(mf))
    elif args.threads:
        exit_code = _apply_v2_result("threads", *cmd_threads(mf))
    elif args.peb:
        exit_code = _apply_v2_result("peb", *cmd_peb(mf))
    elif args.pid:
        exit_code = _apply_v2_result("pid", *cmd_pid(mf))
    elif args.sysinfo:
        exit_code = _apply_v2_result("sysinfo", *cmd_sysinfo(mf))
    elif args.report:
        if not args.report_tid and not args.report_addr and not args.report_string:
            print(RED("[!] --report requires at least one of: --report-tid, --report-addr, --report-string"))
            sys.exit(1)
        cmd_report(mf,
                  report_tid=args.report_tid,
                  report_addr=args.report_addr,
                  report_string=args.report_string,
                  extract_to=args.output,
                  min_len=args.min_len,
                  force=args.force)
    elif args.hunt:
        data = cmd_hunt(mf, args.hunt, verbose=args.verbose, yara_dir=args.yara_dir,
                        ref_dir=args.ref_dir)
        if out and data: out.add("hunt", data)
    elif args.diff:         cmd_diff(mf, args.diff, args.diff_mode, verbose=args.verbose)

    elif args.extract:
        addr = parse_hex_or_int(args.extract)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_extract(mf, addr, size, args.output, auto_size=_req is None, force=args.force)

    elif args.strings:
        addr = parse_hex_or_int(args.strings)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        cmd_strings(mf, addr, size, args.min_len, args.grep, args.encoding, auto_size=_req is None)

    # ── Write structured output ────────────────────────────────────────────
    if out:
        if isinstance(out, V2Output):
            if args.json:
                out.write_json(args.json, cmd_label=cmd_label, force=args.force)
            if args.csv:
                out.write_csv(args.csv,  cmd_label=cmd_label, force=args.force)
        elif out._sections:
            if args.json:
                out.write_json(args.json, cmd_label=cmd_label, force=args.force)
            if args.csv:
                out.write_csv(args.csv,  cmd_label=cmd_label, force=args.force)
        else:
            print(DIM("  [~] --json/--csv: this command does not produce structured output."))

    return exit_code

