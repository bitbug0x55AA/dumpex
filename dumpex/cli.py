"""Command-line entry point."""
import os
import sys
import argparse
import datetime
from minidump.minidumpfile import MinidumpFile

from dumpex.ui.colors import RED, DIM, BOLD
from dumpex.core.memory import open_dump, parse_hex_or_int, _resolve_size
from dumpex.rules_pkg.loader import get_rules, configure_rules_source
from dumpex.ui.structured import _ANSI_RE
from dumpex.output import V2Output
from dumpex.output.envelope import EvidenceInput
from dumpex.output.coverage import EXIT_OK, EXIT_PARTIAL, EXIT_NOT_EVALUATED, exit_code_for
from dumpex.core.safe_io import check_not_dump_path, check_no_output_collisions, AtomicTextTee

from dumpex.commands.list_cmd import cmd_list
from dumpex.commands.modules  import cmd_modules
from dumpex.commands.threads  import cmd_threads
from dumpex.commands.extract  import cmd_extract, cmd_strings
from dumpex.commands.peb      import cmd_peb
from dumpex.commands.sysinfo  import cmd_sysinfo, cmd_pid
from dumpex.commands.report   import cmd_report
from dumpex.commands.diff     import cmd_diff
from dumpex.hunt              import cmd_hunt
from dumpex.hunt.summary      import build_hunt_summary
from dumpex.hunt              import _hunt_coverage_report
from dumpex.output.command_result import CommandResult

# ── v2 structured-output routing ────────────────────────────────────────
# All eleven commands are migrated onto the v2 envelope (see dumpex/output/
# and dumpex-output-v2.5.schema.json); --diff produces a kind="comparison"
# result via V2Output.from_evidence() (two dumps), --report produces a
# kind="report" result (one TriageCardRecord per triage card -- see
# dumpex.commands.report's own module docstring), --hunt produces a
# kind="hunt" result (one HunterRecord per selected TTP -- see
# dumpex.hunt.cmd_hunt()'s own collect_records= docstring), the other
# eight produce their usual single-dump kinds.
_V2_STRUCTURED_MODES = frozenset({"list", "modules", "threads", "pid", "sysinfo", "peb", "diff",
                                    "extract", "strings", "report", "hunt"})

# Exit codes for all eleven v2-routed commands, independent of
# --json/--csv having been requested at all: a SOC script checking `$?`
# on a bare `dumpex --threads dump.dmp` should be able to detect
# incomplete coverage without needing to also parse JSON. `--hunt` uses
# this same convention too -- its exit code is derived from
# `result.coverage.status`, the document-level rollup dumpex.hunt.
# _hunt_coverage_report() builds from every selected hunter's own
# HunterRecord.coverage (see that function's own docstring for why it
# can't just read summary.overall_status's DETECTED/INCONCLUSIVE/... counts
# alone). Every command NOT in _V2_STRUCTURED_MODES keeps its
# exit-code behavior unchanged (0 on completion, an uncaught exception's
# default nonzero exit on a fatal error).
#
# EXIT_OK/EXIT_PARTIAL/EXIT_NOT_EVALUATED and the status->code mapping
# itself (exit_code_for) live in dumpex.output.coverage, not here --
# that's the single place a coverage status becomes a process exit code,
# used by _apply_command_result() below for all eleven of these commands.


def _selected_run_mode(args) -> str:
    """The single mode flag argparse's mutually_exclusive_group(required=True)
    guarantees is set, as a plain string key into _V2_STRUCTURED_MODES --
    kept separate from _cmd_label() below, which returns a filename-oriented
    label (e.g. "hunt_all", "tid_1234"), not a bare mode name."""
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

    command_group = parser.add_argument_group(
        "commands", "Choose exactly one operation for the primary dump.")
    mode = command_group.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list",         action="store_true", help="List all memory regions")
    mode.add_argument("--modules",      action="store_true", help="List loaded modules")
    mode.add_argument("--threads",      action="store_true", help="List threads with analysis")
    mode.add_argument("--extract",      metavar="ADDR",      help="Extract raw bytes at address")
    mode.add_argument("--strings",      metavar="ADDR",      help="Extract strings at address")
    mode.add_argument("--peb",          action="store_true", help="Show PEB info")
    mode.add_argument("--pid",          action="store_true", help="Show the Process ID recorded in the dump")
    mode.add_argument("--sysinfo",      action="store_true", help="Show OS, host, process and CPU summary")
    mode.add_argument("--diff",         metavar="REFERENCE", help="Compare the primary dump against a reference .DMP file")
    mode.add_argument("--report",        action="store_true", help="Generate triage report anchored to a TID, address, or string")
    mode.add_argument("--hunt",          metavar="TTP",       help="TTP detection: injection | hollowing | stomping | pipe | cs-beacon | yara | obfuscation | all")

    region_group = parser.add_argument_group("memory and extraction options")
    region_group.add_argument("--filter", metavar="PROT",
                              help="Filter --list by protection name")
    region_group.add_argument("-s", "--size", metavar="SIZE",
                              help="Region size in hex for --extract or --strings")
    region_group.add_argument("-o", "--output", metavar="FILE",
                              help="Extracted bytes for --extract, or region output for --report")

    strings_group = parser.add_argument_group("string scan options")
    strings_group.add_argument("--grep", metavar="REGEX",
                               help="Regex filter for --strings")
    strings_group.add_argument("--min-len", metavar="N", type=int, default=6,
                               help="Minimum string length for --strings (default: 6)")
    strings_group.add_argument("--strings-encoding", dest="encoding",
                               choices=["ascii", "unicode", "both"], default="both",
                               help="Encoding scanned by --strings (default: both)")
    # Hidden compatibility spelling; --strings-encoding is deliberately
    # explicit that this modifies --strings rather than starting a command.
    parser.add_argument("--encoding", dest="encoding",
                        choices=["ascii", "unicode", "both"],
                        help=argparse.SUPPRESS)

    diff_group = parser.add_argument_group("diff options")
    diff_group.add_argument("--diff-scope", dest="diff_mode",
                            choices=["modules", "threads", "memory", "all"],
                            default="all",
                            help="Evidence type compared by --diff (default: all)")
    # Backward-compatible spelling for scripts written before the option
    # was clarified as a scope/filter rather than a standalone command.
    parser.add_argument("--diff-mode", dest="diff_mode",
                        choices=["modules", "threads", "memory", "all"],
                        help=argparse.SUPPRESS)

    display_group = parser.add_argument_group("display options")
    display_group.add_argument('--verbose', action='store_true',
                               help='Show additional detail for --diff or --hunt')

    hunt_group = parser.add_argument_group("hunt options")
    hunt_group.add_argument('--yara-dir', metavar='DIR', default=None,
                            help='Rule directory for --hunt yara (default: packaged rules)')
    hunt_group.add_argument('--ref-dir', metavar='DIR', default=None,
                            help='Reference-module directory for --hunt stomping')
    hunt_group.add_argument('--rules-file', metavar='FILE', default=None,
                            help='Explicit rules.yaml/.yml/.json for --hunt')

    report_group = parser.add_argument_group("report options")
    report_group.add_argument('--report-tid', metavar='TID',
                              help='Anchor --report to this Thread ID (hex or decimal)')
    report_group.add_argument('--report-addr', metavar='ADDR',
                              help='Anchor --report to this memory address (hex)')
    report_group.add_argument('--report-string', metavar='STRING',
                              help='Search memory and report each matching region')

    output_group = parser.add_argument_group("output and case metadata")
    output_group.add_argument('--json', metavar='FILE', default=None,
                              help='Write structured results as JSON')
    output_group.add_argument('--csv', metavar='PATH', default=None,
                              help='Write CSV to a file, or separate tables to a directory')
    output_group.add_argument('--txt', metavar='FILE', default=None,
                              help='Write a plain-text copy of console output')
    output_group.add_argument('--force', action='store_true',
                              help='Allow overwriting output files (never input dumps)')
    output_group.add_argument('--case-id', metavar='ID', default=None,
                              help='Case/ticket identifier recorded in structured output')
    output_group.add_argument('--analyst', metavar='NAME', default=None,
                              help='Analyst name recorded in structured output')
    output_group.add_argument('--redact-paths', action='store_true',
                              help='Reduce filesystem paths to basenames in structured output')
    args = parser.parse_args()

    run_mode = _selected_run_mode(args)

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
    dump_paths = [args.dumpfile] + ([args.diff] if args.diff else [])
    for out_arg, label in ((args.txt, "--txt"), (args.output, "--output"),
                            (args.json, "--json"), (args.csv, "--csv")):
        if out_arg:
            check_not_dump_path(out_arg, dump_paths, label)

    # This run's own output targets must not collide with EACH OTHER
    # either -- e.g. `--extract 0x1000 --output same.out --json same.out
    # --force` would otherwise let the later --json write silently
    # clobber the just-written extract output (see
    # safe_io.check_no_output_collisions's own docstring). Includes
    # --extract's own auto-generated default filename when --output isn't
    # given, so that collision is caught here too, before the dump is
    # even opened -- not just when both are given explicitly.
    _extract_default_output = None
    if args.extract and not args.output:
        try:
            _extract_default_output = f"region_0x{parse_hex_or_int(args.extract):x}.bin"
        except ValueError:
            pass   # malformed --extract value -- surfaces at its usual place in _run()
    check_no_output_collisions([
        (args.output, "--output"),
        (_extract_default_output, "--extract's default output filename"),
        (args.json, "--json"),
        (args.csv, "--csv"),
        (args.txt, "--txt"),
    ])

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
        if args.extract:
            opts["output"] = args.output
        if args.report:
            opts["report_tid"] = args.report_tid
            opts["report_addr"] = args.report_addr
            opts["report_string"] = args.report_string
            opts["min_len"] = args.min_len
            opts["output"] = args.output
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
        mf        = open_dump(args.dumpfile)
        # Only --diff opens a second dump. If BOTH args.dumpfile and
        # args.diff are bad, only the primary's parse error surfaces here
        # (it's opened first) -- consistent with every other command's
        # single-error-then-exit behavior, not an oversight.
        mf_reference = open_dump(args.diff) if run_mode == "diff" else None

        # Structured output collector — populated by commands that support
        # it. Every v2-routed command (including --hunt) always gets a
        # V2Output (built regardless of --json/--csv, so the exit-code
        # contract below is consistent whether or not structured output was
        # actually written). run_mode is always in _V2_STRUCTURED_MODES
        # (argparse's mode group guarantees exactly one of the eleven flags
        # above is set, and all eleven are v2-routed) — diff just needs its
        # own two-evidence constructor.
        if run_mode == "diff":
            out = V2Output.from_evidence(
                [EvidenceInput(id="baseline", role="baseline", path=args.diff),
                 EvidenceInput(id="target", role="target", path=args.dumpfile)],
                command=cmd_label, options=_build_options(), case_id=args.case_id,
                analyst=args.analyst, redact_paths=args.redact_paths, started_at=started_at)
        else:
            out = V2Output(args.dumpfile, mf, command=cmd_label, options=_build_options(),
                            case_id=args.case_id, analyst=args.analyst,
                            redact_paths=args.redact_paths, started_at=started_at)

        # --json/--csv path resolution (existing-file / dump-path / dir-mode
        # collision handling) is owned entirely by V2Output.write_json /
        # write_csv (via commit_output) — not duplicated here. Likewise
        # --output is checked exactly once, inside cmd_extract/cmd_report
        # right before the write.

        exit_code = _run(args, mf, out, cmd_label, mf_reference=mf_reference)
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


def _run(args, mf, out, cmd_label, *, mf_reference=None) -> "int | None":
    """Returns the process exit code for all eleven v2-routed commands
    (EXIT_OK/EXIT_PARTIAL/EXIT_NOT_EVALUATED — see module docstring), or
    None for every other command (unchanged exit-code behavior: 0 on
    completion, an uncaught exception's default nonzero exit on a fatal
    error)."""
    exit_code = None

    def _apply_command_result(result):
        """CommandResult-based path -- all eleven v2-routed commands
        are migrated onto dumpex.output.coverage/.command_result (see
        those modules). Routed through set_command_result(), which
        forwards every CommandResult field (execution_status, structured
        coverage, diagnostics, artifacts)."""
        if out:
            out.set_command_result(result)
        return exit_code_for(result.coverage.status)

    if args.list:
        exit_code = _apply_command_result(cmd_list(mf, args.filter))
    elif args.modules:
        exit_code = _apply_command_result(cmd_modules(mf))
    elif args.threads:
        exit_code = _apply_command_result(cmd_threads(mf))
    elif args.peb:
        exit_code = _apply_command_result(cmd_peb(mf))
    elif args.pid:
        exit_code = _apply_command_result(cmd_pid(mf))
    elif args.sysinfo:
        exit_code = _apply_command_result(cmd_sysinfo(mf))
    elif args.report:
        if not args.report_tid and not args.report_addr and not args.report_string:
            print(RED("[!] --report requires at least one of: --report-tid, --report-addr, --report-string"))
            sys.exit(1)
        exit_code = _apply_command_result(
            cmd_report(mf, report_tid=args.report_tid, report_addr=args.report_addr,
                       report_string=args.report_string, extract_to=args.output,
                       min_len=args.min_len, force=args.force))
    elif args.hunt:
        # collect_records=True: cmd_hunt() builds each selected hunter's
        # Report exactly once and feeds it to BOTH the console renderer
        # (unchanged) and the v2.4 HunterRecord conversion below, in the
        # same call -- see cmd_hunt()'s own docstring. Calling cmd_hunt()
        # for console and dumpex.hunt.collect_hunt() separately for JSON
        # would scan every selected hunter twice.
        _, hunt_records = cmd_hunt(mf, args.hunt, verbose=args.verbose, yara_dir=args.yara_dir,
                                    ref_dir=args.ref_dir, collect_records=True)
        hunt_summary = build_hunt_summary(hunt_records, selected=args.hunt)
        exit_code = _apply_command_result(
            CommandResult(kind="hunt", records=hunt_records,
                          coverage=_hunt_coverage_report(hunt_records, hunt_summary),
                          summary=hunt_summary))
    elif args.diff:
        exit_code = _apply_command_result(
            cmd_diff(mf, mf_reference, args.diff_mode, verbose=args.verbose))

    elif args.extract:
        addr = parse_hex_or_int(args.extract)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        exit_code = _apply_command_result(
            cmd_extract(mf, addr, size, args.output, auto_size=_req is None, force=args.force))

    elif args.strings:
        addr = parse_hex_or_int(args.strings)
        _req = parse_hex_or_int(args.size) if args.size else None
        size = _resolve_size(mf, addr, _req)
        exit_code = _apply_command_result(
            cmd_strings(mf, addr, size, args.min_len, args.grep, args.encoding, auto_size=_req is None))

    # ── Write structured output ────────────────────────────────────────────
    # `out` is always a V2Output here (see its construction in main() above)
    # -- every v2-routed command produces structured output, so there's no
    # "this command doesn't support --json/--csv" case left to handle.
    if args.json:
        out.write_json(args.json, cmd_label=cmd_label, force=args.force)
    if args.csv:
        out.write_csv(args.csv, cmd_label=cmd_label, force=args.force)

    return exit_code
