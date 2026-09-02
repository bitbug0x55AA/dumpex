"""Unit tests for dumpex.hunt._rescan_command -- the `--hunt-addr` command an
eligible investigation-queue entry hands the analyst.

Every action here is built by the real `build_investigation_queue()` over
synthetic `HunterRecord`/`ScanTarget`/`CoverageLimitation` input (the helpers
tests/hunt/test_investigation.py already owns), so eligibility, deduplication,
and capability filtering are exercised end to end rather than hand-asserted on a
constructed `RecommendedAction`.
"""
import os
import shlex
import shutil
import subprocess
import sys

import pytest

from dumpex.hunt import _registry
from dumpex.hunt._investigation import (
    InvestigationAction, RecommendedAction, SkipRelationship, TriageInfo,
    build_investigation_queue,
)
from dumpex.hunt._rescan_command import (
    PROGRAM_NAME, RescanCommand, UnrenderableArgument, build_rescan_commands,
    is_renderable_argument, quote_argument, unsupported_rescan_hunters,
)
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, CoverageStatus, LimitationCode,
    ScanTarget, ScanTargetKind,
)
from dumpex.output.records import HUNTERS, HunterRecord, InjectionDetails

from tests.hunt.test_investigation import (
    _pipe_budget_limitation, limitation, obfuscation_record, pipe_record, target,
)


DUMP = "/cases/incident.dmp"


def injection_record_with(limitations):
    """An injection record carrying real coverage limitations -- injection has
    no targeted capability, which is the point of every case that uses it."""
    details = InjectionDetails(
        rwx=[], hidden_pe_validated=[], hidden_pe_unvalidated=[],
        suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
        threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[],
        rip_hits=[], rip_full_correlation=[], start_hits=[])
    return HunterRecord(
        hunter="injection", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0, max_score=3,
        verdict_level="clean", confidence="none", lead_count=0, review_priority="none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def one_action(records):
    actions = build_investigation_queue(records, [])
    assert len(actions) == 1
    return actions[0]


def ceiling(hunter: str) -> int:
    return _registry.REGISTRY.get(hunter).targeted_capability.request_ceiling


# ── argument quoting: real shells, not a model of them ───────────────────
# Every rule in `_rescan_command` about what double quotes do -- and about what
# they fail to do -- is checked by running a rendered token through a real
# POSIX shell, a real PowerShell, and a real cmd.exe and comparing the argv the
# program actually received. A hand-written expectation about shell parsing is
# exactly the thing that was wrong before these existed.
#
# Each shell is skipped when absent, so a Linux CI runner exercises `sh` alone
# and a Windows runner exercises all three. The tests below never assert "this
# path is quoted like so"; they assert the only property that matters -- the
# program receives the path that was passed, byte for byte, or no command line
# was produced at all.

_ARGV_ECHO = "import sys\nsys.stdout.buffer.write(sys.argv[1].encode('utf-8'))\n"

# Set in the child environment of every shell run. A rendered token that let a
# shell expand a variable would come back carrying this value instead of the
# literal text, which is the failure the hostile-path cases below are for.
_EXPANSION_MARKER = "EXPANDED-BY-THE-SHELL"

_SHELLS = ("sh", "powershell", "cmd")


def _shell_executable(shell):
    if shell == "powershell":
        return shutil.which("pwsh") or shutil.which("powershell")
    return shutil.which(shell)


def _script_for(shell, tmp_path, line):
    """The command line written to a file the shell then runs -- the same thing
    an analyst does by pasting it. Passing it through `subprocess` as an
    argument list instead would re-quote it under MSVC rules on Windows and
    measure that quoting rather than ours."""
    if shell == "sh":
        path = tmp_path / "run.sh"
        path.write_bytes((line + "\n").encode("utf-8"))
        return [_shell_executable(shell), str(path)]
    if shell == "powershell":
        path = tmp_path / "run.ps1"
        # `&` is the call operator: PowerShell needs it when a command name is
        # quoted, which the interpreter path here may well be. A rendered
        # dumpex command starts with a bare program name and needs no such
        # prefix, so this is a property of the harness, not of what is rendered.
        path.write_text("& " + line + "\n", encoding="utf-8")
        return [_shell_executable(shell), "-NoProfile", "-NonInteractive", "-File", str(path)]
    path = tmp_path / "run.bat"
    path.write_text("@echo off\n" + line + "\n", encoding="utf-8")
    return [_shell_executable(shell), "/d", "/c", str(path)]


def _received_argument(shell, tmp_path, path):
    """The argv[1] a program actually receives when `path` is rendered by
    `quote_argument()` into a command line this shell runs."""
    echo = tmp_path / "argv_echo.py"
    echo.write_text(_ARGV_ECHO, encoding="utf-8")
    for token in (sys.executable, str(echo)):
        if not is_renderable_argument(token):
            pytest.skip(f"the test harness's own path is unrenderable: {token!r}")
    line = " ".join(quote_argument(a) for a in (sys.executable, str(echo), path))
    env = dict(os.environ, DEMO_RESCAN=_EXPANSION_MARKER, DUMPEX_DEMO=_EXPANSION_MARKER,
               # An MSYS/Cygwin `sh` on Windows rewrites POSIX-looking path
               # arguments into Windows paths on the way to a native program.
               # That interop layer runs after the shell has finished parsing,
               # so it measures neither our quoting nor the shell's -- switch it
               # off. Both names are no-ops on a real POSIX system.
               MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    completed = subprocess.run(_script_for(shell, tmp_path, line),
                               capture_output=True, env=env)
    assert completed.returncode == 0, (
        f"{shell} refused the rendered line {line!r}: "
        f"{completed.stderr.decode('utf-8', 'replace')[:400]}")
    return completed.stdout.decode("utf-8")


@pytest.fixture(params=_SHELLS)
def shell(request):
    if _shell_executable(request.param) is None:
        pytest.skip(f"{request.param} is not available on this platform")
    return request.param


# Paths that are legal on at least one supported platform and exercise a
# character class the quoting rules reason about. Which of them are renderable
# is the rules' answer, not this list's -- see the round-trip test below.
_PATHS = [
    pytest.param("/cases/incident.dmp", id="plain-posix"),
    pytest.param(r"C:\cases\incident.dmp", id="windows-backslashes"),
    pytest.param(r"C:\Program Files\case 7.dmp", id="spaces"),
    pytest.param("/cases/it's here/a.dmp", id="single-quote"),
    pytest.param("/cases/a&b(c);d/a.dmp", id="cmd-metacharacters"),
    pytest.param("/cases/a,b=c@d+e/a.dmp", id="powershell-operators"),
    pytest.param("/cases/[x]{y}~z#w/a.dmp", id="globs-and-braces"),
    pytest.param("/cases/a^b/a.dmp", id="cmd-escape-character"),
    pytest.param(r"C:\cases\%DEMO_RESCAN%\incident.dmp", id="cmd-variable"),
    pytest.param(r"C:\cases\$env:DUMPEX_DEMO\incident.dmp", id="powershell-variable"),
    pytest.param("/cases/$DEMO_RESCAN/incident.dmp", id="posix-variable"),
    pytest.param("/cases/$(id)/incident.dmp", id="posix-command-substitution"),
    pytest.param("/cases/`id`/incident.dmp", id="backtick-substitution"),
    pytest.param("/cases/!DEMO_RESCAN!/incident.dmp", id="cmd-delayed-expansion"),
    pytest.param(r"\\server\share\incident.dmp", id="unc-doubled-backslash"),
    pytest.param("C:\\cases\\dir\\", id="trailing-backslash"),
    pytest.param('/cases/od"d/incident.dmp', id="embedded-double-quote"),
    pytest.param("/cases/esc\x1b[31m/incident.dmp", id="control-character"),
]


@pytest.mark.parametrize("path", _PATHS)
def test_a_rendered_path_either_is_refused_or_reaches_the_program_unchanged(
        shell, tmp_path, path):
    """The whole contract, per shell, in one assertion: `quote_argument()` may
    refuse a path, but anything it does render must arrive at the program
    exactly as it went in. A path that expands, splits, or executes fails here
    rather than sending an analyst to rescan the wrong dump."""
    if not is_renderable_argument(path):
        with pytest.raises(UnrenderableArgument):
            quote_argument(path)
        return
    received = _received_argument(shell, tmp_path, path)
    assert received == path
    assert _EXPANSION_MARKER not in received


@pytest.mark.parametrize("path", [
    pytest.param(r"C:\cases\%DEMO_RESCAN%\incident.dmp", id="cmd-variable"),
    pytest.param(r"C:\cases\$env:DUMPEX_DEMO\incident.dmp", id="powershell-variable"),
    pytest.param("/cases/$DEMO_RESCAN/incident.dmp", id="posix-variable"),
    pytest.param("/cases/$(id)/incident.dmp", id="posix-command-substitution"),
    pytest.param("/cases/`id`/incident.dmp", id="backtick-substitution"),
    pytest.param("/cases/!DEMO_RESCAN!/incident.dmp", id="cmd-delayed-expansion"),
    pytest.param(r"\\server\share\incident.dmp", id="unc-doubled-backslash"),
    pytest.param("C:\\cases\\dir\\", id="trailing-backslash"),
    pytest.param('/cases/od"d/incident.dmp', id="embedded-double-quote"),
    pytest.param("/cases/esc\x1b[31m/incident.dmp", id="control-character"),
    pytest.param("", id="empty"),
])
def test_a_path_no_quoting_rule_can_carry_is_refused_outright(path):
    """Named explicitly, so widening the safe set has to delete a case here
    rather than quietly start emitting one of these."""
    assert not is_renderable_argument(path)
    with pytest.raises(UnrenderableArgument):
        quote_argument(path)


def test_an_ordinary_posix_path_is_rendered_bare():
    assert quote_argument("/cases/incident.dmp") == "/cases/incident.dmp"


def test_a_windows_path_is_quoted_because_a_posix_shell_eats_bare_backslashes():
    """Unquoted, `C:\\cases\\a.dmp` reaches a program as `C:casesa.dmp`."""
    assert quote_argument(r"C:\cases\a.dmp") == '"' + r"C:\cases\a.dmp" + '"'


def test_a_control_character_is_refused_rather_than_stripped():
    """Replacing the character would produce a command naming a different file,
    which is a worse outcome than producing no command."""
    assert not is_renderable_argument("case\x1b[31m.dmp")
    with pytest.raises(UnrenderableArgument):
        quote_argument("case\x1b[31m.dmp")


def test_a_quoted_path_survives_as_one_argument_under_posix_word_splitting():
    path = r"/cases/two words/incident.dmp"
    command = RescanCommand(hunter="pipe", dump_path=path, base_address=0x1000,
                            size=0x2000, target_size=0x2000)
    assert shlex.split(command.render()) == list(command.argv)


# ── command shape ────────────────────────────────────────────────────────

def test_the_rendered_command_is_a_single_copyable_invocation():
    command = RescanCommand(hunter="yara", dump_path=DUMP, base_address=0x7ff000,
                            size=0x100000, target_size=0x100000)
    assert command.render() == (
        f"{PROGRAM_NAME} {DUMP} --hunt yara --hunt-addr 0x7ff000 --size 0x100000")
    assert "\n" not in command.render()


def test_the_command_carries_the_registrys_own_source_for_its_hunter():
    for hunter in _registry.REGISTRY.targeted_identities():
        command = RescanCommand(hunter=hunter, dump_path=DUMP, base_address=0x1000,
                                size=0x1000, target_size=0x1000)
        assert command.source == _registry.REGISTRY.targeted_source(hunter)


@pytest.mark.parametrize("field,value", [
    ("hunter", "not-a-hunter"),
    ("dump_path", ""),
    ("size", 0),
    ("base_address", -1),
    ("size", True),
])
def test_a_malformed_command_is_refused(field, value):
    kwargs = dict(hunter="pipe", dump_path=DUMP, base_address=0x1000,
                  size=0x1000, target_size=0x1000)
    kwargs[field] = value
    with pytest.raises(ValueError):
        RescanCommand(**kwargs)


def test_a_command_never_asks_for_more_than_its_own_target():
    with pytest.raises(ValueError):
        RescanCommand(hunter="pipe", dump_path=DUMP, base_address=0x1000,
                      size=0x2000, target_size=0x1000)


# ── eligibility ──────────────────────────────────────────────────────────

def test_one_command_per_supported_skipping_hunter_in_hunters_order():
    t = target(base=0x12000, size=0x40000, size_limit=0x8000)
    action = one_action([
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
        pipe_record([limitation("pipe_name_scan", [t])]),
    ])
    commands = build_rescan_commands(action, DUMP)
    assert [c.hunter for c in commands] == ["pipe", "obfuscation"]
    assert [c.base_address for c in commands] == [0x12000, 0x12000]
    assert [c.size for c in commands] == [0x40000, 0x40000]


def test_one_pipe_target_carrying_both_relationships_renders_one_pipe_command():
    """`pipe_name` and `c2_context` exhausting the same budget over the same
    physical region are two relationships and one range: the analyst runs one
    pipe rescan, whose result is then reconciled against both."""
    t = target(base=0xB000, size=0x1000, size_limit=None, type_="MEM_MAPPED",
               protection="PAGE_READWRITE")
    action = one_action([pipe_record([
        _pipe_budget_limitation("c2_context", [t]),
        _pipe_budget_limitation("pipe_name", [t]),
    ])])
    assert sorted(rel.scope for rel in action.skipped_by) == ["c2_context", "pipe_name"]
    commands = build_rescan_commands(action, DUMP)
    assert [c.hunter for c in commands] == ["pipe"]
    assert commands[0].render().count("--hunt ") == 1


def test_a_reason_only_budget_limitation_fabricates_no_command():
    """A limitation naming a spent budget but no target contributes no queue
    entry, so there is nothing to synthesize a command from."""
    reason_only = CoverageLimitation(
        code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
        scope="c2_context", detail="deadline")
    assert build_investigation_queue([pipe_record([reason_only])], []) == []


def test_a_target_whose_bytes_are_not_captured_gets_no_command():
    t = target(base=0xF000, size=0x2000, size_limit=None, file_offset=None,
               type_="MEM_MAPPED", protection="PAGE_READWRITE")
    action = one_action([pipe_record([limitation(
        "pipe_name_scan", [t], code=LimitationCode.SCAN_REGION_READ_FAILED)])])
    assert action.evidence_availability == "not_captured"
    assert build_rescan_commands(action, DUMP) == ()
    assert "recollect_dump" in [a.type for a in action.recommended_actions]
    assert "targeted_hunter_rescan" not in [a.type for a in action.recommended_actions]


def test_a_partially_captured_target_still_gets_a_command_and_a_recollect():
    """A short read leaves a real prefix in this dump: the rescan is worth
    running over what IS here, and recollection is still the only way to see
    the rest."""
    t = target(base=0x20000, size=0x4000, size_limit=None, captured_size=0x1000,
               type_="MEM_MAPPED", protection="PAGE_READWRITE")
    action = one_action([pipe_record([limitation(
        "pipe_name_scan", [t], code=LimitationCode.SCAN_REGION_SHORT_READ)])])
    assert action.evidence_availability == "partial"
    assert [c.hunter for c in build_rescan_commands(action, DUMP)] == ["pipe"]
    assert "recollect_dump" in [a.type for a in action.recommended_actions]


def test_a_hunter_with_no_targeted_capability_is_named_rather_than_commanded():
    t = target(base=0x40000, size=0x100000, size_limit=0x80000, type_="MEM_MAPPED",
               protection="PAGE_READWRITE")
    action = one_action([
        injection_record_with([limitation("hidden_pe_scan", [t])]),
        pipe_record([limitation("pipe_name_scan", [t])]),
    ])
    assert [c.hunter for c in build_rescan_commands(action, DUMP)] == ["pipe"]
    assert unsupported_rescan_hunters(action) == ("injection",)


def test_an_action_skipped_only_by_unsupported_hunters_carries_no_rescan_action():
    t = target(base=0x50000, size=0x100000, size_limit=0x80000, type_="MEM_MAPPED",
               protection="PAGE_READWRITE")
    action = one_action([injection_record_with([limitation("hidden_pe_scan", [t])])])
    assert build_rescan_commands(action, DUMP) == ()
    assert "targeted_hunter_rescan" not in [a.type for a in action.recommended_actions]
    assert unsupported_rescan_hunters(action) == ("injection",)


def test_unsupported_hunters_are_reported_in_hunters_order():
    action = InvestigationAction(
        target=ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=0x1000, size=0x1000,
                          size_limit=0x800, file_offset=1, allocation_base=0x1000,
                          state="MEM_COMMIT", type="MEM_PRIVATE", protection="PAGE_READWRITE"),
        skipped_by=(
            SkipRelationship(hunter="hollowing", source="pe_header_scan", size_limit=0x800),
            SkipRelationship(hunter="injection", source="hidden_pe_scan", size_limit=0x800),
        ),
        priority="low", priority_reason_codes=(), evidence_availability="captured",
        triage=TriageInfo(),
        recommended_actions=(RecommendedAction(type="inspect_metadata"),))
    assert unsupported_rescan_hunters(action) == ("injection", "hollowing")
    assert unsupported_rescan_hunters(action) == tuple(
        h for h in HUNTERS if h in ("injection", "hollowing"))


def test_every_commanded_hunter_is_one_the_registry_grants():
    t = target(base=0x60000, size=0x8000, size_limit=0x4000)
    action = one_action([
        injection_record_with([limitation("hidden_pe_scan", [t])]),
        pipe_record([limitation("pipe_name_scan", [t])]),
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
    ])
    granted = set(_registry.REGISTRY.targeted_identities())
    assert {c.hunter for c in build_rescan_commands(action, DUMP)} <= granted


# ── request ceiling / chunking ───────────────────────────────────────────

def test_a_target_within_the_ceiling_is_commanded_whole():
    t = target(base=0x70000, size=0x8000, size_limit=0x4000)
    action = one_action([pipe_record([limitation("pipe_name_scan", [t])])])
    command = build_rescan_commands(action, DUMP)[0]
    assert command.size == 0x8000
    assert command.capped is False


def test_a_target_over_the_ceiling_is_capped_to_the_registrys_own_ceiling():
    oversized = ceiling("obfuscation") * 2
    t = target(base=0x80000, size=oversized, size_limit=0x1000)
    action = one_action([
        pipe_record([limitation("pipe_name_scan", [t])]),
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
    ])
    by_hunter = {c.hunter: c for c in build_rescan_commands(action, DUMP)}
    assert by_hunter["obfuscation"].size == ceiling("obfuscation")
    assert by_hunter["obfuscation"].capped is True
    assert by_hunter["obfuscation"].target_size == oversized
    # pipe's own ceiling is larger, and each analyzer is capped by its own.
    assert by_hunter["pipe"].size == min(oversized, ceiling("pipe"))


def test_a_capped_command_never_promises_the_whole_target():
    oversized = ceiling("obfuscation") + 1
    t = target(base=0x90000, size=oversized, size_limit=0x1000)
    action = one_action([obfuscation_record([
        limitation("encoding_scan", [t], scope="entropy")])])
    command = build_rescan_commands(action, DUMP)[0]
    assert command.size < command.target_size
    assert f"--size 0x{ceiling('obfuscation'):x}" in command.render()
    # The queue entry's own coverage effect is unchanged by offering one.
    assert action.coverage_effect == "original_hunter_gap_not_resolved"


def test_no_synthesized_size_ever_exceeds_its_analyzers_ceiling():
    """Every command this module emits is one the CLI would accept: the
    request-ceiling refusal in `cli.main()` is keyed on the same registry
    value."""
    huge = max(ceiling(h) for h in _registry.REGISTRY.targeted_identities()) * 4
    t = target(base=0xA0000, size=huge, size_limit=0x1000)
    action = one_action([
        pipe_record([limitation("pipe_name_scan", [t])]),
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
    ])
    for command in build_rescan_commands(action, DUMP):
        assert 0 < command.size <= ceiling(command.hunter)


# ── input validation ─────────────────────────────────────────────────────

def test_the_builders_reject_anything_that_is_not_an_investigation_action():
    with pytest.raises(TypeError):
        build_rescan_commands({"target": None}, DUMP)
    with pytest.raises(TypeError):
        unsupported_rescan_hunters({"skipped_by": ()})


# ── the registry is the only capability catalog ──────────────────────────

def test_the_capable_roster_is_read_from_the_registry_not_a_local_list(monkeypatch):
    """Neither the queue nor the command builder keeps a hunter allowlist: a
    registry that grants nothing produces no rescan recommendation and no
    command, for hunters that are targeted-capable in the shipped registry."""
    monkeypatch.setattr(_registry.REGISTRY, "targeted_identities", lambda: ())
    t = target(base=0xC0000, size=0x8000, size_limit=0x4000)
    action = one_action([
        pipe_record([limitation("pipe_name_scan", [t])]),
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
    ])
    assert "targeted_hunter_rescan" not in [a.type for a in action.recommended_actions]
    assert build_rescan_commands(action, DUMP) == ()
    assert unsupported_rescan_hunters(action) == ("pipe", "obfuscation")


def test_withdrawing_one_grant_moves_only_that_hunter_to_unsupported(monkeypatch):
    """A future analyzer that registers without a targeted grant -- and any
    existing one whose grant is withdrawn -- is named as unsupported and given
    no command, while every still-granted hunter is unaffected."""
    remaining = tuple(h for h in _registry.REGISTRY.targeted_identities() if h != "obfuscation")
    monkeypatch.setattr(_registry.REGISTRY, "targeted_identities", lambda: remaining)
    t = target(base=0xD0000, size=0x8000, size_limit=0x4000)
    action = one_action([
        pipe_record([limitation("pipe_name_scan", [t])]),
        obfuscation_record([limitation("encoding_scan", [t], scope="entropy")]),
    ])
    assert [c.hunter for c in build_rescan_commands(action, DUMP)] == ["pipe"]
    assert unsupported_rescan_hunters(action) == ("obfuscation",)


def test_no_hunter_name_is_written_down_in_the_command_module():
    """The roster lives in `dumpex.output.records.HUNTERS` and the capability in
    the analyzer registry. A literal hunter name here would be a second, silently
    drifting catalog."""
    import pathlib
    import dumpex.hunt._rescan_command as module

    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#"))
    for hunter in HUNTERS:
        assert f'"{hunter}"' not in code and f"'{hunter}'" not in code, hunter
