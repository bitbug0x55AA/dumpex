"""Unit tests for dumpex.commands.threads's collect/render split.

collect_threads() returns a dumpex.output.command_result.CommandResult
(migrated onto the shared coverage core in dumpex.output.coverage --
see that module and dumpex.output.command_result); accessed via
attributes, never unpacked as a tuple. degraded/has_times -- extra
rendering context this command alone needs -- are derived via
thread_info_is_degraded()/thread_records_have_times() rather than
returned separately."""
from tests.fixtures.fakes import ThreadInfo, Thread, Ctx, Module, FakeStream, FakeMF

from dumpex.commands.threads import (
    collect_threads, render_threads_console, cmd_threads,
    thread_info_is_degraded, thread_records_have_times,
)
from dumpex.output.coverage import LimitationCode
from dumpex.output.records import (
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)


def test_collect_threads_normal_with_thread_info():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    result = collect_threads(mf)
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []
    assert thread_info_is_degraded(result.coverage) is False
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.tid == 1
    assert isinstance(rec.tid, int)
    assert rec.start_address == "0x000000007ffe0000"
    assert rec.module_context == MODULE_CONTEXT_RESOLVED
    assert rec.backing_module == "legit.dll"
    assert result.summary == {"count": 1}


def test_collect_threads_module_list_missing_is_unavailable_not_unregistered():
    # The false-signal bug this fixes: a missing ModuleListStream must
    # never render as a confirmed "not in any module" finding.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    # no mf.modules at all
    result = collect_threads(mf)
    assert result.coverage.status == "partial"
    assert result.records[0].module_context == MODULE_CONTEXT_UNAVAILABLE
    assert result.records[0].backing_module is None
    assert any("ModuleListStream" in r for r in result.coverage.reasons)


def test_collect_threads_confirmed_not_in_any_module_is_unregistered():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x140000000, 0x1000, "other.dll")], "modules")  # doesn't cover 0x7ffe0000
    result = collect_threads(mf)
    assert result.coverage.status == "complete"   # ModuleListStream WAS available; this is a confirmed answer
    assert result.records[0].module_context == MODULE_CONTEXT_UNREGISTERED
    assert result.records[0].backing_module is None


def test_collect_threads_degraded_is_partial():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info stream
    result = collect_threads(mf)
    assert result.coverage.status == "partial"
    assert thread_info_is_degraded(result.coverage) is True
    assert result.coverage.reasons and "ThreadInfoListStream" in result.coverage.reasons[0]
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.tid == 1
    assert rec.start_address is None
    assert rec.backing_module is None
    assert rec.create_time is None
    assert rec.suspend_count is None   # base ThreadListStream fixture has none set


def test_collect_threads_present_but_empty_streams_is_complete():
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    mf.thread_info = FakeStream([], "infos")
    mf.modules = FakeStream([], "modules")
    result = collect_threads(mf)
    assert result.records == []
    assert result.coverage.status == "complete"
    assert thread_info_is_degraded(result.coverage) is False


def test_collect_threads_base_absent_but_info_stream_present_empty_is_complete():
    # ThreadListStream is entirely absent, but ThreadInfoListStream IS
    # present and confirms there are genuinely zero threads -- nothing
    # was actually affected by ThreadListStream's absence (0 threads x
    # missing SuspendCount/Priority/TEB = no real gap), so this must be
    # 'complete', not 'partial' with a nonsensical "0 thread(s) present
    # in ThreadInfoListStream but missing from ThreadListStream" reason.
    mf = FakeMF()
    mf.thread_info = FakeStream([], "infos")
    mf.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    result = collect_threads(mf)
    assert result.records == []
    assert result.coverage.status == "complete"
    assert result.coverage.reasons == []


def test_collect_threads_neither_stream_present_is_not_evaluated():
    # Neither ThreadListStream nor ThreadInfoListStream present at all --
    # must not be indistinguishable from "complete, zero threads."
    result = collect_threads(FakeMF())
    assert result.records == []
    assert result.coverage.status == "not_evaluated"
    assert result.coverage.reasons == [
        "Neither ThreadListStream nor ThreadInfoListStream present in this dump"]


# ── dual-stream TID-set mismatch (collector) ──────────────────────────────

def test_collect_threads_info_stream_present_but_empty_does_not_drop_base_threads():
    # ThreadInfoListStream is present (not absent -> not the 'degraded'
    # path) but reports zero entries, while the base ThreadListStream has
    # real threads. Those threads must still be reported, with a gap.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0)), Thread(2, Ctx(0))], "threads")
    mf.thread_info = FakeStream([], "infos")
    mf.modules = FakeStream([], "modules")
    result = collect_threads(mf)
    assert thread_info_is_degraded(result.coverage) is False   # the stream itself isn't absent, just empty
    assert len(result.records) == 2
    assert result.coverage.status == "partial"
    assert any("missing from ThreadInfoListStream" in r for r in result.coverage.reasons)
    assert all(r.start_address is None for r in result.records)   # no ThreadInfo entry for either


def test_collect_threads_base_list_missing_info_stream_has_threads():
    # The reverse: ThreadInfoListStream has real entries but the base
    # ThreadListStream is entirely absent -- SuspendCount/Priority/TEB
    # must be unavailable, with a gap reported (not silently 'complete').
    mf = FakeMF()
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000), ThreadInfo(2, 0x7fff0000)], "infos")
    mf.modules = FakeStream([], "modules")
    result = collect_threads(mf)
    assert thread_info_is_degraded(result.coverage) is False   # ThreadInfoListStream itself IS present
    assert len(result.records) == 2
    assert result.coverage.status == "partial"
    assert any("missing from ThreadListStream" in r for r in result.coverage.reasons)
    assert all(r.suspend_count is None for r in result.records)

    # ThreadListStream is entirely ABSENT here, not merely partially
    # mismatched with a present ThreadInfoListStream -- the limitation's
    # code must say SOURCE_ABSENT (a real fact about the source itself,
    # discoverable by a consumer scanning for absent sources), not
    # SOURCE_KEY_MISMATCH (which would misrepresent a fully-absent source
    # as a partial disagreement between two present ones), even though
    # the rendered text is identical to what a genuine key mismatch would
    # produce.
    limitation = result.coverage.limitations[0]
    assert limitation.code == LimitationCode.SOURCE_ABSENT
    assert limitation.source == "threads"
    assert limitation.counterpart_source == "thread_info"
    assert limitation.affected_count == 2
    assert limitation.unavailable_fields == ("SuspendCount", "Priority", "TEB")
    assert result.coverage.sources["threads"].state == "absent"


def test_collect_threads_both_present_mismatched_tid_sets_are_unioned():
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0)), Thread(2, Ctx(0)), Thread(3, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000), ThreadInfo(4, 0x7fff0000)], "infos")
    mf.modules = FakeStream([], "modules")
    result = collect_threads(mf)
    tids = sorted(r.tid for r in result.records)
    assert tids == [1, 2, 3, 4]   # union, not either stream's list alone
    assert result.coverage.status == "partial"
    assert any("missing from ThreadInfoListStream" in r for r in result.coverage.reasons)   # tids 2, 3
    assert any("missing from ThreadListStream" in r for r in result.coverage.reasons)      # tid 4
    # tid 1 is real in both streams and must be fully resolved
    rec1 = next(r for r in result.records if r.tid == 1)
    assert rec1.start_address is not None

    # Both streams are genuinely PRESENT here (just partially mismatched)
    # -- unlike the fully-absent-ThreadListStream case above, both
    # limitations must be true SOURCE_KEY_MISMATCH, not SOURCE_ABSENT.
    codes = {l.code for l in result.coverage.limitations}
    assert codes == {LimitationCode.SOURCE_KEY_MISMATCH}
    assert result.coverage.sources["threads"].state == "present"
    assert result.coverage.sources["thread_info"].state == "present"


def test_render_threads_console_normal_does_not_crash(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    result = collect_threads(mf)
    render_threads_console(result.records, result.coverage)
    out = capsys.readouterr().out
    assert "0x1" in out
    assert "1 thread(s)" in out


def test_render_threads_console_present_empty_does_not_crash(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([], "threads")
    mf.thread_info = FakeStream([], "infos")
    mf.modules = FakeStream([], "modules")
    result = collect_threads(mf)
    render_threads_console(result.records, result.coverage)
    out = capsys.readouterr().out
    assert "0 thread(s)" in out


def test_render_threads_console_degraded_prints_warning_banner(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    result = collect_threads(mf)
    render_threads_console(result.records, result.coverage)
    out = capsys.readouterr().out
    assert "ThreadInfoListStream not present" in out
    assert "unavailable" in out


# ── has_times must be per-record, not a single dump-wide flag ────────────

def test_render_threads_console_mixed_records_do_not_misrender_has_times(capsys):
    # TID 1 has a REAL ThreadInfoListStream entry with a real CreateTime;
    # TID 2 is only in the base ThreadListStream (missing from
    # ThreadInfoListStream). Dump-wide has_times is True (tid 1 has a
    # timestamp), but tid 2's block must not borrow that and print a
    # bogus "Created"/"Exited: still running" for data it doesn't have.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0)), Thread(2, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000, create_time=133000000000000000)],
                                 "infos")
    result = collect_threads(mf)
    assert thread_records_have_times(result.records) is True
    rec1 = next(r for r in result.records if r.tid == 1)
    rec2 = next(r for r in result.records if r.tid == 2)
    assert rec1.create_time is not None
    assert rec2.create_time is None   # must not inherit has_times=True from rec1

    render_threads_console(result.records, result.coverage)
    out = capsys.readouterr().out
    tid2_block = out.split("0x2")[1].split("TID")[0]
    assert "Created" not in tid2_block
    assert "still running" not in tid2_block


def test_render_threads_console_stream_present_but_timestamps_empty_is_neutral(capsys):
    # ThreadInfoListStream genuinely IS present (not degraded -- some
    # minidump producers just never populate CreateTime/ExitTime even
    # when the stream exists). The note printed here must not claim the
    # stream is absent, since it isn't.
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")   # CreateTime defaults to None
    result = collect_threads(mf)
    assert thread_info_is_degraded(result.coverage) is False   # the stream itself is present
    assert thread_records_have_times(result.records) is False

    render_threads_console(result.records, result.coverage)
    out = capsys.readouterr().out
    assert "not available in the captured ThreadInfo data" in out
    assert "without ThreadInfoList stream" not in out   # would misreport a present stream as absent


def test_cmd_threads_returns_command_result(capsys):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    result = cmd_threads(mf)
    assert len(result.records) == 1
    assert result.coverage.status == "partial"
    capsys.readouterr()
