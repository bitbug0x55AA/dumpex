"""
Unit tests for dumpex.hunt.yara_hunt's YARA rule provenance tracking
(_load_yara_rules / get_yara_provenance).

The _load_yara_rules() tests below need the real yara-python package to
actually compile a rule file — it's an optional ("full") dependency, not
part of the base dev install, so those tests are skipped (not failed)
when it isn't present. get_yara_provenance() itself is a plain module-
attribute accessor and is tested independently of yara-python.

`_load_yara_rules()` itself no longer touches `_LAST_YARA_PROVENANCE` at
all (a P1 review fix to issue #11's migration: the compatibility global
must never be read back INTO a Report, so it is now written exactly once,
by `_build_yara_report()`'s own `_finish()` helper, as a snapshot copy of
the ALREADY-BUILT Report's own provenance -- never populated by a bare
`_load_yara_rules()` call). Tests that want to see `get_yara_provenance()`
reflect a load now go through `_hunt_yara()`/`_build_yara_report()`, not
`_load_yara_rules()` directly; tests of `_load_yara_rules()` itself check
its own return value.
"""
import os
import tempfile

import pytest

from tests.fixtures.fakes import Region, Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt.yara_hunt as yara_hunt


def test_get_yara_provenance_is_none_before_any_load():
    yara_hunt._LAST_YARA_PROVENANCE = None
    assert yara_hunt.get_yara_provenance() is None


def test_load_yara_rules_records_provenance():
    pytest.importorskip("yara")
    with tempfile.TemporaryDirectory() as d:
        good_path = os.path.join(d, "good.yar")
        with open(good_path, "w") as fh:
            fh.write('rule Good { condition: true }')
        bad_path = os.path.join(d, "bad.yar")
        with open(bad_path, "w") as fh:
            fh.write('rule Bad { condition: this is not valid yara }')

        loaded, provenance = yara_hunt._load_yara_rules(d)

    assert len(loaded) == 1
    assert provenance.compile_failed == 1
    assert provenance.rules_dir == d
    assert provenance.compiled_ok == 1
    assert [f.name for f in provenance.files] == ["bad.yar", "good.yar"]   # sorted

    good_entry = next(f for f in provenance.files if f.name == "good.yar")
    bad_entry  = next(f for f in provenance.files if f.name == "bad.yar")
    assert good_entry.compiled is True
    assert good_entry.error is None
    assert len(good_entry.sha256) == 64
    assert bad_entry.compiled is False
    assert bad_entry.error
    assert len(bad_entry.sha256) == 64

    assert len(provenance.aggregate_sha256) == 64

    # _load_yara_rules() itself never touches the compatibility global --
    # see this module's own docstring.
    assert yara_hunt.get_yara_provenance() is None


def test_load_yara_rules_aggregate_sha256_stable_across_calls():
    pytest.importorskip("yara")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.yar"), "w") as fh:
            fh.write('rule A { condition: true }')

        _, first_provenance = yara_hunt._load_yara_rules(d)
        _, second_provenance = yara_hunt._load_yara_rules(d)

    assert first_provenance.aggregate_sha256 == second_provenance.aggregate_sha256


def test_get_yara_provenance_reflects_the_completed_report_not_the_bare_load():
    """The compatibility global is written exactly once, by
    `_build_yara_report()`'s own `_finish()` helper, from the ALREADY-BUILT
    Report's own provenance -- never fed back INTO a Report, and never set
    by `_load_yara_rules()` alone (see this module's own docstring)."""
    pytest.importorskip("yara")
    seg_va, seg_fo = 0x70000, 0x7000
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "good.yar"), "w") as fh:
            fh.write('rule Good { strings: $a = "nomatch_marker" condition: $a }')

        yara_hunt._load_yara_rules(d)
        assert yara_hunt.get_yara_provenance() is None   # bare load: global untouched

        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        report = yara_hunt._build_yara_report(MF(), rules_dir=d)

    info = yara_hunt.get_yara_provenance()
    assert info is not None
    assert info == report.coverage.rules.provenance.to_dict()


def test_interleaved_report_builds_each_reflect_their_own_provenance():
    """P1 review regression: build Report A, build Report B (a DIFFERENT
    rules directory), and confirm `get_yara_provenance()` reflects
    whichever Report was built MOST RECENTLY, never a stale earlier one --
    and that each Report's OWN `coverage.rules.provenance` (the canonical
    source; `get_yara_provenance()` is only ever a compatibility snapshot
    of "the last one") stays correct regardless of what was built after
    it. A caller that needs A's provenance after B has already been built
    must read `report_a.coverage.rules.provenance` directly -- see
    `get_yara_provenance()`'s own docstring on why the global cannot
    promise more than "last completed build in this process"."""
    pytest.importorskip("yara")
    seg_va, seg_fo = 0x71000, 0x7100
    data = b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        _reader                = FakeReader({seg_va: data})

    with tempfile.TemporaryDirectory() as d_a, tempfile.TemporaryDirectory() as d_b:
        with open(os.path.join(d_a, "a.yar"), "w") as fh:
            fh.write('rule A { condition: true }')
        with open(os.path.join(d_b, "b.yar"), "w") as fh:
            fh.write('rule B { condition: true }')

        report_a = yara_hunt._build_yara_report(MF(), rules_dir=d_a)
        # The global reflects A right after A's own build completes.
        assert yara_hunt.get_yara_provenance()["rules_dir"] == d_a
        assert report_a.coverage.rules.provenance.rules_dir == d_a

        report_b = yara_hunt._build_yara_report(MF(), rules_dir=d_b)
        # The global now reflects B -- and A's OWN Report is untouched:
        # its provenance still names d_a, proving the global was never
        # read back INTO either Report.
        assert yara_hunt.get_yara_provenance()["rules_dir"] == d_b
        assert report_b.coverage.rules.provenance.rules_dir == d_b
        assert report_a.coverage.rules.provenance.rules_dir == d_a


def test_get_yara_provenance_returns_a_fresh_dict_every_call():
    """A caller mutating what `get_yara_provenance()` returns must not
    corrupt this module's own state or a later caller's read of it (P1
    review fix: the function used to return the literal same dict object
    every call)."""
    pytest.importorskip("yara")
    seg_va, seg_fo = 0x72000, 0x7200
    data = b'\x00' * 0x100
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "good.yar"), "w") as fh:
            fh.write('rule Good { condition: true }')
        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        yara_hunt._build_yara_report(MF(), rules_dir=d)

    first = yara_hunt.get_yara_provenance()
    first["rules_dir"] = "corrupted"
    first["files"].append({"name": "poisoned", "sha256": None, "compiled": True, "error": None})

    second = yara_hunt.get_yara_provenance()
    assert second is not first
    assert second["rules_dir"] != "corrupted"
    assert all(f["name"] != "poisoned" for f in second["files"])


# ── a NOT_EVALUATED run must not carry forward a PRIOR successful scan's ──
# provenance -- meta.yara_rules would otherwise silently misreport which
# rules (if any) actually produced this particular result.

# ── a non-SyntaxError exception from yara.compile() must still count as ──
# a compile failure (and leave OTHER files unaffected), not just the
# yara.SyntaxError path that was already covered

def test_load_and_compile_non_syntax_error_still_counts_as_compile_failed(monkeypatch, tmp_path):
    pytest.importorskip("yara")
    import yara
    from dumpex.hunt.yara_hunt import rules

    (tmp_path / "good.yar").write_text('rule Good { condition: true }')
    (tmp_path / "boom.yar").write_text('rule Boom { condition: true }')

    real_compile = yara.compile

    def fake_compile(filepath, **kwargs):
        if os.path.basename(filepath) == "boom.yar":
            raise RuntimeError("simulated non-syntax compile failure")
        return real_compile(filepath=filepath, **kwargs)

    monkeypatch.setattr(yara, "compile", fake_compile)

    rule_files, provenance = rules.load_and_compile(str(tmp_path))

    assert provenance.compile_failed == 1
    assert [fname for fname, _ in rule_files] == ["good.yar"]

    boom_entry = next(f for f in provenance.files if f.name == "boom.yar")
    assert boom_entry.compiled is False
    assert boom_entry.error

    good_entry = next(f for f in provenance.files if f.name == "good.yar")
    assert good_entry.compiled is True
    assert good_entry.error is None


def test_not_evaluated_run_clears_prior_scan_provenance():
    pytest.importorskip("yara")
    seg_va, seg_fo = 0x30000, 0x3000
    data = b'\x00' * 0x1000

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "good.yar"), "w") as fh:
            fh.write('rule Good { strings: $a = "nomatch_marker" condition: $a }')

        seg = Segment(seg_va, seg_fo, len(data))

        class MF(FakeMF):
            memory_segments_64 = FakeStream([seg], "memory_segments")
            _reader                = FakeReader({seg_va: data})

        # A genuine successful scan first -- populates provenance.
        yara_hunt._hunt_yara(MF(), rules_dir=d, verbose=False)
        assert yara_hunt.get_yara_provenance() is not None

        # Same process, second call, but the rules directory doesn't
        # exist this time -- must be NOT_EVALUATED, and must NOT still
        # report the first call's rule file hashes.
        f = yara_hunt._hunt_yara(MF(), rules_dir="/definitely_not_a_real_dir_xyz123",
                                  verbose=False)

    assert f["status"] == "NOT_EVALUATED"
    assert yara_hunt.get_yara_provenance() is None
