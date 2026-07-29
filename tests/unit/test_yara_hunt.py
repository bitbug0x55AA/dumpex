"""
Unit tests for dumpex.hunt.yara_hunt's YARA rule provenance tracking
(_load_yara_rules / get_yara_provenance).

The _load_yara_rules() tests below need the real yara-python package to
actually compile a rule file — it's an optional ("full") dependency, not
part of the base dev install, so those tests are skipped (not failed)
when it isn't present. get_yara_provenance() itself is a plain module-
attribute accessor and is tested independently of yara-python.
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

        loaded, compile_failed = yara_hunt._load_yara_rules(d)

    assert len(loaded) == 1
    assert compile_failed == 1

    info = yara_hunt.get_yara_provenance()
    assert info["rules_dir"] == d
    assert info["compiled_ok"] == 1
    assert info["compile_failed"] == 1
    assert [f["name"] for f in info["files"]] == ["bad.yar", "good.yar"]   # sorted

    good_entry = next(f for f in info["files"] if f["name"] == "good.yar")
    bad_entry  = next(f for f in info["files"] if f["name"] == "bad.yar")
    assert good_entry["compiled"] is True
    assert good_entry["error"] is None
    assert len(good_entry["sha256"]) == 64
    assert bad_entry["compiled"] is False
    assert bad_entry["error"]
    assert len(bad_entry["sha256"]) == 64

    assert len(info["aggregate_sha256"]) == 64


def test_load_yara_rules_aggregate_sha256_stable_across_calls():
    pytest.importorskip("yara")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.yar"), "w") as fh:
            fh.write('rule A { condition: true }')

        yara_hunt._load_yara_rules(d)
        first = yara_hunt.get_yara_provenance()["aggregate_sha256"]
        yara_hunt._load_yara_rules(d)
        second = yara_hunt.get_yara_provenance()["aggregate_sha256"]

    assert first == second


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

    bundle = rules.load_and_compile(str(tmp_path))

    assert bundle.compile_failed == 1
    assert [fname for fname, _ in bundle.rule_files] == ["good.yar"]

    boom_entry = next(f for f in bundle.provenance["files"] if f["name"] == "boom.yar")
    assert boom_entry["compiled"] is False
    assert boom_entry["error"]

    good_entry = next(f for f in bundle.provenance["files"] if f["name"] == "good.yar")
    assert good_entry["compiled"] is True
    assert good_entry["error"] is None


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
