"""
Shared pytest setup for the whole tests/ tree.

No real .dmp/PE sample files are required to run this suite: every test
builds its own synthetic PE header and minidump object graph via
tests/fixtures/fakes.py (imported as `tests.fixtures.fakes` — every
directory under tests/ is a proper package via __init__.py, so pytest
resolves each test module by its fully-qualified dotted name rather than
bare basename; without that, pytest's default "prepend" import mode can
collide/misresolve same-named modules across sibling test directories),
so `pytest` from a bare checkout must succeed with no external fixtures,
network access, or malware corpus.
"""
import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from dumpex.core.memory import get_thread_contexts as _real_get_thread_contexts
import dumpex.hunt.stomping as stomping
import dumpex.hunt.pipe as pipemod
import dumpex.hunt.cs_beacon as cs_beacon

_THREAD_CONTEXT_MODULES = (stomping, pipemod, cs_beacon)


@pytest.fixture(autouse=True)
def _reset_thread_context_monkeypatches():
    """
    hunt/stomping.py, hunt/pipe.py, and hunt/cs_beacon/ all hold
    get_thread_contexts as a plain module attribute (imported from
    dumpex.core.memory) rather than always calling through the module,
    specifically so tests can monkeypatch it to inject a synthetic
    RIP/EIP. That attribute persists at module scope for the rest of the
    process — a test that patches it and doesn't clean up would leak a
    stale thread context into every later test that happens to run after
    it, regardless of file or execution order (a real bug hit during
    phase-two development). This fixture resets all of them to the real
    implementation before AND after every test, so no test's outcome can
    depend on what ran before it.
    """
    for mod in _THREAD_CONTEXT_MODULES:
        mod.get_thread_contexts = _real_get_thread_contexts
    yield
    for mod in _THREAD_CONTEXT_MODULES:
        mod.get_thread_contexts = _real_get_thread_contexts
