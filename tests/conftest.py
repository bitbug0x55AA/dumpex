"""
Shared pytest setup for the whole tests/ tree.

No real .dmp/PE sample files are required to run this suite: every test
builds its own synthetic PE header and minidump object graph via
tests/fixtures/fakes.py, so `pytest` from a bare checkout must succeed
with no external fixtures, network access, or malware corpus.
"""
import os
import sys

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
_FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures")

for _p in (_REPO_ROOT, _FIXTURES_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dumpex.core.memory import get_thread_contexts as _real_get_thread_contexts
import dumpex.hunt.stomping as stomping
import dumpex.hunt.pipe as pipemod


@pytest.fixture(autouse=True)
def _reset_thread_context_monkeypatches():
    """
    hunt/stomping.py and hunt/pipe.py both hold get_thread_contexts as a
    plain module attribute (imported from dumpex.core.memory) rather than
    always calling through the module, specifically so tests can
    monkeypatch it to inject a synthetic RIP/EIP. That attribute persists
    at module scope for the rest of the process — a test that patches it
    and doesn't clean up would leak a stale thread context into every
    later test that happens to run after it, regardless of file or
    execution order (a real bug hit during phase-two development). This
    fixture resets both to the real implementation before AND after every
    test, so no test's outcome can depend on what ran before it.
    """
    stomping.get_thread_contexts = _real_get_thread_contexts
    pipemod.get_thread_contexts = _real_get_thread_contexts
    yield
    stomping.get_thread_contexts = _real_get_thread_contexts
    pipemod.get_thread_contexts = _real_get_thread_contexts
