"""Shared per-call dependency snapshot for split hunter packages.

When a hunter facade (`dumpex/hunt/<name>/__init__.py`) delegates work to
its own submodules (scanner/correlation/...), those submodules must not
import shared dependencies (`read_region`, `get_thread_contexts`,
`time.monotonic`) on their own -- doing so creates a SECOND binding of the
same name, and facade-level monkeypatching (`somehunter.read_region = fake`,
`somehunter.get_thread_contexts = fake`) then silently stops affecting the
submodule's own copy. See dumpex/hunt/encoding/config.py's EncodingConfig
for the same lesson applied to tunable constants.

Instead, the facade builds ONE HunterRuntime from its own (still
monkeypatchable) module globals at the start of every `_hunt_*` call, and
threads it explicitly into whichever submodules need it. Not every hunter
needs every field -- leave the rest at their default (None, or the real
time.monotonic).
"""
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class HunterRuntime:
    read_region: Optional[Callable] = None
    get_thread_contexts: Optional[Callable] = None
    monotonic: Callable = time.monotonic
