"""Unbacked-thread (StartAddress) scan. Only collects facts."""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_thread_infos, addr_to_module


def _hunt_unbacked_threads(mf: MinidumpFile, module_list_available: bool = True) -> list:
    """
    Return list of ThreadInfo with no module backing (by StartAddress).
    Retained as a secondary signal; see dumpex/hunt/injection/__init__.py's
    module docstring for why current RIP/EIP is now the primary
    execution-correlation signal instead.

    Same reasoning as memory_scan._hunt_hidden_pe: without ModuleListStream,
    every thread would look "unbacked" regardless of whether it actually
    is — that's an absence-of-data artifact, not evidence of injection.
    """
    if not module_list_available:
        return []
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    return [ti for ti in infos
            if not addr_to_module(ti.StartAddress or 0, modules)]
