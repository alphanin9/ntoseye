"""Python SDK for the ntoseye Windows kernel debugger.

    import ntoseye
    dbg = ntoseye.attach(backend="kd", connect="/tmp/ntoseye-kd.sock")
    print(dbg.registers())

See the project README and `examples/` for more.
"""

from ._ntoseye import (
    AddressModule,
    Breakpoint,
    Debugger,
    MemoryAccessError,
    MemoryRegion,
    MemorySearchMatch,
    NtoseyeError,
    StopOutcome,
    Struct,
    Type,
    __version__,
    attach,
)

__all__ = [
    "AddressModule",
    "Breakpoint",
    "Debugger",
    "MemoryAccessError",
    "MemoryRegion",
    "MemorySearchMatch",
    "NtoseyeError",
    "StopOutcome",
    "Type",
    "Struct",
    "attach",
    "__version__",
]
