# TODO

## Agent/REPL refactors

- Extract a shared `DebuggerSession` that owns current thread, register cache,
  breakpoints, and continue/step stop handling. Both the REPL and agent stdio
  should call this instead of duplicating state machines.
- Move duplicated inspection code (`idt`, `gdt`, `tss`, `pool`, `dt`,
  `disasm`, stack trace, memory search/fill, and local symbol loading) into
  structured helpers. The REPL should format those structures as tables; the
  agent should serialize them as JSON.
- Unify software-breakpoint step-over behavior. The REPL still has the richer
  wrong-process `int3` and trap-flag handling; agent `continue`/`step` should
  use the same path.
- Add a safe script execution API for agent stdio. `script.list` and
  `script.reload` are exposed now, but direct execution needs stdout/stderr
  capture or a Lua result-returning convention so script `print()` cannot
  corrupt the JSON stream.
- Add tests around the JSON protocol using a fake `DebugBackend`, especially
  for breakpoint lifecycle, stop events, descriptor-table parsing, and
  register-backed expressions like `$rsp`.
