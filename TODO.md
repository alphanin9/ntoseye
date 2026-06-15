# TODO

## Agent stdio rebased onto upstream shared core (done)

The agent stdio frontend now sits on upstream's shared `Session` / `Target` /
`view` instead of the fork's parallel `DebuggerContext` + `DebuggerSession`:

- Shared session/state machine, unified step-over / wrong-process `int3` /
  reload handling, and shared inspection (`dt`, `disasm`, stack trace, etc.) are
  upstream's `Session`/`Target` — the agent calls them instead of duplicating.
- `idt`/`gdt`/`tss` and `pool` inspection are kept as fork-only neutral helpers
  in `src/inspect/` (descriptors, local symbols, pool), re-pointed to `Target`.
- Scripting is the embedded Python interpreter; `script.run`/`script.exec` use
  `embed::dispatch_capture`, which redirects `sys.stdout`/`sys.stderr` so script
  output can't corrupt the JSON-on-stdout protocol.

## Follow-ups

- **Hardware breakpoints.** Upstream's shared `BreakpointManager` is
  software/temporary/condition only. The fork's gdbstub hardware-breakpoint path
  (`Z1`/`z1`, `hwbreak+`, `hbp`, exact-RIP-no-rewind) needs re-porting on top of
  the shared core; until then `bp.set kind:"hardware"` returns "not supported".
- **Protocol tests.** Add tests around the JSON protocol using a fake
  `DebugBackend`: breakpoint lifecycle, the `ContinueOutcome`-derived stop
  shapes, descriptor-table parsing, and register-backed expressions.
- **Live verification.** Exercise the rebased agent against the Win11 VM
  (KD + gdb backends): continue/wait/interrupt/step, breakpoint hits, reboot
  (`target_reloaded`), and a Python `script.run` round-trip.
- **Integration.** Decide the merge strategy back to `master` (the branch is
  built on `upstream/master` directly, so a normal merge of this branch brings
  upstream + the agent layer together). Reconcile `README.md`.
