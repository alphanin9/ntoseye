# NTOSEYE Agent Stdio Command Reference

Use the `agent` subcommand to run NTOSEYE as a newline-delimited JSON control process instead of the interactive REPL (the global `--backend`/`--connect` flags go before the subcommand):

```bash
/usr/local/bin/ntoseye --backend kdnet --kdnet-key <KEY> agent
```

No `sudo`: KD and KDNET carry memory as well as control over the debug transport, so they need no hypervisor-process access. See `SKILL.md` for how to read the current key out of the guest.

The first stdout line is a `ready` event. Each request is one JSON object on one line. Each response is one JSON object on one line.

Request envelope:

```json
{"id":1,"command":"eval","expr":"nt!MmAccessFault"}
```

Response envelope:

```json
{"id":1,"ok":true,"result":{"address":"0xfffff80000000000"}}
```

Errors use `ok:false`:

```json
{"id":1,"ok":false,"error":"missing address"}
```

Addresses are expression strings and use the same parser as the REPL: symbols, `module!symbol`, arithmetic, casts, and register expressions are valid when the debugger has the needed context. Binary memory payloads are hex strings.

## Core Inspection

| Command | Fields | Notes |
| --- | --- | --- |
| `status` | none | Returns running state, current vCPU (`current_vcpu`; legacy alias `current_thread`), current Windows thread, DTB, and attached process info. |
| `capabilities` | none | Returns the selected backend's supported and unsupported debugger capabilities. |
| `eval` | `expr` | Evaluates an expression, returns `address`, and stores it in `$0`. |
| `registers` | none | Reads registers for the current stopped thread. Fails if the VM is running. |
| `disasm` / `u` | `address`, optional `length` | Disassembles bytes at `address`; default length is 32 bytes. |
| `dt` / `type.dump` | `type`, optional `address`, optional `field` | Dumps type layout and, when `address` is present, field values. Leading underscore on the type is optional. |
| `trap-frame` / `tf` | optional `address`, optional `field` | Equivalent to `dt` with type `KTRAP_FRAME`. |
| `k` / `stack` / `stack.trace` | optional `length` | Builds a stack trace for the current stopped thread; default limit is 64 frames. Each frame is `{sp, ip, symbol, source}` (`source` is `current`/`seed`/`unwind`/`scan`). For a thread's trap frame use `threads` (`trap_frame` field) or `tf`. |

## Memory

| Command | Fields | Notes |
| --- | --- | --- |
| `memory.read` / `read-memory` | `address`, optional `length` | Reads memory from the current process address space; default length is 16 bytes. Result `data` is hex. |
| `memory.write` / `write-memory` | `address`, `data` | Writes hex bytes to memory. |
| `memory.search` / `search` | `address`, optional `length`, `pattern` or `data` | Searches a memory range; default length is `0x100`. Pattern can be hex like `488b05` or escaped bytes like `\x48\x8b\x05`. |
| `memory.fill` / `fill` | `address`, `length`, `pattern` or `data` | Repeats a byte pattern over a memory range. |

## Kernel Structures

| Command | Fields | Notes |
| --- | --- | --- |
| `pte` | `address` | Returns page-table traversal entries and flags for the virtual address. |
| `idt` | optional `length` | Reads IDT entries using stopped CPU register state plus QEMU monitor register descriptors. |
| `gdt` | optional `length` | Reads GDT entries using stopped CPU register state plus QEMU monitor register descriptors. |
| `tss` | optional `selector` | Dumps the TSS descriptor and stack bases. If omitted, selector comes from QEMU monitor TR output. |
| `pool` | `address` or `expr` | Classifies nearby pool metadata and big-pool state for a target address. |
| `vmmap` | optional `filter` or `expr` | Lists VAD regions for the attached process, or kernel module ranges when detached. A resolvable expression filters by containing address. |

## Symbols and Variables

| Command | Fields | Notes |
| --- | --- | --- |
| `symbol.search` / `symbols.search` / `x` | `query` or `expr`, optional `limit` | Fuzzy-searches symbols. `module!query` restricts the search to one module. Addresses populate `$0..$N`. Each hit carries `ambiguous:true` when the same name resolves in more than one module; the reported `address` is then the first location by module name. |
| `symbol.nearest` / `symbols.nearest` / `ln` | `address` or `expr` | Returns the nearest symbol, base, and offset. The symbol base is stored in `$0`. |
| `variable.set` / `set` | `name`, `expr` | Defines a convenience variable usable as `$name`. |
| `variables` / `vars` | none | Lists user variables, result slots, their origin, and built-in variables. |
| `variable.unset` / `unset` | `name` or `expr` | Removes a user convenience variable. |

## Processes, Modules, Drivers

| Command | Fields | Notes |
| --- | --- | --- |
| `ps` / `processes` | optional `filter` | Lists processes with PID, name, EPROCESS, and DTB. Filter matches name or PID prefix. |
| `drivers` | optional `filter` | Lists `\Driver` objects with object address, start, size, device object, and unload pointer. Filter matches name, object, or start prefix. |
| `lm` / `modules` | optional `filter` | Lists kernel modules unless attached to a process, in which case it lists that process's modules. |
| `load-symbols` / `symbols.load` | `path` or `expr`, optional `filter` | Loads symbols from a directory and returns module symbol load counts. |
| `attach` | `pid` | Attaches debugger context to a process and loads available symbols. |
| `detach` | none | Returns to kernel context. |

## vCPUs, Windows Threads, and Execution

| Command | Fields | Notes |
| --- | --- | --- |
| `vcpus` | none | Lists backend execution contexts with RIP, CR3, nearest symbol, and active Windows thread when resolvable. |
| `vcpu.set` / `vcpu` | `thread` | Selects a backend vCPU/execution context. |
| `threads` | optional `filter` | Lists Windows threads with ETHREAD/KTHREAD, PID/TID, state, wait reason, stack metadata, pending IRPs, and active vCPU. |
| `thread.set` / `thread` | `thread` | Resolves a Windows thread by TID or ETHREAD. If it is active, selects its vCPU and installs its pseudo-register context. |
| `continue` / `go` | optional `timeout_ms` | Resumes execution. Without `timeout_ms` it returns immediately as `{running:true, stopped:false}` (poll with `wait`). With `timeout_ms` it waits that long and returns stop details or `{running:true, stopped:false}`. |
| `wait` / `wait-for-stop` | optional `timeout_ms` | Waits for the next meaningful stop **without resuming** (drains a parked stop, drives reboot/breakpoint classification, absorbs debugger noise). Returns stop details, or `{running:true, stopped:false}` on timeout. |
| `interrupt` / `break` | none | Interrupts the target and refreshes the current stopped thread when possible. |
| `step` / `si` | none | Single-steps the current thread and returns stop details. Requires the VM halted. |
| `step.over` / `p` / `ni` | optional `timeout_ms` | Steps over a call (runs to its return site) or single-steps a non-call. Requires the VM halted. With `timeout_ms`, returns `{running:true, stopped:false}` if it doesn't complete in time (the VM is left running). |
| `step.out` / `gu` / `finish` | optional `timeout_ms` | Runs to the caller's return address. Requires the VM halted. With `timeout_ms`, returns `{running:true, stopped:false}` if it doesn't complete in time. |

Stop responses carry `running`, `stopped`, a `stop` kind (`"breakpoint"`, `"bugcheck"`, `"exception"`, `"step"`, `"halted"`, `"interrupt"`, or `"target_reloaded"`), `thread`, and — when halted with readable context — `rip`, `cr3`, and nearest `symbol`, plus the attached `process` (`{pid,name}`). Per kind: `breakpoint` adds `breakpoint:{id,address,symbol}` and `temporary`; `bugcheck` adds `is_bugcheck:true` and a structured `bugcheck`; `exception` adds `exception_code`, `first_chance`, and `exception_address` (the faulting address, which differs from `rip` when a second-chance report re-raises at the original site); `target_reloaded` adds `kernel_base` and `coherent` (the guest rebooted — every prior address is stale, re-enumerate; reload classification, stale-breakpoint drop, and guest-state rebuild are handled inside the shared session core); `halted` adds `event:false` and `coherent`.

## Breakpoints

| Command | Fields | Notes |
| --- | --- | --- |
| `bp.set` / `breakpoint.set` | `address`, optional `kind`, `access`, `length`, `condition` | Sets a breakpoint scoped to the current inspection context. An optional `condition` is re-evaluated on each hit. `kind` is `software` (default, `0xCC` patch) or `hardware` (debug register, patches no memory). |
| `bp.clear` / `breakpoint.clear` | `breakpoint` | Clears a breakpoint by numeric ID. |
| `bp.disable` / `breakpoint.disable` | `breakpoint` | Disables a breakpoint by ID. |
| `bp.enable` / `breakpoint.enable` | `breakpoint` | Enables a breakpoint by ID. |
| `bp.list` / `breakpoint.list` | none | Lists IDs, enabled state, `kind`, address, symbol, scope, temporary flag, and condition. Hardware breakpoints also carry `access`, `length`, and `slot`; those three are `null` on software breakpoints. |

### Hardware breakpoints

`kind:"hardware"` (aliases `hbp`, `ba`) uses a debug register instead of patching `0xCC`, so it modifies no guest memory and traps data access as well as execution. Requires a backend advertising `data watchpoints` under `capabilities` — KD and KDNET do; the GDB stub does not, and returns "not supported".

| Field | Values | Default |
| --- | --- | --- |
| `access` | `execute`, `write`, `read_write` (also `e`/`w`/`r`, `read/write`) | `execute` |
| `length` | 1, 2, 4, 8 | 1 |

x86 rules are enforced up front: execute watches are always 1 byte, data widths are 1/2/4/8, and the address must be aligned to its own length — an unaligned debug register silently never fires, so this is rejected rather than accepted quietly. `length` is echoed in the response, since the default is the narrowest legal width rather than an inferred one.

There are only four debug registers, so a fifth concurrent hardware breakpoint fails with "all 4 hardware breakpoint slots are in use". The response and `bp.list` report which `slot` (DR0-3) each occupies; hits are identified by DR6 rather than by RIP, so the slot is how a client correlates them.

```json
{"id":1,"command":"bp.set","address":"mydrv!g_Counter","kind":"hardware","access":"write","length":8}
{"id":2,"command":"bp.set","address":"mydrv!DriverEntry","kind":"hardware"}
```

Passing `access` without `kind:"hardware"` is an error rather than being silently ignored.

## QEMU and Scripts

| Command | Fields | Notes |
| --- | --- | --- |
| `qcmd` | `expr` | Sends a QEMU monitor command and returns `output`. |
| `qlog` | optional `expr` or `filter`, optional `path` | Enables QEMU logging. Default items are `int,cpu_reset,guest_errors`; `path` sets the logfile first. |
| `script.list` / `scripts` | none | Lists registered embedded-Python commands (`ntoseye.repl`) with help and completion strategies. |
| `script.run` / `script.exec` | `expr` | Runs a Python command (`<name> [args...]`); the command's stdout is captured and returned as `output` so it can't corrupt the JSON stream. |
| `script.reload` | none | Reloads the Python commands directory. |
| `quit` | none | Returns `{bye:true}` and exits the agent loop. |

## Minimal Examples

```json
{"id":1,"command":"status"}
{"id":2,"command":"capabilities"}
{"id":3,"command":"eval","expr":"nt!MmAccessFault"}
{"id":4,"command":"symbol.search","query":"MmAccess"}
{"id":5,"command":"vmmap","filter":"ntdll"}
{"id":6,"command":"vcpus"}
{"id":7,"command":"threads","filter":"System"}
{"id":8,"command":"memory.read","address":"nt!MmAccessFault","length":16}
{"id":9,"command":"bp.set","address":"mydrv!DriverEntry"}
{"id":10,"command":"continue","timeout_ms":1000}
{"id":11,"command":"wait","timeout_ms":2000}
{"id":12,"command":"qlog","expr":"int,cpu_reset,guest_errors","path":"/tmp/ntoseye-qemu.log"}
```
