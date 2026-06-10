# NTOSEYE Agent Stdio Command Reference

Use `--agent-stdio` to run NTOSEYE as a newline-delimited JSON control process instead of the interactive REPL:

```bash
sudo /usr/local/bin/ntoseye --backend gdb --connect 127.0.0.1:1234 --agent-stdio
```

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
| `k` / `stack` / `stack.trace` | optional `length` | Builds a stack trace for the current stopped thread; default limit is 64 frames. |

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
| `symbol.search` / `symbols.search` / `x` | `query` or `expr`, optional `limit` | Fuzzy-searches symbols. `module!query` restricts the search to one module. Addresses populate `$0..$N`. |
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
| `continue` / `go` | optional `timeout_ms` | Continues execution. If `timeout_ms` is present, waits that long for a stop and returns stop details or `{running:true, stopped:false}`. |
| `interrupt` / `break` | none | Interrupts the target and refreshes current stopped thread when possible. |
| `step` / `si` | none | Single-steps the current thread and returns stop details. Fails if already running. |
| `step.over` / `p` / `ni` | optional `timeout_ms` | Steps over calls using a temporary breakpoint; non-call instructions single-step. |
| `step.out` / `gu` / `finish` | optional `timeout_ms` | Runs to the caller found by the stack unwinder using a temporary breakpoint. |

Stop responses can include `running`, `stopped`, `thread`, `summary`, `target_exited`, `rip`, `cr3`, nearest `symbol`, `exception_code`, `program_counter`, `is_bugcheck`, structured `bugcheck`, `target_reloaded`, `target_kernel_base_hint`, `assisted_breakin`, and a `reload` rediscovery report. Reload processing drops stale breakpoints and rebuilds guest state.

## Breakpoints

| Command | Fields | Notes |
| --- | --- | --- |
| `bp.set` / `breakpoint.set` | `address`, optional `kind` | `kind` defaults to `software`; use `hardware` or `hbp` for QEMU gdbstub hardware execution breakpoints. |
| `bp.clear` / `breakpoint.clear` | `breakpoint` | Clears a breakpoint by numeric ID. |
| `bp.disable` / `breakpoint.disable` | `breakpoint` | Disables a breakpoint by ID. |
| `bp.enable` / `breakpoint.enable` | `breakpoint` | Enables a breakpoint by ID. |
| `bp.list` / `breakpoint.list` | none | Lists IDs, enabled state, kind, address, symbol, and scope. |

Prefer `kind:"hardware"` for PatchGuard-sensitive driver debugging when QEMU gdbstub support is available. Keep `kind:"software"` for ordinary `0xCC` breakpoints.

## QEMU and Scripts

| Command | Fields | Notes |
| --- | --- | --- |
| `qcmd` | `expr` | Sends a QEMU monitor command and returns `output`. |
| `qlog` | optional `expr` or `filter`, optional `path` | Enables QEMU logging. Default items are `int,cpu_reset,guest_errors`; `path` sets the logfile first. |
| `script.list` / `scripts` | none | Lists loaded Lua script commands with help and completion strategies. |
| `script.reload` | none | Reloads agent-safe built-in scripts. |
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
{"id":9,"command":"bp.set","address":"mydrv!DriverEntry","kind":"hardware"}
{"id":10,"command":"continue","timeout_ms":1000}
{"id":11,"command":"qlog","expr":"int,cpu_reset,guest_errors","path":"/tmp/ntoseye-qemu.log"}
```
