---
name: ntoseye-windows-driver-debugging
description: Windows kernel driver debugging workflow for NTOSEYE-backed QEMU/libvirt Windows VMs, driven from a persistent Python kernel through the ntoseye Python SDK. Use when an agent needs to debug, deploy, reload, or triage a Windows kernel driver with NTOSEYE over KDNET/KDCOM, virtiofs shared folders, QEMU Guest Agent command execution, libvirt/virsh, or host-to-guest driver iteration.
---

# NTOSEYE Windows Driver Debugging

## Overview

Keep Windows driver work anchored to the local VM/debugger setup instead of generic Windows administration:

- **Debugger:** the `ntoseye` Python SDK over KDNET, driven from a persistent Python kernel (the harness's `eval` tool, a Jupyter kernel). It is also the crash-recovery channel.
- **Files:** virtiofs.
- **Guest control:** QEMU Guest Agent (or SSH).

The SDK is the same debugger core as the REPL. `dbg.command("...")` runs any WinDbg-style REPL line, and the typed namespaces (`dbg.processes`, `dbg.modules`, `dbg.breakpoints`, `dbg.types`, `dbg.memory`, ...) return structured values, so a cell can filter and walk the data and print only what matters. The upstream docs are the API reference: `docs/scripting/sdk.md`, the type stub `python/ntoseye/_ntoseye.pyi` (every method, with docstrings), and `docs/using/drivers.md` (driver development from a Linux host).

## First Pass

Discover the actual local setup rather than assuming it:

- `virsh -c qemu:///system list --all` finds the VM. On this host the domain is `win11`.
- `ntoseye status` prints the configured debug transports, endpoints, and launch commands. It reads the *default* libvirt URI, so run it as `LIBVIRT_DEFAULT_URI=qemu:///system ntoseye status`, or the system domains do not appear. If it reports `Debug backend: not configured` on a KDNET guest, check by attaching: KDNET adds no XML device, only the Hyper-V vendor ID.
- Inspect the QEMU command line with `ps -eo pid,cmd | rg -i "qemu|virtiofs|guest-agent|qga|qmp|serial"`.
- Prefer existing virtiofs mounts for moving files. In the known setup, libvirt exposes `virtiofsd --shared-dir /home/user/dev/windows_shared` and the QEMU fs tag is `win_share`. Other setups may differ.
- Test QGA before assuming it works:

```bash
virsh -c qemu:///system qemu-agent-command win11 '{"execute":"guest-ping"}'
```

If `guest-ping` succeeds, QGA command execution is available. On this VM, `guest-exec` runs as `nt authority\system`, which is enough for `bcdedit` and `sc.exe`.

## SDK Environment

Build the extension from this checkout, so the SDK matches the debugger code you are reading:

```bash
cd /home/user/dev/ntoseye/python
uv venv .venv && uv pip install --python .venv/bin/python maturin patchelf
. .venv/bin/activate && maturin develop --release
```

Run the Python kernel from that venv (or `pip install ntoseye` for the latest release instead). After a rebuild, a long-lived kernel still has the old native module loaded. `ntoseye.build` holds the commit stamp of the loaded extension (`<commit>` or `<commit>-dirty`). If it differs from `git rev-parse --short=12 HEAD`, restart the kernel, but close the debugger first (see Attach Rules).

**No `sudo`.** KDNET carries both run control and memory over the debug transport, so the kernel runs as your normal user. Root is only needed to read guest RAM from the QEMU process (`memory_source="host"`, and the `gdb` and `memory` backends), and QEMU runs as `libvirt-qemu`. With the default `memory_source="auto"`, an unprivileged attach prints that host memory is unavailable and falls back to KD memory. This is the intended path, not an error. Pass `memory_source="kd"` to skip the probe.

## Attaching

Read the current KDNET key from the guest instead of hardcoding it, because `bcdedit /dbgsettings net` generates a new key each time it runs. `bcdedit` output is CRLF, and a trailing `\r` makes the last key component 14 characters, which ntoseye rejects with `invalid KDNET key component`:

```bash
KEY=$(python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py --domain win11 \
  -- 'C:\Windows\System32\cmd.exe' /c 'bcdedit /enum {dbgsettings}' \
  | tr -d '\r' | awk '/^key/{print $2}')
```

The guest targets `192.168.122.1:50000` (the host's `virbr0` address), and the `kdnet` backend listens on `0.0.0.0:50000` by default, so `connect` is not needed.

Keep one `Debugger` alive across cells. Do not use a `with` block that spans cells:

```python
import ntoseye
from ntoseye import Stop

dbg = ntoseye.attach("kdnet", key=KEY, memory_source="kd", kd_handshake_timeout=60)
print(ntoseye.build, dbg.stop.kind, dbg.inspect.version())
```

`dbg.close()` removes the debugger's breakpoints, resumes the guest, and releases the transport and the instance lock.

## Attach Rules

These failure modes cost real time to rediscover:

- **Wait for the guest to finish booting before attaching.** An attach in the middle of boot lands in a storm of module loads, the kernel PE read never settles, and ntoseye gives up with `PE view failed`. Wait until `guest-ping` succeeds.
- **Never kill a live session.** If the Python kernel is killed, restarted, or times out while it is attached, the target stays frozen at the break-in: QEMU still reports `running`, but the guest spins in the KD stub and QGA stops answering. Call `dbg.close()` before you restart the kernel. If the guest is already wedged, an ACPI shutdown does not get through, and `virsh destroy win11` is the only way out.
- **Bound every wait.** Pass `timeout=` to `run()`, `wait()`, `step*()`, and `command()`, so a cell cannot block the kernel indefinitely. `run(timeout=...)` returns `None` while the guest keeps running, and `dbg.interrupt()` breaks in.
- The default handshake window is 8 s. For a slow guest, pass `kd_handshake_timeout=60` (or set `NTOSEYE_KD_TIMEOUT=60`).
- `NTOSEYE_TRACE=kd` (set before the kernel starts) writes the KD packet exchange to stderr. It is the fastest way to tell a broken transport from a slow one.
- Only one ntoseye instance can hold a transport. The SDK, the REPL, and `ntoseye mcp` each attach themselves, and a second attach fails at once on the per-target instance lock.

## Debugging From The Kernel

Stop at the driver's load, before `DriverEntry`, with the deferred breakpoints already armed:

```python
dbg.exceptions.set_module_event("ld", "mydrv", mode="break")
stop = dbg.run(timeout=120)          # now start the service via QGA
if isinstance(stop, Stop.ModuleLoad):
    print(stop.module.name, hex(stop.module.base))
    bp = dbg.breakpoints.add("mydrv!DispatchCreate")
```

Run to a hit and inspect it:

```python
match dbg.run(timeout=30):
    case None:
        print("still running")
    case Stop.Breakpoint() as stop if stop.hit(bp):
        thread = dbg.threads[stop.thread]
        for frame in thread.backtrace(limit=8):
            print(frame)
        print(dbg.command("dv /t"))
    case stop:
        print("stopped:", stop.kind, stop.symbol)
```

Other building blocks:

- `dbg.breakpoints.add(target, hardware=True)` sets a debug-register execute breakpoint that writes no guest memory, and `dbg.breakpoints.watch(addr, access="write", length=8)` sets a data watchpoint. AMD64 has four debug-register slots. `condition=` takes a debugger expression and `when=` a Python predicate.
- `dbg.step()`, `dbg.step_over()`, `dbg.step_out()`, and `dbg.step(until="call" | "ret" | "branch" | addr)` give synchronous stepping.
- `dbg.types["mydrv!_DEVICE_EXTENSION"].at(addr)` returns a live struct cursor (fields as attributes, `follow("Ptr")` to dereference a pointer). `dbg.memory.read(addr, n)` reads kernel virtual memory, and `proc.memory` a process's.
- `dbg.cpus[n].idt()` and `.gdt()` decode the descriptor tables. `dbg.command("!pool <addr>")` and `!poolfind` inspect pool allocations.
- `dbg.inspect.triage()` returns what `!analyze` reports, as a structured record. On a bugcheck stop, start there.
- When no typed method fits, use `dbg.command(line, timeout=...)`. REPL state, such as aliases, the radix, and `$vars`, persists between calls.

After a guest reboot (`Stop.Reload`), query process, module, and thread handles again: old handles raise `StaleHandleError`. Breakpoints persist across the reboot.

## Driver Symbols

Your own driver's private PDB does not come from a symbol server. Put the build output directory on the symbol path, then reload:

```python
dbg.symbols.path = [*dbg.symbols.path, "/home/user/dev/windows_shared"]
dbg.symbols.reload(module="mydrv")
dbg.symbols.source_path = ["/home/user/dev/mydrv"]
```

If no symbol source has the PDB, ntoseye reads it from the guest's file cache when the PDB was built in the guest recently. See `docs/using/drivers.md#symbols`.

## Reconfiguring the VM

`ntoseye configure` is interactive and requires the VM to be **shut off**. It makes a backup of the domain XML and prints the guest-side `bcdedit` commands and the launch command:

```bash
LIBVIRT_DEFAULT_URI=qemu:///system ntoseye configure
```

Switching to KDNET sets the Hyper-V vendor ID to `KVMKVMKVM`, which needs a **full power cycle**: a Windows reboot is not enough. The guest side is:

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.122.1 port:50000
```

The second command prints the new key. A single NIC does not need `busparams` (and this build rejects `bcdedit /set {dbgsettings} busparams`).

KDNET requires an Intel `e1000`-family NIC and does **not** work over virtio-net. This VM already uses `e1000e` (QEMU's Intel 82574L). KDCOM also works unprivileged (libvirt creates `/tmp/ntoseye-kd.sock` with mode 775 and owner `libvirt-qemu:kvm`, and this user is in `kvm`), but at 115200 baud a cold attach is impractically slow, so prefer KDNET.

## Driver Deploy Loop

Split the work this way:

- Build on the Linux host.
- Put the `.sys`, `.pdb`, test executables, and deploy scripts in the virtiofs shared folder.
- Use QGA `guest-exec` to run PowerShell or `cmd.exe` in the guest.
- Copy from virtiofs to a normal NTFS path, such as `C:\drv` or `C:\Windows\System32\drivers`, before loading the driver.
- Use the SDK session for breakpoints, register and memory inspection, stop-state recovery, and crash analysis.

Do not load a driver directly from the shared folder unless that path has been tested. Copying to NTFS avoids edge cases in path visibility, filesystem semantics, locking, and policy.

Example guest deploy script:

```powershell
$src = "Z:\MyDrv.sys"
$dst = "C:\drv\MyDrv.sys"

New-Item -ItemType Directory -Force C:\drv | Out-Null
Copy-Item $src $dst -Force

sc.exe stop MyDrv | Out-Null
sc.exe delete MyDrv | Out-Null
sc.exe create MyDrv type= kernel binPath= $dst | Out-Null
sc.exe start MyDrv
```

While the debugger holds the guest stopped, QGA cannot run anything. Resume first (`dbg.run(timeout=0)`, or a `run(timeout=...)` that waits for the module-load stop), then trigger the load through QGA from the shell.

## QGA Helper

Use `scripts/qga-exec.py` to avoid JSON quoting and base64 decoding mistakes:

```bash
python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py \
  --domain win11 -- 'C:\Windows\System32\cmd.exe' /c whoami
```

For PowerShell deploys:

```bash
python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py \
  --domain win11 \
  -- 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
  -ExecutionPolicy Bypass -File 'Z:\deploy.ps1'
```

The raw form is `virsh -c qemu:///system qemu-agent-command win11 '{"execute":"guest-exec",...}'` followed by `guest-exec-status`. The `out-data` and `err-data` fields are base64 encoded.

## Safety Rules

- Re-read the latest trace, crash, or debugger output before you revise a diagnosis.
- Prefer evidence from the local driver, the local kernel image, the local VM, and the current ntoseye checkout over generic claims about Windows internals.
- Do not reboot, reset, or destroy VM state unless the user asked for it or the VM is already unrecoverable. A guest wedged by a killed KD session counts as unrecoverable (see Attach Rules).
- If the guest wedges, expect QGA to stop answering. Use the SDK session, the QEMU monitor or QMP, libvirt state, or a VM reset to recover.
- If you use SSH instead of QGA, treat it as a control shell. Keep file transfer on virtiofs when a shared folder is already present.
