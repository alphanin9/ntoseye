---
name: ntoseye-windows-driver-debugging
description: Windows kernel driver debugging workflow for NTOSEYE-backed QEMU/libvirt Windows VMs, driven from a persistent Python kernel through the ntoseye Python SDK. Use when an agent needs to debug, deploy, reload, or triage a Windows kernel driver with NTOSEYE over KDNET/KDCOM, virtiofs shared folders, QEMU Guest Agent command execution, libvirt/virsh, or host-to-guest driver iteration.
---

# NTOSEYE Windows Driver Debugging

## Overview

Keep Windows driver work anchored to the local VM/debugger setup instead of generic Windows administration:

- **Debugger:** the `ntoseye` Python SDK over KDNET, driven from a persistent Python kernel (the harness's `eval` tool, a Jupyter kernel). It is also the crash-recovery channel.
- **Files:** virtiofs when the domain has a `<filesystem>` device, otherwise QGA `guest-file-write`.
- **Guest control:** QEMU Guest Agent (or SSH).

The SDK is the same debugger core as the REPL. `dbg.command("...")` runs any WinDbg-style REPL line, and the typed namespaces (`dbg.processes`, `dbg.modules`, `dbg.breakpoints`, `dbg.types`, `dbg.memory`, ...) return structured values, so a cell can filter and walk the data and print only what matters. The upstream docs are the API reference: `docs/scripting/sdk.md`, the type stub `python/ntoseye/_ntoseye.pyi` (every method, with docstrings), and `docs/using/drivers.md` (driver development from a Linux host).

## First Pass

Discover the actual local setup rather than assuming it:

- `virsh -c qemu:///system list --all` finds the VM. On this host the domain is `win11`.
- `ntoseye status` prints the configured debug transports, endpoints, and launch commands. It reads the *default* libvirt URI, so run it as `LIBVIRT_DEFAULT_URI=qemu:///system ntoseye status`, or the system domains do not appear. If it reports `Debug backend: not configured` on a KDNET guest, check by attaching: KDNET adds no XML device, only the Hyper-V vendor ID.
- Inspect the QEMU command line with `ps -eo pid,cmd | rg -i "qemu|virtiofs|guest-agent|qga|qmp|serial"`.
- Use an existing virtiofs share for moving files when there is one: `virsh -c qemu:///system dumpxml win11 | rg -A4 '<filesystem'`. One earlier setup exposed `virtiofsd --shared-dir /home/user/dev/windows_shared` with the fs tag `win_share`, mounted in the guest as `Z:`. Without a `<filesystem>` device (as on this VM in the last session), push files over QGA instead (see Driver Deploy Loop).
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

Run the Python kernel from that venv (or `pip install ntoseye` for the latest release instead). The install is editable, so a kernel running a different interpreter can `sys.path.insert(0, "/home/user/dev/ntoseye/python")` instead: a plain site-packages path does not work, because the editable `.pth` file is not processed. After a rebuild, a long-lived kernel still has the old native module loaded. `ntoseye.build` holds the commit stamp of the loaded extension (`<commit>` or `<commit>-dirty`). If it differs from `git rev-parse --short=12 HEAD`, restart the kernel, but close the debugger first (see Attach Rules).

**No `sudo`.** KDNET carries both run control and memory over the debug transport, so the kernel runs as your normal user. Root is only needed to read guest RAM from the QEMU process (`memory_source="host"`, and the `gdb` and `memory` backends), and QEMU runs as `libvirt-qemu`. With the default `memory_source="auto"`, an unprivileged attach prints that host memory is unavailable and falls back to KD memory. This is the intended path, not an error. Pass `memory_source="kd"` to skip the probe.

## Attaching

Read the current KDNET key from the guest instead of hardcoding it, because `bcdedit /dbgsettings net` generates a new key each time it runs. `bcdedit` output is CRLF, and a trailing `\r` makes the last key component 14 characters, which ntoseye rejects with `invalid KDNET key component`:

```bash
KEY=$(python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py --domain win11 \
  -- 'C:\Windows\System32\cmd.exe' /c 'bcdedit /enum {dbgsettings}' \
  | tr -d '\r' | awk '/^key/{print $2}')
```

The guest targets `192.168.122.1:50000` (the host's `virbr0` address), and the `kdnet` backend listens on `0.0.0.0:50000` by default, so `connect` is not needed.

**Warm the symbol cache from a shell first.** A cold attach downloads and indexes the kernel's PDBs, which can take minutes, and the harness can kill the kernel cell during it. The guest then stays frozen (see Attach Rules). After a guest update or a new symbol cache, run one attach-and-close as a standalone script so the slow part happens outside the kernel:

```bash
python/.venv/bin/python -c 'import ntoseye,sys; ntoseye.attach("kdnet", key=sys.argv[1], memory_source="kd", kd_handshake_timeout=60).close()' "$KEY"
```

A warm attach then takes a few seconds. Keep one `Debugger` alive across cells, and do not use a `with` block that spans cells:

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
- **Never kill a live session.** If the Python kernel is killed, restarted, or times out while it is attached, the target stays frozen at the break-in: QEMU still reports `running`, but the guest spins in the KD stub and QGA stops answering. Call `dbg.close()` before you restart the kernel. To recover a wedged guest, attach again and close: `ntoseye.attach(...)` handshakes with the waiting target, and `close()` resumes it, after which `guest-ping` answers again. An ACPI shutdown does not get through; use `virsh destroy win11` only if a new attach also fails.
- **While the guest is stopped, QGA cannot run anything.** Resume first (`dbg.run(timeout=0)` returns at once with the guest running), trigger the guest action through QGA, then collect the stop with `dbg.wait(timeout=...)`. A cell that blocks in `run(timeout=...)` cannot also drive QGA, unless the QGA call runs in a parallel tool call.
- **Bound every wait.** Pass `timeout=` to `run()`, `wait()`, `step*()`, and `command()`, so a cell cannot block the kernel indefinitely. `run(timeout=...)` returns `None` while the guest keeps running, and `dbg.interrupt()` breaks in.
- The default handshake window is 8 s. For a slow guest, pass `kd_handshake_timeout=60` (or set `NTOSEYE_KD_TIMEOUT=60`).
- `NTOSEYE_TRACE=kd` (set before the kernel starts) writes the KD packet exchange to stderr. It is the fastest way to tell a broken transport from a slow one.
- Only one ntoseye instance can hold a transport. The SDK, the REPL, and `ntoseye mcp` each attach themselves, and a second attach fails at once on the per-target instance lock.

## Debugging From The Kernel

Stop in `DriverEntry` with a deferred breakpoint. Put the build directory on the symbol path, add the breakpoint before the driver loads, resume, then start the service through QGA. ntoseye arms the breakpoint when the target reports the load, before `DriverEntry` runs:

```python
dbg.symbols.path = [*dbg.symbols.path, "/path/to/build/release"]
bp = dbg.breakpoints.add("mydrv!DriverEntry")      # deferred until mydrv loads
dbg.exceptions.set_module_event("ld", "mydrv", mode="break")  # optional: stop at the load itself
dbg.run(timeout=0)                                  # then, from the shell: sc start MyDrv
```

Then collect the stops with `dbg.wait(timeout=...)`: first `Stop.ModuleLoad` (at `nt!DebugService2`) if the filter is set, then `Stop.Breakpoint` at `mydrv!DriverEntry`. While the driver sits in `DriverEntry`, `sc start` blocks and QGA stops answering until you resume.

**Limitation: a driver image without a debug directory loads silently.** Load filters, deferred breakpoints, and the module list all depend on the target reporting the load (the `LoadSymbols` state change). On this guest, a `slopfuscator_hello.sys` build with a CodeView (`RSDS`) record was reported. An obfuscated build without one was not: `NTOSEYE_TRACE=kd` showed only the `.kdfiles` lookup. The two builds differ in more than the debug record, so the debug record is the likely cause, not a proven one. With such an image, the `ld` filter never stops, the deferred breakpoint stays `deferred` while `DriverEntry` runs past it, and `dbg.modules` and `lm` miss the driver until `dbg.command(".reload", timeout=120)` or a new attach. A `module+offset` breakpoint cannot be deferred either (`SymbolNotFoundError` while the module is not loaded). Check the image before you deploy it: `python3 -c "import sys; print(open(sys.argv[1],'rb').read().find(b'RSDS') >= 0)" MyDrv.sys`. For an image without one, stop after the load instead: resume, start the service, `interrupt()`, `.reload`, then set breakpoints in the loaded image. For example, `dbg.drivers` gives the driver object's `driver_unload`.

The symbols must also match the deployed image: an `lm` entry with symbols `failed` and `pdb -` means ntoseye found no debug record to match a PDB against. Check `dbg.command("lmv m mydrv")`.

Run to a hit and inspect it:

```python
match dbg.wait(timeout=30):
    case None:
        print("still running")
    case Stop.Breakpoint() as stop if stop.hit(bp):
        thread = dbg.threads[stop.thread]
        for frame in thread.backtrace(limit=8):
            print(frame)
        print(dbg.command("dv", timeout=30))
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

Without virtiofs, write the file straight to its NTFS path through QGA. The guest must be running, and `C:\drv` must exist (`qga-exec.py -- 'C:\Windows\System32\cmd.exe' /c 'mkdir C:\drv'`):

```python
import base64, json, subprocess
def qga(payload):
    out = subprocess.run(["virsh", "-c", "qemu:///system", "qemu-agent-command", "win11", json.dumps(payload)],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["return"]
data = open("/path/to/MyDrv.sys", "rb").read()
handle = qga({"execute": "guest-file-open", "arguments": {"path": r"C:\drv\MyDrv.sys", "mode": "wb"}})
for i in range(0, len(data), 48000):
    qga({"execute": "guest-file-write", "arguments": {"handle": handle, "buf-b64": base64.b64encode(data[i:i + 48000]).decode()}})
qga({"execute": "guest-file-close", "arguments": {"handle": handle}})
```

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

While the debugger holds the guest stopped, QGA cannot run anything. Resume first with `dbg.run(timeout=0)`, then trigger the load through QGA from the shell.

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
