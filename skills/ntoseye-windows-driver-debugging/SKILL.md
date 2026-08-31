---
name: ntoseye-windows-driver-debugging
description: Windows kernel driver debugging workflow for NTOSEYE-backed QEMU/libvirt Windows VMs. Use when Codex needs to debug, deploy, reload, or triage a Windows kernel driver with NTOSEYE over KDNET/KDCOM, virtiofs shared folders, QEMU Guest Agent command execution, libvirt/virsh, or host-to-guest driver iteration.
---

# NTOSEYE Windows Driver Debugging

## Overview

Use this skill to keep Windows driver work anchored to the local VM/debugger setup instead of generic Windows administration. Treat NTOSEYE over KDNET as the debugger and crash-recovery channel, virtiofs as the file-transfer channel, and QEMU Guest Agent or SSH as the guest-control channel.

## First Pass

Discover the actual local setup rather than assuming it:

- `virsh -c qemu:///system list --all` to find the VM. On this host the domain is `win11`.
- `ntoseye status` prints configured debug transports, endpoints, and launch commands. It reads the *default* libvirt URI, so run it as `LIBVIRT_DEFAULT_URI=qemu:///system ntoseye status` or the system domains will not appear. **It reports `Debug backend: not configured` for a KDNET guest** — it only detects the KD serial socket and the gdbstub's qemu args, and KDNET adds no XML device (just the Hyper-V vendor ID). That is a `status` blind spot, not a broken VM; confirm KDNET by attaching.
- Inspect the QEMU command line with `ps -eo pid,cmd | rg -i "qemu|virtiofs|guest-agent|qga|qmp|serial"`.
- Prefer existing virtiofs mounts for bytes. In the known setup, libvirt exposes `virtiofsd --shared-dir /home/user/dev/windows_shared` and the QEMU fs tag is `win_share`. This may not be the case for other setups.
- Test QGA before assuming it is usable:

```bash
virsh -c qemu:///system qemu-agent-command win11 '{"execute":"guest-ping"}'
```

If `guest-ping` succeeds, QGA command execution is available. On this VM, `guest-exec` runs as `nt authority\system`, which is enough for `bcdedit` and `sc.exe`.

## Launching NTOSEYE

**No `sudo`.** The debugger runs as your normal user:

```bash
/usr/local/bin/ntoseye --backend kdnet --kdnet-key <KEY> agent
```

`/usr/local/bin/ntoseye` is a symlink to `/home/user/dev/ntoseye/target/debug/ntoseye`, so rebuilding the debug binary updates the command automatically.

Read the current KDNET key from the guest rather than hardcoding it — it is regenerated whenever `bcdedit /dbgsettings net` is reapplied:

```bash
python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py --domain win11 \
  -- 'C:\Windows\System32\cmd.exe' /c 'bcdedit /enum {dbgsettings}'
```

The guest targets `192.168.122.1:50000` (the host's `virbr0` address); NTOSEYE listens on `0.0.0.0:50000`.

`bcdedit` output is CRLF, so strip carriage returns when scripting the key out — a trailing `\r` makes the final component 14 characters and NTOSEYE rejects it with `invalid KDNET key component`:

```bash
KEY=$(python3 skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py \
  -- 'C:\Windows\System32\cmd.exe' /c 'bcdedit /enum {dbgsettings}' \
  | tr -d '\r' | awk '/^key/{print $2}')
```

### Why KDNET and not the GDB stub

Root was only ever needed because the GDB and `memory` backends read guest RAM through the QEMU process (`process_vm_readv` on a `/dev/kvm` holder), and QEMU runs as `libvirt-qemu`. KD and KDNET carry both control *and* memory over the debug transport, so they need no hypervisor access at all.

Expect this on every unprivileged start, and ignore it — it is the intended path, not an error:

```
kdnet: host memory unavailable (VM process not found ...); falling back to KD memory
kdnet: memory source kd; remote reads may be slow.
```

### Why KDNET and not KDCOM

KDCOM works unprivileged too (libvirt creates `/tmp/ntoseye-kd.sock` mode 775, owner `libvirt-qemu:kvm`, and this user is in the `kvm` group), but it is unusable in practice here. NTOSEYE re-walks the guest page tables over the wire for every read, so a 2 KB read costs five round trips. Measured on this VM:

| | KDCOM (115200 baud) | KDNET (e1000e) |
| --- | --- | --- |
| Effective read throughput | ~32 KB/s | fast enough not to matter |
| Cold attach | did not finish in 20 min | ~1 min |
| Warm attach (PDBs cached) | — | ~20 s |

`Target::with_remote_phys` eagerly loads *all* kernel module symbols at attach, and ntoskrnl alone is ~21 MB, so the KDCOM cost is paid up front on every session.

KDNET requires an Intel `e1000`-family NIC — it does **not** work over virtio-net. This VM already uses `e1000e` (QEMU's Intel 82574L).

## Attach Rules

These are failure modes that cost real time if rediscovered:

- **Wait for the guest to finish booting before attaching.** Attaching mid-boot lands in a module-load storm and the kernel PE read never stabilises; NTOSEYE gives up with `PE view failed`. Gate on `guest-ping` succeeding.
- **Do not `step` while a software breakpoint is set (KD/KDNET).** Confirmed on this VM: after `step`, `bp.clear` fails with `no breakpoint tracked at 0x...` and the breakpoint stays listed but unclearable. Resuming the guest afterwards executes a stray `int3` with nothing tracking it and bugchecks `0x7F` (UNEXPECTED_KERNEL_MODE_TRAP, double fault). Clear every breakpoint *before* stepping.

  Mechanism: `BreakpointManager::refresh_enabled` runs `uninstall` (ignoring its error) then `install_existing_breakpoint`, and `Session::step` swallows the whole result with `let _ =`. When the re-install fails, the KD backend's `bp_handles` entry is gone while the manager still believes the breakpoint is installed. This is upstream code — `src/session.rs` and `src/kd/mod.rs` are unmodified in this fork — not a fork regression.

- **Never `SIGKILL` a KD/KDNET session.** The target stays frozen at the break-in: QEMU still reports `running`, but the guest is spinning in the KD stub and QGA goes silent. Exit the agent by closing stdin so it resumes the target. If it is already wedged, ACPI shutdown will not land and `virsh destroy win11` is the only way out.
- The handshake window is 8 s by default. If the guest is slow, raise it: `NTOSEYE_KD_TIMEOUT=60`.
- `NTOSEYE_KD_TRACE=1` dumps the KD packet exchange to stderr — the fastest way to tell "transport broken" from "transport slow".
- Only one NTOSEYE instance may hold a given transport; a second attach fails fast on the per-target instance lock.

## Reconfiguring the VM

`ntoseye configure` replaces the old `ntoseye virsh` subcommand. It is interactive, requires the VM to be **shut off**, backs up the domain XML, and prints the guest-side `bcdedit` commands plus the launch command:

```bash
LIBVIRT_DEFAULT_URI=qemu:///system ntoseye configure
```

Switching to KDNET sets the Hyper-V vendor ID to `KVMKVMKVM`, which needs a **full power cycle** — a Windows reboot is not enough. The guest side is:

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.122.1 port:50000
```

`bcdedit` prints the new key when the second command runs. `busparams` is unnecessary with a single NIC (and `bcdedit /set {dbgsettings} busparams` is rejected on this build).

## Driver Deploy Loop

Use this split:

- Build on the Linux host.
- Put `.sys`, `.pdb`, test executables, and deploy scripts in the virtiofs shared folder.
- Use QGA `guest-exec` to run PowerShell or `cmd.exe` in the guest.
- Copy from virtiofs into a normal NTFS path before driver loading, such as `C:\drv` or `C:\Windows\System32\drivers`.
- Use NTOSEYE for breakpoints, register/memory inspection, stop-state recovery, and crash analysis.

Do not load a driver directly from the shared folder unless that path has been tested. Copying to NTFS avoids path visibility, filesystem semantics, locking, and policy edge cases.

Example guest deploy script shape:

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

Local symbols for your own driver do not come from a symbol server: load the build's PDB from a host directory with the agent's `load-symbols` command.

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

The raw form is `virsh -c qemu:///system qemu-agent-command win11 '{"execute":"guest-exec",...}'` followed by `guest-exec-status`; `out-data` and `err-data` are base64 encoded.

## Agent Stdio

When the task involves controlling NTOSEYE programmatically, read `references/agent-stdio.md` for the command reference. The protocol is newline-delimited JSON over stdin/stdout:

```bash
/usr/local/bin/ntoseye --backend kdnet --kdnet-key <KEY> agent
```

Use the agent interface for structured inspection and automation. Use the interactive REPL for exploratory manual sessions.

## NTOSEYE Notes

Before changing debugger code, inspect the local checkout and current branch. Current behaviour on this base:

- KDNET, KDCOM, the QEMU gdbstub, and passive `memory` introspection are four separate backends behind one shared debugger core.
- KD and KDNET report a strict superset of the gdbstub's capabilities: execution control, single step, register read/write, context enumeration/selection, kernel **and usermode** breakpoints, data watchpoints, reload detection, bugcheck stop detection and details, and debug output.
- Software breakpoints patch `0xCC` for the AMD64 user-process path; kernel breakpoints go through the target's own debugger API.
- Hardware watchpoints (`ba`) are AMD64-only and live in the debug registers, so they are identified by DR6 rather than by RIP.
- `trap-frame` / `tf` decodes architectural trap frames.

For VMM-layer breakpoint ideas, keep the boundary clear: nested page table behavior belongs below Windows in QEMU/KVM/VMM behavior, not in the guest kernel.

## Safety Rules

- Re-read the latest trace, crash, or debugger output before revising a diagnosis.
- Prefer evidence from the local driver, local kernel image, local VM, and current NTOSEYE checkout over generic Windows internals claims.
- Do not reboot, reset, or destroy VM state unless the user asked for it or the VM is already unrecoverable. A guest wedged by a killed KD session counts as unrecoverable — see Attach Rules.
- If the guest wedges, expect QGA to stop responding; use NTOSEYE, QEMU monitor/QMP, libvirt state, or VM reset workflows for recovery.
- If using SSH instead of QGA, remember it is mainly a control shell. Keep file transfer on virtiofs when a shared folder is already present.
