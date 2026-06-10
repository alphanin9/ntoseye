---
name: ntoseye-windows-driver-debugging
description: Windows kernel driver debugging workflow for NTOSEYE-backed QEMU/libvirt Windows VMs. Use when Codex needs to debug, deploy, reload, or triage a Windows kernel driver with NTOSEYE/KD, QEMU gdbstub hardware breakpoints, virtiofs shared folders, QEMU Guest Agent command execution, libvirt/virsh, or host-to-guest driver iteration.
---

# NTOSEYE Windows Driver Debugging

## Overview

Use this skill to keep Windows driver work anchored to the local VM/debugger setup instead of generic Windows administration. Treat NTOSEYE/KD as the debugger and crash-recovery channel, virtiofs as the file-transfer channel, and QEMU Guest Agent or SSH as the guest-control channel.

## First Pass

Start by discovering the actual local setup:

- Use `virsh -c qemu:///system list --all` to find the VM.
- Inspect the QEMU command line with `ps -eo pid,cmd | rg -i "qemu|virtiofs|guest-agent|qga|qmp|serial"`.
- Prefer existing virtiofs mounts for bytes. In the known setup, libvirt exposes `virtiofsd --shared-dir /home/user/dev/windows_shared` and the QEMU fs tag is `win_share`. This may not be the case for other setups.
- Test QGA before assuming it is usable:

```bash
virsh -c qemu:///system qemu-agent-command 'Win11 Debug target' \
  '{"execute":"guest-ping"}'
```

If `guest-ping` succeeds, QGA command execution is available. On the current Windows debug VM, `guest-exec` runs as `nt authority\system`.
In `virt-manager`-based setups, QEMU will expose a serial port at COM1 that can be listened to via a PTY on `virsh -c qemu:///system console {domain}`. Reading directly from the serial port will generally require root, which is inadvisable.

## Driver Deploy Loop

Use this split:

- Build on the Linux host.
- Put `.sys`, `.pdb`, test executables, and deploy scripts in the virtiofs shared folder.
- Use QGA `guest-exec` to run PowerShell or `cmd.exe` in the guest.
- Copy from virtiofs into a normal NTFS path before driver loading, such as `C:\drv` or `C:\Windows\System32\drivers`.
- Use NTOSEYE/KD for breakpoints, register/memory inspection, stop-state recovery, and crash analysis.

Do not load a driver directly from the shared folder unless that path has been tested. Copying to NTFS avoids path visibility, filesystem semantics, locking, and policy edge cases.

## Local NTOSEYE Launch

On the current machine, launch NTOSEYE with `sudo` when using the KVM/QEMU-backed debugger path:

```bash
sudo /usr/local/bin/ntoseye
```

`/usr/local/bin/ntoseye` is a symlink to `/home/user/dev/ntoseye/target/debug/ntoseye`, so rebuilding the debug binary updates the command automatically. Preserve any backend and agent arguments after the executable, for example:

```bash
sudo /usr/local/bin/ntoseye --backend gdb --connect 127.0.0.1:1234 --agent-stdio
sudo /usr/local/bin/ntoseye --backend memory
```

Treat this as a requirement of this host's KVM/QEMU access setup, not a universal NTOSEYE requirement.

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

QGA manual pattern:

```bash
virsh -c qemu:///system qemu-agent-command 'Win11 Debug target' \
  '{"execute":"guest-exec","arguments":{"path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","arg":["-ExecutionPolicy","Bypass","-File","Z:\\deploy.ps1"],"capture-output":true}}'

virsh -c qemu:///system qemu-agent-command 'Win11 Debug target' \
  '{"execute":"guest-exec-status","arguments":{"pid":PID_HERE}}'
```

`out-data` and `err-data` are base64 encoded.

## QGA Helper

Use `scripts/qga-exec.py` to avoid JSON quoting and base64 decoding mistakes:

```bash
python3 ~/.codex/skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py \
  --domain 'Win11 Debug target' \
  -- 'C:\Windows\System32\cmd.exe' /c whoami
```

For PowerShell deploys:

```bash
python3 ~/.codex/skills/ntoseye-windows-driver-debugging/scripts/qga-exec.py \
  --domain 'Win11 Debug target' \
  -- 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
  -ExecutionPolicy Bypass -File 'Z:\deploy.ps1'
```

## Agent Stdio

When the task involves controlling NTOSEYE programmatically, read `references/agent-stdio.md` for the command reference. The protocol is newline-delimited JSON over stdin/stdout:

```bash
sudo /usr/local/bin/ntoseye --backend gdb --connect 127.0.0.1:1234 --agent-stdio
```

Use the agent interface for structured inspection and automation. Use the interactive REPL for exploratory manual sessions.

## NTOSEYE Notes

Before changing debugger code, inspect the local checkout and current branch. Existing useful behavior in this repo includes:

- KD and QEMU gdbstub are separate debugger paths.
- Software breakpoints use GDB remote `Z0` / `z0` and guest `0xCC` patching.
- QEMU gdbstub hardware execution breakpoints use `Z1` / `z1`.
- The repo advertises `hwbreak+` and exposes `hbp <address>` for hardware breakpoints.
- `bp` should remain the software-breakpoint path.
- Exact-RIP hardware breakpoint hits must not go through RIP-minus-one `int3` rewind logic.
- `cregs` / `control-registers` and `trap-frame` / `tf` exist for architectural inspection when available in the checkout.

For VMM-layer breakpoint ideas, keep the boundary clear: nested page table behavior belongs below Windows in QEMU/KVM/VMM behavior, not in the guest kernel. Host memory access in this repo goes through `/dev/kvm` plus QEMU process memory mechanisms.

## Safety Rules

- Re-read the latest trace, crash, or debugger output before revising a diagnosis.
- Prefer evidence from the local driver, local kernel image, local VM, and current NTOSEYE checkout over generic Windows internals claims.
- Do not reboot, reset, or destroy VM state unless the user asked for it or the VM is already unrecoverable.
- If the guest wedges, expect QGA to stop responding; use KD/NTOSEYE, QEMU monitor/QMP, libvirt state, or VM reset workflows for recovery.
- If using SSH instead of QGA, remember it is mainly a control shell. Keep file transfer on virtiofs when a shared folder is already present.
