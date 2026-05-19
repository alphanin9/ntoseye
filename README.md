<img align="right" width="28%" src="media/ntoseye.png">

# ntoseye ![license](https://img.shields.io/badge/license-MIT-blue) [![crates.io](https://img.shields.io/crates/v/ntoseye.svg)](https://crates.io/crates/ntoseye)

Windows kernel debugger for Linux hosts running Windows under KVM/QEMU. Essentially, WinDbg for Linux.

## Features

- Command line interface
- WinDbg style commands
- Kernel debugging
- PDB fetching & parsing for offsets
- Breakpointing (kernel, usermode)
- Two debug backends: QEMU's `gdbstub` (default) and Windows KD over a serial pipe (KDCOM, see [Choosing a backend](#choosing-a-backend))

### Supported Windows

`ntoseye` currently only supports Windows 10 and 11 guests.

### Disclaimer

`ntoseye` needs to download symbols to initialize required offsets, it will only download symbols from Microsoft's official symbol server. All files which will be read/written to will be located in `$XDG_CONFIG_HOME/ntoseye`.

### Preview

![ntos](media/preview.png)

# Getting started

## Install via cargo

```bash
cargo install ntoseye
```

## Building

```bash
git clone https://github.com/dmaivel/ntoseye.git
cd ntoseye
cargo build --release
```

# Usage

It is recommended that you run the following command before running `ntoseye` or a VM:
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

Note that you may need to run `ntoseye` with `sudo` aswell (last resort, try command above first).

To view command line arguments, run `ntoseye --help`. The debugger is self documented, so pressing tab will display completions and descriptions for commands, symbols, and types.

For examples, refer [here](#usage-examples).

## Choosing a backend

`ntoseye` can talk to the guest two ways. Pick with `--backend gdb` (default) or `--backend kd`.

| | `gdb` (default) | `kd` |
|---|---|---|
| Transport | QEMU's `gdbstub` | Windows KD over a serial pipe (KDCOM) |
| Requires in-guest configuration | No (guest is unaware it's being debugged) | Yes (`bcdedit /debug on`; anti-debug code, PatchGuard, and some Windows behaviour change once enabled) |
| Supports usermode breakpoints | No | Yes |
| Native breakpoints | gdb `Z0` packets | `DbgKdWriteBreakPointApi` |

See [VM configuration](#vm-configuration) for the host-side setup of each backend.

## VM configuration

It is recommended to disable memory paging and memory compression within the guest operating system to avoid memory-related issues. This only needs to be done once per Windows installation. Run the following commands in PowerShell (Run as Administrator):
```
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
Get-CimInstance Win32_PageFileSetting | Remove-CimInstance
Disable-MMAgent -MemoryCompression
Restart-Computer
```

### GDBSTUB

Default backend. Expose QEMU's gdbstub on `127.0.0.1:1234` by passing `-s -S`.

#### QEMU

Append `-s -S` to the qemu command.

#### virt-manager

Add the following to the XML configuration:
```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-s"/>
    <qemu:arg value="-S"/>
  </qemu:commandline>
</domain>
```

### KDCOM

Run with `--backend kd`. In the guest, enable kernel debugging (run as Administrator, then reboot):
```
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```
Use `debugport:2` instead of `:1` if the KD chardev ends up as COM2 (see the virt-manager subsection below).

#### QEMU

Add a Unix-socket chardev and route a serial port to it:
```
-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd
```
Then connect: `ntoseye --backend kd`.

#### virt-manager

> [!WARNING]
> virt-manager auto-adds a `<serial>` console device on every VM, which
> claims COM1. Either replace that device with one pointing at the KD socket
> (KD becomes COM1, use `debugport:1`), or leave it and add the KD chardev
> via `qemu:commandline` (KD becomes COM2, use `debugport:2`).

**Option A (recommended):** replace the auto-added serial. KD is COM1, `debugport:1` is correct.
```xml
<serial type="unix">
  <source mode="bind" path="/tmp/ntoseye-kd.sock"/>
  <target type="isa-serial" port="0"/>
</serial>
```

**Option B:** keep the auto-added serial and append the KD chardev via `qemu:commandline`. KD is COM2, use `debugport:2`.
```xml
<domain xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0" type="kvm">
  ...
  <qemu:commandline>
    <qemu:arg value="-chardev"/>
    <qemu:arg value="socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off"/>
    <qemu:arg value="-serial"/>
    <qemu:arg value="chardev:kd"/>
  </qemu:commandline>
</domain>
```

## Credits

Functionality regarding initialization of guest information was written with the help of the following sources:

- [vmread](https://github.com/h33p/vmread)
- [pcileech](https://github.com/ufrisk/pcileech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
- [ReactOS](https://github.com/reactos/reactos)

## Usage examples

### Privilege escalation

1. Run `ps <filter>` to get the `EPROCESS` address of the process you wish to escalate
2. Run `eq (_EPROCESS)(AddressOfEPROCESS)->Token *(_EPROCESS)*PsInitialSystemProcess->Token` where `AddressOfEPROCESS` is the address from step 1