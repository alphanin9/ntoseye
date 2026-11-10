# Hyper-V

On a Windows host, `ntoseye` debugs Hyper-V VMs over KDNET or over KD on a serial port. It cannot read a Hyper-V VM's memory from the host, because Hyper-V keeps guest RAM in the protected `vmmem` process, so both backends read memory through the target, and the `gdb` and `memory` backends are not available.

`ntoseye configure` sets up either backend for a VM that is turned off. It needs an elevated terminal, or membership in the Hyper-V Administrators group. The rest of this page describes the same steps done by hand.

## KDNET

In a Hyper-V VM, Windows does not send KDNET through a network adapter. When `kdnet.dll` finds that it runs under Hyper-V, it uses a synthetic debug device instead, so the guest needs no NIC for debugging and ignores the `hostip` of its BCD settings. The host end of the device, the VM's worker process (`vmwp.exe`), listens on the VM's debug port, a UDP port that the VM's settings name. It sends the guest's datagrams to whichever address last sent a datagram to that port, and until one has, it drops them.

So the debugger makes the first move: `--connect target=HOST:PORT` binds an ephemeral port and pokes `HOST:PORT` until the target answers, the way WinDbg's `-k net:port=PORT,key=KEY,target=HOST` does. Whenever the target is quiet for a second, `ntoseye` pokes again, which also reconnects it to a VM that was turned off and on.

### Host

The VM's debug port is `DebugPort` in its `Msvm_VirtualSystemSettingData`, and `DebugPortEnabled` turns it on (1) or off (0). `kdnetdebugvm.ps1`, which ships with the Windows Debugging Tools, sets both. From an elevated prompt, with the VM turned off:

```powershell
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kdnetdebugvm.ps1" -vmname "<VM name>" -port 50000
```

The script also adds an inbound firewall rule for the port, which you need only to debug from another machine.

Each running VM needs its own port, because `vmwp.exe` binds the port exclusively. The host applies a change only when the VM is turned on, so a guest restart is not enough.

### Guest

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<any-ipv4> port:50000
Stop-Computer
```

`bcdedit /dbgsettings` shows the key that it generated. `kdnet.exe` inside the VM also detects Hyper-V, and prints the host command and the WinDbg command line.

### Attach

Start the VM, then on the host:

```powershell
ntoseye --backend kdnet --connect target=127.0.0.1:50000 --kdnet-key <key>
```

This does not need an elevated terminal. To debug from another machine, Linux or macOS included, connect to the Hyper-V host's address instead, and allow the port through the host's firewall:

```bash
ntoseye --backend kdnet --connect target=<hyperv-host>:50000 --kdnet-key <key>
```

:::{warning}
Anyone who can send a datagram to the debug port takes the guest's traffic over, and from then on only the key protects the session. Open the port only to networks you trust.
:::

Only one debugger can use a VM's debug port at a time: each one that pokes the port takes the traffic from the one before.

## KD over a serial port

Hyper-V serves a VM's COM port at a named pipe on the host. With the VM turned off, from an elevated prompt:

```powershell
Set-VMComPort -VMName "<VM name>" -Number 1 -Path \\.\pipe\ntoseye-kd
```

Generation 2 VMs have COM ports too, although Hyper-V Manager does not show them. In the guest:

```powershell
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
Stop-Computer
```

Start the VM, then run `ntoseye` from an elevated terminal: `\\.\pipe\ntoseye-kd` is the default for the `kd` backend on Windows, and Hyper-V serves the pipe only to administrators. For a different pipe, pass `--connect \\.\pipe\<name>`.

KD over a serial port is slower than KDNET, because a serial port moves about 11 KB per second.
