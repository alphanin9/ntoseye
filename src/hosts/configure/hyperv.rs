//! Hyper-V: KD over a guest COM port the host serves at a named pipe, and
//! KDNET over the synthetic debug device, whose host end (`vmwp.exe`)
//! listens on the VM's debug port (`Msvm_VirtualSystemSettingData.DebugPort`)
//! and forwards the guest's KDNET to whoever last sent to that port.
//!
//! Driven through Windows PowerShell's Hyper-V module and WMI, which need
//! an elevated terminal or membership in Hyper-V Administrators.

#![cfg_attr(not(windows), allow(dead_code))]

use std::process::Command;

use crate::DEFAULT_KD_SOCKET;
use crate::base::error::{Error, Result};

use super::{
    ApplyResult, BackendSelection, ConfigurationPlan, Configurator, ConfigureBackend,
    ConfigureRequest, ConfiguredTarget, Guest, GuestInspection, Instructions, ProbeStatus,
    backup_file, command_detail, serial_kd_instructions,
};

const BACKENDS: &[BackendSelection] = &[BackendSelection::Kd, BackendSelection::KdNet];
const RECORD_SEPARATOR: char = '\u{1e}';
const FIELD_SEPARATOR: char = '\u{1f}';
/// The guest COM port the KD pipe is attached to.
const KD_COM_PORT: usize = 1;
/// The first debug port handed out; the one `kdnet.exe` defaults to.
const FIRST_DEBUG_PORT: u32 = 50000;
/// `DebugPortEnabled`: off, on at `DebugPort`, on at a port the host picks
/// at power-on.
const DEBUG_PORT_OFF: u16 = 0;
const DEBUG_PORT_ON: u16 = 1;

/// Opens every script: the separators as variables (Windows PowerShell 5.1
/// has no `` `u{} `` escape) and UTF-8 output, so VM names survive.
const PRELUDE: &str = "$ErrorActionPreference = 'Stop'\n\
     [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
     $rs = [string][char]0x1e\n\
     $fs = [string][char]0x1f\n\
     $ns = 'root\\virtualization\\v2'\n";

const PROBE_SCRIPT: &str = "if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { 'missing'; exit }\n\
     try { $count = @(Get-VM).Count; 'ok' + $fs + $count } catch { 'denied' + $fs + $_.Exception.Message }\n";

const LIST_SCRIPT: &str = "(@(Get-VM) | ForEach-Object { $_.Id.ToString() + $fs + $_.Name + $fs + $_.State.ToString() }) -join $rs\n";

/// The realized (not snapshot) settings of every VM, as id, enabled, port.
const DEBUG_PORTS_SCRIPT: &str = "(@(Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSettingData -Filter \"VirtualSystemType='Microsoft:Hyper-V:System:Realized'\") | ForEach-Object { $_.ConfigurationID + $fs + $_.DebugPortEnabled + $fs + $_.DebugPort }) -join $rs\n";

pub struct HyperV;

impl Configurator for HyperV {
    fn name(&self) -> &'static str {
        "Hyper-V"
    }

    fn probe(&self) -> ProbeStatus {
        if !cfg!(windows) {
            return ProbeStatus::NotDetected;
        }
        match powershell(PROBE_SCRIPT) {
            Err(error) => ProbeStatus::Unavailable(error.to_string()),
            Ok(output) => {
                let mut fields = output.splitn(2, FIELD_SEPARATOR);
                match (fields.next(), fields.next()) {
                    (Some("ok"), Some(count)) => {
                        let count = count.trim();
                        ProbeStatus::Detected(format!(
                            "{count} virtual machine{}",
                            if count == "1" { "" } else { "s" }
                        ))
                    }
                    (Some("denied"), detail) => ProbeStatus::Unavailable(format!(
                        "{}; run from an elevated terminal or join Hyper-V Administrators",
                        detail.unwrap_or_default().trim()
                    )),
                    _ => ProbeStatus::NotDetected,
                }
            }
        }
    }

    fn guests(&self) -> Result<Vec<Guest>> {
        Ok(parse_guests(&powershell(LIST_SCRIPT)?))
    }

    fn inspect(&self, guest: &Guest) -> Result<GuestInspection> {
        Ok(inspect_settings(&read_settings(&guest.id)?))
    }

    fn supported_backends(&self) -> &'static [BackendSelection] {
        BACKENDS
    }

    fn plan(&self, guest: &Guest, request: ConfigureRequest) -> Result<Box<dyn ConfigurationPlan>> {
        let original = read_settings(&guest.id)?;
        let others = parse_debug_ports(&powershell(DEBUG_PORTS_SCRIPT)?)
            .into_iter()
            .filter(|(id, _)| !id.eq_ignore_ascii_case(&guest.id))
            .map(|(_, port)| port)
            .collect::<Vec<_>>();
        let configured = plan_settings(&original, request, &others)?;
        Ok(Box::new(HyperVPlan {
            guest_id: guest.id.clone(),
            guest_name: guest.name.clone(),
            changes: describe_changes(&original, &configured),
            instructions: hyperv_instructions(request, &configured),
            original,
            configured,
        }))
    }
}

/// What ntoseye reads and sets of a VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct DebugSettings {
    debug_port_enabled: u16,
    debug_port: u32,
    /// The pipe each COM port is attached to; empty when detached.
    com: [String; 2],
}

struct HyperVPlan {
    guest_id: String,
    guest_name: String,
    original: DebugSettings,
    configured: DebugSettings,
    changes: Vec<String>,
    instructions: Instructions,
}

impl ConfigurationPlan for HyperVPlan {
    fn changes(&self) -> &[String] {
        &self.changes
    }

    fn instructions(&self) -> &Instructions {
        &self.instructions
    }

    fn apply(&self) -> Result<ApplyResult> {
        let backup = backup_file(
            "hyperv",
            &self.guest_name,
            "txt",
            render_backup(&self.original).as_bytes(),
        )?;
        powershell(&write_script(
            &self.guest_id,
            &self.original,
            &self.configured,
        )?)?;
        if read_settings(&self.guest_id)? != self.configured {
            return Err(Error::DebugInfo(format!(
                "Hyper-V configuration verification failed; the original settings are backed up at {}",
                backup.display()
            )));
        }
        Ok(ApplyResult { backup })
    }
}

/// Run `script` in Windows PowerShell, which ships with every Windows that
/// has Hyper-V, and return its trimmed output.
fn powershell(script: &str) -> Result<String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(format!("{PRELUDE}{script}"))
        .output()
        .map_err(|error| Error::DebugInfo(format!("failed to run powershell.exe: {error}")))?;
    if !output.status.success() {
        return Err(Error::DebugInfo(format!(
            "Hyper-V PowerShell command failed: {}",
            command_detail(&output)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// A VM id, checked to be a GUID before it goes into a script.
fn checked_id(id: &str) -> Result<&str> {
    let groups = id.split('-').map(str::len).collect::<Vec<_>>();
    if groups == [8, 4, 4, 4, 12] && id.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err(Error::InvalidArgument(format!("not a Hyper-V VM id: {id}")))
    }
}

/// `value` as a single-quoted PowerShell string.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn settings_query(id: &str) -> String {
    format!(
        "Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemSettingData -Filter \
         \"ConfigurationID='{id}' AND VirtualSystemType='Microsoft:Hyper-V:System:Realized'\""
    )
}

fn read_settings(id: &str) -> Result<DebugSettings> {
    let id = checked_id(id)?;
    let script = format!(
        "$vm = Get-VM -Id {id}\n\
         $s = {query}\n\
         $c1 = (Get-VMComPort -VM $vm -Number 1).Path\n\
         $c2 = (Get-VMComPort -VM $vm -Number 2).Path\n\
         [string]$s.DebugPortEnabled + $fs + $s.DebugPort + $fs + $c1 + $fs + $c2\n",
        query = settings_query(id)
    );
    parse_settings(&powershell(&script)?)
}

fn write_script(id: &str, original: &DebugSettings, configured: &DebugSettings) -> Result<String> {
    let id = checked_id(id)?;
    let mut script = format!("$vm = Get-VM -Id {id}\n");
    for (index, (before, after)) in original.com.iter().zip(&configured.com).enumerate() {
        if before != after {
            script.push_str(&format!(
                "Set-VMComPort -VM $vm -Number {} -Path {}\n",
                index + 1,
                ps_quote(after)
            ));
        }
    }
    if (original.debug_port_enabled, original.debug_port)
        != (configured.debug_port_enabled, configured.debug_port)
    {
        // As kdnetdebugvm.ps1 sets it. A stopped VM's settings change at
        // once; a job (4096) is waited out all the same.
        script.push_str(&format!(
            "$svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemManagementService\n\
             $s = {query}\n\
             $s.DebugPortEnabled = {enabled}\n\
             $s.DebugPort = {port}\n\
             $r = $svc.ModifySystemSettings($s.GetText(1))\n\
             if ($r.ReturnValue -eq 4096) {{\n\
                 do {{ Start-Sleep -Milliseconds 100; $job = [wmi]$r.Job }} while ($job.JobState -lt 7)\n\
                 if ($job.JobState -ne 7) {{ throw \"ModifySystemSettings failed: $($job.ErrorDescription)\" }}\n\
             }} elseif ($r.ReturnValue -ne 0) {{ throw \"ModifySystemSettings returned $($r.ReturnValue)\" }}\n",
            query = settings_query(id),
            enabled = configured.debug_port_enabled,
            port = configured.debug_port,
        ));
    }
    Ok(script)
}

fn parse_guests(output: &str) -> Vec<Guest> {
    output
        .split(RECORD_SEPARATOR)
        .filter_map(|row| {
            let mut fields = row.trim().split(FIELD_SEPARATOR);
            let (Some(id), Some(name), Some(state)) = (fields.next(), fields.next(), fields.next())
            else {
                return None;
            };
            Some(Guest {
                id: id.to_string(),
                name: name.to_string(),
                stopped: state == "Off",
                state: state.to_string(),
            })
        })
        .collect()
}

fn parse_settings(output: &str) -> Result<DebugSettings> {
    let fields = output.split(FIELD_SEPARATOR).collect::<Vec<_>>();
    let invalid = || Error::DebugInfo(format!("unexpected Hyper-V settings output: {output:?}"));
    let [enabled, port, com1, com2] = fields.as_slice() else {
        return Err(invalid());
    };
    Ok(DebugSettings {
        debug_port_enabled: enabled.trim().parse().map_err(|_| invalid())?,
        debug_port: port.trim().parse().map_err(|_| invalid())?,
        com: [com1.trim().to_string(), com2.trim().to_string()],
    })
}

/// The debug port of each VM that has one enabled, by VM id.
fn parse_debug_ports(output: &str) -> Vec<(String, u32)> {
    output
        .split(RECORD_SEPARATOR)
        .filter_map(|row| {
            let mut fields = row.trim().split(FIELD_SEPARATOR);
            let id = fields.next()?;
            let enabled = fields.next()?.parse::<u16>().ok()?;
            let port = fields.next()?.parse::<u32>().ok()?;
            (enabled != DEBUG_PORT_OFF && port != 0).then(|| (id.to_string(), port))
        })
        .collect()
}

fn inspect_settings(settings: &DebugSettings) -> GuestInspection {
    let mut targets = settings
        .com
        .iter()
        .enumerate()
        .filter(|(_, pipe)| !pipe.is_empty())
        .map(|(index, pipe)| ConfiguredTarget::kd(pipe.clone(), index + 1, false))
        .collect::<Vec<_>>();
    if settings.debug_port_enabled != DEBUG_PORT_OFF && settings.debug_port != 0 {
        targets.push(ConfiguredTarget::kdnet(settings.debug_port));
    }
    GuestInspection { targets }
}

/// The settings `request` leaves the VM with. KD takes COM1 for the pipe;
/// KDNET turns the debug port on at a port no other VM holds, keeping one
/// already set. Each drops the other's ntoseye pipe; a COM port or debug
/// port someone else configured is never taken over.
fn plan_settings(
    original: &DebugSettings,
    request: ConfigureRequest,
    other_ports: &[u32],
) -> Result<DebugSettings> {
    let mut configured = original.clone();
    let kd_com = &mut configured.com[KD_COM_PORT - 1];
    let release_pipe = |com: &mut String| {
        if com == DEFAULT_KD_SOCKET {
            com.clear();
        }
    };
    match request {
        ConfigureRequest::Configure {
            backend: ConfigureBackend::Kd,
            ..
        } => {
            if !kd_com.is_empty() && kd_com != DEFAULT_KD_SOCKET {
                return Err(Error::DebugInfo(format!(
                    "COM{KD_COM_PORT} is already attached to {kd_com}; detach it first \
                     (Set-VMComPort -Number {KD_COM_PORT} -Path '')"
                )));
            }
            *kd_com = DEFAULT_KD_SOCKET.to_string();
        }
        ConfigureRequest::Configure {
            backend: ConfigureBackend::KdNet { .. },
            ..
        } => {
            release_pipe(kd_com);
            let keep = original.debug_port_enabled != DEBUG_PORT_OFF
                && original.debug_port != 0
                && !other_ports.contains(&original.debug_port);
            if !keep {
                configured.debug_port = (FIRST_DEBUG_PORT..=u16::MAX as u32)
                    .find(|port| !other_ports.contains(port))
                    .ok_or_else(|| Error::DebugInfo("no free Hyper-V debug port".into()))?;
            }
            configured.debug_port_enabled = DEBUG_PORT_ON;
        }
        #[cfg(any(target_os = "linux", test))]
        ConfigureRequest::Configure {
            backend: ConfigureBackend::Gdb | ConfigureBackend::KdAndGdb,
            ..
        } => {
            return Err(Error::DebugInfo(
                "Hyper-V only supports automatic configuration for KD and KDNET".into(),
            ));
        }
        ConfigureRequest::Remove => {
            configured.com.iter_mut().for_each(release_pipe);
            configured.debug_port_enabled = DEBUG_PORT_OFF;
            configured.debug_port = 0;
        }
    }
    Ok(configured)
}

fn describe_changes(original: &DebugSettings, configured: &DebugSettings) -> Vec<String> {
    let mut changes = Vec::new();
    for (index, (before, after)) in original.com.iter().zip(&configured.com).enumerate() {
        if before != after {
            changes.push(if after.is_empty() {
                format!("detach COM{} from {before}", index + 1)
            } else {
                format!("attach COM{} to {after}", index + 1)
            });
        }
    }
    if (original.debug_port_enabled, original.debug_port)
        != (configured.debug_port_enabled, configured.debug_port)
    {
        changes.push(if configured.debug_port_enabled == DEBUG_PORT_OFF {
            "turn off the KDNET debug port".to_string()
        } else {
            format!("serve KDNET on host UDP port {}", configured.debug_port)
        });
    }
    changes
}

fn render_backup(settings: &DebugSettings) -> String {
    format!(
        "DebugPortEnabled={}\nDebugPort={}\nCOM1={}\nCOM2={}\n",
        settings.debug_port_enabled, settings.debug_port, settings.com[0], settings.com[1]
    )
}

fn hyperv_instructions(request: ConfigureRequest, configured: &DebugSettings) -> Instructions {
    let power_cycle = "Shut the VM down and start it again after changing its BCD settings; \
                       the host applies a new debug configuration only at power-on."
        .to_string();
    match request {
        ConfigureRequest::Configure {
            backend: ConfigureBackend::Kd,
            ..
        } => {
            let mut instructions = serial_kd_instructions(DEFAULT_KD_SOCKET, KD_COM_PORT, false);
            instructions.guest[2] = "Stop-Computer".to_string();
            instructions.notes.push(power_cycle);
            instructions.notes.push(
                "Hyper-V serves the pipe only to an elevated client; run ntoseye elevated."
                    .to_string(),
            );
            instructions
        }
        ConfigureRequest::Configure {
            backend: ConfigureBackend::KdNet { host },
            ..
        } => {
            let port = configured.debug_port;
            Instructions {
                guest: vec![
                    "bcdedit /debug on".to_string(),
                    format!("bcdedit /dbgsettings net hostip:{host} port:{port}"),
                    "Stop-Computer".to_string(),
                ],
                run: vec![format!(
                    "{} --kdnet-key KEY",
                    ConfiguredTarget::kdnet(port).run_command()
                )],
                notes: vec![
                    "Replace KEY with the four-part key printed by bcdedit.".to_string(),
                    "Hyper-V carries KDNET over its synthetic debug device, so the guest needs no \
                     NIC for it and ignores hostip; ntoseye reaches the VM at the host's debug port."
                        .to_string(),
                    power_cycle,
                    format!(
                        "To debug from another machine, run there with --connect target=THIS_HOST:{port} \
                         and allow inbound UDP {port} for vmwp.exe in this host's firewall. Anyone who \
                         can reach the port can take the session over; the key is the only protection."
                    ),
                ],
            }
        }
        _ => Instructions::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn settings(enabled: u16, port: u32, com1: &str) -> DebugSettings {
        DebugSettings {
            debug_port_enabled: enabled,
            debug_port: port,
            com: [com1.to_string(), String::new()],
        }
    }

    fn kdnet() -> ConfigureRequest {
        ConfigureRequest::Configure {
            backend: ConfigureBackend::KdNet {
                host: Ipv4Addr::new(192, 168, 1, 2),
            },
            vmcoreinfo: false,
        }
    }

    fn kd() -> ConfigureRequest {
        ConfigureRequest::Configure {
            backend: ConfigureBackend::Kd,
            vmcoreinfo: false,
        }
    }

    #[test]
    fn kdnet_takes_the_first_port_no_other_vm_holds() {
        let planned = plan_settings(&settings(0, 0, ""), kdnet(), &[50000, 50001]).unwrap();
        assert_eq!(planned, settings(1, 50002, ""));
    }

    #[test]
    fn kdnet_keeps_its_own_port_unless_another_vm_took_it() {
        let own = settings(1, 50007, "");
        assert_eq!(plan_settings(&own, kdnet(), &[50000]).unwrap(), own);
        assert_eq!(
            plan_settings(&own, kdnet(), &[50007]).unwrap(),
            settings(1, 50000, "")
        );
    }

    #[test]
    fn kdnet_releases_the_kd_pipe_and_kd_leaves_the_debug_port() {
        let both = plan_settings(&settings(1, 50000, ""), kd(), &[]).unwrap();
        assert_eq!(both, settings(1, 50000, DEFAULT_KD_SOCKET));
        assert_eq!(
            plan_settings(&both, kdnet(), &[]).unwrap(),
            settings(1, 50000, "")
        );
    }

    #[test]
    fn kd_refuses_a_com_port_someone_else_attached() {
        let error = plan_settings(&settings(0, 0, r"\\.\pipe\other"), kd(), &[]).unwrap_err();
        assert!(error.to_string().contains(r"\\.\pipe\other"));
    }

    #[test]
    fn remove_keeps_foreign_pipes_and_turns_the_debug_port_off() {
        let mut original = settings(1, 50000, DEFAULT_KD_SOCKET);
        original.com[1] = r"\\.\pipe\console".to_string();
        let mut expected = settings(0, 0, "");
        expected.com[1] = r"\\.\pipe\console".to_string();
        assert_eq!(
            plan_settings(&original, ConfigureRequest::Remove, &[]).unwrap(),
            expected
        );
    }

    #[test]
    fn write_script_touches_only_what_changed() {
        let id = "8d3a8e8e-0f5f-4c4b-9a39-5d8e6f9a1b2c";
        let original = settings(0, 0, "");
        let pipe_only = settings(0, 0, DEFAULT_KD_SOCKET);
        let script = write_script(id, &original, &pipe_only).unwrap();
        assert!(script.contains(r"Set-VMComPort -VM $vm -Number 1 -Path '\\.\pipe\ntoseye-kd'"));
        assert!(!script.contains("ModifySystemSettings"));
        let port_only = write_script(id, &original, &settings(1, 50000, "")).unwrap();
        assert!(!port_only.contains("Set-VMComPort"));
        assert!(port_only.contains("$s.DebugPort = 50000"));
        assert!(write_script("x'; Remove-VM *; '", &original, &pipe_only).is_err());
    }

    #[test]
    fn script_output_parses_and_malformed_output_is_an_error() {
        let fs = FIELD_SEPARATOR;
        let rs = RECORD_SEPARATOR;
        assert_eq!(
            parse_settings(&format!("2{fs}50003{fs}{fs}\\\\.\\pipe\\x")).unwrap(),
            DebugSettings {
                debug_port_enabled: 2,
                debug_port: 50003,
                com: [String::new(), r"\\.\pipe\x".to_string()],
            }
        );
        assert!(parse_settings("2").is_err());
        let guests = parse_guests(&format!("a{fs}Win 11{fs}Off{rs}b{fs}Dev{fs}Running"));
        assert_eq!(guests.len(), 2);
        assert!(guests[0].stopped && !guests[1].stopped);
        assert_eq!(
            parse_debug_ports(&format!("a{fs}1{fs}50000{rs}b{fs}0{fs}0{rs}c{fs}2{fs}0")),
            [("a".to_string(), 50000)]
        );
    }

    #[test]
    fn status_shows_the_kdnet_dial_command() {
        let inspection = inspect_settings(&settings(1, 50005, DEFAULT_KD_SOCKET));
        let commands = inspection
            .targets
            .iter()
            .map(ConfiguredTarget::run_command)
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                "ntoseye",
                "ntoseye --backend kdnet --connect target=127.0.0.1:50005"
            ]
        );
    }
}
