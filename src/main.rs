use argh::{FromArgValue, FromArgs};
use single_instance::SingleInstance;

use crate::{
    agent::start_agent_stdio,
    dbg_backend::DebugBackend,
    error::{Error, Result},
    gdb::GdbClient,
    kd::KdBackend,
    repl::start_repl,
    script::ScriptInstallOptions,
};

mod agent;
mod backend;
mod dbg_backend;
mod debugger;
mod error;
mod expr;
mod gdb;
mod guest;
mod host;
mod kd;
mod memory;
mod repl;
mod script;
mod symbols;
mod types;
mod unwind;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Gdb,
    Kd,
}

impl FromArgValue for BackendKind {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "gdb" => Ok(BackendKind::Gdb),
            "kd" => Ok(BackendKind::Kd),
            other => Err(format!("unknown backend '{other}': expected 'gdb' or 'kd'")),
        }
    }
}

#[derive(FromArgs)]
/// Windows kernel debugger for Linux hosts running Windows under KVM/QEMU
struct Args {
    /// print version information
    #[argh(switch, short = 'v', long = "version")]
    version: bool,

    /// force redownloading of symbols
    #[argh(switch, long = "force-download-symbols")]
    redownload_symbols: bool,

    /// help instructions with enabling gdbstub in qemu
    #[argh(switch, long = "gdbstub-instructions")]
    gdbstub_instructions: bool,

    /// help instructions with enabling kd-over-serial in qemu/windows
    #[argh(switch, long = "kd-instructions")]
    kd_instructions: bool,

    /// debugger backend: 'gdb' (QEMU gdbstub, default) or 'kd' (Windows KD over serial pipe)
    #[argh(option, short = 'b', long = "backend", default = "BackendKind::Gdb")]
    backend: BackendKind,

    /// backend connection target. Defaults: '127.0.0.1:1234' for gdb, '/tmp/ntoseye-kd.sock' for kd.
    #[argh(option, long = "connect")]
    connect: Option<String>,

    /// run a newline-delimited JSON agent protocol on stdin/stdout instead of the interactive REPL
    #[argh(switch, long = "agent-stdio")]
    agent_stdio: bool,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Scripts(ScriptsCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "scripts")]
/// manage Lua command scripts
struct ScriptsCommand {
    #[argh(subcommand)]
    command: ScriptsSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum ScriptsSubcommand {
    Install(ScriptsInstallCommand),
    List(ScriptsListCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "install")]
/// install Lua command scripts
struct ScriptsInstallCommand {
    /// optional source: local .lua file, local directory, or HTTPS .lua URL; omit to install bundled scripts
    #[argh(positional)]
    source: Option<String>,

    /// overwrite existing scripts
    #[argh(switch, long = "force")]
    force: bool,

    /// skip trust prompt for local or remote scripts
    #[argh(switch, long = "yes", short = 'y')]
    yes: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
/// list installed Lua command scripts
struct ScriptsListCommand {}

#[cfg(not(target_os = "linux"))]
compile_error!("This application only runs on Linux hosts.");

static GDBSTUB_INSTRUCTIONS: &str = "Although it isn't required, gdbstub allows ntoseye to perform
introspection upon the guests VCPUs, allowing for viewing of
registers and breakpointing. To enable it, you must pass the
following arguments to QEMU:

-s -S

For crash/reset logging while developing low-level code, add QEMU
logging and prevent immediate reboot:

-d int,cpu_reset,guest_errors -D /tmp/qemu-ntoseye.log -no-reboot

Inside ntoseye, the same log masks can be enabled after connection with:

qlog int,cpu_reset,guest_errors /tmp/qemu-ntoseye.log

If you are running QEMU via commandline, simply append them
to your existing command.

If you are running QEMU via virt-manager, you must edit the
libvirt XML file, which can be done through their GUI. Once
there, you must edit & add the following:

<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"kvm\">
  ...
  <qemu:commandline>
    <qemu:arg value=\"-s\"/>
    <qemu:arg value=\"-S\"/>
  </qemu:commandline>
</domain>";

static KD_INSTRUCTIONS: &str = "The KD backend speaks the same wire protocol WinDbg uses, over a
serial pipe between QEMU and ntoseye. It requires Windows to be
booted in debug mode (which removes the 'stealth' property of the
gdb backend: anti-debug code, PatchGuard, and even some Windows
behaviors change when /debug is on).

GUEST: enable kernel debugging over a serial port (run as
Administrator, then reboot):

bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

If your hypervisor wires the KD serial as COM2 (see the libvirt
note below), use 'debugport:2' instead.

QEMU (commandline): route COM1 to a host-side Unix socket. The
path here matches ntoseye's default; adjust both sides if you pick
a different one:

-chardev socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off -serial chardev:kd

QEMU via virt-manager / libvirt: virt-manager auto-adds a <serial>
console device on every VM, and it claims COM1. Either replace or
remove that device so the KD chardev becomes COM1 (recommended), or
leave it in place and the KD chardev will be COM2 (use 'debugport:2'
in bcdedit instead of 'debugport:1').

OPTION A (recommended): replace the auto-added <serial> with one
that points at our Unix socket. KD is COM1, 'debugport:1' is correct.

<serial type=\"unix\">
  <source mode=\"bind\" path=\"/tmp/ntoseye-kd.sock\"/>
  <target type=\"isa-serial\" port=\"0\"/>
</serial>

OPTION B: leave the auto-added serial alone and append the KD
chardev via qemu:commandline. KD ends up as COM2, so use
'debugport:2' in bcdedit.

<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"kvm\">
  ...
  <qemu:commandline>
    <qemu:arg value=\"-chardev\"/>
    <qemu:arg value=\"socket,id=kd,path=/tmp/ntoseye-kd.sock,server=on,wait=off\"/>
    <qemu:arg value=\"-serial\"/>
    <qemu:arg value=\"chardev:kd\"/>
  </qemu:commandline>
</domain>

Once the guest is booting (or already booted and waiting for the
debugger), run:

ntoseye --backend kd --connect /tmp/ntoseye-kd.sock";

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Args = argh::from_env();
    if args.version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.gdbstub_instructions {
        println!("{}", GDBSTUB_INSTRUCTIONS);
        return Ok(());
    }

    if args.kd_instructions {
        println!("{}", KD_INSTRUCTIONS);
        return Ok(());
    }

    if let Some(command) = args.command {
        return match command {
            Command::Scripts(scripts) => match scripts.command {
                ScriptsSubcommand::Install(install) => {
                    script::install_scripts(ScriptInstallOptions {
                        source: install.source,
                        force: install.force,
                        yes: install.yes,
                    })
                }
                ScriptsSubcommand::List(_) => script::list_scripts(),
            },
        };
    }

    let instance = SingleInstance::new("ntoseye").unwrap();
    if !instance.is_single() {
        return Err(Error::AlreadyRunning);
    }

    symbols::FORCE_DOWNLOADS
        .set(args.redownload_symbols)
        .unwrap();
    symbols::set_quiet_progress(args.agent_stdio);

    let mut debugger = debugger::DebuggerContext::new()?;

    let mut backend: Box<dyn DebugBackend> = match args.backend {
        BackendKind::Gdb => {
            let addr = args.connect.as_deref().unwrap_or("127.0.0.1:1234");
            Box::new(GdbClient::connect(addr)?)
        }
        BackendKind::Kd => {
            let path = args.connect.as_deref().unwrap_or("/tmp/ntoseye-kd.sock");
            Box::new(KdBackend::connect(path)?)
        }
    };

    if args.agent_stdio {
        start_agent_stdio(&mut debugger, backend.as_mut())
    } else {
        start_repl(&mut debugger, backend.as_mut())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_startup() -> Result<()> {
//         let mut debugger = debugger::DebuggerContext::new()?;
//         let _ = debugger.get_startup_message_data()?;

//         Ok(())
//     }
// }
