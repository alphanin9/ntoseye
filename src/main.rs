use argh::FromArgs;
use single_instance::SingleInstance;

use crate::{
    error::{Error, Result},
    repl::start_repl,
};

mod backend;
mod debugger;
mod error;
mod expr;
mod gdb;
mod guest;
mod host;
mod memory;
mod repl;
mod symbols;
mod types;

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
}

#[cfg(not(target_os = "linux"))]
compile_error!("This application only runs on Linux hosts.");

static GDBSTUB_INSTRUCTIONS: &str = "Although it isn't required, gdbstub allows ntoseye to perform
introspection upon the guests VCPUs, allowing for viewing of
registers and breakpointing. To enable it, you must pass the
following arguments to QEMU:

-s -S

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

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    if args.version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.gdbstub_instructions {
        println!("{}", GDBSTUB_INSTRUCTIONS);
        return Ok(());
    }

    let instance = SingleInstance::new("ntoseye").unwrap();
    if !instance.is_single() {
        return Err(Error::AlreadyRunning);
    }

    symbols::FORCE_DOWNLOADS
        .set(args.redownload_symbols)
        .unwrap();

    let mut debugger = debugger::DebuggerContext::new()?;

    start_repl(&mut debugger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup() -> Result<()> {
        let mut debugger = debugger::DebuggerContext::new()?;
        let _ = debugger.get_startup_message_data()?;

        Ok(())
    }
}
