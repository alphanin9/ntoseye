use owo_colors::OwoColorize;

use crate::dbg_backend::BugcheckInfo;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

// Bugcheck *analysis* (descriptor lookup, fault site, KiBugCheckData decode) lives
// in core (`crate::bugchecks`), shared with the SDK/MCP; the REPL adds presentation.
pub use crate::bugchecks::{
    BUGCHECK_DATA_SLOTS, CURRENT_KERNEL_RELOAD_WINDOW, analyze_bugcheck, bugcheck_fault_ip,
    bugcheck_site, current_bugcheck, looks_like_kernel_pointer, plausible_bugcheck_code,
    read_bugcheck_data,
};

pub fn print_unresolved_bugcheck_data(
    addr: VirtAddr,
    data: &[u64; BUGCHECK_DATA_SLOTS],
    reason: &str,
) {
    println!(
        "{} unable to resolve nt!KiBugCheckData at {:#x}: {}",
        "bugcheck:".bold(),
        addr,
        reason
    );
    println!(
        "{} raw slots = [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
        "bugcheck:".bold(),
        data[0],
        data[1],
        data[2],
        data[3],
        data[4]
    );
}

pub fn format_arg_value(value: u64) -> String {
    ui::addr(value)
}

/// Render a [`BugcheckInfo`] using the shared core analysis
/// ([`analyze_bugcheck`]), so the REPL and the SDK/MCP never disagree on the
/// name/arguments/responsible driver of a bugcheck.
pub fn print_bugcheck_info(debugger: &Target, info: &BugcheckInfo) {
    let analysis = analyze_bugcheck(debugger, info);

    println!();
    println!(
        "{}",
        format!("{} ({:#010x})", analysis.name, analysis.code)
            .red()
            .bold()
    );
    if let Some(driver) = &analysis.driver {
        println!("  module: {}", driver.green());
    }
    if let Some(description) = &analysis.description {
        println!("  reason: {description}");
    }
    println!();
    println!("{}", "args".bold());
    for (idx, arg) in analysis.args.iter().enumerate() {
        if arg.description.is_empty() {
            println!("  arg{} {}", idx + 1, format_arg_value(arg.value));
        } else {
            println!(
                "  arg{} {}  {}",
                idx + 1,
                format_arg_value(arg.value),
                arg.description
            );
        }
    }
}

pub fn print_bugcheck_summary(debugger: &Target, info: Option<&BugcheckInfo>) {
    if let Some(info) = info {
        print_bugcheck_info(debugger, info);
        return;
    }

    // KD normally sends the bugcheck code and parameters as debug I/O before
    // the stop packet. If that stream is missing, the same values can be read
    // from nt!KiBugCheckData while the guest is frozen mid-bugcheck.
    print_bugcheck_summary_from_memory(debugger);
}

/// Read and display `nt!KiBugCheckData` (BugCheckCode + 4 parameters). The
/// guest is frozen mid-bugcheck, so this is readable over `/dev/kvm`.
pub fn print_bugcheck_summary_from_memory(debugger: &Target) {
    let kernel_dtb = debugger.guest.ntoskrnl.dtb();
    let Some(addr) = debugger
        .symbols
        .find_symbol_across_modules(kernel_dtb, "KiBugCheckData")
    else {
        println!(
            "{} guest is bugchecking (symbol nt!KiBugCheckData unavailable)",
            "bugcheck:".bold()
        );
        return;
    };

    let mem = debugger.guest.ntoskrnl.memory();
    let direct = match read_bugcheck_data(&mem, addr) {
        Ok(data) => data,
        Err(e) => {
            println!(
                "{} failed to read nt!KiBugCheckData: {}",
                "bugcheck:".bold(),
                e
            );
            return;
        }
    };

    let (data, source) = if plausible_bugcheck_code(direct[0]) {
        (direct, None)
    } else if looks_like_kernel_pointer(direct[0]) {
        let indirect_addr = VirtAddr(direct[0]);
        match read_bugcheck_data(&mem, indirect_addr) {
            Ok(indirect) if plausible_bugcheck_code(indirect[0]) => (
                indirect,
                Some(format!("nt!KiBugCheckData -> {:#x}", indirect_addr)),
            ),
            Ok(indirect) => {
                print_unresolved_bugcheck_data(
                    addr,
                    &direct,
                    &format!(
                        "first slot looks like a pointer to {:#x}, but dereferenced first slot {:#x} is not a plausible bugcheck code",
                        indirect_addr, indirect[0]
                    ),
                );
                println!(
                    "{} dereferenced slots = [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
                    "bugcheck:".bold(),
                    indirect[0],
                    indirect[1],
                    indirect[2],
                    indirect[3],
                    indirect[4]
                );
                return;
            }
            Err(e) => {
                print_unresolved_bugcheck_data(
                    addr,
                    &direct,
                    &format!(
                        "first slot looks like a pointer to {:#x}, but reading that address failed: {}",
                        indirect_addr, e
                    ),
                );
                return;
            }
        }
    } else {
        print_unresolved_bugcheck_data(
            addr,
            &direct,
            &format!(
                "first slot {:#x} is not a plausible bugcheck code",
                direct[0]
            ),
        );
        return;
    };

    let info = BugcheckInfo {
        code: data[0] as u32,
        parameters: [data[1], data[2], data[3], data[4]],
        driver: None,
    };
    print_bugcheck_info(debugger, &info);
    if let Some(source) = source {
        println!("  source: {}", source.bright_black());
    }
}
