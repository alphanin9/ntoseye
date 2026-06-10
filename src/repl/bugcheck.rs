use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::bugchecks::{GENERIC_BUGCHECK_ARGS, bugcheck_descriptor};
use crate::dbg_backend::BugcheckInfo;
use crate::debugger::DebuggerContext;
use crate::error::Result;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{ThreadTraceContext, format_symbol, resolve_thread_trace_context};

pub const BUGCHECK_DATA_SLOTS: usize = 5;

pub const CURRENT_KERNEL_RELOAD_WINDOW: u64 = 0x1000_0000;

pub fn plausible_bugcheck_code(code: u64) -> bool {
    code != 0 && code <= u32::MAX as u64
}

pub fn looks_like_kernel_pointer(value: u64) -> bool {
    value >= 0xffff_8000_0000_0000
}

pub fn read_bugcheck_data<M: MemoryOps<VirtAddr>>(
    mem: &M,
    addr: VirtAddr,
) -> Result<[u64; BUGCHECK_DATA_SLOTS]> {
    let mut data = [0u64; BUGCHECK_DATA_SLOTS];
    for (i, slot) in data.iter_mut().enumerate() {
        *slot = mem.read::<u64>(addr + (i * 8) as u64)?;
    }
    Ok(data)
}

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

pub fn module_filename(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_string()
}

pub fn driver_filename_for_address(
    debugger: &DebuggerContext,
    trace: &ThreadTraceContext,
    address: u64,
) -> Option<String> {
    trace
        .kernel_modules
        .iter()
        .chain(trace.process_modules.iter())
        .find(|module| module.contains_address(VirtAddr(address)))
        .map(|module| module_filename(&module.name))
        .filter(|name| name.to_ascii_lowercase().ends_with(".sys"))
        .or_else(|| {
            debugger
                .symbols
                .find_module_for_address(trace.kernel_dtb, VirtAddr(address))
                .map(|module| module_filename(&module.name))
                .filter(|name| name.to_ascii_lowercase().ends_with(".sys"))
        })
}

pub fn bugcheck_fault_ip(info: &BugcheckInfo) -> Option<u64> {
    let ip = match info.code {
        // IRQL_NOT_LESS_OR_EQUAL / DRIVER_IRQL_NOT_LESS_OR_EQUAL:
        // parameter 4 is the instruction address that referenced memory.
        0x0000_000a | 0x0000_00d1 => info.parameters[3],
        // PAGE_FAULT_IN_NONPAGED_AREA: parameter 3 is the instruction address
        // when non-zero.
        0x0000_0050 => info.parameters[2],
        // Other bugchecks may carry addresses, but not necessarily a faulting
        // instruction. For example, 0x4a arg1 is the system-call routine and
        // often resolves to an ntdll syscall stub, not the responsible driver.
        _ => 0,
    };
    (ip != 0).then_some(ip)
}

pub fn bugcheck_site(
    debugger: &DebuggerContext,
    trace: &ThreadTraceContext,
    info: &BugcheckInfo,
) -> Option<(u64, String, Option<String>)> {
    let ip = bugcheck_fault_ip(info)?;
    let symbol = format_symbol(debugger, trace, ip);
    let driver = driver_filename_for_address(debugger, trace, ip);
    Some((ip, symbol, driver))
}

pub fn print_bugcheck_info(debugger: &DebuggerContext, info: &BugcheckInfo) {
    let trace = resolve_thread_trace_context(debugger, debugger.guest.ntoskrnl.dtb());
    let site = bugcheck_site(debugger, &trace, info);
    let descriptor = bugcheck_descriptor(info.code);
    let name = descriptor
        .as_ref()
        .map(|descriptor| descriptor.name)
        .unwrap_or("UNKNOWN_BUGCHECK");
    let driver = info
        .driver
        .as_deref()
        .or_else(|| site.as_ref().and_then(|(_, _, driver)| driver.as_deref()));

    println!();
    println!("{}", format!("{name} ({:#010x})", info.code).red().bold());
    if let Some(driver) = driver {
        println!("  module: {}", driver.green());
    }
    if let Some(description) = descriptor
        .as_ref()
        .and_then(|descriptor| descriptor.description)
    {
        println!("  reason: {description}");
    }
    println!();
    println!("{}", "args".bold());
    let arg_descriptions = descriptor
        .as_ref()
        .map(|descriptor| descriptor.arguments)
        .unwrap_or(GENERIC_BUGCHECK_ARGS);
    for (idx, (value, description)) in info.parameters.iter().zip(arg_descriptions).enumerate() {
        if description.is_empty() {
            println!("  arg{} {}", idx + 1, format_arg_value(*value));
        } else {
            println!(
                "  arg{} {}  {}",
                idx + 1,
                format_arg_value(*value),
                description
            );
        }
    }
}

pub fn print_bugcheck_summary(debugger: &DebuggerContext, info: Option<&BugcheckInfo>) {
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
pub fn print_bugcheck_summary_from_memory(debugger: &DebuggerContext) {
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
