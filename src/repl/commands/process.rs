use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::time::Duration;

use strum::EnumMessage;
use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::debugger::{
    AttachReport, MemoryRegionInfo, ThreadInfo, kthread_state_name, wait_reason_name,
};
use crate::error::Result;
use crate::expr::Expr;
use crate::types::{Value, VirtAddr};
use crate::ui;

use crate::repl::*;

fn thread_state_label(thread: &ThreadInfo) -> String {
    thread
        .state
        .map(|state| format!("{} ({:#x})", kthread_state_name(state), state))
        .unwrap_or_else(|| "?".to_string())
}

fn wait_reason_label(thread: &ThreadInfo) -> String {
    thread
        .wait_reason
        .map(|reason| format!("{} ({:#x})", wait_reason_name(reason), reason))
        .unwrap_or_else(|| "?".to_string())
}

fn thread_matches_filter(thread: &ThreadInfo, filter: &str) -> bool {
    let filter_lower = filter.to_ascii_lowercase();
    thread
        .process_name
        .as_deref()
        .is_some_and(|name| name.to_ascii_lowercase().contains(&filter_lower))
        || thread
            .pid
            .is_some_and(|pid| pid.to_string() == filter || format!("{:#x}", pid) == filter_lower)
        || thread
            .tid
            .is_some_and(|tid| tid.to_string() == filter || format!("{:#x}", tid) == filter_lower)
        || format!("{:#x}", thread.ethread.0) == filter_lower
        || format!("{:x}", thread.ethread.0) == filter_lower.trim_start_matches("0x")
}

fn print_thread_detail(thread: &ThreadInfo) {
    println!(
        "{} {}  TID {}  PID {}  process {}",
        ui::label("thread:"),
        ui::addr(thread.ethread.0),
        thread
            .tid
            .map(Value)
            .map(|tid| tid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .pid
            .map(Value)
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread.process_name.as_deref().unwrap_or("unknown")
    );
    println!(
        "  state={} wait={} kthread={} eprocess={}",
        thread_state_label(thread),
        wait_reason_label(thread),
        ui::addr(thread.kthread.0),
        thread
            .eprocess
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "  start={} win32={} teb={} kernel_stack={}",
        thread
            .start_address
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .win32_start_address
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .teb
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .kernel_stack
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "  priority={} base_priority={} wait_irql={} stack_resident={}",
        thread
            .priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .base_priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .wait_irql
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        thread
            .kernel_stack_resident
            .map(|resident| if resident { "yes" } else { "no" })
            .unwrap_or("-")
    );
    println!(
        "  stack_base={} stack_limit={} trap_frame={}",
        thread
            .stack_base
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .stack_limit
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string()),
        thread
            .trap_frame
            .map(|addr| ui::addr(addr.0))
            .unwrap_or_else(|| "-".to_string())
    );
    if let Some(irps) = &thread.pending_irps {
        if irps.is_empty() {
            println!("  irp_list=empty");
        } else {
            println!("  irp_list={} pending", irps.len());
            for (index, irp) in irps.iter().enumerate() {
                println!("    [{}] {}", index, ui::addr(irp.0));
            }
        }
    }
}

fn format_region_size(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{:#x} ({} MiB)", size, size / (1024 * 1024))
    } else if size >= 1024 {
        format!("{:#x} ({} KiB)", size, size / 1024)
    } else {
        format!("{:#x}", size)
    }
}

fn vad_protection_label(protection: Option<u64>) -> String {
    match protection {
        Some(0) => "none".to_string(),
        Some(1) => "r".to_string(),
        Some(2) => "x".to_string(),
        Some(3) => "x/r".to_string(),
        Some(4) => "rw".to_string(),
        Some(5) => "cow".to_string(),
        Some(6) => "x/rw".to_string(),
        Some(7) => "x/cow".to_string(),
        Some(value) => format!("prot:{value}"),
        None => "-".to_string(),
    }
}

fn vad_type_label(region: &MemoryRegionInfo) -> String {
    match region.vad_type {
        Some(2) => "mapped".to_string(),
        Some(3) => "image".to_string(),
        Some(_) if region.private_memory == Some(true) => "private".to_string(),
        Some(value) => format!("vad:{value}"),
        None => "vad".to_string(),
    }
}

fn region_matches_filter(
    region: &MemoryRegionInfo,
    filter: Option<&str>,
    address: Option<VirtAddr>,
) -> bool {
    if let Some(address) = address
        && address >= region.start
        && address < region.end
    {
        return true;
    }
    let Some(filter) = filter.map(str::to_ascii_lowercase) else {
        return true;
    };
    format!("{:#x}", region.start.0).contains(&filter)
        || format!("{:#x}", region.end.0).contains(&filter)
        || region
            .details
            .as_deref()
            .is_some_and(|details| details.to_ascii_lowercase().contains(&filter))
        || vad_type_label(region).contains(&filter)
        || vad_protection_label(region.protection)
            .to_ascii_lowercase()
            .contains(&filter)
}

impl ReplState<'_> {
    fn active_windows_thread_map(&mut self) -> HashMap<u64, (String, ThreadInfo)> {
        let Ok(original_thread) = self.client.stopped_thread_id() else {
            return HashMap::new();
        };
        let Ok(vcpus) = self.client.thread_list() else {
            return HashMap::new();
        };

        let mut active = HashMap::new();
        for vcpu in &vcpus {
            if self.client.set_current_thread(vcpu).is_err() {
                continue;
            }
            let Some(processor) = processor_index_from_backend_thread_id(vcpu) else {
                continue;
            };
            if let Ok(thread) = self
                .debugger
                .current_windows_thread_for_processor(processor)
            {
                active.insert(thread.ethread.0, (vcpu.clone(), thread));
            }
        }

        let _ = self.client.set_current_thread(&original_thread);
        active
    }

    pub fn cmd_vcpus(&mut self, _parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.black.bright} {msg}")
                .unwrap(),
        );

        pb.set_message(format!("{}", "Waiting on GDB...".bright_black()));
        pb.enable_steady_tick(Duration::from_millis(100));

        let original_thread = match self.client.stopped_thread_id() {
            Ok(thread) => thread,
            Err(e) => {
                pb.finish_and_clear();
                error!("{}", e);
                return Ok(());
            }
        };
        let threads = match self.client.thread_list() {
            Ok(threads) => threads,
            Err(e) => {
                pb.finish_and_clear();
                error!("{}", e);
                return Ok(());
            }
        };

        let processes = self
            .debugger
            .guest
            .enumerate_processes()
            .unwrap_or_default();
        let kernel_dtb = self.debugger.guest.ntoskrnl.dtb();

        let mut vcpu_data: Vec<(String, String, String, String)> = Vec::new();

        for thread in &threads {
            let regs = self
                .client
                .set_current_thread(thread)
                .and_then(|_| self.client.read_registers());
            let regs = match regs {
                Ok(regs) => regs,
                Err(e) => {
                    vcpu_data.push((
                        thread.clone(),
                        ui::muted("unavailable"),
                        String::new(),
                        format!("{e}"),
                    ));
                    continue;
                }
            };
            let (Ok(rip), Ok(cr3)) = (
                self.register_map.read_u64("rip", &regs),
                self.register_map.read_u64("cr3", &regs),
            ) else {
                vcpu_data.push((
                    thread.clone(),
                    ui::muted("unavailable"),
                    String::new(),
                    String::new(),
                ));
                continue;
            };

            let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
            let kernel_dtb_masked = kernel_dtb & 0x000F_FFFF_FFFF_F000;

            let (context, symbol) = if cr3_masked == kernel_dtb_masked {
                let sym = self
                    .debugger
                    .guest
                    .ntoskrnl
                    .closest_symbol(VirtAddr(rip))
                    .map(|(s, o)| format!("{}+{:#x}", s, o))
                    .unwrap_or_else(|_| format!("{:#x}", rip));
                ("kernel".to_string(), sym)
            } else {
                match processes
                    .iter()
                    .find(|p| (p.dtb & 0x000F_FFFF_FFFF_F000) == cr3_masked)
                {
                    Some(proc) => {
                        let sym = self
                            .debugger
                            .symbols
                            .format_closest_symbol_for_address(proc.dtb, VirtAddr(rip))
                            .unwrap_or_else(|| format!("{:#x}", rip));
                        (proc.name.clone(), sym)
                    }
                    None => ("unknown".to_string(), format!("{:#x}", rip)),
                }
            };

            vcpu_data.push((thread.clone(), ui::addr(rip), context, symbol));
        }

        pb.finish_and_clear();

        if let Err(e) = self.client.set_current_thread(&original_thread) {
            error!("failed to restore vcpu context: {}", e);
        }

        let mut builder = Builder::default();
        builder.push_record(vec!["vCPU", "RIP", "Context", "Symbol"]);
        for (vcpu, rip, ctx, sym) in vcpu_data {
            builder.push_record(vec![
                format!("{}  ", vcpu),
                format!("{}  ", rip),
                format!("{}  ", ctx),
                sym,
            ]);
        }

        print_plain_table(builder);

        Ok(())
    }

    pub fn cmd_threads(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let filter = parts.get(1).copied();
        let active = self.active_windows_thread_map();
        let mut threads = match self.debugger.enumerate_threads() {
            Ok(threads) => threads,
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                return Ok(());
            }
        };
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        if let Some(filter) = filter {
            threads.retain(|thread| thread_matches_filter(thread, filter));
        }
        threads.sort_by_key(|thread| (thread.pid.unwrap_or(u64::MAX), thread.tid));
        *self.caches.threads.write().unwrap() = threads.clone();

        if threads.is_empty() {
            println!("{}\n", "no matching threads".bright_black());
            return Ok(());
        }

        let mut builder = Builder::default();
        builder.push_record(vec![
            "Active  ".to_string(),
            "ETHREAD  ".to_string(),
            "PID  ".to_string(),
            "TID  ".to_string(),
            "Process  ".to_string(),
            "State  ".to_string(),
            "Wait  ".to_string(),
            "Start".to_string(),
        ]);
        for thread in &threads {
            let active_vcpu = active
                .get(&thread.ethread.0)
                .map(|(vcpu, _)| vcpu.as_str())
                .unwrap_or("-");
            let start = thread.start_address.or(thread.win32_start_address);
            builder.push_record(vec![
                format!("{}  ", active_vcpu),
                format!("{}  ", ui::addr(thread.ethread.0)),
                format!(
                    "{}  ",
                    thread
                        .pid
                        .map(Value)
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!(
                    "{}  ",
                    thread
                        .tid
                        .map(Value)
                        .map(|tid| tid.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                format!("{}  ", thread.process_name.as_deref().unwrap_or("unknown")),
                format!("{}  ", thread_state_label(thread)),
                format!("{}  ", wait_reason_label(thread)),
                start
                    .map(|addr| ui::addr(addr.0))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_plain_table(builder);
        Ok(())
    }

    pub fn cmd_thread(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let target = require_arg!(parts, 1, ReplCommand::Thread);
        let mut threads = match self.debugger.enumerate_threads() {
            Ok(threads) => threads,
            Err(e) => {
                error!("failed to enumerate threads: {}", e);
                return Ok(());
            }
        };

        let active = self.active_windows_thread_map();
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        *self.caches.threads.write().unwrap() = threads.clone();

        let current_alias_address = if target == "." {
            self.debugger
                .current_windows_thread
                .as_ref()
                .map(|t| t.ethread)
        } else {
            None
        };
        let target_address =
            current_alias_address.or_else(|| Expr::eval(target, self.debugger).ok());
        let matches = threads
            .iter()
            .filter(|thread| {
                thread
                    .tid
                    .is_some_and(|tid| tid.to_string() == target || format!("{:#x}", tid) == target)
                    || target_address.is_some_and(|addr| addr == thread.ethread)
                    || format!("{:#x}", thread.ethread.0) == target
                    || format!("{:x}", thread.ethread.0) == target.trim_start_matches("0x")
            })
            .collect::<Vec<_>>();

        let thread = match matches.as_slice() {
            [thread] => *thread,
            [] => {
                error!("no Windows thread matches '{}'", target);
                return Ok(());
            }
            many => {
                error!(
                    "ambiguous Windows thread '{}': {} matches",
                    target,
                    many.len()
                );
                return Ok(());
            }
        };

        let action = parts.get(2).copied();
        let frame_limit = parts
            .get(3)
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(16)
            .max(1);

        let Some((vcpu, _)) = active.get(&thread.ethread.0) else {
            print_thread_detail(thread);
            println!(
                "{}\n",
                "thread is not currently executing on any vCPU".bright_black()
            );
            return Ok(());
        };

        if let Err(e) = self.client.set_current_thread(vcpu) {
            error!("failed to switch to vCPU {}: {:?}", vcpu, e);
            return Ok(());
        }
        self.current_thread = vcpu.clone();
        self.debugger.clear_context_dtb_override();
        self.debugger
            .set_current_windows_thread_context((*thread).clone());
        self.caches.refresh_symbol_context(self.debugger);
        println!(
            "switched to {} running ETHREAD {}\n",
            self.current_thread,
            ui::addr(thread.ethread.0)
        );
        print_thread_detail(thread);

        match action {
            Some("k") => {
                let regs = match self.client.read_registers() {
                    Ok(regs) => regs,
                    Err(e) => {
                        error!("failed to read registers: {:?}", e);
                        return Ok(());
                    }
                };
                print_stacktrace(
                    self.debugger,
                    &self.register_map,
                    &regs,
                    frame_limit,
                    frame_limit,
                    false,
                );
            }
            Some("r" | "registers") => {
                let regs = match self.client.read_registers() {
                    Ok(regs) => regs,
                    Err(e) => {
                        error!("failed to read registers: {:?}", e);
                        return Ok(());
                    }
                };
                print_registers(&self.register_map, &regs, false);
            }
            Some(other) => error!("unknown thread action '{}': expected k or r", other),
            None => {}
        }
        println!();
        Ok(())
    }

    pub fn cmd_vmmap(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let filter = parts.get(1).copied();
        let filter_address = filter.and_then(|filter| Expr::eval(filter, self.debugger).ok());

        if let Some(process) = self.debugger.current_process_info.clone() {
            let regions = match self
                .debugger
                .enumerate_vad_regions_for_process_info(&process)
            {
                Ok(regions) => regions,
                Err(e) => {
                    error!("failed to enumerate VADs: {}", e);
                    return Ok(());
                }
            };

            let mut builder = Builder::default();
            builder.push_record(vec![
                "Start".to_string(),
                "End".to_string(),
                "Size".to_string(),
                "Protect".to_string(),
                "Type".to_string(),
                "Commit  ".to_string(),
                "Details".to_string(),
            ]);

            let mut shown = 0usize;
            for region in regions
                .iter()
                .filter(|region| region_matches_filter(region, filter, filter_address))
            {
                shown += 1;
                builder.push_record(vec![
                    format!("{}  ", ui::addr(region.start.0)),
                    format!("{}  ", ui::addr(region.end.0)),
                    format!("{}  ", format_region_size(region.size())),
                    format!("{}  ", vad_protection_label(region.protection)),
                    format!("{}  ", vad_type_label(region)),
                    format!(
                        "{}  ",
                        region
                            .commit_charge
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string())
                    ),
                    region.details.as_deref().unwrap_or("-").to_string(),
                ]);
            }

            if shown == 0 {
                println!("{}\n", "no matching memory regions".bright_black());
            } else {
                println!(
                    "{} {} ({})",
                    ui::label("vmmap:"),
                    process.name,
                    Value(process.pid)
                );
                print_plain_table(builder);
            }
            return Ok(());
        }

        let modules = match self.debugger.guest.kernel_modules() {
            Ok(modules) => modules,
            Err(e) => {
                error!("failed to enumerate kernel modules: {}", e);
                return Ok(());
            }
        };
        let mut builder = Builder::default();
        builder.push_record(vec![
            "Start".to_string(),
            "End".to_string(),
            "Size".to_string(),
            "Module".to_string(),
            "Image".to_string(),
        ]);
        let mut shown = 0usize;
        for module in modules {
            let matches = filter.is_none_or(|filter| {
                module
                    .short_name
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
                    || module
                        .name
                        .to_ascii_lowercase()
                        .contains(&filter.to_ascii_lowercase())
                    || filter_address.is_some_and(|address| module.contains_address(address))
            });
            if !matches {
                continue;
            }
            shown += 1;
            builder.push_record(vec![
                format!("{}  ", ui::addr(module.base_address.0)),
                format!("{}  ", ui::addr(module.end_address().0)),
                format!("{}  ", format_region_size(module.size as u64)),
                format!("{}  ", module.short_name),
                module.name,
            ]);
        }

        if shown == 0 {
            println!("no matching kernel regions\n");
        } else {
            println!("{} kernel", ui::label("vmmap:"));
            print_plain_table(builder);
        }
        Ok(())
    }

    pub fn cmd_ps(&mut self, parts: &[&str]) -> Result<()> {
        let filter = parts.get(1).map(|s| s.to_lowercase());

        match self.debugger.guest.enumerate_processes() {
            Ok(processes) => {
                *self.caches.processes.write().unwrap() =
                    processes.iter().map(|p| (p.name.clone(), p.pid)).collect();

                let mut builder = Builder::default();
                builder.push_record(vec![
                    "Name".to_string(),
                    "PID".to_string(),
                    "EPROCESS".to_string(),
                    "DTB".to_string(),
                ]);

                let mut count = 0;
                for proc in processes {
                    if let Some(ref f) = filter
                        && !proc.name.to_lowercase().contains(f)
                    {
                        continue;
                    }
                    count += 1;
                    builder.push_record(vec![
                        format!("{}  ", proc.name),
                        format!("{}  ", Value(proc.pid)),
                        format!("{}  ", ui::addr(proc.eprocess_va.0)),
                        ui::addr(proc.dtb), // TODO technically is phys addr..
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching processes".bright_black());
                } else {
                    print_plain_table(builder);
                }
            }
            Err(e) => {
                error!("failed to enumerate processes: {}", e);
            }
        }

        Ok(())
    }

    pub fn cmd_drivers(&mut self, parts: &[&str]) -> Result<()> {
        let filter = parts.get(1).map(|s| s.to_lowercase());

        match self.debugger.enumerate_driver_objects() {
            Ok(drivers) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "DriverObject  ".to_string(),
                    "Name  ".to_string(),
                    "DriverStart  ".to_string(),
                    "Size  ".to_string(),
                    "Module  ".to_string(),
                    "DeviceObject  ".to_string(),
                    "DriverUnload".to_string(),
                ]);

                let mut count = 0;
                for driver in &drivers {
                    if let Some(ref f) = filter
                        && !driver.name.to_lowercase().contains(f)
                        && !format!("{:#x}", driver.object.0).starts_with(f)
                    {
                        continue;
                    }
                    count += 1;
                    let module = self
                        .debugger
                        .symbols
                        .find_module_for_address(
                            self.debugger.guest.ntoskrnl.dtb(),
                            driver.driver_start,
                        )
                        .map(|module| module.name)
                        .unwrap_or_else(|| "-".to_string());
                    builder.push_record(vec![
                        format!("{}  ", ui::addr(driver.object.0)),
                        format!("{}  ", driver.name),
                        format!("{}  ", ui::addr(driver.driver_start.0)),
                        format!("0x{:x}  ", driver.driver_size),
                        format!("{}  ", module),
                        format!("{}  ", ui::addr(driver.device_object.0)),
                        ui::addr(driver.driver_unload.0),
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching drivers".bright_black());
                } else {
                    print_plain_table(builder);
                }
                *self.caches.drivers.write().unwrap() = drivers;
            }
            Err(e) => {
                error!("failed to list drivers: {}", e);
            }
        }

        Ok(())
    }

    pub fn cmd_lm(&mut self, parts: &[&str]) -> Result<()> {
        let filter = parts.get(1).map(|s| s.to_lowercase());

        let (result, dtb) = if let Some(process_info) = &self.debugger.current_process_info {
            (
                self.debugger.guest.process_modules(process_info),
                process_info.dtb,
            )
        } else {
            (
                self.debugger.guest.kernel_modules(),
                self.debugger.guest.ntoskrnl.dtb(),
            )
        };

        match result {
            Ok(modules) => {
                let mut builder = Builder::default();
                builder.push_record(vec![
                    "Start".to_string(),
                    "End".to_string(),
                    "Module".to_string(),
                    "Symbols".to_string(),
                    "Source".to_string(),
                    "Image".to_string(),
                ]);

                let mut count = 0;
                for module in modules {
                    if let Some(ref f) = filter
                        && !module.short_name.to_lowercase().contains(f)
                        && !module.name.to_lowercase().contains(f)
                    {
                        continue;
                    }
                    count += 1;
                    builder.push_record(vec![
                        format!("{}  ", ui::addr(module.base_address.0)),
                        format!("{}  ", ui::addr(module.end_address().0)),
                        format!("{}  ", module.short_name),
                        format!(
                            "{}  ",
                            self.debugger
                                .symbols
                                .module_symbol_status(dtb, module.base_address)
                                .map(|status| status.label().to_string())
                                .unwrap_or_else(|| "unknown".to_string())
                        ),
                        format!(
                            "{}  ",
                            self.debugger
                                .symbols
                                .module_symbol_source(dtb, module.base_address)
                                .map(|source| source.label().to_string())
                                .unwrap_or_else(|| "-".to_string())
                        ),
                        module.name,
                    ]);
                }

                if count == 0 {
                    println!("{}\n", "no matching modules".bright_black());
                } else {
                    print_plain_table(builder);
                }
            }
            Err(e) => {
                error!("failed to list modules: {}", e);
            }
        }

        Ok(())
    }

    pub fn cmd_attach(&mut self, parts: &[&str]) -> Result<()> {
        let pid_str = require_arg!(parts, 1, ReplCommand::Attach);
        match pid_str.parse::<u64>() {
            Ok(pid) => match self.debugger.attach(pid) {
                Ok(AttachReport {
                    name,
                    symbol_report,
                }) => {
                    self.caches.refresh_symbol_context(self.debugger);
                    if let Err(e) = self.caches.refresh_processes(self.debugger) {
                        error!("failed to refresh process cache: {}", e);
                    }
                    println!("attached to {} (PID {})", name, pid);
                    print_module_symbol_report(&symbol_report);
                    println!();
                }
                Err(e) => {
                    error!("failed to attach: {}", e);
                }
            },
            Err(_) => {
                error!("invalid PID: {}", pid_str);
            }
        }

        Ok(())
    }

    pub fn cmd_detach(&mut self, _parts: &[&str]) -> Result<()> {
        if self.debugger.current_process.is_none() {
            error!("not attached to any process");
        } else {
            self.debugger.detach();
            self.caches.refresh_symbol_context(self.debugger);
            if let Err(e) = self.caches.refresh_processes(self.debugger) {
                error!("failed to refresh process cache: {}", e);
            }
            println!("detached, now in kernel context\n");
        }

        Ok(())
    }

    pub fn cmd_vcpu(&mut self, parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        let thread_id = require_arg!(parts, 1, ReplCommand::Vcpu);

        let threads = match self.client.thread_list() {
            Ok(t) => t,
            Err(e) => {
                error!("failed to get vCPU list: {:?}", e);
                return Ok(());
            }
        };

        if !threads.iter().any(|t| t == thread_id) {
            error!("vCPU '{}' not found (use 'vcpus' to list vCPUs)", thread_id);
            return Ok(());
        }

        if let Err(e) = self.client.set_current_thread(thread_id) {
            error!("failed to switch vCPU: {:?}", e);
            return Ok(());
        }

        self.current_thread = thread_id.to_string();
        refresh_windows_thread_context_for_backend_thread(self.debugger, &self.current_thread);
        self.caches.refresh_symbol_context(self.debugger);
        println!("switched to vCPU {}\n", self.current_thread);

        Ok(())
    }
}
