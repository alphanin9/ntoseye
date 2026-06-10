use std::sync::atomic::Ordering;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::debugger::DebuggerContext;
use crate::error::Result;
use crate::expr::Expr;
use crate::gdb::BreakpointHitResult;
use crate::memory::AddressSpace;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{build_stacktrace, preferred_code_dtb, resolve_thread_trace_context};

use crate::repl::*;

fn split_condition_operator(condition: &str) -> Option<(&str, &str, &str)> {
    const OPS: [&str; 6] = ["==", "!=", "<=", ">=", "<", ">"];
    for op in OPS {
        if let Some((left, right)) = condition.split_once(op) {
            return Some((left.trim(), op, right.trim()));
        }
    }
    None
}

fn eval_breakpoint_condition(condition: &str, debugger: &DebuggerContext) -> Result<bool> {
    if let Some((left, op, right)) = split_condition_operator(condition) {
        let left = Expr::eval(left, debugger)?.0;
        let right = Expr::eval(right, debugger)?.0;
        return Ok(match op {
            "==" => left == right,
            "!=" => left != right,
            "<=" => left <= right,
            ">=" => left >= right,
            "<" => left < right,
            ">" => left > right,
            _ => false,
        });
    }

    Ok(Expr::eval(condition, debugger)?.0 != 0)
}

impl ReplState<'_> {
    pub fn interrupt_running_vm(&mut self) -> Result<()> {
        match surface_pending_stop(
            &mut *self.client,
            &self.register_map,
            self.debugger,
            &mut self.breakpoints,
            &self.caches,
            &mut self.current_thread,
            &mut self.reload_module_list_pending,
        ) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => {
                error!("error checking running VM: {:?}", e);
                return Ok(());
            }
        }

        if let Err(e) = surface_interrupt_stop(
            &mut *self.client,
            &self.register_map,
            self.debugger,
            &mut self.breakpoints,
            &self.caches,
            &mut self.current_thread,
            &mut self.reload_module_list_pending,
        ) {
            error!("failed to interrupt: {:?}", e);
        }

        Ok(())
    }

    pub fn cmd_continue(&mut self, _parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            match surface_pending_stop(
                &mut *self.client,
                &self.register_map,
                self.debugger,
                &mut self.breakpoints,
                &self.caches,
                &mut self.current_thread,
                &mut self.reload_module_list_pending,
            ) {
                Ok(true) => {}
                Ok(false) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {:?}", e),
            }
            return Ok(());
        }

        // If we're sitting on one of our breakpoints, step past it
        // before resuming; otherwise the int3 at RIP fires the BP
        // again on the very next cycle
        if self.breakpoints.has_enabled_breakpoints() {
            if let Err(e) = self.client.set_current_thread(&self.current_thread) {
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            if let Err(e) = step_over_current_breakpoint(
                &mut *self.client,
                &self.register_map,
                self.debugger,
                &mut self.breakpoints,
            ) {
                error!("failed to step over current breakpoint: {:?}", e);
                return Ok(());
            }
        }

        if let Err(e) = self
            .breakpoints
            .refresh_enabled(&mut *self.client, self.debugger)
        {
            error!("failed to refresh breakpoints: {}", e);
            return Ok(());
        }

        if let Err(e) = self.client.continue_execution() {
            error!("failed to continue: {:?}", e);
            return Ok(());
        }

        self.debugger.registers = None;
        self.debugger.clear_context_dtb_override();
        self.debugger.clear_current_windows_thread_context();

        println!(
            "{}",
            "VM running, waiting for stop (Ctrl+C to pause)...".bright_black()
        );

        INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);

        loop {
            let stop_result = if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                println!();
                match self.client.try_wait_for_stop(REPL_STOP_POLL) {
                    Ok(Some(event)) => Ok(Some(event)),
                    Ok(None) => self.client.interrupt().map(Some),
                    Err(e) => Err(e),
                }
            } else {
                self.client.try_wait_for_stop(REPL_STOP_POLL)
            };

            match stop_result {
                Ok(Some(mut event)) => {
                    let reload_status = apply_target_reload_if_needed(
                        &mut *self.client,
                        self.debugger,
                        &mut self.breakpoints,
                        &self.caches,
                        &mut event,
                    );
                    update_reload_module_list_pending(
                        &mut self.reload_module_list_pending,
                        reload_status,
                    );
                    if reload_status.pending_rediscovery() {
                        print_pending_rediscovery_stop_context(
                            &mut *self.client,
                            &self.register_map,
                            self.debugger,
                            &mut self.current_thread,
                            &event,
                            reload_status,
                        );
                        break;
                    }
                    let completed_pending_module_list = try_complete_pending_module_list_reload(
                        &mut *self.client,
                        self.debugger,
                        &self.caches,
                        &mut self.reload_module_list_pending,
                    );
                    if !completed_pending_module_list
                        && !self.reload_module_list_pending
                        && should_resume_assisted_refresh_stop(&event, reload_status)
                    {
                        if let Err(e) = resume_assisted_refresh_stop(&mut *self.client) {
                            error!("failed to resume after assisted refresh break: {:?}", e);
                            break;
                        }
                        continue;
                    }
                    let target_reloaded = reload_status.target_reloaded();
                    let reload_load_symbols_stop =
                        is_target_reload_load_symbols_stop(&event, reload_status);
                    let is_bugcheck = event.is_bugcheck && !target_reloaded;
                    set_current_thread_from_stop(
                        &mut *self.client,
                        &event,
                        &mut self.current_thread,
                    );
                    let modules_changed =
                        refresh_stop_caches_pre(&mut *self.client, self.debugger, &self.caches);
                    if is_bugcheck {
                        print_bugcheck_summary(self.debugger, event.bugcheck.as_ref());
                        println!();
                    }
                    let stop_exception_code = event.exception_code;
                    let stop_pc = event.program_counter;
                    let early_non_breakpoint_stop = !target_reloaded
                        && !is_bugcheck
                        && stop_exception_code.zip(stop_pc).is_some_and(|(_, pc)| {
                            self.breakpoints.breakpoint_id_at_address(pc).is_none()
                        });
                    if early_non_breakpoint_stop {
                        print_stop_notice_parts(stop_exception_code, stop_pc);
                        println!();
                    }

                    refresh_stop_caches_post(
                        self.debugger,
                        &self.caches,
                        target_reloaded,
                        modules_changed,
                    );

                    if self.breakpoints.has_enabled_breakpoints() && !is_bugcheck {
                        // Done before reading the current thread's regs so
                        // the BP-hit check below sees the post-rewind RIP
                        rewind_threads_off_breakpoints(
                            &mut *self.client,
                            &self.register_map,
                            &self.breakpoints,
                            &self.current_thread,
                        );
                    }

                    let hit_result = if early_non_breakpoint_stop
                        || is_bugcheck
                        || reload_load_symbols_stop
                    {
                        BreakpointHitResult::NotBreakpoint
                    } else {
                        let regs = match self.client.read_registers() {
                            Ok(r) => r,
                            Err(e) => {
                                error!("failed to read registers: {:?}", e);
                                break;
                            }
                        };

                        self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
                        let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
                        let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
                        if cr3 != 0 {
                            self.debugger.set_context_dtb_override(cr3);
                            self.caches.refresh_symbol_context(self.debugger);
                        }
                        refresh_windows_thread_context_for_backend_thread(
                            self.debugger,
                            &self.current_thread,
                        );

                        let hit_result = self.breakpoints.check_breakpoint_hit(rip, cr3);

                        // Wrong-process hit on a `GuestMemoryPatch` BP
                        // (shared page, e.g. ntdll/user32): step past
                        // the int3 silently so the wrong process keeps
                        // running, then resume waiting for the right one.
                        if matches!(hit_result, BreakpointHitResult::NotBreakpoint)
                            && self.breakpoints.breakpoint_id_at_address(rip).is_some()
                        {
                            if let Err(e) = step_over_current_breakpoint(
                                &mut *self.client,
                                &self.register_map,
                                self.debugger,
                                &mut self.breakpoints,
                            ) {
                                error!("failed to silent-step over wrong-process int3: {:?}", e);
                                break;
                            }
                            if let Err(e) = self.client.continue_execution() {
                                error!(
                                    "failed to resume after silent step over wrong-process int3: {:?}",
                                    e
                                );
                                break;
                            }
                            continue;
                        }

                        hit_result
                    };

                    match hit_result {
                        BreakpointHitResult::Hit(bp) => {
                            if let Some(condition) = &bp.condition {
                                match eval_breakpoint_condition(condition, self.debugger) {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        if let Err(e) = step_over_current_breakpoint(
                                            &mut *self.client,
                                            &self.register_map,
                                            self.debugger,
                                            &mut self.breakpoints,
                                        ) {
                                            error!(
                                                "failed to step over false conditional breakpoint: {:?}",
                                                e
                                            );
                                            break;
                                        }
                                        if let Err(e) = self.client.continue_execution() {
                                            error!(
                                                "failed to resume after false conditional breakpoint: {:?}",
                                                e
                                            );
                                            break;
                                        }
                                        continue;
                                    }
                                    Err(e) => {
                                        error!(
                                            "breakpoint {} condition failed: {}",
                                            ui::bp_id(bp.id),
                                            e
                                        );
                                    }
                                }
                            }

                            println!();
                            if !bp.temporary {
                                println!(
                                    "{} {} {}",
                                    ui::label("breakpoint:"),
                                    ui::bp_id(bp.id),
                                    bp.symbol
                                        .as_ref()
                                        .map(|s| format!("({})", ui::symbol(s)))
                                        .unwrap_or_default()
                                );
                            }
                            print_break_context(
                                &mut *self.client,
                                &self.register_map,
                                self.debugger,
                                &self.breakpoints,
                                &self.current_thread,
                            );

                            // refresh all breakpoints, the stub may have
                            // lost non-hit breakpoints when the VM stopped
                            let _ = self
                                .breakpoints
                                .refresh_enabled(&mut *self.client, self.debugger);

                            break;
                        }
                        BreakpointHitResult::NotBreakpoint => {
                            if !target_reloaded && !early_non_breakpoint_stop && !is_bugcheck {
                                print_stop_notice_parts(stop_exception_code, stop_pc);
                                println!();
                            }
                            if reload_load_symbols_stop {
                                print_target_reload_notification_context(
                                    self.debugger,
                                    &self.current_thread,
                                    &event,
                                    reload_status,
                                );
                            } else if is_bugcheck {
                                print_break_context_for_bugcheck(
                                    &mut *self.client,
                                    &self.register_map,
                                    self.debugger,
                                    &self.breakpoints,
                                    &self.current_thread,
                                    event.bugcheck.as_ref(),
                                );
                            } else {
                                print_break_context(
                                    &mut *self.client,
                                    &self.register_map,
                                    self.debugger,
                                    &self.breakpoints,
                                    &self.current_thread,
                                );
                            }
                            break;
                        }
                    }
                }
                Ok(None) => {
                    // timeout
                }
                Err(e) => {
                    error!("error waiting for stop: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn cmd_break(&mut self, _parts: &[&str]) -> Result<()> {
        if !self.client.is_running() {
            error!("VM is already paused");
            return Ok(());
        }

        self.interrupt_running_vm()
    }

    pub fn cmd_si(&mut self, _parts: &[&str]) -> Result<()> {
        if self.client.is_running() {
            error!("VM is running");
            return Ok(());
        }

        if let Err(e) = self.client.set_current_thread(&self.current_thread) {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let stepped = match step_over_current_breakpoint(
            &mut *self.client,
            &self.register_map,
            self.debugger,
            &mut self.breakpoints,
        ) {
            Ok(stepped) => stepped,
            Err(e) => {
                error!("failed to step over breakpoint: {:?}", e);
                return Ok(());
            }
        };

        if !stepped && let Err(e) = step_one_and_clear_tf(&mut *self.client, &self.register_map) {
            error!("failed to step: {:?}", e);
            return Ok(());
        }

        if let Err(e) = self
            .breakpoints
            .refresh_enabled(&mut *self.client, self.debugger)
        {
            error!("failed to refresh breakpoints after step: {}", e);
        }

        if let Ok(tid) = self.client.stopped_thread_id() {
            self.current_thread = tid;
        }

        println!();
        print_break_context(
            &mut *self.client,
            &self.register_map,
            self.debugger,
            &self.breakpoints,
            &self.current_thread,
        );

        Ok(())
    }

    fn read_current_registers_for_run_control(&mut self) -> Option<Vec<u8>> {
        if self.client.is_running() {
            error!("VM is running");
            return None;
        }

        if let Err(e) = self.client.set_current_thread(&self.current_thread) {
            error!("failed to select execution context: {:?}", e);
            return None;
        }

        match self.client.read_registers() {
            Ok(regs) => {
                self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
                if let Ok(cr3) = self.register_map.read_u64("cr3", &regs)
                    && cr3 != 0
                {
                    self.debugger.set_context_dtb_override(cr3);
                    self.caches.refresh_symbol_context(self.debugger);
                }
                refresh_windows_thread_context_for_backend_thread(
                    self.debugger,
                    &self.current_thread,
                );
                Some(regs)
            }
            Err(e) => {
                self.debugger.registers = None;
                self.debugger.clear_current_windows_thread_context();
                error!("failed to read registers: {:?}", e);
                None
            }
        }
    }

    fn decode_current_instruction(&self, regs: &[u8]) -> Result<Instruction> {
        let rip = self.register_map.read_u64("rip", regs)?;
        let cr3 = self.register_map.read_u64("cr3", regs).unwrap_or(0);
        let trace = resolve_thread_trace_context(self.debugger, cr3);
        let code_dtb = preferred_code_dtb(&trace, rip);
        let memory = AddressSpace::new(&self.debugger.kvm, code_dtb);
        let mut bytes = [0u8; 16];
        memory.read_bytes(VirtAddr(rip), &mut bytes)?;
        self.breakpoints
            .mask_breakpoint_bytes(VirtAddr(rip), &mut bytes, trace.active_dtb);

        let mut decoder = Decoder::with_ip(64, &bytes, rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(crate::error::Error::DebugInfo(format!(
                "failed to decode instruction at {rip:#x}"
            )));
        }
        Ok(instruction)
    }

    fn run_to_temporary_code_breakpoint(&mut self, address: VirtAddr) -> Result<()> {
        if self
            .breakpoints
            .enabled_breakpoint_id_for_current_context(self.debugger, address)
            .is_some()
        {
            return self.cmd_continue(&["continue"]);
        }

        let temp_id =
            match self
                .breakpoints
                .add_temporary_code(&mut *self.client, self.debugger, address)
            {
                Ok(id) => id,
                Err(e) => {
                    error!(
                        "failed to set temporary breakpoint at {}: {}",
                        ui::addr(address.0),
                        e
                    );
                    return Ok(());
                }
            };
        self.caches.refresh_breakpoints(&self.breakpoints);

        let result = self.cmd_continue(&["continue"]);

        let _ = self
            .breakpoints
            .remove(&mut *self.client, self.debugger, temp_id);
        self.caches.refresh_breakpoints(&self.breakpoints);

        result
    }

    pub fn cmd_p(&mut self, _parts: &[&str]) -> Result<()> {
        let Some(regs) = self.read_current_registers_for_run_control() else {
            return Ok(());
        };
        let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
        let instruction = match self.decode_current_instruction(&regs) {
            Ok(instruction) => instruction,
            Err(e) => {
                error!("failed to decode current instruction: {}", e);
                return Ok(());
            }
        };

        if instruction.mnemonic() != Mnemonic::Call {
            return self.cmd_si(&["si"]);
        }

        let next_ip = rip.saturating_add(instruction.len() as u64);
        self.run_to_temporary_code_breakpoint(VirtAddr(next_ip))
    }

    pub fn cmd_gu(&mut self, _parts: &[&str]) -> Result<()> {
        let Some(regs) = self.read_current_registers_for_run_control() else {
            return Ok(());
        };
        let trace = build_stacktrace(self.debugger, &self.register_map, &regs, 4);
        let Some(caller) = trace.frames.get(1) else {
            error!("could not find caller return address");
            return Ok(());
        };
        if caller.ip == 0 {
            error!("caller return address is null");
            return Ok(());
        }

        self.run_to_temporary_code_breakpoint(VirtAddr(caller.ip))
    }
}

#[cfg(test)]
mod tests {
    use super::split_condition_operator;

    #[test]
    fn condition_operator_splitter_prefers_two_char_operators() {
        assert_eq!(
            split_condition_operator("$rax >= 0x10"),
            Some(("$rax", ">=", "0x10"))
        );
        assert_eq!(
            split_condition_operator("$rax == $rbx"),
            Some(("$rax", "==", "$rbx"))
        );
        assert_eq!(split_condition_operator("$rax"), None);
    }
}
