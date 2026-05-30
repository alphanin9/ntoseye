//! Shared debugger session state machine.
//!
//! [`DebuggerSession`] owns the pieces the REPL and the agent stdio protocol
//! used to track separately: the current thread, the breakpoint set, the
//! register layout, and the management of the cached register snapshot in
//! [`DebuggerContext::registers`]. It also implements the continue/step/stop
//! handling (software-breakpoint step-over, off-by-one rewind, and
//! wrong-process `int3` recovery) so both front-ends drive the exact same
//! logic instead of duplicating it.

use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::debugger::DebuggerContext;
use crate::error::{Error, Result};
use crate::gdb::{Breakpoint, BreakpointHitResult, BreakpointManager, RegisterMap};

/// Result of [`DebuggerSession::step_over_current_breakpoint`].
pub struct StepOver {
    /// Whether an underlying instruction was stepped (i.e. RIP was on a BP).
    pub stepped: bool,
    /// Breakpoints removed because their address space no longer exists.
    pub discarded: Vec<Breakpoint>,
}

/// What a stop event turned out to be after [`DebuggerSession::process_stop`].
pub enum StopOutcome {
    /// One of our breakpoints was hit in its owning context.
    Breakpoint(Breakpoint),
    /// The target stopped, but not on a tracked breakpoint (interrupt, single
    /// step, or a stop we don't own).
    Stopped,
    /// The target exited / reset; there is no guest CPU state to inspect.
    TargetExited,
    /// A wrong-process `int3` on a shared page was stepped over silently and
    /// execution was resumed. Callers should keep waiting for the next stop.
    Resumed,
}

/// Backend-neutral debugger state shared by the REPL and the agent protocol.
pub struct DebuggerSession {
    pub register_map: RegisterMap,
    pub current_thread: String,
    pub breakpoints: BreakpointManager,
}

impl DebuggerSession {
    pub fn new(register_map: RegisterMap, current_thread: String) -> Self {
        Self {
            register_map,
            current_thread,
            breakpoints: BreakpointManager::new(),
        }
    }

    /// Set the gdb stub's control thread to the current thread, read its
    /// registers, and refresh [`DebuggerContext::registers`]. Returns the raw
    /// register bytes for callers that want to format them.
    pub fn refresh_register_cache(
        &self,
        client: &mut dyn DebugBackend,
        debugger: &mut DebuggerContext,
    ) -> Result<Vec<u8>> {
        client.set_current_thread(&self.current_thread)?;
        let regs = client.read_registers()?;
        debugger.registers = Some(self.register_map.to_hashmap(&regs));
        Ok(regs)
    }

    /// Drop the cached register snapshot; call after resuming the target.
    pub fn invalidate_register_cache(&self, debugger: &mut DebuggerContext) {
        debugger.registers = None;
    }

    /// Single-step the current thread and clear `TF` from its RFLAGS afterwards.
    /// KVM sets `TF` when enabling `KVM_GUESTDBG_SINGLESTEP` but doesn't clear
    /// it when SINGLESTEP is removed; without this clear, the stepped thread
    /// keeps trapping after every instruction on resume.
    fn single_step(&self, client: &mut dyn DebugBackend) -> Result<()> {
        client.step()?;
        client.wait_for_stop()?;

        if let Ok(mut regs) = client.read_registers()
            && let Ok(eflags) = self.register_map.read_u64("eflags", &regs)
        {
            let cleared = eflags & !(1u64 << 8);
            if cleared != eflags
                && self
                    .register_map
                    .write_u64("eflags", &mut regs, cleared)
                    .is_ok()
            {
                client.write_registers(&regs)?;
            }
        }

        Ok(())
    }

    /// If the current thread's RIP sits on one of our enabled breakpoints,
    /// disable it, step the underlying instruction, then re-enable it. Returns
    /// whether a step was performed plus any breakpoints discarded because
    /// their address space disappeared. Caller must have set the gdb stub's
    /// control thread first.
    pub fn step_over_current_breakpoint(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
    ) -> Result<StepOver> {
        let regs = client.read_registers()?;
        let rip = self.register_map.read_u64("rip", &regs)?;
        let cr3 = self.register_map.read_u64("cr3", &regs)?;

        // Scope-agnostic: a wrong-process hit on a shared-page BP still needs
        // the disable/step/enable dance so the wrong process can make forward
        // progress.
        let Some(bp_id) = self.breakpoints.breakpoint_id_at_address(rip) else {
            return Ok(StepOver {
                stepped: false,
                discarded: Vec::new(),
            });
        };

        if let Err(err) = self.breakpoints.disable(client, debugger, bp_id) {
            if matches!(err, Error::BadVirtualAddress(_)) {
                self.breakpoints
                    .disable_guest_memory_patch_in_address_space(client, debugger, bp_id, cr3)?;
            } else {
                return Err(err);
            }
        }

        self.single_step(client)?;

        let mut discarded = Vec::new();
        if let Err(err) = self.breakpoints.enable(client, debugger, bp_id) {
            if matches!(err, Error::BadVirtualAddress(_)) {
                discarded.push(self.breakpoints.discard(bp_id)?);
            } else {
                return Err(err);
            }
        }

        Ok(StepOver {
            stepped: true,
            discarded,
        })
    }

    /// For every gdb thread whose RIP sits one byte past one of our
    /// breakpoints, rewind it back to the breakpoint address. The stub doesn't
    /// always adjust RIP back to the int3 when multiple vCPUs hit the same BP
    /// simultaneously; resuming an un-adjusted vCPU would decode the remainder
    /// of the original instruction's bytes as a different instruction and
    /// corrupt guest state. Restores Hg/Hc to the current thread before
    /// returning.
    pub fn rewind_threads_off_breakpoints(&self, client: &mut dyn DebugBackend) {
        let threads = match client.get_thread_list() {
            Ok(t) => t,
            Err(_) => return,
        };

        for tid in &threads {
            if client.set_current_thread(tid).is_err() {
                continue;
            }
            let Ok(regs) = client.read_registers() else {
                continue;
            };
            let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
            let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
            let Some(prev) = rip.checked_sub(1) else {
                continue;
            };
            if !self.breakpoints.int3_breakpoint_hit_at(prev, cr3) {
                continue;
            }
            let mut adjusted = regs.clone();
            if self
                .register_map
                .write_u64("rip", &mut adjusted, prev)
                .is_err()
            {
                continue;
            }
            let _ = client.write_registers(&adjusted);
        }

        let _ = client.set_current_thread(&self.current_thread);
    }

    /// Prepare to resume the target: if we're sitting on one of our
    /// breakpoints, step past it first (otherwise the int3 at RIP fires the BP
    /// again on the very next cycle), then refresh all enabled breakpoints so
    /// the transport's view matches ours. Returns any discarded breakpoints.
    pub fn prepare_resume(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
    ) -> Result<Vec<Breakpoint>> {
        let mut discarded = Vec::new();
        if self.breakpoints.has_enabled_breakpoints() {
            client.set_current_thread(&self.current_thread)?;
            discarded = self
                .step_over_current_breakpoint(client, debugger)?
                .discarded;
        }
        self.breakpoints.refresh_enabled(client, debugger)?;
        Ok(discarded)
    }

    /// Classify a stop event and recover from wrong-process `int3` hits.
    ///
    /// Updates the current thread, rewinds any off-by-one vCPUs, refreshes the
    /// register cache, and checks whether a tracked breakpoint was hit. A
    /// wrong-process hit on a `GuestMemoryPatch` breakpoint (shared page, e.g.
    /// ntdll/user32) is stepped over silently and execution resumed, returning
    /// [`StopOutcome::Resumed`] so the caller keeps waiting for the real hit.
    pub fn process_stop(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &mut DebuggerContext,
        event: &StopEvent,
    ) -> Result<StopOutcome> {
        if event.target_exited {
            self.invalidate_register_cache(debugger);
            return Ok(StopOutcome::TargetExited);
        }

        if let Some(tid) = event
            .thread_id
            .clone()
            .or_else(|| client.get_stopped_thread_id().ok())
        {
            self.current_thread = tid;
            let _ = client.set_current_thread(&self.current_thread);
        }

        // Done before reading the current thread's regs so the BP-hit check
        // below sees the post-rewind RIP.
        self.rewind_threads_off_breakpoints(client);

        let regs = client.read_registers()?;
        let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
        let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);

        let hit_result = self.breakpoints.check_breakpoint_hit(rip, cr3);

        // Wrong-process hit on a `GuestMemoryPatch` BP (shared page): step past
        // the int3 silently so the wrong process keeps running, then resume
        // waiting for the right one.
        if matches!(hit_result, BreakpointHitResult::NotBreakpoint)
            && self.breakpoints.breakpoint_id_at_address(rip).is_some()
        {
            self.step_over_current_breakpoint(client, debugger)?;
            client.continue_execution()?;
            self.invalidate_register_cache(debugger);
            return Ok(StopOutcome::Resumed);
        }

        debugger.registers = Some(self.register_map.to_hashmap(&regs));

        match hit_result {
            BreakpointHitResult::Hit(bp) => Ok(StopOutcome::Breakpoint(bp)),
            BreakpointHitResult::NotBreakpoint => Ok(StopOutcome::Stopped),
        }
    }

    /// Single-step the current thread one instruction. If RIP is on one of our
    /// breakpoints, step over it (disable/step/enable); otherwise do a plain
    /// single step. Refreshes enabled breakpoints and updates the current
    /// thread afterwards. Returns any discarded breakpoints.
    pub fn step(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &DebuggerContext,
    ) -> Result<Vec<Breakpoint>> {
        client.set_current_thread(&self.current_thread)?;

        let StepOver { stepped, discarded } =
            self.step_over_current_breakpoint(client, debugger)?;

        if !stepped {
            self.single_step(client)?;
        }

        self.breakpoints.refresh_enabled(client, debugger)?;

        if let Ok(tid) = client.get_stopped_thread_id() {
            self.current_thread = tid;
        }

        Ok(discarded)
    }
}
