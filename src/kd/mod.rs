//! Windows KD backend over QEMU serial

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::kd::framing::{KdFraming, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_STATE_CHANGE64};

macro_rules! kd_trace {
    ($($arg:tt)*) => {
        if crate::kd::trace_enabled() {
            eprintln!($($arg)*);
        }
    };
}

macro_rules! kd_trace_bytes {
    ($($arg:tt)*) => {
        if crate::kd::trace_bytes_enabled() {
            eprint!($($arg)*);
        }
    };
}

pub(crate) fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_KD_TRACE").is_some())
}

pub(crate) fn trace_bytes_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_KD_TRACE_BYTES").is_some())
}

pub mod api;
pub mod context;
pub mod framing;

#[derive(Debug, Clone, Copy)]
struct StateChange {
    processor: u16,
    number_processors: u16,
    new_state: u32,
    exception_code: u32,
    program_counter: u64,
}

const DBG_KD_EXCEPTION_STATE_CHANGE: u32 = 0x0000_3030;

const AMD64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;
const KSPECIAL_REGISTERS_CR0_OFFSET: usize = 0x00;
const KSPECIAL_REGISTERS_CR2_OFFSET: usize = 0x08;
const KSPECIAL_REGISTERS_CR3_OFFSET: usize = 0x10;
const KSPECIAL_REGISTERS_CR4_OFFSET: usize = 0x18;
const KSPECIAL_REGISTERS_CR8_OFFSET: usize = 0xA0;
const KSPECIAL_REGISTERS_MIN_SIZE: usize = KSPECIAL_REGISTERS_CR8_OFFSET + 8;
const STATUS_BREAKPOINT: u32 = 0x8000_0003;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialHandshakeStimulus {
    ListenOnly,
    BreakIn,
    Reset,
}

fn initial_handshake_stimulus(attempt: u32) -> InitialHandshakeStimulus {
    match attempt {
        0 => InitialHandshakeStimulus::ListenOnly,
        n if n % 2 == 1 => InitialHandshakeStimulus::BreakIn,
        _ => InitialHandshakeStimulus::Reset,
    }
}

fn parse_state_change(payload: &[u8]) -> Result<StateChange> {
    // DBGKD_ANY_WAIT_STATE_CHANGE on x64 starts with:
    //   ULONG NewState         @ 0
    //   USHORT ProcessorLevel  @ 4
    //   USHORT Processor       @ 6
    //   ULONG NumberProcessors @ 8
    //   <4 bytes pad to 8-byte align>
    //   ULONG64 Thread         @ 16
    //   ULONG64 ProgramCounter @ 24
    //   <union starts at 32>:
    //     DBGKM_EXCEPTION64.ExceptionRecord.ExceptionCode @ 32
    //     (and more EXCEPTION_RECORD64 fields)
    if payload.len() < 32 {
        return Err(Error::Kd(format!(
            "state-change payload too short: {} bytes",
            payload.len()
        )));
    }
    let new_state = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let exception_code = if new_state == DBG_KD_EXCEPTION_STATE_CHANGE && payload.len() >= 36 {
        u32::from_le_bytes(payload[32..36].try_into().unwrap())
    } else {
        0
    };
    let number_processors_u32 = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    Ok(StateChange {
        new_state,
        processor: u16::from_le_bytes(payload[6..8].try_into().unwrap()),
        number_processors: number_processors_u32.min(u16::MAX as u32) as u16,
        exception_code,
        program_counter: u64::from_le_bytes(payload[24..32].try_into().unwrap()),
    })
}

struct DebugPrint<'a> {
    text: &'a [u8],
}
pub(crate) fn print_debug_io(payload: &[u8]) {
    if let Some(print) = parse_debug_io_print(payload) {
        let _ = std::io::stderr().write_all(print.text);
    }
}

fn parse_debug_io_print(payload: &[u8]) -> Option<DebugPrint<'_>> {
    // DBGKD_DEBUG_IO:
    //   ULONG ApiNumber          @ 0  (DbgKdPrintStringApi = 0x00003230)
    //   USHORT ProcessorLevel    @ 4
    //   USHORT Processor         @ 6
    //   ULONG LengthOfString     @ 8  (PrintString union member)
    // Total header = 12 bytes, followed by `LengthOfString` bytes of text
    if payload.len() < 12 {
        return None;
    }
    let api = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    if api != 0x0000_3230 {
        return None;
    }
    let len = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
    let text_end = (12 + len).min(payload.len());
    Some(DebugPrint {
        text: &payload[12..text_end],
    })
}

fn thread_id_for(processor: u16) -> String {
    format!("p1.{:x}", processor + 1)
}

fn parse_thread_id(tid: &str) -> Result<u16> {
    let stripped = tid
        .strip_prefix("p1.")
        .ok_or_else(|| Error::Kd(format!("unrecognised thread id {tid}")))?;
    let idx =
        u16::from_str_radix(stripped, 16).map_err(|_| Error::Kd(format!("bad thread id {tid}")))?;
    if idx == 0 {
        return Err(Error::Kd(format!("thread id {tid} has zero index")));
    }
    Ok(idx - 1)
}

fn parse_thread_id_for_processor_count(tid: &str, processor_count: u16) -> Result<u16> {
    let processor = parse_thread_id(tid)?;
    if processor >= processor_count {
        return Err(Error::Kd(format!(
            "thread id {tid} selects processor {}, but guest reports {} processor(s)",
            processor + 1,
            processor_count
        )));
    }
    Ok(processor)
}

/// Initial break-in: listen first, then alternate break-in and RESET
fn poll_for_initial_break(
    framing: &mut KdFraming<UnixStream>,
    budget: Duration,
) -> Result<StateChange> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
    let deadline = Instant::now() + budget;

    framing
        .transport_mut()
        .set_read_timeout(Some(ATTEMPT_TIMEOUT))?;

    let mut attempts = 0u32;
    let result = loop {
        match initial_handshake_stimulus(attempts) {
            InitialHandshakeStimulus::ListenOnly => {}
            InitialHandshakeStimulus::BreakIn => framing.send_breakin()?,
            InitialHandshakeStimulus::Reset => {
                framing.send_reset()?;
                kd_trace!("kd: RESET sent during initial handshake");
            }
        }
        attempts += 1;

        match await_state_change(framing) {
            Ok(stop) => break Ok(stop),
            Err(Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                let elapsed =
                    budget.saturating_sub(deadline.saturating_duration_since(Instant::now()));
                eprintln!("kd: no response yet ({}s)...", elapsed.as_secs());
                if Instant::now() >= deadline {
                    break Err(Error::Kd(format!(
                        "guest did not respond within {}s. \
                         Check: (a) the guest was rebooted after `bcdedit /debug on`, \
                         (b) `bcdedit /dbgsettings` debugport matches the COM port \
                         your QEMU serial is wired to (COM2 if using qemu:commandline \
                         alongside libvirt's default console serial), \
                         (c) baudrate is 115200",
                        budget.as_secs()
                    )));
                }
            }
            Err(e) => break Err(e),
        }
    };

    let _ = framing.transport_mut().set_read_timeout(None);
    result
}

/// Send one break-in byte and wait for the resulting state-change
fn breakin_and_wait(framing: &mut KdFraming<UnixStream>, budget: Duration) -> Result<StateChange> {
    framing.send_breakin()?;
    framing.transport_mut().set_read_timeout(Some(budget))?;
    let result = match await_state_change(framing) {
        Ok(stop) => Ok(stop),
        Err(Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err(Error::Kd(format!(
                "no break-in response within {}s",
                budget.as_secs()
            )))
        }
        Err(e) => Err(e),
    };
    let _ = framing.transport_mut().set_read_timeout(None);
    result
}

fn should_advance_rip_before_continue(exception_code: u32, managed_breakpoint_stop: bool) -> bool {
    exception_code == STATUS_BREAKPOINT && !managed_breakpoint_stop
}

fn append_control_registers_from_special(ctx: &mut Vec<u8>, special: &[u8]) -> Result<()> {
    if special.len() < KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }

    ctx.resize(context::REGISTER_BUFFER_SIZE, 0);

    let copy_reg = |ctx: &mut [u8], ctx_offset: usize, special_offset: usize| {
        ctx[ctx_offset..ctx_offset + 8]
            .copy_from_slice(&special[special_offset..special_offset + 8]);
    };
    copy_reg(ctx, context::OFFSET_CR0, KSPECIAL_REGISTERS_CR0_OFFSET);
    copy_reg(ctx, context::OFFSET_CR2, KSPECIAL_REGISTERS_CR2_OFFSET);
    copy_reg(ctx, context::OFFSET_CR3, KSPECIAL_REGISTERS_CR3_OFFSET);
    copy_reg(ctx, context::OFFSET_CR4, KSPECIAL_REGISTERS_CR4_OFFSET);
    copy_reg(ctx, context::OFFSET_CR8, KSPECIAL_REGISTERS_CR8_OFFSET);
    Ok(())
}

fn context_payload(data: &[u8]) -> Result<&[u8]> {
    if data.len() < context::CONTEXT_SIZE {
        return Err(Error::Kd(format!(
            "CONTEXT buffer too short: {} bytes, expected {}",
            data.len(),
            context::CONTEXT_SIZE
        )));
    }
    Ok(&data[..context::CONTEXT_SIZE])
}

/// Receive packets until a state-change arrives
fn await_state_change(framing: &mut KdFraming<UnixStream>) -> Result<StateChange> {
    loop {
        let pkt = framing.recv_data()?;
        match pkt.packet_type {
            PACKET_TYPE_KD_STATE_CHANGE64 => return parse_state_change(&pkt.payload),
            PACKET_TYPE_KD_DEBUG_IO => print_debug_io(&pkt.payload),
            _ => {
                // Orphan packet, likely a manipulate reply from a previous
                // session. Discard and keep listening
            }
        }
    }
}

pub struct KdBackend {
    framing: KdFraming<UnixStream>,
    register_map: RegisterMap,
    processor_count: u16,
    current_processor: u16,
    pending_stop: Option<StateChange>,
    last_exception_code: u32,
    last_rip: u64,
    last_stop_was_managed_breakpoint: bool,
    bp_handles: HashMap<u64, u32>,
    managed_bp_addresses: std::collections::HashSet<u64>,
    known_spurious_rip: Option<u64>,
    special_register_cache: HashMap<u16, Vec<u8>>,
    is_running: bool,
}

impl KdBackend {
    /// Connect to the KD serial pipe and stop at the initial state-change
    pub fn connect(socket_path: &str) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        let mut framing = KdFraming::new(stream);

        eprintln!("kd: connected to {socket_path}, waiting for guest break-in...");

        // A waiting kernel retransmits state-change; otherwise break in
        let initial_stop = poll_for_initial_break(&mut framing, Duration::from_secs(30))?;
        kd_trace!(
            "kd: initial state-change received: p{}/{}, exc={:#x}, rip={:#x}",
            initial_stop.processor + 1,
            initial_stop.number_processors,
            initial_stop.exception_code,
            initial_stop.program_counter
        );

        let version = api::get_version(&mut framing, initial_stop.processor)?;
        kd_trace!(
            "kd: GetVersion ok: machine={:#x}, kern_base={:#x}",
            version.machine_type,
            version.kern_base
        );

        if version.machine_type != 0x8664 {
            return Err(Error::Kd(format!(
                "KD backend only supports x86_64 guests (machine_type = {:#x})",
                version.machine_type
            )));
        }

        Ok(Self {
            framing,
            register_map: context::build_register_map(),
            processor_count: initial_stop.number_processors.max(1),
            current_processor: initial_stop.processor,
            last_exception_code: initial_stop.exception_code,
            last_rip: initial_stop.program_counter,
            // Don't let a stale initial stop surface later via try_wait
            pending_stop: None,
            bp_handles: HashMap::new(),
            managed_bp_addresses: std::collections::HashSet::new(),
            known_spurious_rip: if initial_stop.exception_code == STATUS_BREAKPOINT {
                Some(initial_stop.program_counter)
            } else {
                None
            },
            last_stop_was_managed_breakpoint: false,
            special_register_cache: HashMap::new(),
            is_running: false,
        })
    }

    fn record_stop(&mut self, stop: StateChange) {
        let managed_breakpoint_stop = stop.exception_code == STATUS_BREAKPOINT
            && self.managed_bp_addresses.contains(&stop.program_counter);
        kd_trace!(
            "kd: stop on p{}, new_state={:#x}, exception_code={:#x}, rip={:#x}, managed_bp={}",
            stop.processor + 1,
            stop.new_state,
            stop.exception_code,
            stop.program_counter,
            managed_breakpoint_stop
        );
        self.current_processor = stop.processor;
        self.last_exception_code = stop.exception_code;
        self.last_rip = stop.program_counter;
        self.last_stop_was_managed_breakpoint = managed_breakpoint_stop;
        self.special_register_cache.clear();
        self.is_running = false;
    }

    fn record_running(&mut self) {
        self.is_running = true;
        self.special_register_cache.clear();
    }

    /// KD reports raw int3 stops with RIP still pointing at the int3
    fn advance_rip_past_int3(&mut self) -> Result<()> {
        let mut ctx = api::get_context(&mut self.framing, self.current_processor)?;
        let rip = self.register_map.read_u64("rip", &ctx)?;
        kd_trace!(
            "kd: advance_rip: read rip={:#x}, ctx.len={}",
            rip,
            ctx.len()
        );
        self.register_map
            .write_u64("rip", &mut ctx, rip.wrapping_add(1))?;
        api::set_context(&mut self.framing, self.current_processor, &ctx)?;
        if trace_enabled() {
            // Read back to verify it took
            if let Ok(verify_ctx) = api::get_context(&mut self.framing, self.current_processor)
                && let Ok(verify_rip) = self.register_map.read_u64("rip", &verify_ctx)
            {
                kd_trace!(
                    "kd: advance_rip: wrote {:#x}, read back {:#x}",
                    rip.wrapping_add(1),
                    verify_rip
                );
            }
        }
        Ok(())
    }

    fn read_special_registers(&mut self) -> Result<&[u8]> {
        if !self
            .special_register_cache
            .contains_key(&self.current_processor)
        {
            let data = api::read_control_space(
                &mut self.framing,
                self.current_processor,
                AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
                KSPECIAL_REGISTERS_MIN_SIZE as u32,
            )?;
            self.special_register_cache
                .insert(self.current_processor, data);
        }

        self.special_register_cache
            .get(&self.current_processor)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::Kd("special-register cache lookup failed".into()))
    }

    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        let special = self.read_special_registers()?;
        append_control_registers_from_special(ctx, &special)
    }
}

impl DebugBackend for KdBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        kd_trace!(
            "kd: read_registers: GetContext on p{}",
            self.current_processor + 1
        );
        let mut ctx = api::get_context(&mut self.framing, self.current_processor)?;
        kd_trace!("kd: read_registers: got {} context bytes", ctx.len());
        self.append_control_registers(&mut ctx)?;
        kd_trace!("kd: read_registers: extended to {} bytes", ctx.len());
        Ok(ctx)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let context = context_payload(data)?;
        api::set_context(&mut self.framing, self.current_processor, context)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let handle = api::write_breakpoint(&mut self.framing, self.current_processor, addr)?;
        self.bp_handles.insert(addr, handle);
        self.managed_bp_addresses.insert(addr);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let handle = self
            .bp_handles
            .remove(&addr)
            .ok_or_else(|| Error::Kd(format!("no breakpoint tracked at {addr:#x}")))?;
        self.managed_bp_addresses.remove(&addr);
        api::restore_breakpoint(&mut self.framing, self.current_processor, handle)
    }

    fn supports_process_breakpoints(&self) -> bool {
        true
    }

    fn note_breakpoint_installed(&mut self, addr: u64) {
        self.managed_bp_addresses.insert(addr);
    }

    fn note_breakpoint_uninstalled(&mut self, addr: u64) {
        self.managed_bp_addresses.remove(&addr);
    }

    fn continue_execution(&mut self) -> Result<()> {
        // Drain stale break-in bytes consumed by KdPollBreakIn after resume
        const MAX_DRAIN_ITERATIONS: u32 = 64;
        const DRAIN_POLL: Duration = Duration::from_millis(1000);

        let mut drained = 0u32;
        loop {
            if should_advance_rip_before_continue(
                self.last_exception_code,
                self.last_stop_was_managed_breakpoint,
            ) {
                kd_trace!(
                    "kd: continue: advancing RIP past raw int3 (last_exception_code={:#x})",
                    self.last_exception_code
                );
                self.advance_rip_past_int3()?;
            } else {
                kd_trace!(
                    "kd: continue: not advancing (last_exception_code={:#x}, managed_bp={})",
                    self.last_exception_code,
                    self.last_stop_was_managed_breakpoint
                );
            }
            let resumed_from_rip = self.last_rip;
            kd_trace!(
                "kd: continue: sending ContinueApi2 on p{}",
                self.current_processor + 1
            );
            api::continue_api2(
                &mut self.framing,
                self.current_processor,
                api::DBG_CONTINUE,
                false,
            )?;
            kd_trace!("kd: continue: ContinueApi2 ACKed, VM should resume");
            self.record_running();

            self.framing
                .transport_mut()
                .set_read_timeout(Some(DRAIN_POLL))?;
            let result = await_state_change(&mut self.framing);
            let _ = self.framing.transport_mut().set_read_timeout(None);

            match result {
                Ok(stop) => {
                    // Don't drain managed BPs; the REPL handles wrong-process hits
                    let is_spurious = stop.exception_code == STATUS_BREAKPOINT
                        && (stop.program_counter == resumed_from_rip
                            || Some(stop.program_counter) == self.known_spurious_rip)
                        && !self.managed_bp_addresses.contains(&stop.program_counter);
                    if is_spurious && drained < MAX_DRAIN_ITERATIONS {
                        drained += 1;
                        self.known_spurious_rip = Some(stop.program_counter);
                        kd_trace!(
                            "kd: continue: spurious re-break at {:#x} (drain {}/{})",
                            stop.program_counter,
                            drained,
                            MAX_DRAIN_ITERATIONS
                        );
                        self.record_stop(stop);
                        continue;
                    }
                    kd_trace!(
                        "kd: continue: real stop at {:#x} (exc={:#x}), stashing as pending",
                        stop.program_counter,
                        stop.exception_code
                    );
                    self.record_stop(stop);
                    self.pending_stop = Some(stop);
                    return Ok(());
                }
                Err(Error::Io(e))
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                {
                    if drained > 0 {
                        kd_trace!(
                            "kd: continue: drained {} spurious break(s), VM now running",
                            drained
                        );
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn step(&mut self) -> Result<()> {
        // Managed BP step-over needs to execute the original instruction
        api::continue_api2(
            &mut self.framing,
            self.current_processor,
            api::DBG_CONTINUE,
            true,
        )?;
        self.record_running();
        Ok(())
    }

    fn interrupt(&mut self) -> Result<()> {
        // Consume the resulting state-change inline
        let stop = breakin_and_wait(&mut self.framing, Duration::from_secs(10))?;
        self.record_stop(stop);
        Ok(())
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        if let Some(stop) = self.pending_stop.take() {
            self.record_stop(stop);
            return Ok(StopEvent {
                thread_id: Some(thread_id_for(stop.processor)),
            });
        }
        let stop = await_state_change(&mut self.framing)?;
        self.record_stop(stop);
        Ok(StopEvent {
            thread_id: Some(thread_id_for(stop.processor)),
        })
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        if let Some(stop) = self.pending_stop.take() {
            kd_trace!(
                "kd: try_wait: surfacing pending_stop rip={:#x} (bypassing spurious check)",
                stop.program_counter
            );
            self.record_stop(stop);
            return Ok(Some(StopEvent {
                thread_id: Some(thread_id_for(stop.processor)),
            }));
        }
        kd_trace!(
            "kd: try_wait: entry timeout={}ms, known_spurious={:?}",
            timeout.as_millis(),
            self.known_spurious_rip
        );

        self.framing
            .transport_mut()
            .set_read_timeout(Some(timeout))?;
        let result = await_state_change(&mut self.framing);
        // Restore blocking mode regardless of how the wait turned out
        let _ = self.framing.transport_mut().set_read_timeout(None);

        let stop = match result {
            Ok(stop) => stop,
            Err(Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        // Silently drain stale break-in stops at the known spurious RIP
        let is_known_spurious = stop.exception_code == STATUS_BREAKPOINT
            && Some(stop.program_counter) == self.known_spurious_rip
            && !self.managed_bp_addresses.contains(&stop.program_counter);
        kd_trace!(
            "kd: try_wait: stop rip={:#x} exc={:#x} known_spurious={:?} in_managed={} → spurious={}",
            stop.program_counter,
            stop.exception_code,
            self.known_spurious_rip,
            self.managed_bp_addresses.contains(&stop.program_counter),
            is_known_spurious
        );
        if is_known_spurious {
            kd_trace!(
                "kd: try_wait: silent drain at {:#x} (matches known spurious)",
                stop.program_counter
            );
            self.record_stop(stop);
            self.advance_rip_past_int3()?;
            api::continue_api2(
                &mut self.framing,
                self.current_processor,
                api::DBG_CONTINUE,
                false,
            )?;
            self.is_running = true;
            return Ok(None);
        }

        self.record_stop(stop);
        Ok(Some(StopEvent {
            thread_id: Some(thread_id_for(stop.processor)),
        }))
    }

    fn get_thread_list(&mut self) -> Result<Vec<String>> {
        Ok((0..self.processor_count).map(thread_id_for).collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        // Local-only; SwitchProcessor emits an unsolicited state-change
        self.current_processor =
            parse_thread_id_for_processor_count(thread_id, self.processor_count)?;
        Ok(())
    }

    fn get_stopped_thread_id(&mut self) -> Result<String> {
        Ok(thread_id_for(self.current_processor))
    }

    fn is_running(&self) -> bool {
        self.is_running
    }
}

/// Resume a stopped guest during normal teardown
impl Drop for KdBackend {
    fn drop(&mut self) {
        if !self.is_running
            && should_advance_rip_before_continue(
                self.last_exception_code,
                self.last_stop_was_managed_breakpoint,
            )
        {
            let _ = self.advance_rip_past_int3();
        }
        if !self.is_running {
            let _ = api::continue_api2(
                &mut self.framing,
                self.current_processor,
                api::DBG_CONTINUE,
                false,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_state_change_extracts_processor_and_pc() {
        let mut payload = vec![0u8; 64];
        payload[0..4].copy_from_slice(&0x3030u32.to_le_bytes()); // NewState
        payload[6..8].copy_from_slice(&2u16.to_le_bytes()); // Processor = 2
        payload[8..12].copy_from_slice(&4u32.to_le_bytes()); // NumberProcessors
        payload[24..32].copy_from_slice(&0xfffff800deadbeefu64.to_le_bytes());

        let s = parse_state_change(&payload).unwrap();
        assert_eq!(s.processor, 2);
        assert_eq!(s.number_processors, 4);
        assert_eq!(s.new_state, 0x3030);
        assert_eq!(s.program_counter, 0xfffff800deadbeef);
    }

    #[test]
    fn parse_debug_io_print_extracts_string() {
        let mut payload = vec![0u8; 12];
        payload[0..4].copy_from_slice(&0x0000_3230u32.to_le_bytes()); // DbgKdPrintStringApi
        payload[8..12].copy_from_slice(&5u32.to_le_bytes());
        payload.extend_from_slice(b"hello");

        let print = parse_debug_io_print(&payload).unwrap();
        assert_eq!(print.text, b"hello");
    }

    #[test]
    fn parse_debug_io_print_rejects_other_api() {
        let mut payload = vec![0u8; 12];
        payload[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        assert!(parse_debug_io_print(&payload).is_none());
    }

    #[test]
    fn parse_state_change_rejects_short_payload() {
        let err = parse_state_change(&[0u8; 10]).unwrap_err();
        match err {
            Error::Kd(msg) => assert!(msg.contains("too short")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn continue_advance_policy_skips_only_raw_int3() {
        assert!(should_advance_rip_before_continue(STATUS_BREAKPOINT, false));
        assert!(!should_advance_rip_before_continue(STATUS_BREAKPOINT, true));
        assert!(!should_advance_rip_before_continue(0x8000_0004, false)); // STATUS_SINGLE_STEP
    }

    #[test]
    fn initial_handshake_tries_breakin_before_reset() {
        assert_eq!(
            initial_handshake_stimulus(0),
            InitialHandshakeStimulus::ListenOnly
        );
        assert_eq!(
            initial_handshake_stimulus(1),
            InitialHandshakeStimulus::BreakIn
        );
        assert_eq!(
            initial_handshake_stimulus(2),
            InitialHandshakeStimulus::Reset
        );
        assert_eq!(
            initial_handshake_stimulus(3),
            InitialHandshakeStimulus::BreakIn
        );
    }

    #[test]
    fn context_payload_accepts_synthetic_register_buffer() {
        let synthetic = vec![0u8; context::REGISTER_BUFFER_SIZE];
        assert_eq!(
            context_payload(&synthetic).unwrap().len(),
            context::CONTEXT_SIZE
        );
    }

    #[test]
    fn context_payload_rejects_short_buffers() {
        let short = vec![0u8; context::CONTEXT_SIZE - 1];
        assert!(context_payload(&short).is_err());
    }

    #[test]
    fn append_control_registers_extends_context() {
        let mut ctx = vec![0u8; context::CONTEXT_SIZE];
        let mut special = vec![0u8; KSPECIAL_REGISTERS_MIN_SIZE];
        special[KSPECIAL_REGISTERS_CR0_OFFSET..KSPECIAL_REGISTERS_CR0_OFFSET + 8]
            .copy_from_slice(&0x8005_0033u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR2_OFFSET..KSPECIAL_REGISTERS_CR2_OFFSET + 8]
            .copy_from_slice(&0x1111_2222u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR3_OFFSET..KSPECIAL_REGISTERS_CR3_OFFSET + 8]
            .copy_from_slice(&0x1234_5000u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR4_OFFSET..KSPECIAL_REGISTERS_CR4_OFFSET + 8]
            .copy_from_slice(&0x350ef8u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR8_OFFSET..KSPECIAL_REGISTERS_CR8_OFFSET + 8]
            .copy_from_slice(&2u64.to_le_bytes());

        append_control_registers_from_special(&mut ctx, &special).unwrap();
        let map = context::build_register_map();

        assert_eq!(ctx.len(), context::REGISTER_BUFFER_SIZE);
        assert_eq!(map.read_u64("cr0", &ctx).unwrap(), 0x8005_0033);
        assert_eq!(map.read_u64("cr2", &ctx).unwrap(), 0x1111_2222);
        assert_eq!(map.read_u64("cr3", &ctx).unwrap(), 0x1234_5000);
        assert_eq!(map.read_u64("cr4", &ctx).unwrap(), 0x350ef8);
        assert_eq!(map.read_u64("cr8", &ctx).unwrap(), 2);
    }

    #[test]
    fn thread_id_uses_one_based_hex() {
        assert_eq!(thread_id_for(0), "p1.1");
        assert_eq!(thread_id_for(3), "p1.4");
        assert_eq!(thread_id_for(15), "p1.10");
    }

    #[test]
    fn thread_id_round_trips() {
        for proc in [0u16, 1, 7, 15, 31] {
            let tid = thread_id_for(proc);
            assert_eq!(parse_thread_id(&tid).unwrap(), proc);
        }
    }

    #[test]
    fn parse_thread_id_rejects_garbage() {
        assert!(parse_thread_id("p2.1").is_err()); // wrong pid
        assert!(parse_thread_id("p1.zz").is_err()); // not hex
        assert!(parse_thread_id("garbage").is_err());
        assert!(parse_thread_id("p1.0").is_err()); // zero index reserved
    }

    #[test]
    fn parse_thread_id_for_processor_count_rejects_out_of_range() {
        assert_eq!(parse_thread_id_for_processor_count("p1.4", 4).unwrap(), 3);
        assert!(parse_thread_id_for_processor_count("p1.5", 4).is_err());
    }
}
