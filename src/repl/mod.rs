#[cfg(feature = "cli")]
use nu_ansi_term::{Color, Style};
#[cfg(feature = "cli")]
use reedline::{
    DescriptionMode, Emacs, IdeMenu, KeyCode, KeyModifiers, MenuBuilder, ReedlineEvent,
    ReedlineMenu, default_emacs_keybindings,
};
#[cfg(feature = "cli")]
use reedline::{Reedline, Signal};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
#[cfg(feature = "cli")]
use std::sync::atomic::Ordering;

use strum_macros::{Display, EnumIter, EnumMessage, EnumString};
use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

#[cfg(feature = "cli")]
use crate::dbg_backend::DebugBackend;
use crate::dbg_backend::{BackendCapability, DebugCapability};
use crate::diagnostics;
use crate::error::Result;
use crate::guest::ModuleSymbolLoadReport;
#[cfg(feature = "python")]
use crate::python::embed;
use crate::session::Session;
#[cfg(feature = "cli")]
use crate::target::Target;
#[cfg(feature = "cli")]
use crate::ui;

pub static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);
pub const BREAK_STACKTRACE_DISPLAY_LIMIT: usize = 8;
pub const BREAK_STACKTRACE_PROBE_LIMIT: usize = 64;
macro_rules! require_arg {
    ($parts:expr, $idx:expr, $cmd:expr) => {
        match $parts.get($idx) {
            Some(a) => *a,
            None => {
                println!("{}\n", $cmd.get_message().unwrap_or("invalid usage"));
                return Ok(());
            }
        }
    };
}

// TODO
//
// Memory Display:
//   da, du       - Display ASCII/Unicode strings
//   dps          - Display pointers with symbol resolution
// Memory Write:
//   ea, eu       - Write ASCII/Unicode string
// Execution Control:
//   t / si       - Single step (step into)
//   p / ni       - Step over
//   gu           - Go until return
//   st           - Switch threads/VCPU
// Breakpoints:
//   Conditional breakpoints
// Registers:
//   context      - Auto-display regs/stack/disasm on break
// Stack Analysis:
//   k            - Stack backtrace
//   kv, kp       - Backtrace with locals/params
// Search:
//   x            - Search symbols by wildcard
//   ln           - List nearest symbols to address
// Expression Evaluation
// Misc:
//   vmmap        - Memory region map

#[derive(Debug, Clone, Copy, PartialEq, EnumIter, Display, EnumString, EnumMessage)]
#[strum(serialize_all = "kebab-case")]
pub enum ReplCommand {
    // memory read
    #[strum(message = "Display memory as bytes.\n(usage: db <address> [length or end])")]
    Db,
    #[strum(
        message = "Display memory as doublewords (4 bytes).\n(usage: dd <address> [length or end])"
    )]
    Dd,
    #[strum(
        message = "Display memory as quadwords (8 bytes).\n(usage: dq <address> [length or end])"
    )]
    Dq,
    #[strum(
        message = "Disassemble memory at a symbol or address.\n(usage: disasm <address> [length or end])"
    )]
    Disasm,
    #[strum(message = "Display type definition.\n(usage: dt <type> [address] [field])")]
    Dt,

    // memory write
    #[strum(message = "Write a byte to memory.\n(usage: eb <address> <expr>)")]
    Eb,
    #[strum(message = "Write a doubleword (4 bytes) to memory.\n(usage: ed <address> <expr>)")]
    Ed,
    #[strum(message = "Write a quadword (8 bytes) to memory.\n(usage: eq <address> <expr>)")]
    Eq,
    #[strum(
        message = "Fill memory with a repeated byte pattern.\n(usage: f <address> <hex bytes> [length or end])\nhex bytes: 90, 4883792000740a, or \\x90\\x90"
    )]
    F,

    // memory search
    #[strum(
        message = "Search memory for a byte pattern.\n(usage: s <address> <hex bytes> [length])\nhex bytes: 4883792000740a or \\x48\\x83\\x79\\x20\\x00\\x74\\x0a"
    )]
    S,

    // symbol search
    #[strum(
        message = "Fuzzy-search symbols by name.\n(usage: x <query>  or  x <module>!<query>)\noperators: ^prefix  suffix$  'exact  !negate  (space = AND)"
    )]
    X,
    #[strum(message = "List the nearest symbol to an address.\n(usage: ln <address>)")]
    Ln,

    // expression
    #[strum(message = "Evaluate an expression.\n(usage: ev <expression>)")]
    Ev,
    #[strum(
        message = "Define a convenience variable usable in expressions as $<name>.\n(usage: set $<name> <expression>)"
    )]
    Set,
    #[strum(message = "List defined convenience variables and result slots.\n(usage: vars)")]
    Vars,
    #[strum(message = "Remove a convenience variable.\n(usage: unset $<name>)")]
    Unset,

    // page table
    #[strum(message = "Display page table entries for an address.\n(usage: pte <address>)")]
    Pte,
    #[strum(
        message = "Inspect the pool page containing an address.\n(usage: pool <address-expression>)"
    )]
    Pool,
    #[strum(
        message = "Display virtual memory regions for the attached process, or kernel modules when detached.\n(usage: vmmap [address|filter])"
    )]
    Vmmap,

    // execution
    #[strum(message = "Resume VM execution.\n(usage: continue)")]
    Continue,
    #[strum(message = "Break/pause VM execution.\n(usage: break)")]
    Break,
    #[strum(message = "Single step (step into).\n(usage: si)")]
    Si,
    #[strum(
        serialize = "ni",
        to_string = "p",
        message = "Step over the current instruction.\n(usage: p or ni)"
    )]
    P,
    #[strum(
        serialize = "finish",
        to_string = "gu",
        message = "Run until the current function returns.\n(usage: gu or finish)"
    )]
    Gu,

    // breakpoints
    #[strum(message = "Set a breakpoint.\n(usage: bp <address> [<expr>])")]
    Bp,
    #[strum(message = "List all breakpoints.\n(usage: bl)")]
    Bl,
    #[strum(message = "Clear a breakpoint by ID.\n(usage: bc <id>)")]
    Bc,
    #[strum(message = "Disable a breakpoint by ID.\n(usage: bd <id>)")]
    Bd,
    #[strum(message = "Enable a breakpoint by ID.\n(usage: be <id>)")]
    Be,

    // inspection
    #[strum(message = "Display CPU registers.\n(usage: registers)")]
    Registers,
    #[strum(message = "Display stack backtrace.\n(usage: k [count])")]
    K,
    #[strum(message = "Display current VM status.\n(usage: status)")]
    Status,
    #[strum(message = "Display backend capabilities.\n(usage: capabilities)")]
    Capabilities,
    #[strum(message = "Show captured guest debug output (DbgPrint).\n(usage: dbgprint [count])")]
    Dbgprint,
    #[strum(
        message = "Inspect an IRP and its current IO_STACK_LOCATION.\n(usage: irp <address-expression>)"
    )]
    Irp,
    #[strum(
        message = "Discover in-flight IRPs from thread IrpLists and device CurrentIrp.\n(usage: irps [process-filter|driver-filter])"
    )]
    Irps,
    #[strum(
        message = "Inspect a DRIVER_OBJECT, its device chain and dispatch table.\n(usage: drvobj <driver-object-expression-or-name>)"
    )]
    Drvobj,
    #[strum(
        message = "Inspect a DEVICE_OBJECT and its attached stack.\n(usage: devobj <device-object-expression>)"
    )]
    Devobj,
    #[strum(
        message = "Inspect an executive object header and body.\n(usage: object <object-expression>)"
    )]
    Object,
    #[strum(
        message = "Enumerate process/thread/image notification callbacks.\n(usage: callbacks [symbol-filter])"
    )]
    Callbacks,
    #[strum(message = "Dump the SSDT and shadow SSDT.\n(usage: ssdt)")]
    Ssdt,
    #[strum(
        message = "Describe what an address belongs to (module+section, or VAD region).\n(usage: address <address-expression>)"
    )]
    Address,

    // execution contexts / processes / modules
    #[strum(message = "List vCPU contexts and their RIP values.\n(usage: vcpus)")]
    Vcpus,
    #[strum(message = "Switch to a different vCPU context.\n(usage: vcpu <id>)")]
    Vcpu,
    #[strum(
        message = "List Windows threads, optionally filtered by process, PID, TID, or ETHREAD.\n(usage: threads [filter])"
    )]
    Threads,
    #[strum(
        message = "Inspect a Windows thread and switch to it if it is currently running.\n(usage: thread <tid|ethread|.> [k|r] [count])"
    )]
    Thread,
    #[strum(message = "List running processes.\n(usage: ps [filter])")]
    Ps,
    #[strum(message = "List loaded modules.\n(usage: lm [filter])")]
    Lm,
    #[strum(
        message = "List driver objects from the \\Driver object directory.\n(usage: drivers [filter])"
    )]
    Drivers,
    #[strum(message = "Attach to a process by PID.\n(usage: attach <pid>)")]
    Attach,
    #[strum(message = "Detach from current process.\n(usage: detach)")]
    Detach,

    #[strum(
        message = "Reload custom commands from $XDG_CONFIG_HOME/ntoseye/commands.\n(usage: reload)"
    )]
    Reload,

    #[strum(message = "Exit the application.")]
    Quit,
}

impl ReplCommand {
    pub fn completion_type(&self) -> CompletionStrategy {
        match self {
            Self::Db
            | Self::Dd
            | Self::Dq
            | Self::Disasm
            | Self::Eb
            | Self::Ed
            | Self::Eq
            | Self::F
            | Self::S
            | Self::Ev
            | Self::Set
            | Self::X
            | Self::Ln
            | Self::Pte
            | Self::Pool
            | Self::Vmmap
            | Self::Irp
            | Self::Devobj
            | Self::Object
            | Self::Callbacks
            | Self::Address
            | Self::Bp => CompletionStrategy::Symbol,
            Self::Dt => CompletionStrategy::Type,
            Self::Drvobj => CompletionStrategy::Driver,
            Self::Attach | Self::Threads | Self::Irps => CompletionStrategy::Process,
            Self::Thread => CompletionStrategy::Thread,
            Self::Vcpu => CompletionStrategy::Vcpu,
            Self::Bc | Self::Bd | Self::Be => CompletionStrategy::Breakpoint,
            _ => CompletionStrategy::None,
        }
    }
}

pub fn error(msg: &str) {
    diagnostics::print_error(msg);
}

macro_rules! error {
    ($($arg:tt)*) => {
        error(&format!($($arg)*))
    };
}

mod bugcheck;
mod commands;
mod completion;
mod disasm;
#[cfg(feature = "cli")]
mod line_editor;
mod memory_view;
mod pool;
mod stop;

pub use bugcheck::*;
pub use completion::CompletionStrategy;
pub use completion::*;
pub use disasm::*;
#[cfg(feature = "cli")]
pub use line_editor::*;
pub use memory_view::*;
pub use pool::*;
pub use stop::*;

pub fn print_module_symbol_report(report: &ModuleSymbolLoadReport) {
    let mut summary = format!("symbols: loaded {}/{}", report.loaded, report.total);
    if report.failed_count() > 0 {
        summary.push_str(&format!(", {} failed", report.failed_count()));
    }
    if report.no_pdb > 0 {
        summary.push_str(&format!(", {} no-pdb", report.no_pdb));
    }
    if report.skipped > 0 {
        summary.push_str(&format!(", {} skipped", report.skipped));
    }
    println!("{summary}");
}

pub fn print_backend_capabilities(capabilities: &[BackendCapability]) {
    const COLUMNS: usize = 4;

    println!("{}", "capabilities".bold());

    let mut builder = Builder::default();
    for chunk in capabilities.chunks(COLUMNS) {
        let mut row = chunk
            .iter()
            .enumerate()
            .map(|(idx, capability)| {
                let marker = if capability.supported {
                    "+".green().to_string()
                } else {
                    "-".red().to_string()
                };
                let cell = format!("{} {}", marker, capability.capability.label());
                if idx + 1 == COLUMNS {
                    cell
                } else {
                    format!("{cell}  ")
                }
            })
            .collect::<Vec<_>>();
        row.resize(COLUMNS, String::new());
        builder.push_record(row);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    for line in table.to_string().lines() {
        println!("  {line}");
    }
    println!();
}

pub fn supports_capability(
    capabilities: &[BackendCapability],
    capability: DebugCapability,
) -> bool {
    capabilities
        .iter()
        .any(|entry| entry.capability == capability && entry.supported)
}

pub fn print_backend_capability_warning(capabilities: &[BackendCapability]) {
    if capabilities.iter().all(|capability| capability.supported) {
        return;
    }

    diagnostics::print_warning(
        "selected backend has reduced capabilities; run `capabilities` for details, or use KDCOM",
    );
    println!();
}

pub fn print_plain_table(builder: Builder) {
    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{table}\n");
}

pub enum Flow {
    Continue,
    Quit,
}

pub struct ReplState<'a> {
    pub ctx: &'a mut Session,
    pub caches: ReplCaches,
    pub line: String,
}

/// The user-command completion set: the registered Python commands when the
/// binary embeds Python (`python-embed`), else empty.
pub(crate) fn initial_user_commands() -> Vec<(String, String, Vec<CompletionStrategy>)> {
    #[allow(unused_mut)]
    let mut cmds: Vec<(String, String, Vec<CompletionStrategy>)> = Vec::new();
    #[cfg(feature = "python")]
    for (name, help, strategies) in embed::command_list() {
        cmds.push((name, help, strategies));
    }
    cmds
}

impl<'a> ReplState<'a> {
    /// Build a transient REPL state around an existing context for one-off
    /// command dispatch (e.g. the Python SDK's `run_command`). Completion caches
    /// start empty (no live REPL to populate them). Output goes to stdout, as in
    /// the REPL.
    pub fn for_oneshot(ctx: &'a mut Session) -> Self {
        let caches = ReplCaches {
            symbols: Arc::new(RwLock::new(ctx.target.current_symbol_index())),
            types: Arc::new(RwLock::new(ctx.target.current_types_index())),
            symbol_store: Arc::clone(&ctx.target.symbols),
            dtb: Arc::new(RwLock::new(ctx.target.current_dtb())),
            processes: Arc::new(RwLock::new(Vec::new())),
            threads: Arc::new(RwLock::new(Vec::new())),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            breakpoints: Arc::new(RwLock::new(Vec::new())),
            drivers: Arc::new(RwLock::new(Vec::new())),
            user_commands: Arc::new(RwLock::new(initial_user_commands())),
        };

        ReplState {
            ctx,
            caches,
            line: String::new(),
        }
    }
}

#[cfg(feature = "cli")]
pub fn start_repl(ctx: &mut Session) -> Result<()> {
    // Borrow the two owned fields disjointly; the rest of this function (and
    // ReplState) consumes them exactly as before.
    let debugger: &mut Target = &mut ctx.target;
    let client: &mut dyn DebugBackend = ctx.backend.as_mut();

    ctrlc::set_handler(move || {
        INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
    })?;

    let message_data = debugger.startup_message_data()?;

    println!("{}", "target".bold());
    println!("  kernel: Windows {}", message_data.build_number.0);
    println!("  base:   {}", ui::addr(message_data.base_address.0));
    println!(
        "  psmods: {}",
        ui::addr_opt(message_data.loaded_module_list)
    );
    println!();
    let capabilities = client.capabilities();
    print_backend_capability_warning(&capabilities);

    let has_register_context = supports_capability(&capabilities, DebugCapability::ReadRegisters);

    let reload_module_list_pending = message_data.loaded_module_list.is_zero();

    if has_register_context {
        print_break_context(
            &mut *client,
            &ctx.register_map,
            debugger,
            &ctx.breakpoints,
            &ctx.current_thread,
        );
    }

    let min_completion_width: u16 = 0;
    let max_completion_width: u16 = 50;
    let max_completion_height: u16 = 12;
    let padding: u16 = 0;
    let border: bool = true;
    let cursor_offset: i16 = 0;
    let description_mode: DescriptionMode = DescriptionMode::PreferRight;
    let min_description_width: u16 = 0;
    let max_description_width: u16 = 50;
    let description_offset: u16 = 1;
    let correct_cursor_pos: bool = false;

    let mut ide_menu = IdeMenu::default()
        .with_name("completion_menu")
        .with_min_completion_width(min_completion_width)
        .with_max_completion_width(max_completion_width)
        .with_max_completion_height(max_completion_height)
        .with_padding(padding)
        .with_cursor_offset(cursor_offset)
        .with_description_mode(description_mode)
        .with_min_description_width(min_description_width)
        .with_max_description_width(max_description_width)
        .with_description_offset(description_offset)
        .with_correct_cursor_pos(correct_cursor_pos)
        .with_marker(" ")
        .with_text_style(Style::new().fg(Color::LightGray));

    if border {
        ide_menu = ide_menu.with_default_border();
    }

    let completion_menu = Box::new(ide_menu);

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuPrevious,
        ]),
    );
    // The default Left/Right bindings route through MenuLeft/MenuRight first,
    // which the open completion menu swallows so the cursor never moves. The
    // IdeMenu is a single column (Up/Down navigate it), so drop the menu nav and
    // let the arrows always move the cursor; keep history-hint accept on Right.
    keybindings.add_binding(KeyModifiers::NONE, KeyCode::Left, ReedlineEvent::Left);
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Right,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::HistoryHintComplete,
            ReedlineEvent::Right,
        ]),
    );

    let edit_mode = Box::new(Emacs::new(keybindings));

    let initial_processes = debugger
        .guest
        .enumerate_processes()
        .map(|procs| procs.into_iter().map(|p| (p.name, p.pid)).collect())
        .unwrap_or_default();
    let initial_vcpus = if supports_capability(&capabilities, DebugCapability::ThreadList) {
        client.thread_list().unwrap_or_default()
    } else {
        Vec::new()
    };
    let initial_drivers = debugger.enumerate_driver_objects().unwrap_or_default();

    // In-REPL Python commands (the embedded-interpreter build). Loaded here so
    // they're in the completion set below.
    #[cfg(feature = "python")]
    {
        let py_report = embed::load_commands_dir();
        embed::print_script_load_report(&py_report, true);
    }

    let caches = ReplCaches {
        symbols: Arc::new(RwLock::new(debugger.current_symbol_index())),
        types: Arc::new(RwLock::new(debugger.current_types_index())),
        symbol_store: Arc::clone(&debugger.symbols),
        dtb: Arc::new(RwLock::new(debugger.current_dtb())),
        processes: Arc::new(RwLock::new(initial_processes)),
        // populated on demand by the threads/thread commands
        threads: Arc::new(RwLock::new(Vec::new())),
        vcpus: Arc::new(RwLock::new(initial_vcpus)),
        breakpoints: Arc::new(RwLock::new(Vec::new())),
        drivers: Arc::new(RwLock::new(initial_drivers)),
        user_commands: Arc::new(RwLock::new(initial_user_commands())),
    };

    let completor = Box::new(MyCompleter {
        caches: caches.clone(),
    });

    let had_content = Arc::new(AtomicBool::new(false));
    let highlighter = TrackingHighlighter {
        had_content: Arc::clone(&had_content),
    };

    let mut line_editor = Reedline::create()
        .with_completer(completor)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_highlighter(Box::new(highlighter));
    let prompt = CustomPrompt {};

    let mut state = ReplState {
        ctx,
        caches,
        line: String::new(),
    };
    // The reload state machine lives on the Session now; seed it from the
    // startup message (an empty module list means we attached very early in
    // boot, before rediscovery completed).
    state.ctx.reload_module_list_pending = reload_module_list_pending;

    loop {
        let sig = line_editor.read_line(&prompt)?;
        match sig {
            Signal::Success(buffer) => {
                let parts: Vec<&str> = buffer.split_whitespace().collect();
                if !parts.is_empty() {
                    // TODO: add first-class aliases (`lt` -> `vcpus`,
                    // `thread` -> `vcpu`) without making them primary names.
                    state.line = buffer.trim().to_string();
                    match state.dispatch(&parts)? {
                        Flow::Quit => break,
                        Flow::Continue => {}
                    }
                }
            }
            Signal::CtrlD => {
                break;
            }
            Signal::CtrlC => {
                if had_content.load(Ordering::Relaxed) {
                    had_content.store(false, Ordering::Relaxed);
                    continue;
                }

                if state.ctx.backend.is_running() {
                    state.interrupt_running_vm()?;
                } else {
                    error!("VM is already paused");
                }
            }
        }
    }

    let was_running_on_exit = state.ctx.backend.is_running();
    let mut resume_on_exit = !was_running_on_exit;
    if was_running_on_exit && !state.ctx.breakpoints.list().is_empty() {
        match state.ctx.backend.try_wait_for_stop(REPL_STOP_POLL) {
            Ok(Some(mut event)) => {
                let reload_status = apply_target_reload_if_needed(
                    &mut *state.ctx.backend,
                    &mut state.ctx.target,
                    &mut state.ctx.breakpoints,
                    &state.caches,
                    &mut event,
                );
                update_reload_module_list_pending(
                    &mut state.ctx.reload_module_list_pending,
                    reload_status,
                );
                if !reload_status.pending_rediscovery() {
                    set_current_thread_from_stop(
                        &mut *state.ctx.backend,
                        &event,
                        &mut state.ctx.current_thread,
                    );
                }
                resume_on_exit = true;
            }
            Ok(None) => match state.ctx.backend.interrupt() {
                Ok(mut event) => {
                    let reload_status = apply_target_reload_if_needed(
                        &mut *state.ctx.backend,
                        &mut state.ctx.target,
                        &mut state.ctx.breakpoints,
                        &state.caches,
                        &mut event,
                    );
                    update_reload_module_list_pending(
                        &mut state.ctx.reload_module_list_pending,
                        reload_status,
                    );
                    if !reload_status.pending_rediscovery() {
                        set_current_thread_from_stop(
                            &mut *state.ctx.backend,
                            &event,
                            &mut state.ctx.current_thread,
                        );
                    }
                    resume_on_exit = true;
                }
                Err(e) => {
                    error!("failed to interrupt during exit: {:?}", e);
                    resume_on_exit = false;
                }
            },
            Err(e) => {
                error!("error checking running VM during exit: {:?}", e);
                resume_on_exit = false;
            }
        }
    }

    // Best effort even if the interrupt above failed: a leftover int3 in guest
    // code with no debugger attached is worse than a failed removal
    let bp_ids: Vec<u32> = state
        .ctx
        .breakpoints
        .list()
        .iter()
        .map(|bp| bp.id)
        .collect();
    for id in bp_ids {
        if let Err(e) = state
            .ctx
            .breakpoints
            .remove(&mut *state.ctx.backend, &state.ctx.target, id)
        {
            error!("failed to uninstall breakpoint #{} on exit: {}", id, e);
        }
    }

    let leave_running_on_exit = resume_on_exit || state.ctx.backend.is_running();
    if let Err(e) = state.ctx.backend.prepare_for_exit(leave_running_on_exit) {
        error!("failed to prepare backend for exit: {:?}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::dbg_backend::BugcheckInfo;
    use crate::types::VirtAddr;

    use super::{
        bugcheck_fault_ip, looks_like_kernel_pointer, parse_byte_pattern, plausible_bugcheck_code,
        repeat_pattern, resolve_length_or_end,
    };

    #[test]
    fn parse_byte_pattern_accepts_contiguous_hex() {
        assert_eq!(
            parse_byte_pattern("4883792000740a"),
            Some(vec![0x48, 0x83, 0x79, 0x20, 0x00, 0x74, 0x0a])
        );
    }

    #[test]
    fn plausible_bugcheck_code_rejects_pointer_like_values() {
        assert!(plausible_bugcheck_code(0xe2));
        assert!(plausible_bugcheck_code(0x0000_0139));
        assert!(!plausible_bugcheck_code(0));
        assert!(!plausible_bugcheck_code(0xfffff8007f1afb50));
    }

    #[test]
    fn kernel_pointer_heuristic_accepts_canonical_kernel_addresses() {
        assert!(looks_like_kernel_pointer(0xfffff8007f1afb50));
        assert!(!looks_like_kernel_pointer(0x00000000000000e2));
    }

    #[test]
    fn bugcheck_fault_ip_uses_only_real_fault_instruction_arguments() {
        let mut info = BugcheckInfo {
            code: 0x50,
            parameters: [0x1, 0x2, 0xfffff804877d1805, 0x4],
            driver: None,
        };
        assert_eq!(bugcheck_fault_ip(&info), Some(0xfffff804877d1805));

        info.code = 0xd1;
        info.parameters = [0x1, 0x2, 0x0, 0xfffff804877d1730];
        assert_eq!(bugcheck_fault_ip(&info), Some(0xfffff804877d1730));

        info.code = 0x4a;
        info.parameters = [0x00007ffb32481d84, 0x2, 0x0, 0xffffdf8669067b20];
        assert_eq!(bugcheck_fault_ip(&info), None);
    }

    #[test]
    fn parse_byte_pattern_accepts_hex_escape_bytes() {
        assert_eq!(
            parse_byte_pattern(r"\x48\x83\x79\x20\x00\x74\x0a"),
            Some(vec![0x48, 0x83, 0x79, 0x20, 0x00, 0x74, 0x0a])
        );
    }

    #[test]
    fn parse_byte_pattern_rejects_odd_length_hex() {
        assert_eq!(parse_byte_pattern("488379200074a"), None);
    }

    #[test]
    fn resolve_length_or_end_treats_small_value_as_length() {
        assert_eq!(
            resolve_length_or_end(VirtAddr(0xfffff8075b471000), VirtAddr(0x20)),
            Some(0x20)
        );
    }

    #[test]
    fn resolve_length_or_end_treats_large_value_as_end() {
        assert_eq!(
            resolve_length_or_end(VirtAddr(0x1000), VirtAddr(0x1020)),
            Some(0x20)
        );
    }

    #[test]
    fn repeat_pattern_repeats_and_truncates() {
        assert_eq!(repeat_pattern(&[0x90], 4), vec![0x90, 0x90, 0x90, 0x90]);
        assert_eq!(
            repeat_pattern(&[0x48, 0x83, 0x79], 8),
            vec![0x48, 0x83, 0x79, 0x48, 0x83, 0x79, 0x48, 0x83]
        );
    }

    #[test]
    fn repeat_pattern_allows_zero_length() {
        assert_eq!(repeat_pattern(&[0x90], 0), Vec::<u8>::new());
    }
}
