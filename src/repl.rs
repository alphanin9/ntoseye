use indicatif::{ProgressBar, ProgressStyle};
use nu_ansi_term::{Color, Style};
use reedline::{
    Completer, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline,
    Signal, Span, Suggestion,
};
use reedline::{
    DescriptionMode, Emacs, Highlighter, IdeMenu, KeyCode, KeyModifiers, MenuBuilder,
    ReedlineEvent, ReedlineMenu, StyledText, default_emacs_keybindings,
};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use strum::EnumMessage;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumMessage, EnumString};
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Padding, Panel};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, MemorySizeOptions, NasmFormatter,
};
use owo_colors::OwoColorize;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

use crate::backend::MemoryOps;
use crate::dbg_backend::DebugBackend;
use crate::debugger::{AttachReport, DebuggerContext, DriverObjectInfo};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::{BreakpointHitResult, BreakpointKind, BreakpointManager, RegisterMap};
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::memory::AddressSpace;
use crate::script::{LoadReport, ScriptHost};
use crate::symbols::{ModuleSymbolDiscovery, ParsedType, SymbolIndex, SymbolStore, TypeInfo};
use crate::types::{Dtb, Value, VirtAddr};
use crate::unwind::{
    FrameSource, ThreadTraceContext, build_stacktrace, format_symbol, preferred_code_dtb,
    resolve_thread_trace_context,
};

static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);
const BREAK_STACKTRACE_DISPLAY_LIMIT: usize = 8;
const BREAK_STACKTRACE_PROBE_LIMIT: usize = 64;

#[derive(Clone)]
pub struct CustomPrompt;
pub static DEFAULT_MULTILINE_INDICATOR: &str = "     ::: ";
impl Prompt for CustomPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned("ntoseye>".bright_black().to_string())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Owned("".into())
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(" ".to_string())
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(DEFAULT_MULTILINE_INDICATOR)
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

#[derive(Clone, Copy)]
pub enum CompletionStrategy {
    None,
    Symbol,
    Type,
    Process,
    Thread,
    Breakpoint,
    Driver,
}

impl CompletionStrategy {
    pub fn from_kebab(s: &str) -> Option<Self> {
        Some(match s {
            "none" | "" => Self::None,
            "symbol" => Self::Symbol,
            "type" => Self::Type,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "breakpoint" => Self::Breakpoint,
            "driver" => Self::Driver,
            _ => return None,
        })
    }
}

fn make_suggestions(
    names: Vec<String>,
    description: &str,
    span_start: usize,
    pos: usize,
) -> Vec<Suggestion> {
    names
        .into_iter()
        .map(|name| Suggestion {
            value: name,
            description: Some(description.to_string()),
            style: None,
            extra: None,
            match_indices: None,
            span: Span::new(span_start, pos),
            append_whitespace: false,
        })
        .collect()
}

macro_rules! require_arg {
    ($parts:expr, $idx:expr, $cmd:expr) => {
        match $parts.get($idx) {
            Some(a) => *a,
            None => {
                println!("{}\n", $cmd.get_message().unwrap_or("invalid usage"));
                continue;
            }
        }
    };
}

struct AddressRange {
    start: VirtAddr,
    end: VirtAddr,
}

impl AddressRange {
    fn parse(
        parts: &[&str],
        debugger: &DebuggerContext,
        default_count: u64,
        item_size: u64,
    ) -> Result<Self> {
        let start_arg = parts.get(1).ok_or(Error::InvalidRange)?;
        let start = Expr::eval(start_arg, debugger)?;

        let end = if let Some(end_arg) = parts.get(2) {
            let end = Expr::eval(end_arg, debugger)?;
            if end.0 < start.0 {
                start + end.0 * item_size
            } else {
                end
            }
        } else {
            start + default_count * item_size
        };

        if end.0 < start.0 {
            return Err(Error::InvalidRange);
        }

        Ok(AddressRange { start, end })
    }

    fn len(&self) -> usize {
        (self.end.0 - self.start.0) as usize
    }
}

fn parse_byte_pattern(pattern: &str) -> Option<Vec<u8>> {
    if pattern.is_empty() {
        return None;
    }

    if pattern.starts_with("\\x") || pattern.starts_with("\\X") {
        let mut bytes = Vec::new();
        let mut rest = pattern;

        while let Some(stripped) = rest
            .strip_prefix("\\x")
            .or_else(|| rest.strip_prefix("\\X"))
        {
            if stripped.len() < 2 {
                return None;
            }

            let byte = u8::from_str_radix(&stripped[..2], 16).ok()?;
            bytes.push(byte);
            rest = &stripped[2..];
        }

        if rest.is_empty() && !bytes.is_empty() {
            return Some(bytes);
        }

        return None;
    }

    if pattern.len() % 2 != 0 || !pattern.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    hex::decode(pattern).ok()
}

fn resolve_length_or_end(start: VirtAddr, end_or_length: VirtAddr) -> Option<usize> {
    let length = if end_or_length.0 < start.0 {
        end_or_length.0
    } else {
        end_or_length.0 - start.0
    };

    usize::try_from(length).ok()
}

fn repeat_pattern(pattern: &[u8], length: usize) -> Vec<u8> {
    let mut filled = Vec::with_capacity(length);

    while filled.len() < length {
        let remaining = length - filled.len();
        filled.extend_from_slice(&pattern[..remaining.min(pattern.len())]);
    }

    filled
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
enum ReplCommand {
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

    // expression
    #[strum(message = "Evaluate an expression.\n(usage: ev <expression>)")]
    Ev,

    // page table
    #[strum(message = "Display page table entries for an address.\n(usage: pte <address>)")]
    Pte,
    #[strum(
        message = "Dump the current processor's interrupt descriptor table.\n(usage: idt [count])"
    )]
    Idt,
    #[strum(
        message = "Dump the current processor's global descriptor table.\n(usage: gdt [count])"
    )]
    Gdt,
    #[strum(message = "Dump the current processor's TSS stack bases.\n(usage: tss [selector])")]
    Tss,
    #[strum(
        message = "Run a raw QEMU monitor command through the gdbstub.\n(usage: qcmd <command>)"
    )]
    Qcmd,
    #[strum(
        message = "Enable QEMU logging through the monitor.\n(usage: qlog [items] [logfile])\ndefault items: int,cpu_reset,guest_errors"
    )]
    Qlog,
    #[strum(
        message = "Inspect the pool page containing an address.\n(usage: pool <address-expression>)"
    )]
    Pool,

    // execution
    #[strum(message = "Resume VM execution.\n(usage: continue)")]
    Continue,
    #[strum(message = "Break/pause VM execution.\n(usage: break)")]
    Break,
    #[strum(message = "Single step (step into).\n(usage: si)")]
    Si,

    // breakpoints
    #[strum(message = "Set a breakpoint.\n(usage: bp <address>)")]
    Bp,
    #[strum(message = "Set a hardware execution breakpoint.\n(usage: hbp <address>)")]
    Hbp,
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
    #[strum(
        serialize = "cregs",
        serialize = "control-registers",
        message = "Display control registers.\n(usage: cregs)"
    )]
    Cregs,
    #[strum(message = "Display stack backtrace.\n(usage: k [count])")]
    K,
    #[strum(
        serialize = "trap-frame",
        serialize = "tf",
        message = "Dump a _KTRAP_FRAME at an address.\n(usage: trap-frame <address> [field])"
    )]
    TrapFrame,
    #[strum(message = "Display current VM status.\n(usage: status)")]
    Status,

    // threads / processes / modules
    #[strum(message = "List all threads and their RIP values.\n(usage: lt)")]
    Lt,
    #[strum(message = "Switch to a different thread/vCPU.\n(usage: thread <id>)")]
    Thread,
    #[strum(message = "List running processes.\n(usage: ps [filter])")]
    Ps,
    #[strum(message = "List loaded modules.\n(usage: lm [filter])")]
    Lm,
    #[strum(
        message = "Load symbols for loaded modules from a local directory.\n(usage: load-symbols <directory> [module-filter])"
    )]
    LoadSymbols,
    #[strum(
        message = "List driver objects from the \\Driver object directory.\n(usage: drivers [filter])"
    )]
    Drivers,
    #[strum(message = "Attach to a process by PID.\n(usage: attach <pid>)")]
    Attach,
    #[strum(message = "Detach from current process.\n(usage: detach)")]
    Detach,

    #[strum(
        message = "Reload Lua command scripts from $XDG_CONFIG_HOME/ntoseye/commands.\n(usage: reload)"
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
            | Self::Pte
            | Self::Pool
            | Self::TrapFrame
            | Self::Bp
            | Self::Hbp => CompletionStrategy::Symbol,
            Self::Dt => CompletionStrategy::Type,
            Self::Attach => CompletionStrategy::Process,
            Self::Thread => CompletionStrategy::Thread,
            Self::Bc | Self::Bd | Self::Be => CompletionStrategy::Breakpoint,
            _ => CompletionStrategy::None,
        }
    }
}

/// Cached process info for completion (name, PID)
type ProcessCache = Vec<(String, u64)>;

/// Cached thread IDs for completion
type ThreadCache = Vec<String>;

/// Cached breakpoint info for completion (id, enabled, address, symbol)
type BreakpointCache = Vec<(u32, bool, VirtAddr, Option<String>)>;

/// Cached driver object info for completion
type DriverObjectCache = Vec<DriverObjectInfo>;

/// Cached (name, help, per-arg strategies) for script-registered commands
type UserCommandCache = Vec<(String, String, Vec<CompletionStrategy>)>;

struct MyCompleter {
    symbols: Arc<RwLock<SymbolIndex>>,
    types: Arc<RwLock<SymbolIndex>>,
    symbol_store: Arc<SymbolStore>,
    dtb: Arc<RwLock<Dtb>>,
    processes: Arc<RwLock<ProcessCache>>,
    threads: Arc<RwLock<ThreadCache>>,
    breakpoints: Arc<RwLock<BreakpointCache>>,
    drivers: Arc<RwLock<DriverObjectCache>>,
    user_commands: Arc<RwLock<UserCommandCache>>,
}

impl Completer for MyCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let text_before_cursor = &line[..pos];
        let mut parts = text_before_cursor.split_whitespace();

        let command_str = parts.next().unwrap_or("");
        let is_command_context = !text_before_cursor.contains(' ');

        if is_command_context {
            let mut suggestions: Vec<Suggestion> = ReplCommand::iter()
                .filter_map(|cmd| {
                    let c_str = cmd.to_string();
                    if c_str.starts_with(command_str) {
                        Some(Suggestion {
                            value: c_str,
                            description: cmd.get_message().map(String::from),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let user_cmds = self.user_commands.read().unwrap();
            for (name, help, _) in user_cmds.iter() {
                if name.starts_with(command_str) {
                    suggestions.push(Suggestion {
                        value: name.clone(),
                        description: Some(help.clone()),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(0, pos),
                        append_whitespace: true,
                    });
                }
            }
            return suggestions;
        }

        if let Ok(cmd) = ReplCommand::from_str(command_str) {
            let arg_start = text_before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let raw_prefix = &text_before_cursor[arg_start..];

            // find the start of the identifier being typed by scanning backward
            // for expression boundary characters (operators, parens, dereference)
            let ident_start = raw_prefix
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .map(|i| i + 1)
                .unwrap_or(0);
            let prefix = &raw_prefix[ident_start..];
            let span_start = arg_start + ident_start;

            match cmd.completion_type() {
                CompletionStrategy::Type => {
                    // dt has a special third-arg promotion to symbol completion
                    let mut arg_count = text_before_cursor.split_whitespace().count();
                    if text_before_cursor.ends_with(char::is_whitespace) {
                        arg_count += 1;
                    }
                    if arg_count > 2 {
                        return self.apply_strategy(
                            CompletionStrategy::Symbol,
                            raw_prefix,
                            ident_start,
                            prefix,
                            span_start,
                            pos,
                        );
                    }
                    return self.apply_strategy(
                        CompletionStrategy::Type,
                        raw_prefix,
                        ident_start,
                        prefix,
                        span_start,
                        pos,
                    );
                }
                strat => {
                    return self.apply_strategy(
                        strat,
                        raw_prefix,
                        ident_start,
                        prefix,
                        span_start,
                        pos,
                    );
                }
            }
        }

        // Fallback: script-registered command with per-arg completion hints
        let user_cmds = self.user_commands.read().unwrap();
        if let Some((_, _, strategies)) = user_cmds.iter().find(|(n, _, _)| n == command_str) {
            let mut arg_count = text_before_cursor.split_whitespace().count();
            if text_before_cursor.ends_with(char::is_whitespace) {
                arg_count += 1;
            }
            let arg_index = arg_count.saturating_sub(2);
            let strat = strategies
                .get(arg_index)
                .copied()
                .unwrap_or(CompletionStrategy::None);

            let arg_start = text_before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let raw_prefix = &text_before_cursor[arg_start..];
            let ident_start = raw_prefix
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .map(|i| i + 1)
                .unwrap_or(0);
            let prefix = &raw_prefix[ident_start..];
            let span_start = arg_start + ident_start;
            return self.apply_strategy(strat, raw_prefix, ident_start, prefix, span_start, pos);
        }

        vec![]
    }
}

impl MyCompleter {
    fn apply_strategy(
        &self,
        strategy: CompletionStrategy,
        raw_prefix: &str,
        ident_start: usize,
        prefix: &str,
        span_start: usize,
        pos: usize,
    ) -> Vec<Suggestion> {
        match strategy {
            CompletionStrategy::None => vec![],

            CompletionStrategy::Symbol => {
                if ident_start > 0 {
                    let preceding = &raw_prefix[..ident_start];

                    if preceding.ends_with('+')
                        || preceding.ends_with('-')
                        || preceding.ends_with('[')
                    {
                        return vec![];
                    }

                    if let Some(expr_text) = preceding.strip_suffix("->") {
                        if let Ok(expr) = Expr::parse(expr_text) {
                            let dtb = *self.dtb.read().unwrap();
                            let fields = expr.complete_fields(&self.symbol_store, dtb, prefix);
                            if !fields.is_empty() {
                                return make_suggestions(fields, "Field", span_start, pos);
                            }
                        }
                        return vec![];
                    }

                    if preceding.ends_with('(') {
                        let types = self.types.read().unwrap();
                        let mut results = types.search(prefix, 512);
                        if !prefix.starts_with('_') {
                            results.extend(types.search(&format!("_{}", prefix), 512));
                        }
                        if !results.is_empty() {
                            return make_suggestions(results, "Type", span_start, pos);
                        }
                    }
                }

                let symbols = self.symbols.read().unwrap();
                let results = symbols.search(prefix, 1024);
                make_suggestions(results, "Symbol", span_start, pos)
            }

            CompletionStrategy::Type => {
                let types = self.types.read().unwrap();
                let results = types.search(prefix, 1024);
                make_suggestions(results, "Structure", span_start, pos)
            }

            CompletionStrategy::Process => {
                let processes = self.processes.read().unwrap();
                let prefix_lower = prefix.to_lowercase();
                processes
                    .iter()
                    .filter(|(name, pid)| {
                        name.to_lowercase().contains(&prefix_lower)
                            || pid.to_string().starts_with(prefix)
                    })
                    .map(|(name, pid)| Suggestion {
                        value: pid.to_string(),
                        description: Some(format!("{} (PID {})", name, pid)),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(span_start, pos),
                        append_whitespace: false,
                    })
                    .collect()
            }

            CompletionStrategy::Thread => {
                let threads = self.threads.read().unwrap();
                threads
                    .iter()
                    .filter(|tid| tid.starts_with(prefix))
                    .map(|tid| Suggestion {
                        value: tid.clone(),
                        description: Some("Thread/vCPU".to_string()),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(span_start, pos),
                        append_whitespace: false,
                    })
                    .collect()
            }

            CompletionStrategy::Breakpoint => {
                let breakpoints = self.breakpoints.read().unwrap();
                breakpoints
                    .iter()
                    .filter(|(id, _, _, _)| id.to_string().starts_with(prefix))
                    .map(|(id, _, addr, symbol)| {
                        let sym_str = symbol.as_deref().unwrap_or("-");
                        Suggestion {
                            value: id.to_string(),
                            description: Some(format!("{} @ {:#x}", sym_str, addr.0)),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(span_start, pos),
                            append_whitespace: false,
                        }
                    })
                    .collect()
            }

            CompletionStrategy::Driver => {
                let drivers = self.drivers.read().unwrap();
                let prefix_lower = prefix.to_lowercase();
                let arg_start = span_start - ident_start;
                drivers
                    .iter()
                    .filter(|driver| {
                        driver.name.to_lowercase().contains(&prefix_lower)
                            || format!("{:#x}", driver.object.0).starts_with(prefix)
                    })
                    .map(|driver| Suggestion {
                        value: format!("{:#x}", driver.object.0),
                        description: Some(format!(
                            "{} start={:#x}",
                            driver.name, driver.driver_start.0
                        )),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(arg_start, pos),
                        append_whitespace: false,
                    })
                    .collect()
            }
        }
    }
}

fn error(msg: &str) {
    eprintln!("{} {}", "error:".red(), msg);
}

macro_rules! error {
    ($($arg:tt)*) => {
        error(&format!($($arg)*))
    };
}

fn print_module_symbol_report(report: &ModuleSymbolLoadReport) {
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

fn print_qemu_monitor_output(output: &str) {
    if output.trim().is_empty() {
        println!("{}\n", "qemu monitor command completed".bright_black());
    } else {
        println!("{}\n", output.trim_end());
    }
}

fn print_script_load_report(report: &LoadReport, startup_hint: bool) {
    if report.loaded.is_empty() && report.failed.is_empty() {
        if startup_hint {
            println!("scripts: 0 installed (run `ntoseye scripts install` to add bundled scripts)");
        } else {
            println!("scripts: 0 loaded");
        }
    } else {
        let mut summary = format!("scripts: loaded {}", report.loaded.len());
        if !report.failed.is_empty() {
            summary.push_str(&format!(", {} failed", report.failed.len()));
        }
        println!("{}", summary);
        for (path, err) in &report.failed {
            eprintln!("{} {}: {}", "error:".red(), path.display(), err);
        }
    }
}

fn refresh_process_cache(
    debugger: &DebuggerContext,
    shared_processes: &Arc<RwLock<ProcessCache>>,
) -> Result<()> {
    let processes = debugger
        .guest
        .enumerate_processes(&debugger.kvm, &debugger.symbols)?;
    *shared_processes.write().unwrap() = processes.into_iter().map(|p| (p.name, p.pid)).collect();
    Ok(())
}

macro_rules! update_breakpoint_cache {
    ($breakpoints:expr, $cache:expr) => {
        *$cache.write().unwrap() = $breakpoints
            .list()
            .iter()
            .map(|bp| (bp.id, bp.enabled, bp.address, bp.symbol.clone()))
            .collect();
    };
}

fn print_registers(register_map: &RegisterMap, regs: &[u8]) {
    let read_reg = |name: &str| -> String {
        register_map
            .read_u64(name, regs)
            .map(|v| format!("{:#018x}", VirtAddr(v)))
            .unwrap_or_else(|_| "N/A".to_string())
    };

    println!(
        "{}",
        "─── registers ─────────────────────────────────────────────────────".bright_black()
    );
    println!(
        "rax={}  rbx={}  rcx={}",
        read_reg("rax"),
        read_reg("rbx"),
        read_reg("rcx")
    );
    println!(
        "rdx={}  rsi={}  rdi={}",
        read_reg("rdx"),
        read_reg("rsi"),
        read_reg("rdi")
    );
    println!(
        "rsp={}  rbp={}  rip={}",
        read_reg("rsp"),
        read_reg("rbp"),
        read_reg("rip")
    );
    println!(
        "r8 ={}  r9 ={}  r10={}",
        read_reg("r8"),
        read_reg("r9"),
        read_reg("r10")
    );
    println!(
        "r11={}  r12={}  r13={}",
        read_reg("r11"),
        read_reg("r12"),
        read_reg("r13")
    );
    println!(
        "r14={}  r15={}  rflags={}",
        read_reg("r14"),
        read_reg("r15"),
        read_reg("eflags")
    );
}

fn print_control_registers(register_map: &RegisterMap, regs: &[u8]) {
    let read_reg = |name: &str| -> String {
        register_map
            .read_u64(name, regs)
            .map(|v| format!("{:#018x}", VirtAddr(v)))
            .unwrap_or_else(|_| "N/A".to_string())
    };

    println!(
        "{}",
        "─── control registers ─────────────────────────────────────────────".bright_black()
    );
    println!(
        "cr0={}  cr2={}  cr3={}",
        read_reg("cr0"),
        read_reg("cr2"),
        read_reg("cr3")
    );
    println!("cr4={}  cr8={}", read_reg("cr4"), read_reg("cr8"));
}

fn typed_field_value(
    debugger: &DebuggerContext,
    address: VirtAddr,
    info: &crate::symbols::FieldInfo,
) -> Result<String> {
    if address.0 == 0 {
        return Ok(String::new());
    }

    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let value = match &info.type_data {
        ParsedType::Primitive(p) => {
            if p.contains("*") || p.contains("LONGLONG") {
                let val: u64 = mem.read(address + info.offset)?;
                format!(" = {:#x}", Value(val))
            } else if p.contains("LONG") {
                let val: u32 = mem.read(address + info.offset)?;
                format!(" = {:#x}", Value(val))
            } else if p.contains("SHORT") || p.contains("WCHAR") {
                let val: u16 = mem.read(address + info.offset)?;
                format!(" = {:#x}", Value(val))
            } else if p.contains("CHAR") {
                let val: u8 = mem.read(address + info.offset)?;
                format!(" = {:#x}", Value(val))
            } else {
                String::new()
            }
        }
        ParsedType::Pointer(_) => {
            let val: u64 = mem.read(address + info.offset)?;
            format!(" = {:#x}", Value(val))
        }
        ParsedType::Bitfield { pos, len, .. } => {
            let val: u64 = mem.read(address + info.offset)?;
            let mask = if *len == 64 {
                u64::MAX
            } else {
                (1u64 << *len) - 1
            };
            let val = (val >> pos) & mask;

            if *len == 1 {
                if val == 1 {
                    format!(" = {}", "Y".green())
                } else {
                    format!(" = {}", "N".red())
                }
            } else {
                format!(" = {}", Value(val))
            }
        }
        _ => String::new(),
    };

    Ok(value)
}

fn print_type_instance(
    debugger: &DebuggerContext,
    type_info: &TypeInfo,
    address: VirtAddr,
    field_name: Option<&str>,
) -> Result<()> {
    let mut builder = Builder::default();
    builder.push_record(vec![format!(
        "{} ({} bytes)",
        type_info.name,
        Value(type_info.size)
    )]);

    let mut sorted_fields: Vec<_> = type_info.fields.iter().collect();
    sorted_fields.sort_by_key(|(_, info)| {
        let bitfield_pos = match &info.type_data {
            ParsedType::Bitfield { pos, .. } => *pos,
            _ => 0,
        };
        (info.offset, bitfield_pos)
    });

    for (name, info) in sorted_fields {
        if field_name.is_some_and(|field| field != name) {
            continue;
        }

        builder.push_record(vec![
            format!("  + {:#06x} {:-12}", VirtAddr(info.offset.into()), name),
            format!("  : {}", info.type_data.green()),
            format!("  {}", typed_field_value(debugger, address, info)?),
        ]);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{}\n", table);
    Ok(())
}

fn dump_trap_frame(
    debugger: &DebuggerContext,
    address: VirtAddr,
    field_name: Option<&str>,
) -> Result<()> {
    let type_info = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_KTRAP_FRAME")
        .ok_or_else(|| Error::StructNotFound("_KTRAP_FRAME".to_string()))?;
    print_type_instance(debugger, &type_info, address, field_name)
}

/// Single-step the current thread and clear `TF` from its RFLAGS afterwards.
/// KVM sets `TF` when enabling `KVM_GUESTDBG_SINGLESTEP` but doesn't clear it
/// when SINGLESTEP is removed; without this clear, the stepped thread keeps
/// trapping after every instruction on resume
fn step_one_and_clear_tf(client: &mut dyn DebugBackend, register_map: &RegisterMap) -> Result<()> {
    client.step()?;
    client.wait_for_stop()?;

    if let Ok(mut regs) = client.read_registers()
        && let Ok(eflags) = register_map.read_u64("eflags", &regs)
    {
        let cleared = eflags & !(1u64 << 8);
        if cleared != eflags && register_map.write_u64("eflags", &mut regs, cleared).is_ok() {
            client.write_registers(&regs)?;
        }
    }

    Ok(())
}

/// If the current thread's RIP sits on one of our enabled breakpoints,
/// disable it, step the underlying instruction, then re-enable. Returns
/// whether a step was performed. Caller must have set the gdb stub's
/// control thread first
fn step_over_current_breakpoint(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &DebuggerContext,
    breakpoints: &mut BreakpointManager,
) -> Result<bool> {
    let regs = client.read_registers()?;
    let rip = register_map.read_u64("rip", &regs)?;
    let cr3 = register_map.read_u64("cr3", &regs)?;

    // Scope-agnostic: a wrong-process hit on a shared-page BP still needs the
    // disable/step/enable dance so the wrong process can make forward progress
    let Some(bp_id) = breakpoints.breakpoint_id_at_address(rip) else {
        return Ok(false);
    };

    if let Err(err) = breakpoints.disable(client, debugger, bp_id) {
        if matches!(err, Error::BadVirtualAddress(_)) {
            breakpoints
                .disable_guest_memory_patch_in_address_space(client, debugger, bp_id, cr3)?;
        } else {
            return Err(err);
        }
    }

    step_one_and_clear_tf(client, register_map)?;

    if let Err(err) = breakpoints.enable(client, debugger, bp_id) {
        if matches!(err, Error::BadVirtualAddress(_)) {
            let removed = breakpoints.discard(bp_id)?;
            println!(
                "{}",
                format!(
                    "breakpoint #{} removed: {} address space no longer exists",
                    removed.id,
                    removed.scope.label()
                )
                .yellow()
            );
        } else {
            return Err(err);
        }
    }
    Ok(true)
}

/// For every gdb thread whose RIP sits one byte past one of our breakpoints,
/// rewind it back to the breakpoint address. The stub doesn't always adjust
/// RIP back to the int3 when multiple vCPUs hit the same BP simultaneously;
/// resuming an un-adjusted vCPU would decode the remainder of the original
/// instruction's bytes as a different instruction and corrupt guest state.
/// Restores Hg/Hc to `restore_thread` before returning
fn rewind_threads_off_breakpoints(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    restore_thread: &str,
) {
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
        let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
        let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
        let Some(prev) = rip.checked_sub(1) else {
            continue;
        };
        if !breakpoints.int3_breakpoint_hit_at(prev, cr3) {
            continue;
        }
        let mut adjusted = regs.clone();
        if register_map.write_u64("rip", &mut adjusted, prev).is_err() {
            continue;
        }
        let _ = client.write_registers(&adjusted);
    }

    let _ = client.set_current_thread(restore_thread);
}

fn print_disasm_context(debugger: &DebuggerContext, trace: &ThreadTraceContext, rip: u64) {
    println!(
        "{}",
        "─── disasm ────────────────────────────────────────────────────────".bright_black()
    );

    let pre_bytes: u64 = 64;
    let post_bytes: u64 = 64;
    let start_addr = rip.saturating_sub(pre_bytes);
    let total_len = (pre_bytes + post_bytes) as usize;
    let active_memory = AddressSpace::new(&debugger.kvm, trace.active_dtb);
    let code_dtb = preferred_code_dtb(trace, rip);
    let code_memory = AddressSpace::new(&debugger.kvm, code_dtb);

    let mut bytes = vec![0u8; total_len];
    if active_memory
        .read_bytes(VirtAddr(start_addr), &mut bytes)
        .is_err()
        && (code_dtb == trace.active_dtb
            || code_memory
                .read_bytes(VirtAddr(start_addr), &mut bytes)
                .is_err())
    {
        println!("{}", "  (could not read memory at RIP)".bright_black());
        return;
    }

    let mut decoder = Decoder::with_ip(64, &bytes, start_addr, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let options = formatter.options_mut();
    options.set_space_after_operand_separator(true);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_first_operand_char_index(5);
    options.set_memory_size_options(MemorySizeOptions::Always);
    options.set_show_branch_size(false);
    options.set_rip_relative_addresses(true);

    let mut instructions: Vec<(u64, usize, String)> = Vec::new();
    let mut instruction = Instruction::default();
    let mut output = String::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID {
            continue;
        }
        output.clear();
        formatter.format(&instruction, &mut output);

        let ip = instruction.ip();
        let len = instruction.len();

        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + len];
        let hex: String = instr_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        let mut line = format!("{hex:<24} {output}");

        if instruction.is_ip_rel_memory_operand() {
            let target = instruction.ip_rel_memory_address();
            let sym = format_symbol(debugger, trace, target);
            line.push_str(&format!(" ; {}", sym));
        } else if instruction.is_call_near()
            || instruction.is_jmp_near()
            || instruction.is_jcc_near()
        {
            let target = instruction.near_branch_target();
            let sym = format_symbol(debugger, trace, target);
            line.push_str(&format!(" ; {}", sym));
        }

        instructions.push((ip, len, line));
    }

    // find which instruction corresponds to RIP
    let rip_idx = instructions.iter().position(|(ip, _, _)| *ip == rip);

    if let Some(idx) = rip_idx {
        let context_before = 5;
        let context_after = 5;
        let start = idx.saturating_sub(context_before);
        let end = (idx + context_after + 1).min(instructions.len());

        for (ip, _, line) in instructions.iter().take(end).skip(start) {
            if *ip == rip {
                println!(
                    " {} {}  {}",
                    ">".green(),
                    format!("{:016x}", VirtAddr(*ip)).green(),
                    line.green()
                );
            } else {
                println!("   {:016x}  {}", VirtAddr(*ip), line.bright_black());
            }
        }
    } else {
        let mut forward_buf = vec![0u8; post_bytes as usize];
        if active_memory
            .read_bytes(VirtAddr(rip), &mut forward_buf)
            .is_ok()
            || (code_dtb != trace.active_dtb
                && code_memory
                    .read_bytes(VirtAddr(rip), &mut forward_buf)
                    .is_ok())
        {
            let mut dec = Decoder::with_ip(64, &forward_buf, rip, DecoderOptions::NONE);
            let mut inst = Instruction::default();
            let mut out = String::new();
            let mut count = 0;
            while dec.can_decode() && count < 11 {
                dec.decode_out(&mut inst);
                if inst.code() == Code::INVALID {
                    continue;
                }
                out.clear();
                formatter.format(&inst, &mut out);
                let ip = inst.ip();
                let start_index = (ip - rip) as usize;
                let instr_bytes = &forward_buf[start_index..start_index + inst.len()];
                let hex: String = instr_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                if ip == rip {
                    println!(
                        " {} {}  {:<24} {}",
                        "=>".green(),
                        format!("{:016x}", VirtAddr(ip)).green(),
                        hex.green(),
                        out.green()
                    );
                } else {
                    println!(
                        "   {:016x}  {:<24} {}",
                        VirtAddr(ip),
                        hex.bright_black(),
                        out.bright_black()
                    );
                }
                count += 1;
            }
        } else {
            println!("{}", "  (could not read memory at RIP)".bright_black());
        }
    }
}

fn print_stacktrace(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
    display_limit: usize,
) {
    println!(
        "{}",
        "─── stack trace ───────────────────────────────────────────────────".bright_black()
    );

    let stacktrace = build_stacktrace(debugger, register_map, regs, build_limit);
    let shown = stacktrace.frames.len().min(display_limit);

    for (num, frame) in stacktrace.frames.iter().take(shown).enumerate() {
        let suffix = if frame.source == FrameSource::Scan {
            format!(" {}", "[scan]".bright_black())
        } else {
            String::new()
        };
        let trap_frame = frame
            .trap_frame
            .map(|addr| {
                format!("  trap_frame={:#018x}", VirtAddr(addr))
                    .cyan()
                    .to_string()
            })
            .unwrap_or_default();
        println!(
            " {:>2}  {:#018x}  {:#018x}  {}{}{}",
            num,
            VirtAddr(frame.sp),
            VirtAddr(frame.ip),
            frame.symbol,
            suffix,
            trap_frame
        );
    }

    let hidden = stacktrace.frames.len().saturating_sub(display_limit) + stacktrace.truncated;
    if hidden > 0 {
        println!(
            " {}",
            format!("... {} more frames truncated", hidden).bright_black()
        );
    }
}

fn print_break_context(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut DebuggerContext,
    thread_id: &str,
) {
    let _ = client.set_current_thread(thread_id);

    let regs = match client.read_registers() {
        Ok(r) => r,
        Err(e) => {
            debugger.registers = None;
            println!(
                "{} thread {} (read_registers failed: {})\n",
                "break:".magenta(),
                thread_id,
                e
            );
            return;
        }
    };

    debugger.registers = Some(register_map.to_hashmap(&regs));

    let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let trace = resolve_thread_trace_context(debugger, cr3);
    let symbol = format_symbol(debugger, &trace, rip);

    println!(
        "{} {} {} {} {} {}",
        "break:".magenta(),
        format!("thread {}", thread_id).bright_black(),
        "in".bright_black(),
        trace.description.cyan(),
        "at".bright_black(),
        symbol.green()
    );

    print_registers(register_map, &regs);
    print_disasm_context(debugger, &trace, rip);
    print_stacktrace(
        debugger,
        register_map,
        &regs,
        BREAK_STACKTRACE_PROBE_LIMIT,
        BREAK_STACKTRACE_DISPLAY_LIMIT,
    );
    println!();
}

enum ItemFormat {
    Bytes,
    Dwords,
    Qwords,
}

struct MemoryDisplayMode {
    bytes_per_row: usize,
    item_size: usize,
    item_format: ItemFormat,
    show_ascii: bool,
}

impl MemoryDisplayMode {
    fn bytes() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 1,
            item_format: ItemFormat::Bytes,
            show_ascii: true,
        }
    }

    fn dwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 4,
            item_format: ItemFormat::Dwords,
            show_ascii: false,
        }
    }

    fn qwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 8,
            item_format: ItemFormat::Qwords,
            show_ascii: false,
        }
    }
}

fn display_memory(start_address: VirtAddr, data: &[u8], mode: &MemoryDisplayMode) {
    for (i, chunk) in data.chunks(mode.bytes_per_row).enumerate() {
        print!(
            "{:08x}  ",
            start_address + ((i * mode.bytes_per_row) as u64)
        );

        let items_per_row = mode.bytes_per_row / mode.item_size;
        let mut printed = 0;

        for item in chunk.chunks(mode.item_size) {
            match mode.item_format {
                ItemFormat::Bytes => {
                    print!("{:02x} ", item[0]);
                }
                ItemFormat::Dwords => {
                    if item.len() == 4 {
                        let val = u32::from_le_bytes([item[0], item[1], item[2], item[3]]);
                        print!("{:08x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
                ItemFormat::Qwords => {
                    if item.len() == 8 {
                        let val = u64::from_le_bytes([
                            item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7],
                        ]);
                        print!("{:016x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
            }
            printed += 1;
        }

        // pad remaining items if needed
        for _ in printed..items_per_row {
            match mode.item_format {
                ItemFormat::Bytes => print!("   "),
                ItemFormat::Dwords => print!("         "),
                ItemFormat::Qwords => print!("                 "),
            }
        }

        if mode.show_ascii {
            print!(" ");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!("{}", ".".bright_black());
                }
            }
        }

        println!();
    }

    println!();
}

#[derive(Debug, Clone, Copy)]
struct Idtr {
    base: VirtAddr,
    limit: u16,
}

#[derive(Debug, Clone, Copy)]
struct Gdtr {
    base: VirtAddr,
    limit: u16,
}

#[derive(Debug, Clone, Copy)]
struct IdtEntry {
    vector: usize,
    handler: VirtAddr,
    selector: u16,
    ist: u8,
    gate_type: u8,
    dpl: u8,
    present: bool,
}

#[derive(Debug, Clone)]
struct GdtEntry {
    index: usize,
    selector: u16,
    base: u64,
    effective_limit: u64,
    ty: u8,
    system: bool,
    dpl: u8,
    present: bool,
    long_mode: bool,
    default_big: bool,
    granularity: bool,
    avl: bool,
    raw: u128,
}

#[derive(Debug, Clone)]
struct TssStackBases {
    rsp: [VirtAddr; 3],
    ist: [VirtAddr; 7],
    io_map_base: u16,
}

fn parse_hex_u64(token: &str) -> Option<u64> {
    let stripped = token
        .trim_matches(|c: char| c == ',' || c == ';')
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(stripped, 16).ok()
}

fn parse_idtr_from_qemu_registers(output: &str) -> Option<Idtr> {
    for line in output.lines() {
        let Some((_, rest)) = line.split_once("IDT=") else {
            continue;
        };
        let mut values = rest.split_whitespace().filter_map(parse_hex_u64);
        let base = values.next()?;
        let limit = values.next()?;
        return Some(Idtr {
            base: VirtAddr(base),
            limit: limit as u16,
        });
    }
    None
}

fn parse_gdtr_from_qemu_registers(output: &str) -> Option<Gdtr> {
    for line in output.lines() {
        let Some((_, rest)) = line.split_once("GDT=") else {
            continue;
        };
        let mut values = rest.split_whitespace().filter_map(parse_hex_u64);
        let base = values.next()?;
        let limit = values.next()?;
        return Some(Gdtr {
            base: VirtAddr(base),
            limit: limit as u16,
        });
    }
    None
}

fn parse_tr_selector_from_qemu_registers(output: &str) -> Option<u16> {
    for line in output.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("TR") else {
            continue;
        };
        let Some((_, value_text)) = rest.split_once('=') else {
            continue;
        };
        let selector = value_text
            .split_whitespace()
            .next()
            .and_then(parse_hex_u64)?;
        return Some(selector as u16);
    }
    None
}

fn parse_idt_entry(vector: usize, bytes: &[u8]) -> IdtEntry {
    let offset_low = u16::from_le_bytes([bytes[0], bytes[1]]) as u64;
    let selector = u16::from_le_bytes([bytes[2], bytes[3]]);
    let ist = bytes[4] & 0x07;
    let attr = bytes[5];
    let offset_mid = u16::from_le_bytes([bytes[6], bytes[7]]) as u64;
    let offset_high = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as u64;

    IdtEntry {
        vector,
        handler: VirtAddr(offset_low | (offset_mid << 16) | (offset_high << 32)),
        selector,
        ist,
        gate_type: attr & 0x1f,
        dpl: (attr >> 5) & 0x03,
        present: attr & 0x80 != 0,
    }
}

fn read_gdt_entry(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<GdtEntry> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    let index = (selector >> 3) as usize;
    let offset = index * 8;
    if offset + 8 > gdtr.limit as usize + 1 {
        return Err(Error::InvalidRange);
    }

    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let memory = AddressSpace::new(&debugger.kvm, cr3);
    let mut bytes = [0u8; 16];
    memory.read_bytes(gdtr.base + offset as u64, &mut bytes[..8])?;

    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let system = ((lo >> 44) & 1) == 0;
    let ty = ((lo >> 40) & 0x0f) as u8;
    if system && matches!(ty, 0x2 | 0x9 | 0xb) && offset + 16 <= gdtr.limit as usize + 1 {
        memory.read_bytes(gdtr.base + offset as u64 + 8u64, &mut bytes[8..16])?;
    }

    Ok(parse_gdt_entry(index, &bytes))
}

fn parse_gdt_entry(index: usize, data: &[u8]) -> GdtEntry {
    let lo = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let ty = ((lo >> 40) & 0x0f) as u8;
    let system = ((lo >> 44) & 1) == 0;
    let dpl = ((lo >> 45) & 0x03) as u8;
    let present = ((lo >> 47) & 1) != 0;
    let long_mode = ((lo >> 53) & 1) != 0;
    let default_big = ((lo >> 54) & 1) != 0;
    let granularity = ((lo >> 55) & 1) != 0;
    let avl = ((lo >> 52) & 1) != 0;

    let limit = ((lo & 0xffff) | (((lo >> 48) & 0x0f) << 16)) as u32;
    let effective_limit = if granularity {
        ((limit as u64) << 12) | 0xfff
    } else {
        limit as u64
    };

    let base_low = ((lo >> 16) & 0x00ff_ffff) | (((lo >> 56) & 0xff) << 24);
    let base = if system && data.len() >= 16 {
        let hi = u64::from_le_bytes(data[8..16].try_into().unwrap()) & 0xffff_ffff;
        base_low | (hi << 32)
    } else {
        base_low
    };

    let raw = if data.len() >= 16 {
        u128::from_le_bytes(data[0..16].try_into().unwrap())
    } else {
        lo as u128
    };

    GdtEntry {
        index,
        selector: (index * 8) as u16,
        base,
        effective_limit,
        ty,
        system,
        dpl,
        present,
        long_mode,
        default_big,
        granularity,
        avl,
        raw,
    }
}

fn parse_tss_stack_bases(data: &[u8]) -> Result<TssStackBases> {
    if data.len() < 0x68 {
        return Err(Error::BufferNotEnough);
    }

    let read_u64 = |offset: usize| -> VirtAddr {
        VirtAddr(u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap(),
        ))
    };

    Ok(TssStackBases {
        rsp: [read_u64(0x04), read_u64(0x0c), read_u64(0x14)],
        ist: [
            read_u64(0x24),
            read_u64(0x2c),
            read_u64(0x34),
            read_u64(0x3c),
            read_u64(0x44),
            read_u64(0x4c),
            read_u64(0x54),
        ],
        io_map_base: u16::from_le_bytes(data[0x66..0x68].try_into().unwrap()),
    })
}

fn gdt_type_label(entry: &GdtEntry) -> String {
    if !entry.system {
        let exec = entry.ty & 0x08 != 0;
        let conforming_or_expand_down = entry.ty & 0x04 != 0;
        let writable_or_readable = entry.ty & 0x02 != 0;
        let accessed = entry.ty & 0x01 != 0;
        let mut flags = String::new();
        flags.push(if exec { 'C' } else { 'D' });
        if conforming_or_expand_down {
            flags.push(if exec { 'c' } else { 'e' });
        }
        if writable_or_readable {
            flags.push(if exec { 'r' } else { 'w' });
        }
        if accessed {
            flags.push('a');
        }
        return flags;
    }

    match entry.ty {
        0x2 => "LDT".to_string(),
        0x9 => "TSS64-avail".to_string(),
        0xb => "TSS64-busy".to_string(),
        0xc => "call-gate64".to_string(),
        0xe => "int-gate64".to_string(),
        0xf => "trap-gate64".to_string(),
        _ => format!("sys-{:#x}", entry.ty),
    }
}

fn parse_selector_arg(arg: &str) -> Option<u16> {
    let stripped = arg.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(stripped, 16)
        .or_else(|_| arg.parse::<u16>())
        .ok()
}

fn dump_idt(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    idtr: Idtr,
    max_entries: Option<usize>,
) -> Result<()> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let idt_size = idtr.limit as usize + 1;
    let entry_count = max_entries.map_or(idt_size / 16, |count| count.min(idt_size / 16));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }

    let mut data = vec![0u8; entry_count * 16];
    let memory = AddressSpace::new(&debugger.kvm, cr3);
    memory.read_bytes(idtr.base, &mut data)?;

    println!(
        "IDTR base={:#018x} limit={:#06x} entries={}\n",
        idtr.base, idtr.limit, entry_count
    );

    let mut builder = Builder::default();
    builder.push_record(vec![
        "Vec  ".to_string(),
        "Handler             ".to_string(),
        "Sel     ".to_string(),
        "IST  ".to_string(),
        "Type  ".to_string(),
        "DPL  ".to_string(),
        "P  ".to_string(),
        "Symbol".to_string(),
    ]);

    for entry in data
        .chunks_exact(16)
        .enumerate()
        .map(|(vector, bytes)| parse_idt_entry(vector, bytes))
    {
        let symbol = debugger
            .symbols
            .find_closest_symbol_for_address(debugger.guest.ntoskrnl.dtb(), entry.handler)
            .map(|(module, sym, offset)| {
                if offset == 0 {
                    format!("{}!{}", module, sym)
                } else {
                    format!("{}!{}+{:#x}", module, sym, offset)
                }
            })
            .unwrap_or_else(|| "-".to_string());

        builder.push_record(vec![
            format!("{:#04x}  ", entry.vector),
            format!("{:#018x}  ", entry.handler),
            format!("{:#06x}  ", entry.selector),
            format!("{}  ", entry.ist),
            format!("{:#04x}  ", entry.gate_type),
            format!("{}  ", entry.dpl),
            format!("{}  ", if entry.present { "Y" } else { "N" }),
            symbol,
        ]);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{}\n", table);
    Ok(())
}

fn dump_tss_stack_bases(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<()> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    let entry = read_gdt_entry(debugger, register_map, regs, gdtr, selector)?;
    if !entry.system || !matches!(entry.ty, 0x9 | 0xb) {
        return Err(Error::InvalidExpression(format!(
            "selector {:#x} is not an x64 TSS descriptor ({})",
            selector,
            gdt_type_label(&entry)
        )));
    }

    let size = ((entry.effective_limit + 1).min(0x1000) as usize).max(0x68);
    let mut data = vec![0u8; size];
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let memory = AddressSpace::new(&debugger.kvm, cr3);
    memory.read_bytes(VirtAddr(entry.base), &mut data)?;
    let stacks = parse_tss_stack_bases(&data)?;

    println!(
        "TSS selector={:#06x} base={:#018x} limit={:#x} type={}\n",
        selector,
        VirtAddr(entry.base),
        entry.effective_limit,
        gdt_type_label(&entry)
    );

    let mut builder = Builder::default();
    builder.push_record(vec!["Slot  ".to_string(), "Base".to_string()]);
    for (idx, addr) in stacks.rsp.iter().enumerate() {
        builder.push_record(vec![format!("RSP{}  ", idx), format!("{:#018x}", addr)]);
    }
    for (idx, addr) in stacks.ist.iter().enumerate() {
        builder.push_record(vec![format!("IST{}  ", idx + 1), format!("{:#018x}", addr)]);
    }
    builder.push_record(vec![
        "I/O map  ".to_string(),
        format!("{:#06x}", stacks.io_map_base),
    ]);

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{}\n", table);
    Ok(())
}

fn dump_gdt(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    max_entries: Option<usize>,
) -> Result<()> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let gdt_size = gdtr.limit as usize + 1;
    let entry_count = max_entries.map_or(gdt_size / 8, |count| count.min(gdt_size / 8));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }

    let read_len = gdt_size.min(entry_count * 8 + 8);
    let mut data = vec![0u8; read_len];
    let memory = AddressSpace::new(&debugger.kvm, cr3);
    memory.read_bytes(gdtr.base, &mut data)?;

    println!(
        "GDTR base={:#018x} limit={:#06x} entries={}\n",
        gdtr.base, gdtr.limit, entry_count
    );

    let mut builder = Builder::default();
    builder.push_record(vec![
        "Idx  ".to_string(),
        "Sel     ".to_string(),
        "Base                ".to_string(),
        "Limit       ".to_string(),
        "Type        ".to_string(),
        "DPL  ".to_string(),
        "P  ".to_string(),
        "L  ".to_string(),
        "DB  ".to_string(),
        "G  ".to_string(),
        "AVL  ".to_string(),
        "Raw".to_string(),
    ]);

    for index in 0..entry_count {
        let offset = index * 8;
        let Some(first) = data.get(offset..offset + 8) else {
            break;
        };
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(first);

        let lo = u64::from_le_bytes(first.try_into().unwrap());
        let system = ((lo >> 44) & 1) == 0;
        if system
            && matches!(((lo >> 40) & 0x0f) as u8, 0x2 | 0x9 | 0xb)
            && let Some(second) = data.get(offset + 8..offset + 16)
        {
            bytes[8..16].copy_from_slice(second);
        }

        let entry = parse_gdt_entry(index, &bytes);
        builder.push_record(vec![
            format!("{:<5}", entry.index),
            format!("{:#06x}  ", entry.selector),
            format!("{:#018x}  ", VirtAddr(entry.base)),
            format!("{:#010x}  ", entry.effective_limit),
            format!("{}  ", gdt_type_label(&entry)),
            format!("{}  ", entry.dpl),
            format!("{}  ", if entry.present { "Y" } else { "N" }),
            format!("{}  ", if entry.long_mode { "Y" } else { "N" }),
            format!("{}   ", if entry.default_big { "Y" } else { "N" }),
            format!("{}  ", if entry.granularity { "Y" } else { "N" }),
            format!("{}    ", if entry.avl { "Y" } else { "N" }),
            format!("{:#018x}", entry.raw),
        ]);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{}\n", table);
    Ok(())
}

fn find_file_case_insensitive(dir: &Path, filename: &str) -> Option<PathBuf> {
    let wanted = filename.to_lowercase();
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .find_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().to_lowercase();
            if name == wanted { Some(path) } else { None }
        })
}

fn local_symbol_plan_for_module(
    debugger: &DebuggerContext,
    dir: &Path,
    dtb: Dtb,
    module: &ModuleInfo,
) -> Result<Option<(PathBuf, u128)>> {
    match SymbolStore::extract_download_job(&debugger.kvm, dtb, &module.name, module.base_address)?
    {
        ModuleSymbolDiscovery::Ready { job, guid, .. } => {
            Ok(find_file_case_insensitive(dir, &job.filename).map(|path| (path, guid)))
        }
        ModuleSymbolDiscovery::NeedsImage { image_job } => {
            let Some(image_path) = find_file_case_insensitive(dir, &image_job.filename) else {
                return Ok(None);
            };
            let Some((job, guid)) = SymbolStore::extract_download_job_from_image_file(&image_path)?
            else {
                return Ok(None);
            };
            Ok(find_file_case_insensitive(dir, &job.filename).map(|path| (path, guid)))
        }
    }
}

fn load_symbols_from_directory(
    debugger: &DebuggerContext,
    dir: &Path,
    filter: Option<&str>,
) -> Result<ModuleSymbolLoadReport> {
    let (modules, dtb) = if let Some(process_info) = &debugger.current_process_info {
        (
            debugger
                .guest
                .get_process_modules(&debugger.kvm, &debugger.symbols, process_info)?,
            process_info.dtb,
        )
    } else {
        (
            debugger
                .guest
                .get_kernel_modules(&debugger.kvm, &debugger.symbols)?,
            debugger.guest.ntoskrnl.dtb(),
        )
    };

    let filter = filter.map(str::to_lowercase);
    let selected: Vec<ModuleInfo> = modules
        .into_iter()
        .filter(|module| {
            filter.as_ref().is_none_or(|filter| {
                module.short_name.to_lowercase().contains(filter)
                    || module.name.to_lowercase().contains(filter)
            })
        })
        .collect();

    let mut report = ModuleSymbolLoadReport {
        total: selected.len(),
        ..ModuleSymbolLoadReport::default()
    };

    for module in selected {
        match local_symbol_plan_for_module(debugger, dir, dtb, &module) {
            Ok(Some((pdb_path, guid))) => {
                match debugger
                    .symbols
                    .load_local_pdb_for_module(dtb, module, guid, &pdb_path)
                {
                    Ok(()) => report.loaded += 1,
                    Err(_) => report.failed += 1,
                }
            }
            Ok(None) => report.no_pdb += 1,
            Err(_) => report.failed += 1,
        }
    }

    Ok(report)
}

const POOL_ALIGN: u64 = 0x10;
const POOL_PAGE_SIZE: u64 = 0x1000;
const POOL_FREE_TAG: u32 = 0x6565_7246;
const POOL_MAX_GAP_UNITS: u64 = 4;

#[derive(Clone, Copy)]
struct PoolHeader {
    header: VirtAddr,
    body: VirtAddr,
    size: u64,
    previous_size: u64,
    pool_type: u8,
    tag: u32,
    synthetic_free: bool,
}

struct BigPoolEntry {
    va: VirtAddr,
    entry: VirtAddr,
    index: u64,
    nonpaged: bool,
    size: u64,
    tag: u32,
    pattern: u8,
    pool_flags: u16,
    slush_size: u16,
}

/// PDB-driven layout for `_POOL_HEADER` and `_POOL_TRACKER_BIG_PAGES`. Field
/// presence varies across Windows builds; the `*_uses_struct` flags say whether
/// we can decode each entry field-by-field or have to fall back to fixed offsets
struct PoolLayout {
    pool_header: TypeInfo,
    header_size: u64,
    pool_tag_offset: u64,
    pool_header_uses_struct: bool,
    big_pool_type: Option<TypeInfo>,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    big_pool_entry_size: Option<u64>,
}

fn pool_layout(debugger: &DebuggerContext) -> Result<PoolLayout> {
    let pool_header = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_HEADER")
        .ok_or_else(|| Error::StructNotFound("_POOL_HEADER".to_string()))?;
    let pool_tag_offset = pool_header.try_get_field_offset("PoolTag")?;
    let pool_header_uses_struct = [
        "PreviousSize",
        "PoolIndex",
        "BlockSize",
        "PoolType",
        "PoolTag",
    ]
    .iter()
    .all(|name| pool_header.fields.contains_key(*name));

    let big_pool_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_BIG_PAGES");
    let (big_pool_uses_struct, big_pool_has_pool_type, big_pool_has_slush) = match &big_pool_type {
        Some(ti) => (
            ["Va", "Key", "NumberOfBytes", "Pattern"]
                .iter()
                .all(|name| ti.fields.contains_key(*name)),
            ti.fields.contains_key("PoolType"),
            ti.fields.contains_key("SlushSize"),
        ),
        None => (false, false, false),
    };
    let big_pool_entry_size = big_pool_type.as_ref().map(|ti| ti.size as u64);

    Ok(PoolLayout {
        header_size: pool_header.size as u64,
        pool_header,
        pool_tag_offset,
        pool_header_uses_struct,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
        big_pool_entry_size,
    })
}

fn read_pool_field(
    ti: &TypeInfo,
    mem: &impl MemoryOps<VirtAddr>,
    addr: VirtAddr,
    field: &str,
) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let field_addr = addr + f.offset as u64;
    if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
        let raw: u64 = mem.read(field_addr).ok()?;
        let mask = if *len == 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        return Some((raw >> *pos) & mask);
    }

    match field {
        "PreviousSize" | "PoolIndex" | "BlockSize" | "PoolType" | "Pattern" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u8 as u64)
        }
        "SlushSize" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some((value & 0xfff) as u64)
        }
        "PoolTag" | "Key" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u64)
        }
        "Va" | "NumberOfBytes" => mem.read(field_addr).ok(),
        _ => None,
    }
}

fn tag_string(tag: u32) -> String {
    let mut s = String::with_capacity(4);
    for i in 0..4 {
        let c = ((tag >> (i * 8)) & 0xff) as u8;
        s.push(if (0x20..=0x7e).contains(&c) {
            c as char
        } else {
            '.'
        });
    }
    s
}

fn tag_looks_printable(tag: u32) -> bool {
    (0..4).all(|i| (0x20..=0x7e).contains(&((tag >> (i * 8)) & 0xff)))
}

fn plausible_pool_tag(tag: u32) -> bool {
    tag == POOL_FREE_TAG || tag_looks_printable(tag)
}

fn pool_block_state(h: &PoolHeader) -> &'static str {
    if h.synthetic_free || h.tag == POOL_FREE_TAG {
        "Free"
    } else if h.pool_type == 0 {
        "Free?"
    } else if tag_looks_printable(h.tag) {
        "Allocated"
    } else {
        "Allocated?"
    }
}

fn parse_pool_header(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    header: VirtAddr,
) -> Option<PoolHeader> {
    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let (previous_size, block_units, pool_type, tag) = if layout.pool_header_uses_struct {
        let previous_size =
            read_pool_field(&layout.pool_header, &mem, header, "PreviousSize")? as u8;
        let block_units = read_pool_field(&layout.pool_header, &mem, header, "BlockSize")? as u8;
        let pool_type = read_pool_field(&layout.pool_header, &mem, header, "PoolType")? as u8;
        let tag = read_pool_field(&layout.pool_header, &mem, header, "PoolTag")? as u32;
        (previous_size, block_units, pool_type, tag)
    } else {
        let word0: u32 = mem.read(header).ok()?;
        let tag: u32 = mem.read(header + layout.pool_tag_offset).ok()?;
        (
            (word0 & 0xff) as u8,
            ((word0 >> 16) & 0xff) as u8,
            ((word0 >> 24) & 0xff) as u8,
            tag,
        )
    };
    if block_units == 0 {
        return None;
    }
    Some(PoolHeader {
        header,
        body: header + layout.header_size,
        size: block_units as u64 * POOL_ALIGN,
        previous_size: previous_size as u64 * POOL_ALIGN,
        pool_type,
        tag,
        synthetic_free: false,
    })
}

fn pool_header_plausible(layout: &PoolLayout, h: &PoolHeader) -> bool {
    h.size >= layout.header_size
        && h.size <= POOL_PAGE_SIZE
        && (h.header.0 & !(POOL_PAGE_SIZE - 1))
            == ((h.header.0 + h.size - 1) & !(POOL_PAGE_SIZE - 1))
        && (plausible_pool_tag(h.tag) || (h.pool_type == 0 && h.previous_size == 0))
}

fn try_pool_header_lax(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    addr: VirtAddr,
) -> Option<PoolHeader> {
    let h = parse_pool_header(debugger, layout, addr)?;
    pool_header_plausible(layout, &h).then_some(h)
}

fn gap_free_pool_block(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    header: VirtAddr,
    size: u64,
) -> PoolHeader {
    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let tag: u32 = mem.read(header + layout.pool_tag_offset).unwrap_or(0);
    PoolHeader {
        header,
        body: header + layout.header_size,
        size,
        previous_size: 0,
        pool_type: 0,
        tag,
        synthetic_free: true,
    }
}

fn walk_pool_page_lax(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut blocks = Vec::new();
    let mut addr = base;
    while addr.0 < base.0 + POOL_PAGE_SIZE {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            addr += h.size;
            blocks.push(h);
        } else {
            let mut advanced = false;
            for step in 1..=POOL_MAX_GAP_UNITS {
                let probe = addr + step * POOL_ALIGN;
                if probe.0 >= base.0 + POOL_PAGE_SIZE {
                    break;
                }
                if let Some(h2) = try_pool_header_lax(debugger, layout, probe)
                    .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
                {
                    addr = h2.header;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
    }
    blocks
}

fn scan_pool_page_lax(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut candidates = Vec::new();
    let mut off = 0;
    while off < POOL_PAGE_SIZE {
        let addr = base + off;
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            candidates.push(h);
        }
        off += POOL_ALIGN;
    }
    let mut blocks = Vec::new();
    let mut cursor = base;
    for (i, h) in candidates.iter().copied().enumerate() {
        if h.header < cursor {
            continue;
        }
        if h.header == cursor
            && h.size == POOL_ALIGN
            && pool_block_state(&h) == "Free?"
            && let Some(next) = candidates.get(i + 1)
            && next.header.0 > h.header.0 + POOL_ALIGN
        {
            let free_size = next.header.0 - h.header.0 - POOL_ALIGN;
            blocks.push(gap_free_pool_block(debugger, layout, h.header, free_size));
            cursor = h.header + free_size;
        } else {
            if h.header > cursor {
                let free_size = h.header.0.saturating_sub(cursor.0 + POOL_ALIGN);
                if free_size >= POOL_ALIGN * 2 {
                    blocks.push(gap_free_pool_block(debugger, layout, cursor, free_size));
                }
            }
            blocks.push(h);
            cursor = h.header + h.size;
        }
    }
    blocks
}

fn find_pool_block_index(blocks: &[PoolHeader], needle: &PoolHeader) -> Option<usize> {
    blocks
        .iter()
        .position(|h| h.header == needle.header && h.size == needle.size)
}

fn locate_pool_block_in_page(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    target: VirtAddr,
) -> (Vec<PoolHeader>, Option<usize>, VirtAddr) {
    let base = VirtAddr(target.0 & !(POOL_PAGE_SIZE - 1));
    let aligned = VirtAddr(target.0 & !(POOL_ALIGN - 1));
    let mut anchor = None;
    let mut addr = aligned;
    loop {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| target >= h.header && target.0 < h.header.0 + h.size)
        {
            anchor = Some(h);
            break;
        }
        if addr <= base {
            break;
        }
        addr -= POOL_ALIGN;
    }
    let Some(anchor) = anchor else {
        return (Vec::new(), None, base);
    };
    let blocks = walk_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    let blocks = scan_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    (vec![anchor], Some(0), base)
}

fn classify_pool_region(
    debugger: &DebuggerContext,
    addr: VirtAddr,
) -> Option<(&'static str, VirtAddr, VirtAddr)> {
    for (name, start, stop) in [
        ("NonPagedPool", "MmNonPagedPoolStart", "MmNonPagedPoolEnd"),
        ("PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd"),
        ("SpecialPool", "MmSpecialPoolStart", "MmSpecialPoolEnd"),
    ] {
        let s_addr = debugger
            .symbols
            .find_symbol_across_modules(debugger.current_dtb(), start)?;
        let e_addr = debugger
            .symbols
            .find_symbol_across_modules(debugger.current_dtb(), stop)?;
        let mem = debugger.get_current_process().memory(&debugger.kvm);
        let s = VirtAddr(mem.read::<u64>(s_addr).ok()?);
        let e = VirtAddr(mem.read::<u64>(e_addr).ok()?);
        if addr >= s && addr < e {
            return Some((name, s, e));
        }
    }
    None
}

fn parse_big_pool_entry(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    entry: VirtAddr,
) -> Option<BigPoolEntry> {
    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let ti = layout.big_pool_type.as_ref()?;
    let (va_raw, size, tag, pattern, pool_flags, slush_size) = if layout.big_pool_uses_struct {
        let va_raw = read_pool_field(ti, &mem, entry, "Va")?;
        let size = read_pool_field(ti, &mem, entry, "NumberOfBytes")?;
        let tag = read_pool_field(ti, &mem, entry, "Key")? as u32;
        let pattern = read_pool_field(ti, &mem, entry, "Pattern")? as u8;
        let pool_flags = if layout.big_pool_has_pool_type {
            read_pool_field(ti, &mem, entry, "PoolType").unwrap_or(0) as u16 & 0xfff
        } else {
            0
        };
        let slush_size = if layout.big_pool_has_slush {
            read_pool_field(ti, &mem, entry, "SlushSize").unwrap_or(0) as u16 & 0xfff
        } else {
            0
        };
        (va_raw, size, tag, pattern, pool_flags, slush_size)
    } else {
        let va_raw: u64 = mem.read(entry + ti.try_get_field_offset("Va").ok()?).ok()?;
        let size: u64 = mem
            .read(entry + ti.try_get_field_offset("NumberOfBytes").ok()?)
            .ok()?;
        let tag: u32 = mem
            .read(entry + ti.try_get_field_offset("Key").ok()?)
            .ok()?;
        let flags_word: u32 = mem
            .read(entry + ti.try_get_field_offset("Pattern").ok()?)
            .ok()?;
        (
            va_raw,
            size,
            tag,
            (flags_word & 0xff) as u8,
            ((flags_word >> 8) & 0xfff) as u16,
            ((flags_word >> 20) & 0xfff) as u16,
        )
    };
    let va = VirtAddr(va_raw & !1);
    if va.is_zero() || size == 0 || !plausible_pool_tag(tag) {
        return None;
    }
    Some(BigPoolEntry {
        va,
        entry,
        index: 0,
        nonpaged: va_raw & 1 != 0,
        size,
        tag,
        pattern,
        pool_flags,
        slush_size,
    })
}

fn find_big_pool(
    debugger: &DebuggerContext,
    layout: &PoolLayout,
    target: VirtAddr,
) -> Option<BigPoolEntry> {
    let table_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "PoolBigPageTable")?;
    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let table_addr = VirtAddr(mem.read::<u64>(table_sym).ok()?);
    let count_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "PoolBigPageTableSize")?;
    let count: u64 = mem.read(count_sym).ok()?;
    if count == 0 || count > 0x100000 {
        return None;
    }
    let entry_size = layout.big_pool_entry_size?;
    for i in 0..count {
        let entry_addr = table_addr + i * entry_size;
        if let Some(mut entry) = parse_big_pool_entry(debugger, layout, entry_addr)
            .filter(|e| target >= e.va && target.0 < e.va.0 + e.size)
        {
            entry.index = i;
            return Some(entry);
        }
    }
    None
}

fn segment_heap_hint(debugger: &DebuggerContext) -> Option<&'static str> {
    debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "RtlpHpHeapGlobals")?;
    Some(
        "kernel has RtlpHpHeapGlobals (segment heap is enabled); address may be a _HEAP_VS_CHUNK_HEADER / LFH chunk instead of a _POOL_HEADER",
    )
}

fn annotate_near_symbol(debugger: &DebuggerContext, addr: VirtAddr) -> Option<String> {
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.current_dtb(), addr)?;
    (offset <= 0x1000).then(|| format!("{}!{}+0x{:x}", module, name, offset))
}

fn print_pool_page_listing(blocks: &[PoolHeader], target_idx: Option<usize>, target: VirtAddr) {
    if blocks.is_empty() {
        println!("  (no plausible pool block found for this address)");
        return;
    }
    println!(
        "  {:<3} {:<18} {:<8} {:<8} {:<12} {:<6} tag",
        "", "header", "size", "prev", "state", "type"
    );
    for (i, h) in blocks.iter().enumerate() {
        let marker = if Some(i) == target_idx { "->" } else { "  " };
        println!(
            "  {:<3} {:#018x} 0x{:<6x} 0x{:<6x} {:<12} 0x{:<4x} '{}'",
            marker,
            h.header,
            h.size,
            h.previous_size,
            pool_block_state(h),
            h.pool_type,
            tag_string(h.tag)
        );
    }
    if let Some(idx) = target_idx {
        let h = &blocks[idx];
        let offset = target.0.saturating_sub(h.body.0);
        println!(
            "  target offset : 0x{:x} into body (block @ {:#x}, body @ {:#x})",
            offset, h.header, h.body
        );
    }
}

fn print_big_pool(target: VirtAddr, entry: &BigPoolEntry) {
    let offset = target.0 - entry.va.0;
    let end_addr = entry.va + entry.size;
    println!("big pool @ {:#x}", entry.va);
    println!("  target        : {:#x}", target);
    println!(
        "  range         : {:#x} - {:#x} ({} bytes)",
        entry.va, end_addr, entry.size
    );
    println!("  offset        : 0x{:x} / 0x{:x}", offset, entry.size);
    println!(
        "  tag           : '{}' (0x{:08x})",
        tag_string(entry.tag),
        entry.tag
    );
    println!("  table entry   : {:#x}[{}]", entry.entry, entry.index);
    println!(
        "  nonpaged      : {}",
        if entry.nonpaged { "yes" } else { "no" }
    );
    println!("  pattern       : 0x{:x}", entry.pattern);
    println!("  pool flags    : 0x{:x}", entry.pool_flags);
    println!("  slush size    : 0x{:x}", entry.slush_size);
}

struct TrackingHighlighter {
    had_content: Arc<AtomicBool>,
}

impl Highlighter for TrackingHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        self.had_content.store(!line.is_empty(), Ordering::Relaxed);

        let mut styled = StyledText::new();
        styled.push((Style::new(), line.to_string()));
        styled
    }
}

pub fn start_repl(debugger: &mut DebuggerContext, client: &mut dyn DebugBackend) -> Result<()> {
    ctrlc::set_handler(move || {
        INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
    })?;

    let message_data = debugger.get_startup_message_data()?;

    let splash_text = format!(
        "{} {}\n{} Kernel version = {}\n{} Kernel base = {:#x}\n{} PsLoadedModuleList = {:#x}\n",
        "    ⢀⣴⠶⣶⡄⠀⠀⠀⠀".bright_blue(),
        format!(
            "Windows kernel debugger for Linux ({} {})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
        .bright_magenta()
        .bold(),
        "⢀⣴⣧⠀⠸⣿⣀⣸⡇⠀⢨⡦⣄".bright_blue(),
        message_data.build_number,
        "⠘⣿⣿⣄⠀⠈⠛⠉⠀⣠⣾⡿⠋".bright_blue(),
        message_data.base_address,
        "⠀⠀⠈⠛⠿⠶⣶⡶⠿⠟⠉⠀⠀".bright_blue(),
        message_data.loaded_module_list
    );

    println!("{}", splash_text);

    let register_map = client.register_map().clone();

    let mut current_thread = client
        .get_stopped_thread_id()
        .unwrap_or_else(|_| "1".to_string());

    let mut breakpoints = BreakpointManager::new();

    print_break_context(&mut *client, &register_map, debugger, &current_thread);

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

    let edit_mode = Box::new(Emacs::new(keybindings));

    let shared_symbols = Arc::new(RwLock::new(debugger.current_symbol_index()));
    let shared_types = Arc::new(RwLock::new(debugger.current_types_index()));
    let shared_symbol_store = Arc::clone(&debugger.symbols);
    let shared_dtb = Arc::new(RwLock::new(debugger.current_dtb()));

    let initial_processes = debugger
        .guest
        .enumerate_processes(&debugger.kvm, &debugger.symbols)
        .map(|procs| procs.into_iter().map(|p| (p.name, p.pid)).collect())
        .unwrap_or_default();
    let shared_processes: Arc<RwLock<ProcessCache>> = Arc::new(RwLock::new(initial_processes));

    let initial_threads = client.get_thread_list().unwrap_or_default();
    let shared_threads: Arc<RwLock<ThreadCache>> = Arc::new(RwLock::new(initial_threads));

    let shared_breakpoints: Arc<RwLock<BreakpointCache>> = Arc::new(RwLock::new(Vec::new()));
    let initial_drivers = debugger.enumerate_driver_objects().unwrap_or_default();
    let shared_drivers: Arc<RwLock<DriverObjectCache>> = Arc::new(RwLock::new(initial_drivers));

    let mut script_host = ScriptHost::new();
    let builtin_names: HashSet<String> = ReplCommand::iter().map(|c| c.to_string()).collect();
    let load_report = script_host.load_all(&builtin_names, Some(debugger));
    print_script_load_report(&load_report, true);
    let shared_user_cmds: Arc<RwLock<UserCommandCache>> =
        Arc::new(RwLock::new(script_host.command_names()));

    let completor = Box::new(MyCompleter {
        symbols: Arc::clone(&shared_symbols),
        types: Arc::clone(&shared_types),
        symbol_store: Arc::clone(&shared_symbol_store),
        dtb: Arc::clone(&shared_dtb),
        processes: Arc::clone(&shared_processes),
        threads: Arc::clone(&shared_threads),
        breakpoints: Arc::clone(&shared_breakpoints),
        drivers: Arc::clone(&shared_drivers),
        user_commands: Arc::clone(&shared_user_cmds),
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

    loop {
        let sig = line_editor.read_line(&prompt)?;
        match sig {
            Signal::Success(buffer) => {
                let parts: Vec<&str> = buffer.split_whitespace().collect();
                if let Some(cmd_str) = parts.first() {
                    match ReplCommand::from_str(cmd_str) {
                        Ok(ReplCommand::Quit) => {
                            break;
                        }
                        Ok(ReplCommand::Pte) => {
                            let address =
                                match Expr::eval(parts.get(1).copied().unwrap_or(""), debugger) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!("{}", e);
                                        continue;
                                    }
                                };
                            match debugger.pte_traverse(address) {
                                Ok(result) => {
                                    let mut levels = vec![result.pxe, result.ppe];

                                    if let Some(x) = result.pde {
                                        levels.push(x);
                                    }

                                    if let Some(x) = result.pte {
                                        levels.push(x);
                                    }

                                    let header = format!("VA {:016x}", result.address);
                                    let mut builder = Builder::default();

                                    let row_strings: Vec<String> =
                                        levels.iter().map(|l| l.to_string()).collect();
                                    builder.push_record(row_strings);

                                    let mut table = builder.build();
                                    table
                                        .with(Panel::header(header))
                                        .with(Modify::new(Rows::first()).with(Alignment::center()))
                                        .with(tabled::settings::Style::empty());

                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("{}\n", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Idt) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let max_entries = match parts.get(1) {
                                Some(count) => match count.parse::<usize>() {
                                    Ok(count) => Some(count),
                                    Err(_) => {
                                        error!("invalid IDT entry count: {}", count);
                                        continue;
                                    }
                                },
                                None => None,
                            };

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            let monitor_output = match client.monitor_command("info registers") {
                                Ok(output) => output,
                                Err(Error::NotSupported) => {
                                    error!(
                                        "backend does not expose QEMU monitor commands over gdbstub"
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    error!("failed to read QEMU registers: {}", e);
                                    continue;
                                }
                            };

                            let Some(idtr) = parse_idtr_from_qemu_registers(&monitor_output) else {
                                error!("QEMU monitor output did not contain an IDT descriptor");
                                continue;
                            };

                            if let Err(e) =
                                dump_idt(debugger, &register_map, &regs, idtr, max_entries)
                            {
                                error!("failed to dump IDT: {}", e);
                            }
                        }
                        Ok(ReplCommand::Gdt) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let max_entries = match parts.get(1) {
                                Some(count) => match count.parse::<usize>() {
                                    Ok(count) => Some(count),
                                    Err(_) => {
                                        error!("invalid GDT entry count: {}", count);
                                        continue;
                                    }
                                },
                                None => None,
                            };

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            let monitor_output = match client.monitor_command("info registers") {
                                Ok(output) => output,
                                Err(Error::NotSupported) => {
                                    error!(
                                        "backend does not expose QEMU monitor commands over gdbstub"
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    error!("failed to read QEMU registers: {}", e);
                                    continue;
                                }
                            };

                            let Some(gdtr) = parse_gdtr_from_qemu_registers(&monitor_output) else {
                                error!("QEMU monitor output did not contain a GDT descriptor");
                                continue;
                            };

                            if let Err(e) =
                                dump_gdt(debugger, &register_map, &regs, gdtr, max_entries)
                            {
                                error!("failed to dump GDT: {}", e);
                            }
                        }
                        Ok(ReplCommand::Tss) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let selector_arg = match parts.get(1) {
                                Some(selector) => match parse_selector_arg(selector) {
                                    Some(selector) => Some(selector),
                                    None => {
                                        error!("invalid TSS selector: {}", selector);
                                        continue;
                                    }
                                },
                                None => None,
                            };

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            let monitor_output = match client.monitor_command("info registers") {
                                Ok(output) => output,
                                Err(Error::NotSupported) => {
                                    error!(
                                        "backend does not expose QEMU monitor commands over gdbstub"
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    error!("failed to read QEMU registers: {}", e);
                                    continue;
                                }
                            };

                            let Some(gdtr) = parse_gdtr_from_qemu_registers(&monitor_output) else {
                                error!("QEMU monitor output did not contain a GDT descriptor");
                                continue;
                            };

                            let selector = match selector_arg {
                                Some(selector) => selector,
                                None => {
                                    match parse_tr_selector_from_qemu_registers(&monitor_output) {
                                        Some(selector) => selector,
                                        None => {
                                            error!(
                                                "QEMU monitor output did not contain a TR selector"
                                            );
                                            continue;
                                        }
                                    }
                                }
                            };

                            if let Err(e) =
                                dump_tss_stack_bases(debugger, &register_map, &regs, gdtr, selector)
                            {
                                error!("failed to dump TSS stack bases: {}", e);
                            }
                        }
                        Ok(ReplCommand::Qcmd) => {
                            if parts.len() < 2 {
                                println!(
                                    "{}\n",
                                    ReplCommand::Qcmd.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let command = parts[1..].join(" ");
                            match client.monitor_command(&command) {
                                Ok(output) => print_qemu_monitor_output(&output),
                                Err(Error::NotSupported) => {
                                    error!(
                                        "backend does not expose QEMU monitor commands over gdbstub"
                                    );
                                }
                                Err(e) => error!("QEMU monitor command failed: {}", e),
                            }
                        }
                        Ok(ReplCommand::Qlog) => {
                            let items = parts
                                .get(1)
                                .copied()
                                .unwrap_or("int,cpu_reset,guest_errors");
                            let logfile = parts.get(2).copied();

                            if let Some(path) = logfile {
                                match client.monitor_command(&format!("logfile {}", path)) {
                                    Ok(output) => print_qemu_monitor_output(&output),
                                    Err(Error::NotSupported) => {
                                        error!(
                                            "backend does not expose QEMU monitor commands over gdbstub"
                                        );
                                        continue;
                                    }
                                    Err(e) => {
                                        error!("failed to set QEMU logfile: {}", e);
                                        continue;
                                    }
                                }
                            }

                            match client.monitor_command(&format!("log {}", items)) {
                                Ok(output) => {
                                    print_qemu_monitor_output(&output);
                                    println!(
                                        "{} {}\n",
                                        "enabled QEMU log masks:".bright_black(),
                                        items.green()
                                    );
                                }
                                Err(Error::NotSupported) => {
                                    error!(
                                        "backend does not expose QEMU monitor commands over gdbstub"
                                    );
                                }
                                Err(e) => error!("failed to enable QEMU logging: {}", e),
                            }
                        }
                        Ok(ReplCommand::Pool) => {
                            let Some(expr) = parts.get(1).copied() else {
                                println!(
                                    "{}\n",
                                    ReplCommand::Pool.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            };

                            let target = match Expr::eval(expr, debugger) {
                                Ok(target) => target,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let layout = match pool_layout(debugger) {
                                Ok(l) => l,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            if target.0 & (POOL_PAGE_SIZE - 1) == 0
                                && let Some(big) = find_big_pool(debugger, &layout, target)
                            {
                                print_big_pool(target, &big);
                                continue;
                            }

                            let region = classify_pool_region(debugger, target);
                            let (blocks, idx, base) =
                                locate_pool_block_in_page(debugger, &layout, target);
                            println!("pool page {:#x}", base);
                            println!("  target        : {:#x}", target);
                            if let Some((name, start, end)) = region {
                                println!("  region        : {} [{:#x} - {:#x}]", name, start, end);
                            }
                            if let Some(idx) = idx {
                                println!(
                                    "  blocks in run : {} (target is #{})",
                                    blocks.len(),
                                    idx + 1
                                );
                            }
                            println!();
                            print_pool_page_listing(&blocks, idx, target);

                            if idx.is_none() {
                                if let Some(big) = find_big_pool(debugger, &layout, target) {
                                    println!();
                                    print_big_pool(target, &big);
                                    continue;
                                }
                                println!(
                                    "  address does not lie inside a recognizable _POOL_HEADER block."
                                );
                                println!(
                                    "  it may be segment heap, special pool, a mapped view, or image/stack."
                                );
                                if let Some(hint) = segment_heap_hint(debugger) {
                                    println!("  hint          : {}", hint);
                                }
                                if let Some(near) = annotate_near_symbol(debugger, target) {
                                    println!("  near symbol   : {}", near);
                                }
                            }
                        }
                        Ok(ReplCommand::Db) => {
                            let range = match AddressRange::parse(&parts, debugger, 128, 1) {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mut data: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(range.start, &mut data)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            display_memory(range.start, &data, &MemoryDisplayMode::bytes());
                        }
                        Ok(ReplCommand::Dd) => {
                            let range = match AddressRange::parse(&parts, debugger, 16, 4) {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mut data: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(range.start, &mut data)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            display_memory(range.start, &data, &MemoryDisplayMode::dwords());
                        }
                        Ok(ReplCommand::Dq) => {
                            let range = match AddressRange::parse(&parts, debugger, 8, 8) {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mut data: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(range.start, &mut data)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            display_memory(range.start, &data, &MemoryDisplayMode::qwords());
                        }
                        Ok(ReplCommand::Disasm) => {
                            let range = match AddressRange::parse(&parts, debugger, 32, 1) {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let start_addr = range.start;
                            let mut bytes: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(start_addr, &mut bytes)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            let mut decoder = Decoder::with_ip(
                                64, /* TODO dont hardcode for WOW64 process? */
                                &bytes,
                                start_addr.0,
                                DecoderOptions::NONE,
                            );

                            // TODO support other formats?
                            let mut formatter = NasmFormatter::new();
                            let options = formatter.options_mut();
                            options.set_space_after_operand_separator(true);
                            options.set_hex_prefix("0x");
                            options.set_hex_suffix("");
                            options.set_first_operand_char_index(5);
                            options.set_memory_size_options(MemorySizeOptions::Always);
                            options.set_show_branch_size(false);
                            options.set_rip_relative_addresses(true);

                            let mut output = String::new();
                            let mut instruction = Instruction::default();

                            while decoder.can_decode() {
                                decoder.decode_out(&mut instruction);
                                if instruction.code() == Code::INVALID {
                                    continue;
                                }

                                output.clear();
                                formatter.format(&instruction, &mut output);

                                print!("{:016x} ", VirtAddr(instruction.ip()));
                                let start_index = (instruction.ip() - start_addr.0) as usize;
                                let instr_bytes =
                                    &bytes[start_index..start_index + instruction.len()];
                                for b in instr_bytes.iter() {
                                    print!("{:02x}", Value(b));
                                }
                                if instr_bytes.len() < 12 {
                                    for _ in 0..12 - instr_bytes.len() {
                                        print!("  ");
                                    }
                                }
                                print!(" {}", output);

                                if instruction.is_ip_rel_memory_operand() {
                                    let target_address = instruction.ip_rel_memory_address();
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(target_address))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))
                                        .unwrap_or_else(|_| format!("{:#X}", target_address));
                                    print!("{}", format!(" ; {}", sym).bright_black());
                                } else if instruction.is_call_near()
                                    || instruction.is_jmp_near()
                                    || instruction.is_jcc_near()
                                {
                                    let target_address = instruction.near_branch_target();
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(target_address))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))
                                        .unwrap_or_else(|_| format!("{:#X}", target_address));
                                    print!("{}", format!(" ; {}", sym).bright_black());
                                }

                                println!();
                            }
                            println!();
                        }
                        Ok(ReplCommand::Eb) => {
                            if parts.len() < 3 {
                                println!(
                                    "{}\n",
                                    ReplCommand::Eb.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let address = match Expr::eval(parts[1], debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let expr_str = parts[2..].join(" ");
                            let value: u8 = match Expr::eval(&expr_str, debugger) {
                                Ok(v) => v.0 as u8,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mem = debugger.get_current_process().memory(&debugger.kvm);
                            if let Err(e) = mem.write_bytes(address, &[value]) {
                                error!("failed to write byte: {}", e);
                            } else {
                                println!("{} {:02x} -> {:#x}\n", "wrote".green(), value, address);
                            }
                        }
                        Ok(ReplCommand::Ed) => {
                            if parts.len() < 3 {
                                println!(
                                    "{}\n",
                                    ReplCommand::Ed.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let address = match Expr::eval(parts[1], debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let expr_str = parts[2..].join(" ");
                            let value: u32 = match Expr::eval(&expr_str, debugger) {
                                Ok(v) => v.0 as u32,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mem = debugger.get_current_process().memory(&debugger.kvm);
                            if let Err(e) = mem.write_bytes(address, &value.to_le_bytes()) {
                                error!("failed to write dword: {}", e);
                            } else {
                                println!("{} {:#x} -> {:#x}\n", "wrote".green(), value, address);
                            }
                        }
                        Ok(ReplCommand::Eq) => {
                            if parts.len() < 3 {
                                println!(
                                    "{}\n",
                                    ReplCommand::Eq.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let address = match Expr::eval(parts[1], debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let expr_str = parts[2..].join(" ");
                            let value: u64 = match Expr::eval(&expr_str, debugger) {
                                Ok(v) => v.0,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let mem = debugger.get_current_process().memory(&debugger.kvm);
                            if let Err(e) = mem.write_bytes(address, &value.to_le_bytes()) {
                                error!("failed to write qword: {}", e);
                            } else {
                                println!("{} {:#x} -> {:#x}\n", "wrote".green(), value, address);
                            }
                        }
                        Ok(ReplCommand::F) => {
                            if parts.len() < 3 {
                                println!(
                                    "{}\n",
                                    ReplCommand::F.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let address = match Expr::eval(parts[1], debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let pattern_str = parts[2];
                            let pattern = match parse_byte_pattern(pattern_str) {
                                Some(pattern) => pattern,
                                None => {
                                    error!("invalid pattern: {}", pattern_str);
                                    continue;
                                }
                            };

                            let length = match parts.get(3) {
                                Some(length_arg) => match Expr::eval(length_arg, debugger) {
                                    Ok(value) => match resolve_length_or_end(address, value) {
                                        Some(length) => length,
                                        None => {
                                            error!("invalid length or end: {}", length_arg);
                                            continue;
                                        }
                                    },
                                    Err(e) => {
                                        error!("{}", e);
                                        continue;
                                    }
                                },
                                None => pattern.len(),
                            };

                            let data = repeat_pattern(&pattern, length);
                            let mem = debugger.get_current_process().memory(&debugger.kvm);

                            if let Err(e) = mem.write_bytes(address, &data) {
                                error!("failed to fill memory: {}", e);
                            } else {
                                println!(
                                    "{} {:#x} bytes at {:#x} with {}\n",
                                    "filled".green(),
                                    length,
                                    address,
                                    format!("[{}]", pattern_str).green()
                                );
                            }
                        }
                        Ok(ReplCommand::S) => {
                            if parts.len() < 3 {
                                println!(
                                    "{}\n",
                                    ReplCommand::S.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let pattern_str = parts[2];

                            let start_addr = match Expr::eval(parts[1], debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let pattern = match parse_byte_pattern(pattern_str) {
                                Some(pattern) => pattern,
                                None => {
                                    error!("invalid pattern: {}", pattern_str);
                                    continue;
                                }
                            };

                            let length = match parts.get(3) {
                                Some(length_arg) => match Expr::eval(length_arg, debugger) {
                                    Ok(value) => match usize::try_from(value.0) {
                                        Ok(length) => length,
                                        Err(_) => {
                                            error!("invalid length: {}", length_arg);
                                            continue;
                                        }
                                    },
                                    Err(e) => {
                                        error!("{}", e);
                                        continue;
                                    }
                                },
                                None => 0x100,
                            };

                            let mut data = vec![0u8; length];
                            let mem = debugger.get_current_process().memory(&debugger.kvm);

                            if let Err(e) = mem.read_bytes(start_addr, &mut data) {
                                error!("failed to read memory: {}", e);
                                continue;
                            }

                            let mut found = 0;
                            if pattern.len() <= data.len() {
                                for i in 0..=data.len() - pattern.len() {
                                    if &data[i..i + pattern.len()] == pattern.as_slice() {
                                        let addr = start_addr + i as u64;
                                        let sym = debugger
                                            .guest
                                            .ntoskrnl
                                            .closest_symbol(&debugger.symbols, addr)
                                            .map(|(s, o)| {
                                                if o == 0 {
                                                    format!("{}+{:#x}", s, o)
                                                } else {
                                                    s.to_string()
                                                }
                                            })
                                            .unwrap_or_default();

                                        println!(
                                            "{:#16x}  {} {}",
                                            addr,
                                            sym.bright_black(),
                                            format!("[{}]", pattern_str).green()
                                        );
                                        found += 1;
                                    }
                                }
                            }

                            if found == 0 {
                                println!(
                                    "{} (searched {:#x} bytes at {:#x})",
                                    "no matches found".bright_black(),
                                    length,
                                    start_addr
                                );
                            } else {
                                println!(
                                    "\n{} {}",
                                    found,
                                    if found == 1 { "match" } else { "matches" }
                                );
                            }
                            println!();
                        }
                        Ok(ReplCommand::Ev) => {
                            if parts.is_empty() {
                                println!(
                                    "{}\n",
                                    ReplCommand::Ev.get_message().unwrap_or("invalid usage")
                                );
                                continue;
                            }

                            let expr_str = if parts.len() > 2 {
                                parts[1..].join(" ")
                            } else {
                                parts[1].to_string()
                            };

                            match Expr::eval(&expr_str, debugger) {
                                Ok(addr) => println!("{:#16x}", addr),
                                Err(e) => error!("{}", e),
                            }
                        }
                        Ok(ReplCommand::Lt) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let pb = ProgressBar::new_spinner();
                            pb.set_style(
                                ProgressStyle::default_spinner()
                                    .template("{spinner:.black.bright} {msg}")
                                    .unwrap(),
                            );

                            pb.set_message(format!(
                                "{}",
                                owo_colors::OwoColorize::bright_black(&"Waiting on GDB...")
                            ));
                            pb.enable_steady_tick(Duration::from_millis(100));

                            let original_thread = client.get_stopped_thread_id()?;
                            let threads = client.get_thread_list()?;

                            let processes = debugger
                                .guest
                                .enumerate_processes(&debugger.kvm, &debugger.symbols)
                                .unwrap_or_default();
                            let kernel_dtb = debugger.guest.ntoskrnl.dtb();

                            let mut thread_data: Vec<(String, String, String, String)> = Vec::new();

                            for thread in &threads {
                                client.set_current_thread(thread)?;

                                let regs = client.read_registers()?;
                                let rip = register_map.read_u64("rip", &regs)?;
                                let cr3 = register_map.read_u64("cr3", &regs)?;

                                let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
                                let kernel_dtb_masked = kernel_dtb & 0x000F_FFFF_FFFF_F000;

                                let (context, symbol) = if cr3_masked == kernel_dtb_masked {
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(rip))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))?;
                                    ("kernel".to_string(), sym)
                                } else {
                                    match processes
                                        .iter()
                                        .find(|p| (p.dtb & 0x000F_FFFF_FFFF_F000) == cr3_masked)
                                    {
                                        Some(proc) => {
                                            let sym = debugger
                                                .symbols
                                                .find_closest_symbol_for_address(
                                                    proc.dtb,
                                                    VirtAddr(rip),
                                                )
                                                .map(|(module, sym, offset)| {
                                                    if offset == 0 {
                                                        format!("{}!{}", module, sym)
                                                    } else {
                                                        format!("{}!{}+{:#x}", module, sym, offset)
                                                    }
                                                })
                                                .unwrap_or_else(|| format!("{:#x}", rip));
                                            (proc.name.clone(), sym)
                                        }
                                        None => ("unknown".to_string(), format!("{:#x}", rip)),
                                    }
                                };

                                thread_data.push((
                                    thread.clone(),
                                    format!("{:#018x}", VirtAddr(rip)),
                                    context,
                                    symbol,
                                ));
                            }

                            client.set_current_thread(&original_thread)?;

                            let mut builder = Builder::default();
                            builder.push_record(vec!["Thread", "RIP", "Context", "Symbol"]);
                            for (tid, rip, ctx, sym) in thread_data {
                                builder.push_record(vec![
                                    format!("{}  ", tid),
                                    format!("{}  ", rip),
                                    format!("{}  ", ctx),
                                    sym,
                                ]);
                            }

                            pb.finish_and_clear();

                            let mut table = builder.build();
                            table
                                .with(tabled::settings::Style::empty())
                                .with(Padding::zero());
                            println!("{}\n", table);
                        }
                        Ok(ReplCommand::Continue) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            // If we're sitting on one of our breakpoints, step past it
                            // before resuming; otherwise the int3 at RIP fires the BP
                            // again on the very next cycle
                            if breakpoints.has_enabled_breakpoints() {
                                if let Err(e) = client.set_current_thread(&current_thread) {
                                    error!("failed to set thread context: {:?}", e);
                                    continue;
                                }
                                if let Err(e) = step_over_current_breakpoint(
                                    &mut *client,
                                    &register_map,
                                    debugger,
                                    &mut breakpoints,
                                ) {
                                    error!("failed to step over current breakpoint: {:?}", e);
                                    continue;
                                }
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut *client, debugger) {
                                error!("failed to refresh breakpoints: {}", e);
                                continue;
                            }

                            if let Err(e) = client.continue_execution() {
                                error!("failed to continue: {:?}", e);
                                continue;
                            }

                            debugger.registers = None;

                            if breakpoints.has_enabled_breakpoints() {
                                println!(
                                    "{}",
                                    "VM running, waiting for breakpoint (Ctrl+C to pause)..."
                                        .bright_black()
                                );

                                INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);

                                loop {
                                    // if user pressed Ctrl+C
                                    if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                                        if let Err(e) = client.interrupt() {
                                            error!("failed to interrupt VM: {:?}", e);
                                            break;
                                        }

                                        if let Ok(tid) = client.get_stopped_thread_id() {
                                            current_thread = tid;
                                        }
                                        if let Err(e) =
                                            refresh_process_cache(debugger, &shared_processes)
                                        {
                                            error!("failed to refresh process cache: {}", e);
                                        }
                                        println!();
                                        print_break_context(
                                            &mut *client,
                                            &register_map,
                                            debugger,
                                            &current_thread,
                                        );
                                        break;
                                    }

                                    match client.try_wait_for_stop(Duration::from_millis(100)) {
                                        Ok(Some(event)) => {
                                            if let Some(summary) = &event.summary {
                                                println!(
                                                    "{} {}",
                                                    "target stop:".yellow(),
                                                    summary.bright_black()
                                                );
                                            }
                                            if event.target_exited {
                                                println!(
                                                    "{}",
                                                    "target is no longer stopped at guest CPU state; use QEMU logs/QMP for reset cause details"
                                                        .yellow()
                                                );
                                                break;
                                            }

                                            let stopped_tid = event
                                                .thread_id
                                                .or_else(|| client.get_stopped_thread_id().ok());
                                            if let Some(tid) = stopped_tid {
                                                current_thread = tid;
                                                let _ = client.set_current_thread(&current_thread);
                                            }
                                            if let Err(e) =
                                                refresh_process_cache(debugger, &shared_processes)
                                            {
                                                error!("failed to refresh process cache: {}", e);
                                            }

                                            // Done before reading the current thread's regs so
                                            // the BP-hit check below sees the post-rewind RIP
                                            rewind_threads_off_breakpoints(
                                                &mut *client,
                                                &register_map,
                                                &breakpoints,
                                                &current_thread,
                                            );

                                            let regs = match client.read_registers() {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    error!("failed to read registers: {:?}", e);
                                                    break;
                                                }
                                            };

                                            let rip =
                                                register_map.read_u64("rip", &regs).unwrap_or(0);
                                            let cr3 =
                                                register_map.read_u64("cr3", &regs).unwrap_or(0);

                                            let hit_result =
                                                breakpoints.check_breakpoint_hit(rip, cr3);

                                            // Wrong-process hit on a `GuestMemoryPatch` BP
                                            // (shared page, e.g. ntdll/user32): step past
                                            // the int3 silently so the wrong process keeps
                                            // running, then resume waiting for the right one.
                                            if matches!(
                                                hit_result,
                                                BreakpointHitResult::NotBreakpoint
                                            ) && breakpoints
                                                .breakpoint_id_at_address(rip)
                                                .is_some()
                                            {
                                                if let Err(e) = step_over_current_breakpoint(
                                                    &mut *client,
                                                    &register_map,
                                                    debugger,
                                                    &mut breakpoints,
                                                ) {
                                                    error!(
                                                        "failed to silent-step over wrong-process int3: {:?}",
                                                        e
                                                    );
                                                    break;
                                                }
                                                if let Err(e) = client.continue_execution() {
                                                    error!(
                                                        "failed to resume after silent step over wrong-process int3: {:?}",
                                                        e
                                                    );
                                                    break;
                                                }
                                                continue;
                                            }

                                            match hit_result {
                                                BreakpointHitResult::Hit(bp) => {
                                                    println!();
                                                    println!(
                                                        "{} {} {}",
                                                        "breakpoint".magenta(),
                                                        format!("#{}", bp.id).cyan(),
                                                        bp.symbol
                                                            .as_ref()
                                                            .map(|s| format!("({})", s))
                                                            .unwrap_or_default()
                                                            .green()
                                                    );
                                                    print_break_context(
                                                        &mut *client,
                                                        &register_map,
                                                        debugger,
                                                        &current_thread,
                                                    );

                                                    // refresh all breakpoints, the stub may have
                                                    // lost non-hit breakpoints when the VM stopped
                                                    let _ = breakpoints
                                                        .refresh_enabled(&mut *client, debugger);

                                                    break;
                                                }
                                                BreakpointHitResult::NotBreakpoint => {
                                                    println!();
                                                    print_break_context(
                                                        &mut *client,
                                                        &register_map,
                                                        debugger,
                                                        &current_thread,
                                                    );
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
                            }
                        }
                        Ok(ReplCommand::Break) => {
                            if !client.is_running() {
                                error!("VM is already paused");
                                continue;
                            }

                            if let Err(e) = client.interrupt() {
                                error!("failed to interrupt: {:?}", e);
                                continue;
                            }

                            if let Ok(tid) = client.get_stopped_thread_id() {
                                current_thread = tid;
                            }
                            if let Err(e) = refresh_process_cache(debugger, &shared_processes) {
                                error!("failed to refresh process cache: {}", e);
                            }
                            println!();
                            print_break_context(
                                &mut *client,
                                &register_map,
                                debugger,
                                &current_thread,
                            );
                        }
                        Ok(ReplCommand::Dt) => {
                            let arg = require_arg!(parts, 1, ReplCommand::Dt);

                            let address =
                                match Expr::eval(parts.get(2).copied().unwrap_or("0"), debugger) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!("{}", e);
                                        continue;
                                    }
                                };

                            let field_name = parts.get(3);

                            match debugger
                                .symbols
                                .find_type_across_modules(debugger.current_dtb(), arg)
                            {
                                Some(type_info) => {
                                    if let Err(e) = print_type_instance(
                                        debugger,
                                        &type_info,
                                        address,
                                        field_name.copied(),
                                    ) {
                                        error!("{}", e);
                                    }
                                }
                                None => {
                                    error!(
                                        "failed to get type information: type `{}` not found\n",
                                        arg
                                    );
                                }
                            }
                        }
                        Ok(ReplCommand::TrapFrame) => {
                            let address_arg = require_arg!(parts, 1, ReplCommand::TrapFrame);
                            let address = match Expr::eval(address_arg, debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            if let Err(e) =
                                dump_trap_frame(debugger, address, parts.get(2).copied())
                            {
                                error!("{}", e);
                            }
                        }
                        Ok(ReplCommand::Ps) => {
                            let filter = parts.get(1).map(|s| s.to_lowercase());

                            match debugger
                                .guest
                                .enumerate_processes(&debugger.kvm, &debugger.symbols)
                            {
                                Ok(processes) => {
                                    *shared_processes.write().unwrap() =
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
                                            format!("{:#018x}  ", proc.eprocess_va),
                                            format!("{:#018x}", VirtAddr(proc.dtb)), // TODO technically is phys addr..
                                        ]);
                                    }

                                    if count == 0 {
                                        println!("{}\n", "no matching processes".bright_black());
                                    } else {
                                        let mut table = builder.build();
                                        table
                                            .with(tabled::settings::Style::empty())
                                            .with(Padding::zero());
                                        println!("{}\n", table);
                                    }
                                }
                                Err(e) => {
                                    error!("failed to enumerate processes: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Drivers) => {
                            let filter = parts.get(1).map(|s| s.to_lowercase());

                            match debugger.enumerate_driver_objects() {
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
                                        let module = debugger
                                            .symbols
                                            .find_module_for_address(
                                                debugger.guest.ntoskrnl.dtb(),
                                                driver.driver_start,
                                            )
                                            .map(|module| module.name)
                                            .unwrap_or_else(|| "-".to_string());
                                        builder.push_record(vec![
                                            format!("{:#018x}  ", driver.object),
                                            format!("{}  ", driver.name),
                                            format!("{:#018x}  ", driver.driver_start),
                                            format!("0x{:x}  ", driver.driver_size),
                                            format!("{}  ", module),
                                            format!("{:#018x}  ", driver.device_object),
                                            format!("{:#018x}", driver.driver_unload),
                                        ]);
                                    }

                                    if count == 0 {
                                        println!("{}\n", "no matching drivers".bright_black());
                                    } else {
                                        let mut table = builder.build();
                                        table
                                            .with(tabled::settings::Style::empty())
                                            .with(Padding::zero());
                                        println!("{}\n", table);
                                    }
                                    *shared_drivers.write().unwrap() = drivers;
                                }
                                Err(e) => {
                                    error!("failed to list drivers: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Lm) => {
                            let filter = parts.get(1).map(|s| s.to_lowercase());

                            let (result, dtb) =
                                if let Some(process_info) = &debugger.current_process_info {
                                    (
                                        debugger.guest.get_process_modules(
                                            &debugger.kvm,
                                            &debugger.symbols,
                                            process_info,
                                        ),
                                        process_info.dtb,
                                    )
                                } else {
                                    (
                                        debugger
                                            .guest
                                            .get_kernel_modules(&debugger.kvm, &debugger.symbols),
                                        debugger.guest.ntoskrnl.dtb(),
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
                                            format!("{:#018x}  ", module.base_address),
                                            format!("{:#018x}  ", module.end_address()),
                                            format!("{}  ", module.short_name),
                                            format!(
                                                "{}  ",
                                                debugger
                                                    .symbols
                                                    .module_symbol_status(dtb, module.base_address)
                                                    .map(|status| status.label().to_string())
                                                    .unwrap_or_else(|| "unknown".to_string())
                                            ),
                                            format!(
                                                "{}  ",
                                                debugger
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
                                        let mut table = builder.build();
                                        table
                                            .with(tabled::settings::Style::empty())
                                            .with(Padding::zero());
                                        println!("{}\n", table);
                                    }
                                }
                                Err(e) => {
                                    error!("failed to list modules: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::LoadSymbols) => {
                            let dir_arg = require_arg!(parts, 1, ReplCommand::LoadSymbols);
                            let dir = Path::new(dir_arg);
                            if !dir.is_dir() {
                                error!("not a directory: {}", dir.display());
                                continue;
                            }

                            match load_symbols_from_directory(debugger, dir, parts.get(2).copied())
                            {
                                Ok(report) => {
                                    *shared_symbols.write().unwrap() =
                                        debugger.current_symbol_index();
                                    *shared_types.write().unwrap() = debugger.current_types_index();
                                    print_module_symbol_report(&report);
                                    println!();
                                }
                                Err(e) => {
                                    error!("failed to load local symbols: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Attach) => {
                            let pid_str = require_arg!(parts, 1, ReplCommand::Attach);
                            match pid_str.parse::<u64>() {
                                Ok(pid) => match debugger.attach(pid) {
                                    Ok(AttachReport {
                                        name,
                                        symbol_report,
                                    }) => {
                                        *shared_symbols.write().unwrap() =
                                            debugger.current_symbol_index();
                                        *shared_types.write().unwrap() =
                                            debugger.current_types_index();
                                        *shared_dtb.write().unwrap() = debugger.current_dtb();
                                        if let Err(e) =
                                            refresh_process_cache(debugger, &shared_processes)
                                        {
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
                        }
                        Ok(ReplCommand::Reload) => {
                            script_host.reset();
                            let report = script_host.load_all(&builtin_names, Some(debugger));
                            print_script_load_report(&report, false);
                            *shared_user_cmds.write().unwrap() = script_host.command_names();
                        }
                        Ok(ReplCommand::Detach) => {
                            if debugger.current_process.is_none() {
                                error!("not attached to any process");
                            } else {
                                debugger.detach();
                                *shared_symbols.write().unwrap() = debugger.current_symbol_index();
                                *shared_types.write().unwrap() = debugger.current_types_index();
                                *shared_dtb.write().unwrap() = debugger.current_dtb();
                                if let Err(e) = refresh_process_cache(debugger, &shared_processes) {
                                    error!("failed to refresh process cache: {}", e);
                                }
                                println!("detached, now in kernel context\n");
                            }
                        }
                        Ok(ReplCommand::Registers) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            debugger.registers = Some(register_map.to_hashmap(&regs));
                            print_registers(&register_map, &regs);
                            println!();
                            print_control_registers(&register_map, &regs);
                            println!();

                            let read_reg = |name: &str| -> String {
                                register_map
                                    .read_u64(name, &regs)
                                    .map(|v| format!("{:#018x}", VirtAddr(v)))
                                    .unwrap_or_else(|_| "N/A".to_string())
                            };

                            println!(
                                "cs={}  ds={}  es={}",
                                read_reg("cs"),
                                read_reg("ds"),
                                read_reg("es")
                            );
                            println!(
                                "fs={}  gs={}  ss={}",
                                read_reg("fs"),
                                read_reg("gs"),
                                read_reg("ss")
                            );
                            println!();
                        }
                        Ok(ReplCommand::Cregs) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            debugger.registers = Some(register_map.to_hashmap(&regs));
                            print_control_registers(&register_map, &regs);
                            println!();
                        }
                        Ok(ReplCommand::Si) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let stepped = match step_over_current_breakpoint(
                                &mut *client,
                                &register_map,
                                debugger,
                                &mut breakpoints,
                            ) {
                                Ok(stepped) => stepped,
                                Err(e) => {
                                    error!("failed to step over breakpoint: {:?}", e);
                                    continue;
                                }
                            };

                            if !stepped
                                && let Err(e) = step_one_and_clear_tf(&mut *client, &register_map)
                            {
                                error!("failed to step: {:?}", e);
                                continue;
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut *client, debugger) {
                                error!("failed to refresh breakpoints after step: {}", e);
                            }

                            if let Ok(tid) = client.get_stopped_thread_id() {
                                current_thread = tid;
                            }

                            println!();
                            print_break_context(
                                &mut *client,
                                &register_map,
                                debugger,
                                &current_thread,
                            );
                        }
                        Ok(ReplCommand::Thread) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let thread_id = require_arg!(parts, 1, ReplCommand::Thread);

                            let threads = match client.get_thread_list() {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("failed to get thread list: {:?}", e);
                                    continue;
                                }
                            };

                            if !threads.iter().any(|t| t == thread_id) {
                                error!(
                                    "thread '{}' not found (use 'lt' to list threads)",
                                    thread_id
                                );
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(thread_id) {
                                error!("failed to switch thread: {:?}", e);
                                continue;
                            }

                            current_thread = thread_id.to_string();
                            println!("switched to thread {}\n", current_thread);
                        }
                        Ok(cmd @ (ReplCommand::Bp | ReplCommand::Hbp)) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            // Software process-scope BP support is per-backend;
                            // hardware BPs can still be CR3-filtered by the manager.

                            let addr_str = require_arg!(parts, 1, cmd);
                            let address = match Expr::eval(addr_str, debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let symbol = debugger
                                .symbols
                                .find_closest_symbol_for_address(debugger.current_dtb(), address)
                                .map(|(module, sym, offset)| {
                                    if offset == 0 {
                                        format!("{}!{}", module, sym)
                                    } else {
                                        format!("{}!{}+{:#x}", module, sym, offset)
                                    }
                                });

                            let kind = match cmd {
                                ReplCommand::Bp => BreakpointKind::Software,
                                ReplCommand::Hbp => BreakpointKind::Hardware,
                                _ => unreachable!(),
                            };

                            let add_result = match kind {
                                BreakpointKind::Software => {
                                    breakpoints.add(&mut *client, debugger, address, symbol.clone())
                                }
                                BreakpointKind::Hardware => breakpoints.add_hardware(
                                    &mut *client,
                                    debugger,
                                    address,
                                    symbol.clone(),
                                ),
                            };

                            match add_result {
                                Ok(id) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!(
                                        "{} breakpoint {} set at {}{}{}\n",
                                        kind.label(),
                                        format!("#{}", id).cyan(),
                                        format!("{:#x}", address).yellow(),
                                        symbol
                                            .map(|s| format!(" ({})", s))
                                            .unwrap_or_default()
                                            .green(),
                                        format!(
                                            " ({})",
                                            breakpoints
                                                .list()
                                                .into_iter()
                                                .find(|bp| bp.id == id)
                                                .map(|bp| bp.scope.label())
                                                .unwrap_or_else(|| "global".to_string())
                                        )
                                        .bright_black()
                                    );
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Bl) => {
                            let bps = breakpoints.list();
                            if bps.is_empty() {
                                println!("no breakpoints set\n");
                            } else {
                                let mut builder = Builder::default();
                                builder.push_record(vec![
                                    "ID".to_string(),
                                    "Status".to_string(),
                                    "Type".to_string(),
                                    "Address".to_string(),
                                    "Symbol".to_string(),
                                    "Scope".to_string(),
                                ]);

                                for bp in bps {
                                    let status = if bp.enabled { "enabled" } else { "disabled" };
                                    let scope = bp.scope.label();

                                    builder.push_record(vec![
                                        format!("{}   ", bp.id),
                                        format!("{}  ", status),
                                        format!("{}  ", bp.kind.label()),
                                        format!("{:#018x}  ", bp.address),
                                        format!("{}  ", bp.symbol.as_deref().unwrap_or("-")),
                                        scope,
                                    ]);
                                }

                                let mut table = builder.build();
                                table
                                    .with(tabled::settings::Style::empty())
                                    .with(Padding::zero());
                                println!("{}\n", table);
                            }
                        }
                        Ok(ReplCommand::Bc) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Bc);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.remove(&mut *client, debugger, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} cleared\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Bd) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Bd);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.disable(&mut *client, debugger, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} disabled\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Be) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Be);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.enable(&mut *client, debugger, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} enabled\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        // TODO extend `k` with chained-unwind and machframe support; user symbols
                        // may still need lazy per-process loading on first stop.
                        Ok(ReplCommand::K) => {
                            if client.is_running() {
                                error!("VM is running");
                                continue;
                            }

                            let frame_limit: usize =
                                parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            print_stacktrace(
                                debugger,
                                &register_map,
                                &regs,
                                frame_limit,
                                frame_limit,
                            );
                            println!();
                        }
                        Ok(ReplCommand::Status) => {
                            if client.is_running() {
                                println!("VM is running\n");
                            } else {
                                if let Err(e) = client.set_current_thread(&current_thread) {
                                    error!("failed to set thread context: {:?}", e);
                                    continue;
                                }
                                print_break_context(
                                    &mut *client,
                                    &register_map,
                                    debugger,
                                    &current_thread,
                                );
                            }
                        }
                        Err(_) => {
                            if script_host.has(cmd_str) {
                                let args: Vec<&str> = parts.iter().skip(1).copied().collect();
                                if let Err(e) = script_host.dispatch(
                                    cmd_str,
                                    &args,
                                    debugger,
                                    &mut *client,
                                    &register_map,
                                ) {
                                    error!("{}: {}", cmd_str, e);
                                }
                            } else {
                                println!(
                                    "unknown command: '{}' (try pressing tab to see available commands)\n",
                                    cmd_str
                                );
                            }
                        }
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

                if client.is_running() {
                    if let Err(e) = client.interrupt() {
                        error!("failed to interrupt: {:?}", e);
                        continue;
                    }

                    if let Ok(thread_id) = client.get_stopped_thread_id() {
                        current_thread = thread_id;
                    }
                    if let Err(e) = refresh_process_cache(debugger, &shared_processes) {
                        error!("failed to refresh process cache: {}", e);
                    }
                    if let Ok(drivers) = debugger.enumerate_driver_objects() {
                        *shared_drivers.write().unwrap() = drivers;
                    }
                    println!();
                    print_break_context(&mut *client, &register_map, debugger, &current_thread);
                } else {
                    error!("VM is already paused");
                }
            }
        }
    }

    if client.is_running() {
        let _ = client.interrupt();
    }

    let bp_ids: Vec<u32> = breakpoints.list().iter().map(|bp| bp.id).collect();
    for id in bp_ids {
        if let Err(e) = breakpoints.remove(&mut *client, debugger, id) {
            error!("failed to uninstall breakpoint #{} on exit: {}", id, e);
        }
    }

    let _ = client.continue_execution();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{VirtAddr, parse_byte_pattern, repeat_pattern, resolve_length_or_end};

    #[test]
    fn parse_byte_pattern_accepts_contiguous_hex() {
        assert_eq!(
            parse_byte_pattern("4883792000740a"),
            Some(vec![0x48, 0x83, 0x79, 0x20, 0x00, 0x74, 0x0a])
        );
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
