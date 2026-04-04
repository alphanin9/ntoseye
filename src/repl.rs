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

use crate::backend::MemoryOps;
use crate::debugger::DebuggerContext;
use crate::expr::Expr;
use crate::error::{Error, Result};
use crate::gdb::{BreakpointHitResult, BreakpointManager, GdbClient, RegisterMap};
use crate::symbols::{ParsedType, SymbolIndex, SymbolStore};
use crate::types::{Dtb, Value, VirtAddr};

static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);

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

enum CompletionStrategy {
    None,
    Symbol,
    Type,
    Process,
    Thread,
    Breakpoint,
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
            append_whitespace: true,
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
    fn parse(parts: &[&str], debugger: &DebuggerContext, default_count: u64, item_size: u64) -> Result<Self> {
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

// TODO
//
// Memory Display:
//   da, du       - Display ASCII/Unicode strings
//   dps          - Display pointers with symbol resolution
// Memory Write:
//   ea, eu       - Write ASCII/Unicode string
//   f            - Fill memory with pattern
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
    #[strum(
        message = "Display memory as bytes.\n(usage: db <address> [length or end])"
    )]
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
    #[strum(
        message = "Display type definition.\n(usage: dt <type> [address] [field])"
    )]
    Dt,

    // memory write
    #[strum(message = "Write a byte to memory.\n(usage: eb <address> <expr>)")]
    Eb,
    #[strum(message = "Write a doubleword (4 bytes) to memory.\n(usage: ed <address> <expr>)")]
    Ed,
    #[strum(message = "Write a quadword (8 bytes) to memory.\n(usage: eq <address> <expr>)")]
    Eq,

    // memory search
    #[strum(message = "Search memory for a byte pattern.\n(usage: s <address> <hex bytes> [length])")]
    S,

    // expression
    #[strum(message = "Evaluate an expression.\n(usage: ev <expression>)")]
    Ev,

    // page table
    #[strum(message = "Display page table entries for an address.\n(usage: pte <address>)")]
    Pte,

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

    // threads / processes / modules
    #[strum(message = "List all threads and their RIP values.\n(usage: lt)")]
    Lt,
    #[strum(message = "Switch to a different thread/vCPU.\n(usage: thread <id>)")]
    Thread,
    #[strum(message = "List running processes.\n(usage: ps [filter])")]
    Ps,
    #[strum(message = "List loaded modules.\n(usage: lm [filter])")]
    Lm,
    #[strum(message = "Attach to a process by PID.\n(usage: attach <pid>)")]
    Attach,
    #[strum(message = "Detach from current process.\n(usage: detach)")]
    Detach,

    #[strum(message = "Exit the application.")]
    Quit,
}

impl ReplCommand {
    pub fn completion_type(&self) -> CompletionStrategy {
        match self {
            Self::Db | Self::Dd | Self::Dq | Self::Disasm
            | Self::Eb | Self::Ed | Self::Eq
            | Self::S | Self::Ev | Self::Pte | Self::Bp => CompletionStrategy::Symbol,
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

struct MyCompleter {
    symbols: Arc<RwLock<SymbolIndex>>,
    types: Arc<RwLock<SymbolIndex>>,
    symbol_store: Arc<SymbolStore>,
    dtb: Arc<RwLock<Dtb>>,
    processes: Arc<RwLock<ProcessCache>>,
    threads: Arc<RwLock<ThreadCache>>,
    breakpoints: Arc<RwLock<BreakpointCache>>,
}

impl Completer for MyCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let text_before_cursor = &line[..pos];
        let mut parts = text_before_cursor.split_whitespace();

        let command_str = parts.next().unwrap_or("");
        let is_command_context = !text_before_cursor.contains(' ');

        if is_command_context {
            return ReplCommand::iter()
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
                CompletionStrategy::None => return vec![],

                CompletionStrategy::Symbol => {
                    if ident_start > 0 {
                        let preceding = &raw_prefix[..ident_start];

                        // after +/-/[ numeric operand expected, no completion
                        if preceding.ends_with('+') || preceding.ends_with('-') || preceding.ends_with('[') {
                            return vec![];
                        }

                        // after -> complete field names from the resolved type
                        if preceding.ends_with("->") {
                            let expr_text = &preceding[..preceding.len() - 2];
                            if let Ok(expr) = Expr::parse(expr_text) {
                                let dtb = *self.dtb.read().unwrap();
                                let fields = expr.complete_fields(&self.symbol_store, dtb, prefix);
                                if !fields.is_empty() {
                                    return make_suggestions(fields, "Field", span_start, pos);
                                }
                            }
                            return vec![];
                        }

                        // inside parentheses: likely a cast, try type completion first
                        if preceding.ends_with('(') {
                            let types = self.types.read().unwrap();
                            let mut results = types.search(prefix, 512);
                            // also try with underscore prefix (_EPROCESS, etc.)
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
                    return make_suggestions(results, "Symbol", span_start, pos);
                }

                CompletionStrategy::Type => {
                    let mut arg_count = text_before_cursor.split_whitespace().count();
                    if text_before_cursor.ends_with(char::is_whitespace) {
                        arg_count += 1;
                    }

                    let results = if arg_count > 2 {
                        let symbols = self.symbols.read().unwrap();
                        symbols.search(prefix, 1024)
                    } else {
                        let types = self.types.read().unwrap();
                        types.search(prefix, 1024)
                    };

                    let description = if arg_count > 2 { "Symbol" } else { "Structure" };
                    return make_suggestions(results, description, span_start, pos);
                }

                CompletionStrategy::Process => {
                    let processes = self.processes.read().unwrap();
                    let prefix_lower = prefix.to_lowercase();
                    return processes
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
                            append_whitespace: true,
                        })
                        .collect();
                }

                CompletionStrategy::Thread => {
                    let threads = self.threads.read().unwrap();
                    return threads
                        .iter()
                        .filter(|tid| tid.starts_with(prefix))
                        .map(|tid| Suggestion {
                            value: tid.clone(),
                            description: Some("Thread/vCPU".to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(span_start, pos),
                            append_whitespace: true,
                        })
                        .collect();
                }

                CompletionStrategy::Breakpoint => {
                    let breakpoints = self.breakpoints.read().unwrap();
                    return breakpoints
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
                                append_whitespace: true,
                            }
                        })
                        .collect();
                }
            }
        }

        vec![]
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
        "{}", "─── registers ─────────────────────────────────────────────────────".bright_black()
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

fn print_disasm_context(debugger: &DebuggerContext, rip: u64) {
    println!(
        "{}", "─── disasm ────────────────────────────────────────────────────────".bright_black()
    );

    let pre_bytes: u64 = 64;
    let post_bytes: u64 = 64;
    let start_addr = rip.saturating_sub(pre_bytes);
    let total_len = (pre_bytes + post_bytes) as usize;

    let mut bytes = vec![0u8; total_len];
    if debugger
        .get_current_process()
        .memory(&debugger.kvm)
        .read_bytes(VirtAddr(start_addr), &mut bytes)
        .is_err()
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
            let sym = debugger
                .get_current_process()
                .closest_symbol(&debugger.symbols, VirtAddr(target))
                .map(|(s, o)| format!("{}+{:#x}", s, o))
                .unwrap_or_else(|_| format!("{:#X}", target));
            line.push_str(&format!(" ; {}", sym));
        } else if instruction.is_call_near()
            || instruction.is_jmp_near()
            || instruction.is_jcc_near()
        {
            let target = instruction.near_branch_target();
            let sym = debugger
                .get_current_process()
                .closest_symbol(&debugger.symbols, VirtAddr(target))
                .map(|(s, o)| format!("{}+{:#x}", s, o))
                .unwrap_or_else(|_| format!("{:#X}", target));
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

        for i in start..end {
            let (ip, _, ref line) = instructions[i];
            if ip == rip {
                println!(
                    " {} {}  {}",
                    ">".green(),
                    format!("{:016x}", VirtAddr(ip)).green(),
                    line.green()
                );
            } else {
                println!(
                    "   {:016x}  {}",
                    VirtAddr(ip),
                    line.bright_black()
                );
            }
        }
    } else {
        let mut forward_buf = vec![0u8; post_bytes as usize];
        if debugger
            .get_current_process()
            .memory(&debugger.kvm)
            .read_bytes(VirtAddr(rip), &mut forward_buf)
            .is_ok()
        {
            let mut dec =
                Decoder::with_ip(64, &forward_buf, rip, DecoderOptions::NONE);
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
    limit: usize,
) {
    println!(
        "{}", "─── stack trace ───────────────────────────────────────────────────".bright_black()
    );

    let rip = register_map.read_u64("rip", regs).unwrap_or(0);
    let rsp = register_map.read_u64("rsp", regs).unwrap_or(0);
    let cr3 = register_map.read_u64("cr3", regs).unwrap_or(0);

    let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
    let kernel_dtb_masked = debugger.guest.ntoskrnl.dtb() & 0x000F_FFFF_FFFF_F000;
    let is_kernel = cr3_masked == kernel_dtb_masked;

    let modules = if is_kernel {
        debugger
            .guest
            .get_kernel_modules(&debugger.kvm, &debugger.symbols)
            .unwrap_or_default()
    } else if let Some(ref proc_info) = debugger.current_process_info {
        debugger
            .guest
            .get_process_modules(&debugger.kvm, &debugger.symbols, proc_info)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let is_code_addr = |addr: u64| -> bool {
        modules.iter().any(|m| {
            let start = m.base_address.0;
            let end = start + m.size as u64;
            addr >= start && addr < end
        })
    };

    let resolve_symbol = |addr: u64| -> String {
        if is_kernel {
            debugger
                .guest
                .ntoskrnl
                .closest_symbol(&debugger.symbols, VirtAddr(addr))
                .map(|(s, o)| if o == 0 { s } else { format!("{}+{:#x}", s, o) })
                .unwrap_or_else(|_| format!("{:#x}", addr))
        } else {
            debugger
                .symbols
                .find_closest_symbol_for_address(debugger.current_dtb(), VirtAddr(addr))
                .map(|(module, sym, offset)| {
                    if offset == 0 {
                        format!("{}!{}", module, sym)
                    } else {
                        format!("{}!{}+{:#x}", module, sym, offset)
                    }
                })
                .unwrap_or_else(|| format!("{:#x}", addr))
        }
    };

    let mem = debugger.get_current_process().memory(&debugger.kvm);
    let mut frames: Vec<(usize, u64, u64, String)> = Vec::new();
    const STACK_SCAN_SIZE: usize = 0x1000;

    frames.push((0, rsp, rip, resolve_symbol(rip)));

    let mut stack_data = vec![0u8; STACK_SCAN_SIZE];
    if mem.read_bytes(VirtAddr(rsp), &mut stack_data).is_ok() {
        for offset in (0..STACK_SCAN_SIZE - 8).step_by(8) {
            if frames.len() >= limit {
                break;
            }

            let potential_addr =
                u64::from_le_bytes(stack_data[offset..offset + 8].try_into().unwrap());

            if potential_addr == rip {
                continue;
            }

            if is_code_addr(potential_addr) {
                let stack_addr = rsp + offset as u64;
                let symbol = resolve_symbol(potential_addr);
                frames.push((frames.len(), stack_addr, potential_addr, symbol));
            }
        }
    }

    for (num, sp, addr, sym) in &frames {
        println!(
            " {:>2}  {:#018x}  {:#018x}  {}",
            num,
            VirtAddr(*sp),
            VirtAddr(*addr),
            sym
        );
    }
}

fn print_break_context(
    client: &mut GdbClient,
    register_map: &RegisterMap,
    debugger: &mut DebuggerContext,
    thread_id: &str,
) {
    let regs = match client.read_registers() {
        Ok(r) => r,
        Err(_) => {
            debugger.registers = None;
            println!("{} thread {}\n", "break:".magenta(), thread_id);
            return;
        }
    };

    debugger.registers = Some(register_map.to_hashmap(&regs));

    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
    let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
    let kernel_dtb_masked = debugger.guest.ntoskrnl.dtb() & 0x000F_FFFF_FFFF_F000;

    let (context, symbol) = if cr3_masked == kernel_dtb_masked {
        let sym = debugger
            .guest
            .ntoskrnl
            .closest_symbol(&debugger.symbols, VirtAddr(rip))
            .map(|(s, o)| if o == 0 { s } else { format!("{}+{:#x}", s, o) })
            .unwrap_or_else(|_| format!("{:#x}", rip));
        ("kernel".to_string(), sym)
    } else {
        let processes = debugger
            .guest
            .enumerate_processes(&debugger.kvm, &debugger.symbols)
            .unwrap_or_default();

        match processes
            .iter()
            .find(|p| (p.dtb & 0x000F_FFFF_FFFF_F000) == cr3_masked)
        {
            Some(proc) => {
                let sym = debugger
                    .symbols
                    .find_closest_symbol_for_address(proc.dtb, VirtAddr(rip))
                    .map(|(module, sym, offset)| {
                        if offset == 0 {
                            format!("{}!{}", module, sym)
                        } else {
                            format!("{}!{}+{:#x}", module, sym, offset)
                        }
                    })
                    .unwrap_or_else(|| format!("{:#x}", rip));
                (format!("{} ({})", proc.name.clone(), proc.pid), sym)
            }
            None => ("unknown".to_string(), format!("{:#x}", rip)),
        }
    };

    println!(
        "{} {} {} {} {} {}",
        "break:".magenta(),
        format!("thread {}", thread_id).bright_black(),
        "in".bright_black(),
        context.cyan(),
        "at".bright_black(),
        symbol.green()
    );

    print_registers(register_map, &regs);
    print_disasm_context(debugger, rip);
    print_stacktrace(debugger, register_map, &regs, 8);
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
        print!("{:08x}  ", start_address + ((i * mode.bytes_per_row) as u64));

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
                            item[0], item[1], item[2], item[3],
                            item[4], item[5], item[6], item[7],
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

pub fn start_repl(debugger: &mut DebuggerContext) -> Result<()> {
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

    // TODO make this non-fatal
    let mut client = GdbClient::connect("127.1:1234")?;

    let register_map = client.get_register_map()?;

    let mut current_thread = client
        .get_stopped_thread_id()
        .unwrap_or_else(|_| "1".to_string());

    let mut breakpoints = BreakpointManager::new();

    print_break_context(&mut client, &register_map, debugger, &current_thread);

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

    let completor = Box::new(MyCompleter {
        symbols: Arc::clone(&shared_symbols),
        types: Arc::clone(&shared_types),
        symbol_store: Arc::clone(&shared_symbol_store),
        dtb: Arc::clone(&shared_dtb),
        processes: Arc::clone(&shared_processes),
        threads: Arc::clone(&shared_threads),
        breakpoints: Arc::clone(&shared_breakpoints),
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
                            let address = match Expr::eval(parts.get(1).copied().unwrap_or(""), debugger) {
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

                            let pattern: Vec<u8> = pattern_str
                                .split(|c| c == ':' || c == ' ')
                                .filter(|s| !s.is_empty())
                                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                                .collect();

                            if pattern.is_empty() {
                                error!("invalid pattern: {}", pattern_str);
                                continue;
                            }

                            let length: usize = parts.get(3)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0x100);

                            let mut data = vec![0u8; length];
                            let mem = debugger.get_current_process().memory(&debugger.kvm);

                            if let Err(e) = mem.read_bytes(start_addr, &mut data) {
                                error!("failed to read memory: {}", e);
                                continue;
                            }

                            let mut found = 0;
                            for i in 0..=data.len().saturating_sub(pattern.len()) {
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
                                                format!("{}", s)
                                            }
                                        })
                                        .unwrap_or_default();

                                    println!("{:#16x}  {} {}", addr, sym.bright_black(), format!("[{}]", pattern_str).green());
                                    found += 1;

                                    if found >= 50 {
                                        println!("... (showing first 50 matches)");
                                        break;
                                    }
                                }
                            }

                            if found == 0 {
                                println!("{} (searched {:#x} bytes at {:#x})", "no matches found".bright_black(), length, start_addr);
                            } else {
                                println!("\n{} {}", found, if found == 1 { "match" } else { "matches" });
                            }
                            println!();
                        }
                        Ok(ReplCommand::Ev) => {
                            if parts.is_empty() {
                                println!("{}\n", ReplCommand::Ev.get_message().unwrap_or("invalid usage"));
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
                            if client.is_running {
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
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut client) {
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
                                if let Err(e) =
                                    client.set_read_timeout(Some(Duration::from_millis(100)))
                                {
                                    error!("failed to set timeout: {:?}", e);
                                    continue;
                                }

                                loop {
                                    // if user pressed Ctrl+C
                                    if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                                        // restore blocking mode before interrupt
                                        let _ = client.set_read_timeout(None);
                                        if let Err(e) = client.interrupt() {
                                            error!("failed to interrupt VM: {:?}", e);
                                            break;
                                        }

                                        if let Ok(tid) = client.get_stopped_thread_id() {
                                            current_thread = tid;
                                        }
                                        println!();
                                        print_break_context(
                                            &mut client,
                                            &register_map,
                                            debugger,
                                            &current_thread,
                                        );
                                        break;
                                    }

                                    match client.try_wait_for_stop() {
                                        Ok(Some(_)) => {
                                            // restore blocking mode for subsequent operations
                                            let _ = client.set_read_timeout(None);

                                            // VM stopped, check if it's our breakpoint
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

                                            match breakpoints.check_breakpoint_hit(rip, cr3) {
                                                BreakpointHitResult::Hit(bp) => {
                                                    if let Ok(tid) = client.get_stopped_thread_id()
                                                    {
                                                        current_thread = tid;
                                                    }
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
                                                        &mut client,
                                                        &register_map,
                                                        debugger,
                                                        &current_thread,
                                                    );

                                                    // reset the breakpoint to ensure it's still active
                                                    let _ = client.set_breakpoint(bp.address.0, 1);

                                                    break;
                                                }
                                                BreakpointHitResult::WrongProcess(bp) => {
                                                    // temporarily disable the breakpoint to step over it
                                                    if let Err(e) =
                                                        breakpoints.disable(&mut client, bp.id)
                                                    {
                                                        error!(
                                                            "failed to disable breakpoint for step: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) = client.step() {
                                                        let _ =
                                                            breakpoints.enable(&mut client, bp.id);
                                                        error!("failed to step: {:?}", e);
                                                        break;
                                                    }
                                                    if let Err(e) = client.wait_for_stop() {
                                                        let _ =
                                                            breakpoints.enable(&mut client, bp.id);
                                                        error!(
                                                            "failed to wait after step: {:?}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    // reenable the breakpoint after stepping
                                                    if let Err(e) =
                                                        breakpoints.enable(&mut client, bp.id)
                                                    {
                                                        error!(
                                                            "failed to re-enable breakpoint: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) =
                                                        breakpoints.refresh_enabled(&mut client)
                                                    {
                                                        error!(
                                                            "failed to refresh breakpoints after step: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) = client.continue_execution() {
                                                        error!("failed to continue: {:?}", e);
                                                        break;
                                                    }

                                                    let _ = client.set_read_timeout(Some(
                                                        Duration::from_millis(100),
                                                    ));
                                                }
                                                BreakpointHitResult::NotBreakpoint => {
                                                    if let Ok(tid) = client.get_stopped_thread_id()
                                                    {
                                                        current_thread = tid;
                                                    }

                                                    println!();
                                                    print_break_context(
                                                        &mut client,
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
                                            let _ = client.set_read_timeout(None);
                                            error!("error waiting for stop: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(ReplCommand::Break) => {
                            if !client.is_running {
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
                            println!();
                            print_break_context(
                                &mut client,
                                &register_map,
                                debugger,
                                &current_thread,
                            );
                        }
                        Ok(ReplCommand::Dt) => {
                            let arg = require_arg!(parts, 1, ReplCommand::Dt);

                            let address = match Expr::eval(parts.get(2).copied().unwrap_or("0"), debugger) {
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
                                    let mut builder = Builder::default();
                                    builder.push_record(vec![format!(
                                        "{} ({} bytes)",
                                        type_info.name,
                                        Value(type_info.size)
                                    )]);

                                    let mut sorted_fields: Vec<_> =
                                        type_info.fields.iter().collect();
                                    sorted_fields.sort_by_key(|(_, info)| {
                                        let bitfield_pos = match &info.type_data {
                                            ParsedType::Bitfield { pos, .. } => *pos,
                                            _ => 0,
                                        };
                                        (info.offset, bitfield_pos)
                                    });

                                    for (name, info) in sorted_fields {
                                        let value = if address.0 != 0 {
                                            let mem = debugger
                                                .get_current_process()
                                                .memory(&debugger.kvm);
                                            match &info.type_data {
                                                ParsedType::Primitive(p) => {
                                                    if p.contains("*") || p.contains("LONGLONG") {
                                                        let val: u64 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("LONG") {
                                                        let val: u32 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("SHORT")
                                                        || p.contains("WCHAR")
                                                    {
                                                        let val: u16 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("CHAR") {
                                                        let val: u8 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else {
                                                        "".into()
                                                    }
                                                }
                                                ParsedType::Pointer(_) => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset)?;
                                                    format!(" = {:#x}", Value(val))
                                                }
                                                ParsedType::Bitfield { pos, len, .. } => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset)?;
                                                    let val = (val >> pos) & ((1u64 << len) - 1);

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
                                                _ => "".into(),
                                            }
                                        } else {
                                            "".into()
                                        };

                                        if field_name.is_none() || field_name.unwrap() == name {
                                            builder.push_record(vec![
                                                format!(
                                                    "  + {:#06x} {:-12}",
                                                    VirtAddr(info.offset.into()),
                                                    name
                                                ),
                                                format!("  : {}", info.type_data.green()),
                                                format!("  {}", value),
                                            ]);
                                        }
                                    }

                                    let mut table = builder.build();
                                    table
                                        .with(tabled::settings::Style::empty())
                                        .with(Padding::zero());
                                    println!("{}\n", table);
                                }
                                None => {
                                    error!(
                                        "failed to get type information: type `{}` not found\n",
                                        arg
                                    );
                                }
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
                                        if let Some(ref f) = filter {
                                            if !proc.name.to_lowercase().contains(f) {
                                                continue;
                                            }
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
                        Ok(ReplCommand::Lm) => {
                            let filter = parts.get(1).map(|s| s.to_lowercase());

                            let result = if let Some(process_info) = &debugger.current_process_info
                            {
                                debugger.guest.get_process_modules(
                                    &debugger.kvm,
                                    &debugger.symbols,
                                    process_info,
                                )
                            } else {
                                debugger
                                    .guest
                                    .get_kernel_modules(&debugger.kvm, &debugger.symbols)
                            };

                            match result {
                                Ok(modules) => {
                                    let mut builder = Builder::default();
                                    builder.push_record(vec![
                                        "Start".to_string(),
                                        "End".to_string(),
                                        "Module".to_string(),
                                        "Image".to_string(),
                                    ]);

                                    let mut count = 0;
                                    for module in modules {
                                        if let Some(ref f) = filter {
                                            if !module.short_name.to_lowercase().contains(f)
                                                && !module.name.to_lowercase().contains(f)
                                            {
                                                continue;
                                            }
                                        }
                                        count += 1;
                                        let end_address =
                                            module.base_address.0 + module.size as u64;
                                        builder.push_record(vec![
                                            format!("{:#018x}  ", module.base_address),
                                            format!("{:#018x}  ", VirtAddr(end_address)),
                                            format!("{}  ", module.short_name),
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
                        Ok(ReplCommand::Attach) => {
                            let pid_str = require_arg!(parts, 1, ReplCommand::Attach);
                            match pid_str.parse::<u64>() {
                                Ok(pid) => match debugger.attach(pid) {
                                    Ok(name) => {
                                        *shared_symbols.write().unwrap() =
                                            debugger.current_symbol_index();
                                        *shared_types.write().unwrap() =
                                            debugger.current_types_index();
                                        *shared_dtb.write().unwrap() = debugger.current_dtb();
                                        println!("attached to {} (PID {})\n", name, pid);
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
                        Ok(ReplCommand::Detach) => {
                            if debugger.current_process.is_none() {
                                error!("not attached to any process");
                            } else {
                                debugger.detach();
                                *shared_symbols.write().unwrap() = debugger.current_symbol_index();
                                *shared_types.write().unwrap() = debugger.current_types_index();
                                *shared_dtb.write().unwrap() = debugger.current_dtb();
                                println!("detached, now in kernel context\n");
                            }
                        }
                        Ok(ReplCommand::Registers) => {
                            if client.is_running {
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

                            let read_reg = |name: &str| -> String {
                                register_map
                                    .read_u64(name, &regs)
                                    .map(|v| format!("{:#018x}", VirtAddr(v)))
                                    .unwrap_or_else(|_| "N/A".to_string())
                            };

                            println!();
                            println!(
                                "cr0={}  cr2={}  cr3={}",
                                read_reg("cr0"),
                                read_reg("cr2"),
                                read_reg("cr3")
                            );
                            println!("cr4={}  cr8={}", read_reg("cr4"), read_reg("cr8"));
                            println!();

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
                        Ok(ReplCommand::Si) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            // check if we're at a breakpoint address and temporarily remove it
                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };
                            let rip = register_map.read_u64("rip", &regs).unwrap_or(0);

                            let bp_at_rip = breakpoints
                                .list()
                                .iter()
                                .find(|bp| bp.enabled && bp.address.0 == rip)
                                .map(|bp| bp.id);

                            // temporarily disable breakpoint at current rip if present
                            if let Some(bp_id) = bp_at_rip
                                && let Err(e) = breakpoints.disable(&mut client, bp_id)
                            {
                                error!("failed to disable breakpoint for step: {}", e);
                                continue;
                            }

                            if let Err(e) = client.step() {
                                // reenable breakpoint on error
                                if let Some(bp_id) = bp_at_rip {
                                    let _ = breakpoints.enable(&mut client, bp_id);
                                }
                                error!("failed to step: {:?}", e);
                                continue;
                            }

                            if let Err(e) = client.wait_for_stop() {
                                // reenable breakpoint on error
                                if let Some(bp_id) = bp_at_rip {
                                    let _ = breakpoints.enable(&mut client, bp_id);
                                }
                                error!("failed to wait after step: {:?}", e);
                                continue;
                            }

                            // reenable the breakpoint after stepping
                            if let Some(bp_id) = bp_at_rip
                                && let Err(e) = breakpoints.enable(&mut client, bp_id)
                            {
                                error!("failed to re-enable breakpoint after step: {}", e);
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut client) {
                                error!("failed to refresh breakpoints after step: {}", e);
                            }

                            if let Ok(tid) = client.get_stopped_thread_id() {
                                current_thread = tid;
                            }

                            println!();
                            print_break_context(&mut client, &register_map, debugger, &current_thread);
                        }
                        Ok(ReplCommand::Thread) => {
                            if client.is_running {
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
                        Ok(ReplCommand::Bp) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let addr_str = require_arg!(parts, 1, ReplCommand::Bp);
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

                            let target_cr3 = debugger.current_process_info.as_ref().map(|p| p.dtb);

                            match breakpoints.add(&mut client, address, target_cr3, symbol.clone())
                            {
                                Ok(id) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    let scope = if let Some(target_cr3) = target_cr3 {
                                        format!(" (process-specific, CR3={:#x})", target_cr3)
                                    } else {
                                        " (global)".to_string()
                                    };
                                    println!(
                                        "breakpoint {} set at {}{}{}\n",
                                        format!("#{}", id).cyan(),
                                        format!("{:#x}", address).yellow(),
                                        symbol
                                            .map(|s| format!(" ({})", s))
                                            .unwrap_or_default()
                                            .green(),
                                        scope.bright_black()
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
                                    "Address".to_string(),
                                    "Symbol".to_string(),
                                    "Scope".to_string(),
                                ]);

                                for bp in bps {
                                    let status = if bp.enabled { "enabled" } else { "disabled" };
                                    let scope = bp
                                        .target_cr3
                                        .map(|cr3| format!("CR3={:#x}", cr3))
                                        .unwrap_or_else(|| "global".to_string());

                                    builder.push_record(vec![
                                        format!("{}   ", bp.id),
                                        format!("{}  ", status),
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
                            if client.is_running {
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

                            match breakpoints.remove(&mut client, id) {
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
                            if client.is_running {
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

                            match breakpoints.disable(&mut client, id) {
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
                            if client.is_running {
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

                            match breakpoints.enable(&mut client, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} enabled\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        // TODO look into using UNWIND info?
                        Ok(ReplCommand::K) => {
                            if client.is_running {
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

                            print_stacktrace(debugger, &register_map, &regs, frame_limit);
                            println!();
                        }
                        Ok(ReplCommand::Status) => {
                            if client.is_running {
                                println!("VM is running\n");
                            } else {
                                if let Err(e) = client.set_current_thread(&current_thread) {
                                    error!("failed to set thread context: {:?}", e);
                                    continue;
                                }
                                print_break_context(
                                    &mut client,
                                    &register_map,
                                    debugger,
                                    &current_thread,
                                );
                            }
                        }
                        Err(_) => {
                            println!(
                                "unknown command: '{}' (try pressing tab to see available commands)\n",
                                cmd_str
                            );
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

                if client.is_running {
                    if let Err(e) = client.interrupt() {
                        error!("failed to interrupt: {:?}", e);
                        continue;
                    }

                    if let Ok(thread_id) = client.get_stopped_thread_id() {
                        current_thread = thread_id;
                    }
                    println!();
                    print_break_context(&mut client, &register_map, debugger, &current_thread);
                } else {
                    error!("VM is already paused");
                }
            }
        }
    }

    if !client.is_running {
        let _ = client.continue_execution();
    }

    Ok(())
}
