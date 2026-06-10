use nu_ansi_term::Style;
use reedline::{
    Completer, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Span,
    Suggestion,
};
use reedline::{Highlighter, StyledText};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use strum::EnumMessage;
use strum::IntoEnumIterator;

use owo_colors::OwoColorize;
use std::borrow::Cow;

use crate::dbg_backend::DebugBackend;
use crate::debugger::{DebuggerContext, DriverObjectInfo, ThreadInfo};
use crate::error::Result;
use crate::expr::Expr;
use crate::gdb::BreakpointManager;
use crate::symbols::{SymbolIndex, SymbolStore};
use crate::types::{Dtb, VirtAddr};

use crate::repl::*;

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
    Vcpu,
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
            "vcpu" => Self::Vcpu,
            "breakpoint" => Self::Breakpoint,
            "driver" => Self::Driver,
            _ => return None,
        })
    }
}

pub fn make_suggestions(
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

/// Cached process info for completion (name, PID)
pub type ProcessCache = Vec<(String, u64)>;

/// Cached execution-context IDs for completion
pub type VcpuCache = Vec<String>;

/// Cached Windows thread info for completion
pub type ThreadCache = Vec<ThreadInfo>;

/// Cached breakpoint info for completion (id, enabled, address, symbol)
pub type BreakpointCache = Vec<(u32, bool, VirtAddr, Option<String>)>;

/// Cached driver object info for completion
pub type DriverObjectCache = Vec<DriverObjectInfo>;

/// Cached (name, help, per-arg strategies) for script-registered commands
pub type UserCommandCache = Vec<(String, String, Vec<CompletionStrategy>)>;

/// Completion-facing state shared between the REPL loop (which rewrites the
/// caches as the target's state changes) and the tab completer. Every field is
/// a cheap-to-clone handle, so the loop and the completer each hold a clone.
#[derive(Clone)]
pub struct ReplCaches {
    pub symbols: Arc<RwLock<SymbolIndex>>,
    pub types: Arc<RwLock<SymbolIndex>>,
    pub symbol_store: Arc<SymbolStore>,
    pub dtb: Arc<RwLock<Dtb>>,
    pub processes: Arc<RwLock<ProcessCache>>,
    pub threads: Arc<RwLock<ThreadCache>>,
    pub vcpus: Arc<RwLock<VcpuCache>>,
    pub breakpoints: Arc<RwLock<BreakpointCache>>,
    pub drivers: Arc<RwLock<DriverObjectCache>>,
    pub user_commands: Arc<RwLock<UserCommandCache>>,
}

impl ReplCaches {
    /// Re-enumerate the guest's process list into the completion cache
    pub fn refresh_processes(&self, debugger: &DebuggerContext) -> Result<()> {
        let processes = debugger.guest.enumerate_processes()?;
        *self.processes.write().unwrap() = processes.into_iter().map(|p| (p.name, p.pid)).collect();
        Ok(())
    }

    pub fn refresh_vcpus(&self, client: &mut dyn DebugBackend) {
        if let Ok(vcpus) = client.thread_list() {
            *self.vcpus.write().unwrap() = vcpus;
        }
    }

    /// The thread cache is only populated on demand (threads/thread commands);
    /// a full thread walk is far too expensive to run on every stop, especially
    /// over serial KD. Reloads just drop the now-stale entries.
    pub fn clear_threads(&self) {
        self.threads.write().unwrap().clear();
    }

    /// Snapshot the current breakpoint set into the completion cache
    pub fn refresh_breakpoints(&self, breakpoints: &BreakpointManager) {
        *self.breakpoints.write().unwrap() = breakpoints
            .list()
            .iter()
            .map(|bp| (bp.id, bp.enabled, bp.address, bp.symbol.clone()))
            .collect();
    }

    /// Rebuild the symbol/type/DTB completion caches after the active context
    /// changes (kernel reload, process attach/detach)
    pub fn refresh_symbol_context(&self, debugger: &DebuggerContext) {
        *self.symbols.write().unwrap() = debugger.current_symbol_index();
        *self.types.write().unwrap() = debugger.current_types_index();
        *self.dtb.write().unwrap() = debugger.current_dtb();
    }

    /// Best-effort re-enumeration of driver objects into the completion cache,
    /// leaving the previous entries in place if enumeration fails
    pub fn refresh_drivers(&self, debugger: &DebuggerContext) {
        if let Ok(drivers) = debugger.enumerate_driver_objects() {
            *self.drivers.write().unwrap() = drivers;
        }
    }
}

pub struct MyCompleter {
    pub caches: ReplCaches,
}

#[derive(Clone, Copy)]
struct CompletionInput<'a> {
    raw_prefix: &'a str,
    ident_start: usize,
    prefix: &'a str,
    arg_start: usize,
    span_start: usize,
    pos: usize,
}

impl<'a> CompletionInput<'a> {
    fn new(text_before_cursor: &'a str, pos: usize) -> Self {
        let arg_start = text_before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let raw_prefix = &text_before_cursor[arg_start..];

        // Find the start of the identifier being typed by scanning backward for
        // expression boundary characters (operators, parens, dereference).
        let ident_start = raw_prefix
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map(|i| i + 1)
            .unwrap_or(0);
        let prefix = &raw_prefix[ident_start..];
        let span_start = arg_start + ident_start;

        Self {
            raw_prefix,
            ident_start,
            prefix,
            arg_start,
            span_start,
            pos,
        }
    }
}

fn completion_arg_count(text_before_cursor: &str) -> usize {
    let mut arg_count = text_before_cursor.split_whitespace().count();
    if text_before_cursor.ends_with(char::is_whitespace) {
        arg_count += 1;
    }
    arg_count
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

            let user_cmds = self.caches.user_commands.read().unwrap();
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
            let input = CompletionInput::new(text_before_cursor, pos);

            match cmd.completion_type() {
                CompletionStrategy::Type => {
                    // dt has a special third-arg promotion to symbol completion
                    if completion_arg_count(text_before_cursor) > 2 {
                        return self.apply_strategy(CompletionStrategy::Symbol, input);
                    }
                    return self.apply_strategy(CompletionStrategy::Type, input);
                }
                strat => {
                    return self.apply_strategy(strat, input);
                }
            }
        }

        // Fallback: script-registered command with per-arg completion hints
        let user_cmds = self.caches.user_commands.read().unwrap();
        if let Some((_, _, strategies)) = user_cmds.iter().find(|(n, _, _)| n == command_str) {
            let arg_count = completion_arg_count(text_before_cursor);
            let arg_index = arg_count.saturating_sub(2);
            let strat = strategies
                .get(arg_index)
                .copied()
                .unwrap_or(CompletionStrategy::None);

            return self.apply_strategy(strat, CompletionInput::new(text_before_cursor, pos));
        }

        vec![]
    }
}

impl MyCompleter {
    fn apply_strategy(
        &self,
        strategy: CompletionStrategy,
        input: CompletionInput<'_>,
    ) -> Vec<Suggestion> {
        match strategy {
            CompletionStrategy::None => vec![],

            CompletionStrategy::Symbol => {
                if input.ident_start > 0 {
                    let preceding = &input.raw_prefix[..input.ident_start];

                    if preceding.ends_with('+')
                        || preceding.ends_with('-')
                        || preceding.ends_with('[')
                    {
                        return vec![];
                    }

                    if let Some(expr_text) = preceding.strip_suffix("->") {
                        if let Ok(expr) = Expr::parse(expr_text) {
                            let dtb = *self.caches.dtb.read().unwrap();
                            let fields =
                                expr.complete_fields(&self.caches.symbol_store, dtb, input.prefix);
                            if !fields.is_empty() {
                                return make_suggestions(
                                    fields,
                                    "Field",
                                    input.span_start,
                                    input.pos,
                                );
                            }
                        }
                        return vec![];
                    }

                    if preceding.ends_with('(') {
                        let types = self.caches.types.read().unwrap();
                        let mut results = types.search(input.prefix, 512);
                        if !input.prefix.starts_with('_') {
                            results.extend(types.search(&format!("_{}", input.prefix), 512));
                        }
                        if !results.is_empty() {
                            return make_suggestions(results, "Type", input.span_start, input.pos);
                        }
                    }

                    // `module!<prefix>` -> complete symbols within that module
                    if let Some(module_part) = preceding.strip_suffix('!') {
                        let module = module_part
                            .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                            .next()
                            .unwrap_or("");
                        if !module.is_empty() {
                            let dtb = *self.caches.dtb.read().unwrap();
                            let results = self.caches.symbol_store.search_symbols_in_module(
                                dtb,
                                module,
                                input.prefix,
                                1024,
                            );
                            return make_suggestions(
                                results,
                                "Symbol",
                                input.span_start,
                                input.pos,
                            );
                        }
                    }
                }

                let symbols = self.caches.symbols.read().unwrap();
                let results = symbols.search(input.prefix, 1024);
                make_suggestions(results, "Symbol", input.span_start, input.pos)
            }

            CompletionStrategy::Type => {
                let types = self.caches.types.read().unwrap();
                let results = types.search(input.prefix, 1024);
                make_suggestions(results, "Structure", input.span_start, input.pos)
            }

            CompletionStrategy::Process => {
                let processes = self.caches.processes.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                processes
                    .iter()
                    .filter(|(name, pid)| {
                        name.to_lowercase().contains(&prefix_lower)
                            || pid.to_string().starts_with(input.prefix)
                    })
                    .map(|(name, pid)| Suggestion {
                        value: pid.to_string(),
                        description: Some(format!("{} (PID {})", name, pid)),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(input.span_start, input.pos),
                        append_whitespace: false,
                    })
                    .collect()
            }

            CompletionStrategy::Thread => {
                let threads = self.caches.threads.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                threads
                    .iter()
                    .filter(|thread| {
                        thread
                            .tid
                            .is_some_and(|tid| tid.to_string().starts_with(input.prefix))
                            || format!("{:#x}", thread.ethread.0).starts_with(input.prefix)
                            || thread
                                .process_name
                                .as_deref()
                                .is_some_and(|name| name.to_lowercase().contains(&prefix_lower))
                    })
                    .map(|thread| {
                        let value = thread
                            .tid
                            .map(|tid| tid.to_string())
                            .unwrap_or_else(|| format!("{:#x}", thread.ethread.0));
                        let process = thread.process_name.as_deref().unwrap_or("unknown");
                        let tid = thread
                            .tid
                            .map(|tid| tid.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        Suggestion {
                            value,
                            description: Some(format!(
                                "{} TID {} ETHREAD {:#x}",
                                process, tid, thread.ethread.0
                            )),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(input.span_start, input.pos),
                            append_whitespace: false,
                        }
                    })
                    .collect()
            }

            CompletionStrategy::Vcpu => {
                let vcpus = self.caches.vcpus.read().unwrap();
                vcpus
                    .iter()
                    .filter(|tid| tid.starts_with(input.prefix))
                    .map(|tid| Suggestion {
                        value: tid.clone(),
                        description: Some("vCPU".to_string()),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(input.span_start, input.pos),
                        append_whitespace: false,
                    })
                    .collect()
            }

            CompletionStrategy::Breakpoint => {
                let breakpoints = self.caches.breakpoints.read().unwrap();
                breakpoints
                    .iter()
                    .filter(|(id, _, _, _)| id.to_string().starts_with(input.prefix))
                    .map(|(id, _, addr, symbol)| {
                        let sym_str = symbol.as_deref().unwrap_or("-");
                        Suggestion {
                            value: id.to_string(),
                            description: Some(format!("{} @ {:#x}", sym_str, addr.0)),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(input.span_start, input.pos),
                            append_whitespace: false,
                        }
                    })
                    .collect()
            }

            CompletionStrategy::Driver => {
                let drivers = self.caches.drivers.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                drivers
                    .iter()
                    .filter(|driver| {
                        driver.name.to_lowercase().contains(&prefix_lower)
                            || format!("{:#x}", driver.object.0).starts_with(input.prefix)
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
                        span: Span::new(input.arg_start, input.pos),
                        append_whitespace: false,
                    })
                    .collect()
            }
        }
    }
}

pub struct TrackingHighlighter {
    pub had_content: Arc<AtomicBool>,
}

impl Highlighter for TrackingHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        self.had_content.store(!line.is_empty(), Ordering::Relaxed);

        let mut styled = StyledText::new();
        styled.push((Style::new(), line.to_string()));
        styled
    }
}
