//! Line-delimited JSON stdio debugger protocol for AI agent workflows.
//!
//! Each line on stdin is one [`AgentRequest`]; each line on stdout is one JSON
//! response (`{ id, ok, result | error }`). The frontend drives the shared
//! [`Session`] directly (it is single-threaded, so no actor is needed, unlike
//! the MCP server) and renders guest state through [`crate::view`] where a
//! neutral shape already exists, falling back to bespoke JSON for the agent-only
//! surfaces (descriptor tables, pool blocks, QEMU monitor passthrough).
//!
//! Scripting is the embedded Python interpreter (`ntoseye.repl` commands); the
//! `script.*` commands run a registered command with its stdout captured so it
//! cannot corrupt the JSON-on-stdout protocol.

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, MemorySizeOptions, NasmFormatter,
};

use crate::backend::MemoryOps;
use crate::dbg_backend::DebugCapability;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::inspect::descriptors::{
    GdtEntry, gdt_type_label, parse_gdtr_from_qemu_registers, parse_idtr_from_qemu_registers,
    parse_selector_arg, parse_tr_selector_from_qemu_registers, read_gdt_entries, read_idt_entries,
    read_tss_stack_bases,
};
use crate::inspect::local_symbols::load_symbols_from_directory;
use crate::inspect::pool::{
    BigPoolEntry, PoolHeader, annotate_near_symbol, classify_pool_region, find_big_pool,
    locate_pool_block_in_page, pool_block_state, pool_layout, segment_heap_hint, tag_string,
};
use crate::python::embed;
use crate::repl::{
    processor_index_from_backend_thread_id, refresh_windows_thread_context_for_backend_thread,
};
use crate::session::{ContinueOutcome, Session};
use crate::symbols::{ParsedType, TypeInfo};
use crate::target::{
    AttachReport, DriverObjectInfo, MemoryRegionInfo, ThreadInfo, UserVar, kthread_state_name,
    wait_reason_name,
};
use crate::types::VirtAddr;
use crate::unwind::{FrameSource, build_stacktrace};
use crate::view;
use crate::bugchecks::{analyze_bugcheck, current_bugcheck};

#[derive(Debug, Deserialize)]
struct AgentRequest {
    #[serde(default)]
    id: Value,
    command: String,
    #[serde(default)]
    expr: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    length: Option<usize>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    pid: Option<u64>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    breakpoint: Option<u32>,
    #[serde(default)]
    thread: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    selector: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    condition: Option<String>,
}

struct AgentSession<'a> {
    session: &'a mut Session,
}

/// A never-cancelled token for run-control calls whose `Session` method already
/// enforces a timeout internally (`continue_until_break` / `wait_for_stop_bounded`).
fn no_cancel() -> AtomicBool {
    AtomicBool::new(false)
}

/// Sets a cancel flag after `timeout_ms` unless dropped first. Lets the agent
/// bound `Session::step_over`/`step_out`, whose underlying `run_to` waits with no
/// internal timeout (unlike `continue_until_break`); without this a step over a
/// call that never returns would hang the single-threaded agent forever.
struct TimeoutCanceller {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TimeoutCanceller {
    fn start(timeout_ms: Option<u64>, cancel: Arc<AtomicBool>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = timeout_ms.map(|ms| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(ms);
                while Instant::now() < deadline {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                cancel.store(true, Ordering::Relaxed);
            })
        });
        Self { stop, handle }
    }
}

impl Drop for TimeoutCanceller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Drive the agent stdio protocol against a live [`Session`] until EOF or `quit`.
pub fn run(session: &mut Session) -> Result<()> {
    // Load the embedded Python commands so `script.*` works out of the box, the
    // same way the REPL does at startup.
    let script_report = embed::load_commands_dir();

    let mut session = AgentSession { session };

    write_json(json!({
        "ok": true,
        "event": "ready",
        "result": session.status(),
        "scripts": script_load_report_json(&script_report),
    }))?;

    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request = match serde_json::from_str::<AgentRequest>(&line) {
            Ok(request) => request,
            Err(e) => {
                writeln!(
                    stdout,
                    "{}",
                    json!({
                        "id": Value::Null,
                        "ok": false,
                        "error": format!("invalid request JSON: {e}"),
                    })
                )?;
                stdout.flush()?;
                continue;
            }
        };

        let id = request.id.clone();
        let should_quit = request.command == "quit";
        let response = match session.handle(request) {
            Ok(result) => json!({ "id": id, "ok": true, "result": result }),
            Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;

        if should_quit {
            break;
        }
    }

    // Best-effort: uninstall breakpoints and leave the guest usable on exit,
    // matching the REPL and MCP frontends (the agent shouldn't be the one
    // frontend that leaves int3 patches behind).
    let _ = session.session.cleanup_for_exit();
    Ok(())
}

impl AgentSession<'_> {
    fn handle(&mut self, request: AgentRequest) -> Result<Value> {
        match request.command.as_str() {
            "status" => Ok(self.status()),
            "capabilities" => Ok(self.capabilities()),
            "eval" => {
                let expr = required(request.expr, "expr")?;
                let address = self.eval_address(expr)?;
                self.session.target.set_results(vec![address.0], "eval");
                Ok(json!({ "address": fmt_addr(address.0) }))
            }
            "registers" => self.registers(),
            "read-memory" | "memory.read" => self.read_memory(request),
            "write-memory" | "memory.write" => self.write_memory(request),
            "memory.search" | "search" => self.search_memory(request),
            "memory.fill" | "fill" => self.fill_memory(request),
            "disasm" | "u" => self.disasm(request),
            "dt" | "type.dump" => self.dump_type(request),
            "trap-frame" | "tf" => self.dump_trap_frame(request),
            "pte" => self.pte(request),
            "idt" => self.idt(request.length),
            "gdt" => self.gdt(request.length),
            "tss" => self.tss(request.selector),
            "pool" => self.pool(request),
            "stack" | "stack.trace" | "k" => self.stack_trace(request.length),
            "drivers" => self.drivers(request.filter),
            "processes" | "ps" => self.processes(request.filter),
            "modules" | "lm" => self.modules(request.filter),
            "vmmap" => self.vmmap(request),
            "symbols.search" | "symbol.search" | "x" => self.search_symbols(request),
            "symbols.nearest" | "symbol.nearest" | "ln" => self.nearest_symbol(request),
            "variables" | "vars" => Ok(self.variables()),
            "variable.set" | "set" => self.set_variable(request),
            "variable.unset" | "unset" => self.unset_variable(request),
            "load-symbols" | "symbols.load" => self.load_symbols(request),
            "attach" => self.attach(request.pid),
            "detach" => {
                self.session.target.detach();
                Ok(self.status())
            }
            "vcpus" => self.vcpus(),
            "vcpu" | "vcpu.set" => self.set_vcpu(required(request.thread, "thread")?),
            "threads" => self.windows_threads(request.filter),
            "thread" | "thread.set" => self.set_windows_thread(required(request.thread, "thread")?),
            "breakpoint.set" | "bp.set" => self.set_breakpoint(request),
            "breakpoint.clear" | "bp.clear" => self.clear_breakpoint(request.breakpoint),
            "breakpoint.disable" | "bp.disable" => self.disable_breakpoint(request.breakpoint),
            "breakpoint.enable" | "bp.enable" => self.enable_breakpoint(request.breakpoint),
            "breakpoint.list" | "bp.list" => self.list_breakpoints(),
            "continue" | "go" => self.continue_execution(request.timeout_ms),
            "wait" | "wait-for-stop" => self.wait_for_stop_cmd(request.timeout_ms),
            "interrupt" | "break" => self.interrupt(),
            "step" | "si" => self.step(),
            "step.over" | "p" | "ni" => self.step_over(request.timeout_ms),
            "step.out" | "gu" | "finish" => self.step_out(request.timeout_ms),
            "qcmd" => {
                let command = required(request.expr, "expr")?;
                self.session
                    .backend
                    .monitor_command(&command)
                    .map(|output| json!({ "output": output }))
            }
            "qlog" => self.qlog(request),
            "scripts" | "script.list" => Ok(json!({
                "commands": embed::command_list().into_iter().map(|(name, help, strategies)| json!({
                    "name": name,
                    "help": help,
                    "strategies": strategies.into_iter().map(completion_strategy_name).collect::<Vec<_>>(),
                })).collect::<Vec<_>>()
            })),
            "script.reload" => {
                let report = embed::load_commands_dir();
                Ok(script_load_report_json(&report))
            }
            "script.run" | "script.exec" => self.run_script(request),
            "quit" => Ok(json!({ "bye": true })),
            other => Err(Error::InvalidExpression(format!(
                "unknown agent command: {other}"
            ))),
        }
    }

    fn run_script(&mut self, request: AgentRequest) -> Result<Value> {
        let line = required(request.expr, "expr")?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some((name, args)) = parts.split_first() else {
            return Err(Error::InvalidExpression("empty script command".into()));
        };
        if !embed::has_command(name) {
            return Err(Error::InvalidExpression(format!(
                "no such script command: {name}"
            )));
        }
        let output = embed::dispatch_capture(name, args, self.session)
            .map_err(Error::InvalidExpression)?;
        Ok(json!({ "command": name, "output": output }))
    }

    fn status(&self) -> Value {
        let target = &self.session.target;
        let process = target
            .current_process_info
            .as_ref()
            .map(|p| json!({ "pid": p.pid, "name": p.name, "dtb": fmt_addr(p.dtb) }));

        json!({
            "running": self.session.backend.is_running(),
            "current_vcpu": self.session.current_thread,
            "current_thread": self.session.current_thread,
            "current_dtb": fmt_addr(target.current_dtb()),
            "current_process": process,
            "current_windows_thread": target.current_windows_thread.as_ref().map(
                |thread| thread_json(thread, Some(&self.session.current_thread))
            ),
        })
    }

    fn capabilities(&self) -> Value {
        json!({
            "capabilities": self.session.backend.capabilities().into_iter().map(|entry| json!({
                "name": entry.capability.label(),
                "supported": entry.supported,
            })).collect::<Vec<_>>()
        })
    }

    fn registers(&mut self) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        let regs = self.current_regs()?;
        let map = self.session.register_map.to_hashmap(&regs);
        Ok(json!({
            "thread": self.session.current_thread,
            "registers": map.into_iter()
                .map(|(name, value)| (name, json!(fmt_addr(value))))
                .collect::<serde_json::Map<_, _>>()
        }))
    }

    fn read_memory(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let length = request.length.unwrap_or(16);
        let mut bytes = vec![0u8; length];
        self.session
            .target
            .current_process()
            .memory()
            .read_bytes(address, &mut bytes)?;
        Ok(json!({
            "address": fmt_addr(address.0),
            "data": hex::encode(bytes),
        }))
    }

    fn write_memory(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let data = hex::decode(required(request.data, "data")?)?;
        self.session
            .target
            .current_process()
            .memory()
            .write_bytes(address, &data)?;
        Ok(json!({
            "address": fmt_addr(address.0),
            "written": data.len(),
        }))
    }

    fn search_memory(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let length = request.length.unwrap_or(0x100);
        let pattern = decode_byte_pattern(&required(request.pattern.or(request.data), "pattern")?)?;
        if pattern.is_empty() {
            return Err(Error::InvalidExpression("empty pattern".into()));
        }

        let mut bytes = vec![0u8; length];
        self.session
            .target
            .current_process()
            .memory()
            .read_bytes(address, &mut bytes)?;

        let mut matches = Vec::new();
        if pattern.len() <= bytes.len() {
            for offset in 0..=bytes.len() - pattern.len() {
                if bytes[offset..offset + pattern.len()] == pattern {
                    let addr = address + offset as u64;
                    matches.push(json!({
                        "address": fmt_addr(addr.0),
                        "offset": offset,
                        "symbol": self.format_symbol(addr),
                    }));
                }
            }
        }

        Ok(json!({
            "address": fmt_addr(address.0),
            "length": length,
            "pattern": hex::encode(pattern),
            "matches": matches,
        }))
    }

    fn fill_memory(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let length = request.length.ok_or_else(|| {
            Error::InvalidExpression("missing length for memory.fill".to_string())
        })?;
        let pattern = decode_byte_pattern(&required(request.pattern.or(request.data), "pattern")?)?;
        if pattern.is_empty() {
            return Err(Error::InvalidExpression("empty pattern".into()));
        }

        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let remaining = length - bytes.len();
            bytes.extend_from_slice(&pattern[..remaining.min(pattern.len())]);
        }

        self.session
            .target
            .current_process()
            .memory()
            .write_bytes(address, &bytes)?;
        Ok(json!({
            "address": fmt_addr(address.0),
            "written": bytes.len(),
            "pattern": hex::encode(pattern),
        }))
    }

    fn disasm(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let length = request.length.unwrap_or(32);
        let mut bytes = vec![0u8; length];
        self.session
            .target
            .current_process()
            .memory()
            .read_bytes(address, &mut bytes)?;

        let mut decoder = Decoder::with_ip(64, &bytes, address.0, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let options = formatter.options_mut();
        options.set_space_after_operand_separator(true);
        options.set_hex_prefix("0x");
        options.set_hex_suffix("");
        options.set_first_operand_char_index(5);
        options.set_memory_size_options(MemorySizeOptions::Always);
        options.set_show_branch_size(false);
        options.set_rip_relative_addresses(true);

        let mut instruction = Instruction::default();
        let mut output = String::new();
        let mut rows = Vec::new();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.code() == Code::INVALID {
                continue;
            }

            output.clear();
            formatter.format(&instruction, &mut output);

            let ip = instruction.ip();
            let start_index = (ip - address.0) as usize;
            let instr_bytes = &bytes[start_index..start_index + instruction.len()];
            let target = instruction_target(&instruction);
            rows.push(json!({
                "address": fmt_addr(ip),
                "bytes": hex::encode(instr_bytes),
                "text": output,
                "target": target.map(fmt_addr),
                "target_symbol": target.map(|addr| self.format_symbol(VirtAddr(addr))),
            }));
        }

        Ok(json!({
            "address": fmt_addr(address.0),
            "length": length,
            "instructions": rows,
        }))
    }

    fn dump_type(&mut self, request: AgentRequest) -> Result<Value> {
        let type_name = required(request.type_name, "type")?;
        let lookup = if type_name.starts_with('_') {
            type_name.clone()
        } else {
            format!("_{type_name}")
        };
        let dtb = self.session.target.current_dtb();
        let type_info = self
            .session
            .target
            .symbols
            .find_type_across_modules(dtb, &lookup)
            .or_else(|| {
                self.session
                    .target
                    .symbols
                    .find_type_across_modules(dtb, &type_name)
            })
            .ok_or_else(|| Error::StructNotFound(type_name.clone()))?;
        let address = request
            .address
            .map(|expr| self.eval_address(expr))
            .transpose()?;
        Ok(json!({
            "type": type_info.name,
            "size": type_info.size,
            "address": address.map(|addr| fmt_addr(addr.0)),
            "fields": self.type_fields(&type_info, address, request.field.as_deref())?,
        }))
    }

    fn dump_trap_frame(&mut self, mut request: AgentRequest) -> Result<Value> {
        request.type_name = Some("KTRAP_FRAME".to_string());
        self.dump_type(request)
    }

    fn type_fields(
        &self,
        type_info: &TypeInfo,
        address: Option<VirtAddr>,
        field_filter: Option<&str>,
    ) -> Result<Vec<Value>> {
        let mut sorted_fields: Vec<_> = type_info.fields.iter().collect();
        sorted_fields.sort_by_key(|(_, info)| {
            let bitfield_pos = match &info.type_data {
                ParsedType::Bitfield { pos, .. } => *pos,
                _ => 0,
            };
            (info.offset, bitfield_pos)
        });

        let mut fields = Vec::new();
        for (name, info) in sorted_fields {
            if field_filter.is_some_and(|field| field != name) {
                continue;
            }
            let field_address = address.map(|addr| addr + info.offset as u64);
            fields.push(json!({
                "name": name,
                "offset": info.offset,
                "size": info.size,
                "type": info.type_data.to_string(),
                "address": field_address.map(|addr| fmt_addr(addr.0)),
                "value": field_address
                    .and_then(|addr| self.read_typed_field_value(addr, &info.type_data).ok()),
            }));
        }
        Ok(fields)
    }

    fn read_typed_field_value(&self, address: VirtAddr, ty: &ParsedType) -> Result<Value> {
        let mem = self.session.target.current_process().memory();
        match ty {
            ParsedType::Primitive(name) => {
                let value = match name.as_str() {
                    "bool" | "char" | "unsigned char" | "uint8_t" | "UCHAR" | "BYTE" => {
                        mem.read::<u8>(address)? as u64
                    }
                    "wchar_t" | "short" | "unsigned short" | "uint16_t" | "USHORT" | "WORD" => {
                        mem.read::<u16>(address)? as u64
                    }
                    "long" | "unsigned long" | "int" | "unsigned int" | "uint32_t" | "ULONG"
                    | "DWORD" => mem.read::<u32>(address)? as u64,
                    _ => mem.read::<u64>(address)?,
                };
                Ok(json!(fmt_addr(value)))
            }
            ParsedType::Pointer(_) => {
                let value: u64 = mem.read(address)?;
                Ok(json!(fmt_addr(value)))
            }
            ParsedType::Bitfield { pos, len, .. } => {
                let raw: u64 = mem.read(address)?;
                let mask = if *len == 64 {
                    u64::MAX
                } else {
                    (1u64 << *len) - 1
                };
                Ok(json!((raw >> pos) & mask))
            }
            _ => Ok(Value::Null),
        }
    }

    fn pte(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let traversal = self.session.target.pte_traverse(address)?;
        let mut levels = vec![traversal.pxe, traversal.ppe];
        if let Some(pde) = traversal.pde {
            levels.push(pde);
        }
        if let Some(pte) = traversal.pte {
            levels.push(pte);
        }

        Ok(json!({
            "address": fmt_addr(traversal.address.0),
            "levels": levels.into_iter().map(|entry| json!({
                "level": entry.name,
                "address": fmt_addr(entry.address.0),
                "value": fmt_addr(entry.value.0),
                "pfn": entry.value.pfn(),
                "page_frame": fmt_addr(entry.value.page_frame()),
                "present": entry.value.is_present(),
                "large_page": entry.value.is_large_page(),
                "user": entry.value.is_user(),
                "writable": entry.value.is_writable(),
                "nx": entry.value.is_nx(),
                "flags": entry.value.flags(),
            })).collect::<Vec<_>>()
        }))
    }

    /// Read the current thread's registers, caching them into the target so
    /// expression evaluation (`@rip`, etc.) resolves, and return the raw bytes
    /// for the descriptor/stack helpers that decode register context directly.
    fn current_regs(&mut self) -> Result<Vec<u8>> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let regs = self.session.backend.read_registers()?;
        self.session.target.registers = Some(self.session.register_map.to_hashmap(&regs));
        Ok(regs)
    }

    fn qemu_register_descriptors(&mut self) -> Result<String> {
        self.session.backend.monitor_command("info registers")
    }

    fn idt(&mut self, max_entries: Option<usize>) -> Result<Value> {
        let regs = self.current_regs()?;
        let monitor_output = self.qemu_register_descriptors()?;
        let idtr = parse_idtr_from_qemu_registers(&monitor_output).ok_or_else(|| {
            Error::InvalidExpression("QEMU monitor output did not contain IDT".into())
        })?;
        let entries = read_idt_entries(
            &self.session.target,
            &self.session.register_map,
            &regs,
            idtr,
            max_entries,
        )?;
        Ok(json!({
            "base": fmt_addr(idtr.base.0),
            "limit": idtr.limit,
            "entries": entries.into_iter().map(|entry| json!({
                "vector": entry.vector,
                "handler": fmt_addr(entry.handler.0),
                "selector": entry.selector,
                "ist": entry.ist,
                "gate_type": entry.gate_type,
                "dpl": entry.dpl,
                "present": entry.present,
                "symbol": self.format_symbol(entry.handler),
            })).collect::<Vec<_>>()
        }))
    }

    fn gdt(&mut self, max_entries: Option<usize>) -> Result<Value> {
        let regs = self.current_regs()?;
        let monitor_output = self.qemu_register_descriptors()?;
        let gdtr = parse_gdtr_from_qemu_registers(&monitor_output).ok_or_else(|| {
            Error::InvalidExpression("QEMU monitor output did not contain GDT".into())
        })?;
        let entries = read_gdt_entries(
            &self.session.target,
            &self.session.register_map,
            &regs,
            gdtr,
            max_entries,
        )?;
        Ok(json!({
            "base": fmt_addr(gdtr.base.0),
            "limit": gdtr.limit,
            "entries": entries.into_iter().map(gdt_entry_json).collect::<Vec<_>>()
        }))
    }

    fn tss(&mut self, selector_arg: Option<String>) -> Result<Value> {
        let regs = self.current_regs()?;
        let monitor_output = self.qemu_register_descriptors()?;
        let gdtr = parse_gdtr_from_qemu_registers(&monitor_output).ok_or_else(|| {
            Error::InvalidExpression("QEMU monitor output did not contain GDT".into())
        })?;
        let selector = match selector_arg {
            Some(selector) => parse_selector_arg(&selector).ok_or_else(|| {
                Error::InvalidExpression(format!("invalid TSS selector: {selector}"))
            })?,
            None => parse_tr_selector_from_qemu_registers(&monitor_output).ok_or_else(|| {
                Error::InvalidExpression("QEMU monitor output did not contain TR".into())
            })?,
        };
        let (entry, stacks) = read_tss_stack_bases(
            &self.session.target,
            &self.session.register_map,
            &regs,
            gdtr,
            selector,
        )?;
        Ok(json!({
            "selector": selector,
            "descriptor": gdt_entry_json(entry),
            "rsp": stacks.rsp.into_iter().map(|addr| fmt_addr(addr.0)).collect::<Vec<_>>(),
            "ist": stacks.ist.into_iter().map(|addr| fmt_addr(addr.0)).collect::<Vec<_>>(),
            "io_map_base": stacks.io_map_base,
        }))
    }

    fn pool(&mut self, request: AgentRequest) -> Result<Value> {
        let target = self.eval_address(required(request.address.or(request.expr), "address")?)?;
        let layout = pool_layout(&self.session.target)?;
        let region =
            classify_pool_region(&self.session.target, target).map(|(name, start, end)| {
                json!({
                    "name": name,
                    "start": fmt_addr(start.0),
                    "end": fmt_addr(end.0),
                })
            });
        let (blocks, target_index, page) =
            locate_pool_block_in_page(&self.session.target, &layout, target);
        let big_pool = find_big_pool(&self.session.target, &layout, target).map(big_pool_json);
        Ok(json!({
            "target": fmt_addr(target.0),
            "page": fmt_addr(page.0),
            "region": region,
            "target_index": target_index,
            "blocks": blocks.into_iter().map(pool_header_json).collect::<Vec<_>>(),
            "big_pool": big_pool,
            "segment_heap_hint": if target_index.is_none() { segment_heap_hint(&self.session.target) } else { None },
            "near_symbol": if target_index.is_none() { annotate_near_symbol(&self.session.target, target) } else { None },
        }))
    }

    fn stack_trace(&mut self, limit: Option<usize>) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let regs = self.current_regs()?;
        let limit = limit.unwrap_or(64);
        let trace = build_stacktrace(&self.session.target, &self.session.register_map, &regs, limit);
        Ok(json!({
            "thread": self.session.current_thread,
            "truncated": trace.truncated,
            "frames": trace.frames.into_iter().map(|frame| json!({
                "sp": fmt_addr(frame.sp),
                "ip": fmt_addr(frame.ip),
                "symbol": frame.symbol,
                "source": match frame.source {
                    FrameSource::Current => "current",
                    FrameSource::Unwind => "unwind",
                    FrameSource::Scan => "scan",
                },
            })).collect::<Vec<_>>()
        }))
    }

    fn drivers(&self, filter: Option<String>) -> Result<Value> {
        let filter = filter.map(|s| s.to_lowercase());
        Ok(json!({
            "drivers": self.session.target.enumerate_driver_objects()?
                .into_iter()
                .filter(|driver| driver_matches(driver, filter.as_deref()))
                .map(driver_json)
                .collect::<Vec<_>>()
        }))
    }

    fn processes(&self, filter: Option<String>) -> Result<Value> {
        let filter = filter.map(|s| s.to_lowercase());
        let rows: Vec<_> = self
            .session
            .target
            .guest
            .enumerate_processes()?
            .into_iter()
            .filter(|p| {
                filter.as_ref().is_none_or(|f| {
                    p.name.to_lowercase().contains(f) || p.pid.to_string().starts_with(f)
                })
            })
            .map(|p| {
                json!({
                    "pid": p.pid,
                    "name": p.name,
                    "eprocess": fmt_addr(p.eprocess_va.0),
                    "dtb": fmt_addr(p.dtb),
                })
            })
            .collect();
        Ok(json!({ "processes": rows }))
    }

    fn modules(&self, filter: Option<String>) -> Result<Value> {
        let filter = filter.map(|s| s.to_lowercase());
        let modules = if let Some(process_info) = &self.session.target.current_process_info {
            self.session.target.guest.process_modules(process_info)?
        } else {
            self.session.target.guest.kernel_modules()?
        };
        Ok(json!({
            "modules": modules
                .into_iter()
                .filter(|m| module_matches(m, filter.as_deref()))
                .map(|m| json!({
                    "name": m.name,
                    "short_name": m.short_name,
                    "base": fmt_addr(m.base_address.0),
                    "end": fmt_addr(m.end_address().0),
                    "size": m.size,
                }))
                .collect::<Vec<_>>()
        }))
    }

    fn vmmap(&mut self, request: AgentRequest) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        let filter = request.filter.or(request.expr);
        let filter_address = filter
            .as_ref()
            .and_then(|value| self.eval_address(value.clone()).ok());
        if let Some(process) = self.session.target.current_process_info.clone() {
            let regions = self
                .session
                .target
                .enumerate_vad_regions_for_process_info(&process)?
                .into_iter()
                .filter(|region| region_matches_filter(region, filter.as_deref(), filter_address))
                .map(memory_region_json)
                .collect::<Vec<_>>();
            return Ok(json!({
                "context": "process",
                "pid": process.pid,
                "name": process.name,
                "regions": regions,
            }));
        }

        let filter_lower = filter.as_deref().map(str::to_ascii_lowercase);
        let regions = self
            .session
            .target
            .guest
            .kernel_modules()?
            .into_iter()
            .filter(|module| {
                filter_lower.as_ref().is_none_or(|filter| {
                    module.short_name.to_ascii_lowercase().contains(filter)
                        || module.name.to_ascii_lowercase().contains(filter)
                        || filter_address.is_some_and(|address| module.contains_address(address))
                })
            })
            .map(|module| {
                json!({
                    "start": fmt_addr(module.base_address.0),
                    "end": fmt_addr(module.end_address().0),
                    "size": module.size,
                    "module": module.short_name,
                    "image": module.name,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({ "context": "kernel", "regions": regions }))
    }

    fn search_symbols(&mut self, request: AgentRequest) -> Result<Value> {
        let query = required(request.query.or(request.expr), "query")?;
        let limit = request.limit.unwrap_or(4096).max(1);
        let dtb = self.session.target.current_dtb();
        let (module_filter, names) = match query.split_once('!') {
            Some((module, query)) => (
                Some(module.to_string()),
                self.session
                    .target
                    .symbols
                    .search_symbols_in_module(dtb, module, query, limit),
            ),
            None => (
                None,
                self.session.target.current_symbol_index().search(&query, limit),
            ),
        };

        let mut results = Vec::new();
        let mut addresses = Vec::new();
        for name in names {
            let lookup = module_filter
                .as_ref()
                .map(|module| format!("{module}!{name}"))
                .unwrap_or_else(|| name.clone());
            if let Some((address, module)) = self
                .session
                .target
                .symbols
                .find_symbol_with_module(dtb, &lookup)
            {
                addresses.push(address.0);
                results.push(json!({
                    "address": fmt_addr(address.0),
                    "module": module,
                    "name": name,
                    "symbol": format!("{module}!{name}"),
                }));
            }
        }
        self.session
            .target
            .set_results(addresses, format!("symbol.search {query}"));
        Ok(json!({
            "query": query,
            "limit": limit,
            "truncated": results.len() >= limit,
            "symbols": results,
        }))
    }

    fn nearest_symbol(&mut self, request: AgentRequest) -> Result<Value> {
        let expression = required(request.address.or(request.expr), "address")?;
        let address = self.eval_address(expression)?;
        let dtb = self.session.target.current_dtb();
        let result = self
            .session
            .target
            .symbols
            .find_closest_symbol_for_address(dtb, address)
            .map(|(module, name, offset)| {
                let base = address.0.saturating_sub(offset as u64);
                self.session.target.set_results(vec![base], "symbol.nearest");
                json!({
                    "address": fmt_addr(address.0),
                    "base": fmt_addr(base),
                    "module": module,
                    "name": name,
                    "offset": offset,
                    "symbol": if offset == 0 {
                        format!("{module}!{name}")
                    } else {
                        format!("{module}!{name}+0x{offset:x}")
                    },
                })
            });
        Ok(json!({ "result": result }))
    }

    fn variables(&self) -> Value {
        let target = &self.session.target;
        let mut user = target
            .user_vars
            .iter()
            .map(|(name, variable)| {
                json!({
                    "name": name,
                    "value": fmt_addr(variable.value),
                    "source": variable.source,
                })
            })
            .collect::<Vec<_>>();
        user.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        json!({
            "user": user,
            "results": target.results.iter().enumerate().map(|(index, value)| json!({
                "name": format!("${index}"),
                "value": fmt_addr(*value),
            })).collect::<Vec<_>>(),
            "results_origin": target.results_origin,
            "builtins": target.builtin_variables().into_iter().map(|variable| json!({
                "name": variable.name,
                "value": fmt_addr(variable.value),
                "source": variable.source,
            })).collect::<Vec<_>>(),
        })
    }

    fn set_variable(&mut self, request: AgentRequest) -> Result<Value> {
        let raw_name = required(request.name, "name")?;
        let name = raw_name.trim().trim_start_matches('$');
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(Error::InvalidExpression(format!(
                "invalid variable name '${name}'"
            )));
        }
        let source = required(request.expr, "expr")?;
        let value = self.eval_address(source.clone())?;
        self.session.target.user_vars.insert(
            name.to_string(),
            UserVar {
                value: value.0,
                source,
            },
        );
        Ok(json!({ "name": format!("${name}"), "value": fmt_addr(value.0) }))
    }

    fn unset_variable(&mut self, request: AgentRequest) -> Result<Value> {
        let raw_name = required(request.name.or(request.expr), "name")?;
        let name = raw_name.trim().trim_start_matches('$');
        let removed = self.session.target.user_vars.remove(name).is_some();
        Ok(json!({ "name": format!("${name}"), "removed": removed }))
    }

    fn load_symbols(&mut self, request: AgentRequest) -> Result<Value> {
        let path = required(request.path.or(request.expr), "path")?;
        let report = load_symbols_from_directory(
            &self.session.target,
            Path::new(&path),
            request.filter.as_deref(),
        )?;
        Ok(module_symbol_report_json(report))
    }

    fn attach(&mut self, pid: Option<u64>) -> Result<Value> {
        let pid = pid.ok_or_else(|| Error::InvalidExpression("missing pid".into()))?;
        let AttachReport {
            name,
            symbol_report,
        } = self.session.target.attach(pid)?;
        Ok(json!({
            "pid": pid,
            "name": name,
            "symbols": {
                "total": symbol_report.total,
                "loaded": symbol_report.loaded,
                "no_pdb": symbol_report.no_pdb,
                "skipped": symbol_report.skipped,
                "failed": symbol_report.failed,
            },
            "status": self.status(),
        }))
    }

    fn vcpus(&mut self) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let original_vcpu = self.session.backend.stopped_thread_id().ok();
        let mut rows = Vec::new();
        for vcpu in self.session.backend.thread_list()? {
            let mut row = json!({ "id": vcpu });
            if self.session.backend.set_current_thread(&vcpu).is_ok()
                && let Ok(regs) = self.session.backend.read_registers()
            {
                let rip = self.session.register_map.read_u64("rip", &regs).ok();
                let cr3 = self.session.register_map.read_u64("cr3", &regs).ok();
                row["rip"] = json!(rip.map(fmt_addr));
                row["cr3"] = json!(cr3.map(fmt_addr));
                row["symbol"] = json!(rip.and_then(|rip| self.format_symbol(VirtAddr(rip))));
                if let Some(processor) = backend_processor_index(&vcpu)
                    && let Ok(thread) = self
                        .session
                        .target
                        .current_windows_thread_for_processor(processor)
                {
                    row["windows_thread"] = thread_json(&thread, Some(&vcpu));
                }
            }
            rows.push(row);
        }
        if let Some(vcpu) = original_vcpu {
            let _ = self.session.backend.set_current_thread(&vcpu);
        }
        Ok(json!({ "vcpus": rows }))
    }

    fn set_vcpu(&mut self, vcpu: String) -> Result<Value> {
        let vcpus = self.session.backend.thread_list()?;
        if !vcpus.iter().any(|candidate| candidate == &vcpu) {
            return Err(Error::InvalidExpression(format!("vCPU '{vcpu}' not found")));
        }
        self.session.backend.set_current_thread(&vcpu)?;
        self.session.current_thread = vcpu;
        self.session.target.clear_context_dtb_override();
        refresh_windows_thread_context_for_backend_thread(
            &mut self.session.target,
            &self.session.current_thread,
        );
        Ok(self.status())
    }

    fn windows_threads(&mut self, filter: Option<String>) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let active = self.session.active_thread_map();
        let mut threads = self.session.target.enumerate_threads()?;
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        if let Some(filter) = filter.as_deref() {
            threads.retain(|thread| windows_thread_matches(thread, filter));
        }
        threads.sort_by_key(|thread| (thread.pid.unwrap_or(u64::MAX), thread.tid));
        Ok(json!({
            "threads": threads.into_iter().map(|thread| {
                let active_vcpu = active.get(&thread.ethread.0).map(|(vcpu, _)| vcpu.as_str());
                thread_json(&thread, active_vcpu)
            }).collect::<Vec<_>>()
        }))
    }

    fn set_windows_thread(&mut self, target: String) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let active = self.session.active_thread_map();
        let mut threads = self.session.target.enumerate_threads()?;
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        let target_address = if target == "." {
            self.session
                .target
                .current_windows_thread
                .as_ref()
                .map(|thread| thread.ethread)
        } else {
            self.eval_address(target.clone()).ok()
        };
        let matches = threads
            .into_iter()
            .filter(|thread| {
                thread
                    .tid
                    .is_some_and(|tid| tid.to_string() == target || format!("{tid:#x}") == target)
                    || target_address.is_some_and(|address| address == thread.ethread)
                    || format!("{:#x}", thread.ethread.0) == target
                    || format!("{:x}", thread.ethread.0) == target.trim_start_matches("0x")
            })
            .collect::<Vec<_>>();
        let thread = match matches.as_slice() {
            [thread] => thread.clone(),
            [] => {
                return Err(Error::InvalidExpression(format!(
                    "no Windows thread matches '{target}'"
                )));
            }
            _ => {
                return Err(Error::InvalidExpression(format!(
                    "ambiguous Windows thread '{target}': {} matches",
                    matches.len()
                )));
            }
        };
        let active_vcpu = active.get(&thread.ethread.0).map(|(vcpu, _)| vcpu.clone());
        if let Some(vcpu) = &active_vcpu {
            self.session.backend.set_current_thread(vcpu)?;
            self.session.current_thread = vcpu.clone();
            self.session.target.clear_context_dtb_override();
            self.session
                .target
                .set_current_windows_thread_context(thread.clone());
        }
        Ok(json!({
            "selected": active_vcpu.is_some(),
            "vcpu": active_vcpu,
            "thread": thread_json(&thread, active_vcpu.as_deref()),
        }))
    }

    fn set_breakpoint(&mut self, request: AgentRequest) -> Result<Value> {
        if self.session.backend.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        // Upstream's shared breakpoint manager is software/temporary only; the
        // fork's hardware-breakpoint extension is a separate follow-up.
        if let Some(kind) = request.kind.as_deref()
            && matches!(kind, "hardware" | "hbp")
        {
            return Err(Error::NotSupported);
        }

        let address = self.eval_address(required(request.address, "address")?)?;
        let dtb = self.session.target.current_dtb();
        let symbol = self
            .session
            .target
            .symbols
            .find_closest_symbol_for_address(dtb, address)
            .map(|(module, sym, offset)| {
                if offset == 0 {
                    format!("{module}!{sym}")
                } else {
                    format!("{module}!{sym}+0x{offset:x}")
                }
            });

        let id = self.session.breakpoints.add(
            self.session.backend.as_mut(),
            &self.session.target,
            address,
            symbol.clone(),
            request.condition.clone(),
        )?;

        Ok(json!({
            "id": id,
            "kind": "software",
            "address": fmt_addr(address.0),
            "symbol": symbol,
            "condition": request.condition,
        }))
    }

    fn clear_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.remove_breakpoint(id)?;
        Ok(json!({ "cleared": id }))
    }

    fn disable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.disable_breakpoint(id)?;
        Ok(json!({ "disabled": id }))
    }

    fn enable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.enable_breakpoint(id)?;
        Ok(json!({ "enabled": id }))
    }

    fn list_breakpoints(&self) -> Result<Value> {
        Ok(json!({
            "breakpoints": self.session.breakpoints.list().into_iter().map(|bp| json!({
                "id": bp.id,
                "enabled": bp.enabled,
                // Software-only on the shared core; kept for consumer compatibility.
                "kind": "software",
                "address": fmt_addr(bp.address.0),
                "symbol": bp.symbol,
                "scope": bp.scope.label(),
                "temporary": bp.temporary,
                "condition": bp.condition,
            })).collect::<Vec<_>>()
        }))
    }

    fn continue_execution(&mut self, timeout_ms: Option<u64>) -> Result<Value> {
        self.session.settle_pending_stop()?;
        match timeout_ms {
            None => {
                if !self.session.backend.is_running() {
                    self.session.resume()?;
                }
                Ok(json!({ "running": true, "stopped": false }))
            }
            Some(ms) => {
                let cancel = no_cancel();
                let outcome = self
                    .session
                    .continue_until_break(Some(Duration::from_millis(ms)), &cancel)?;
                self.outcome_json(outcome)
            }
        }
    }

    fn wait_for_stop_cmd(&mut self, timeout_ms: Option<u64>) -> Result<Value> {
        // A stop the background servicer already parked is the proper event for
        // this wait; surface it before waiting for a new one.
        if let Some(parked) = self.session.take_parked_stop() {
            return self.outcome_json(parked);
        }
        let cancel = no_cancel();
        let timeout = timeout_ms.map(Duration::from_millis);
        let outcome = self.session.wait_for_stop_bounded(timeout, &cancel)?;
        self.outcome_json(outcome)
    }

    fn interrupt(&mut self) -> Result<Value> {
        self.session.settle_pending_stop()?;
        if self.session.backend.is_running() {
            let _ = self.session.interrupt()?;
        }
        self.stopped_envelope("interrupt")
    }

    fn step(&mut self) -> Result<Value> {
        self.require_halted()?;
        self.session.step()?;
        self.stopped_envelope("step")
    }

    fn step_over(&mut self, timeout_ms: Option<u64>) -> Result<Value> {
        self.require_halted()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let _timer = TimeoutCanceller::start(timeout_ms, cancel.clone());
        let outcome = self.session.step_over(&cancel)?;
        self.outcome_json(outcome)
    }

    fn step_out(&mut self, timeout_ms: Option<u64>) -> Result<Value> {
        self.require_halted()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let _timer = TimeoutCanceller::start(timeout_ms, cancel.clone());
        let outcome = self.session.step_out(&cancel)?;
        self.outcome_json(outcome)
    }

    fn qlog(&mut self, request: AgentRequest) -> Result<Value> {
        let items = request
            .expr
            .or(request.filter)
            .unwrap_or_else(|| "int,cpu_reset,guest_errors".to_string());
        if let Some(path) = request.path {
            let _ = self.session.backend.monitor_command(&format!("logfile {path}"))?;
        }
        let output = self.session.backend.monitor_command(&format!("log {items}"))?;
        Ok(json!({
            "items": items,
            "output": output,
        }))
    }

    /// Require the VM halted for an inspection/step op, settling any pending stop
    /// and finishing memory-completable rediscovery first (mirrors the MCP guard
    /// and the REPL): only a truly running VM, or one stopped at a real site,
    /// reaches the caller.
    fn require_halted(&mut self) -> Result<()> {
        self.session.settle_pending_stop()?;
        self.session.try_finish_rediscovery_from_memory();
        self.session.clear_deferred_reload_surface();
        if self.session.backend.is_running() {
            Err(Error::InvalidExpression(
                "VM is running; interrupt first".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Render a [`ContinueOutcome`] into the agent's stop envelope.
    fn outcome_json(&mut self, outcome: ContinueOutcome) -> Result<Value> {
        match outcome {
            ContinueOutcome::Running => Ok(json!({ "running": true, "stopped": false })),
            ContinueOutcome::Breakpoint {
                id,
                address,
                symbol,
                temporary,
                rip,
            } => {
                let mut out = self.stopped_envelope("breakpoint")?;
                out["rip"] = json!(fmt_addr(rip));
                out["breakpoint"] = json!({
                    "id": id,
                    "address": fmt_addr(address),
                    "symbol": symbol.or_else(|| self.format_symbol(VirtAddr(rip))),
                });
                out["temporary"] = json!(temporary);
                Ok(out)
            }
            ContinueOutcome::Bugcheck { rip, info } => {
                let analysis = info
                    .map(|i| analyze_bugcheck(&self.session.target, &i))
                    .or_else(|| current_bugcheck(&self.session.target));
                let mut out = self.stopped_envelope("bugcheck")?;
                if let Some(rip) = rip {
                    out["rip"] = json!(fmt_addr(rip));
                }
                out["is_bugcheck"] = json!(true);
                out["bugcheck"] = analysis
                    .as_ref()
                    .map(|a| view::to_json(&view::bugcheck(a)))
                    .unwrap_or(Value::Null);
                Ok(out)
            }
            ContinueOutcome::Stopped {
                rip,
                exception_code,
            } => {
                let mut out = self.stopped_envelope("exception")?;
                out["rip"] = json!(fmt_addr(rip));
                out["exception_code"] = json!(exception_code.map(|code| format!("0x{code:08x}")));
                Ok(out)
            }
            ContinueOutcome::Step { rip } => {
                let mut out = self.stopped_envelope("step")?;
                out["rip"] = json!(fmt_addr(rip));
                Ok(out)
            }
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
            } => Ok(json!({
                "running": false,
                "stopped": true,
                "stop": "target_reloaded",
                "thread": self.session.current_thread,
                "target_reloaded": true,
                "kernel_base": kernel_base.map(fmt_addr),
                "coherent": coherent,
            })),
            ContinueOutcome::Halted { rip } => {
                let mut out = self.stopped_envelope("halted")?;
                // Not a fresh event; the VM was already parked here.
                out["event"] = json!(false);
                out["rip"] = json!(fmt_addr(rip));
                out["coherent"] = json!(self.session.kernel_coherent());
                Ok(out)
            }
        }
    }

    /// Base stop envelope: refreshes the current thread's registers (caching them
    /// for expression evaluation), and fills rip/cr3/symbol/process from the
    /// current context.
    fn stopped_envelope(&mut self, stop: &str) -> Result<Value> {
        let mut out = json!({
            "running": false,
            "stopped": true,
            "stop": stop,
            "thread": self.session.current_thread,
        });

        if let Ok(regs) = self.session.backend.read_registers() {
            let rip = self.session.register_map.read_u64("rip", &regs).unwrap_or(0);
            let cr3 = self.session.register_map.read_u64("cr3", &regs).unwrap_or(0);
            self.session.target.registers = Some(self.session.register_map.to_hashmap(&regs));
            out["rip"] = json!(fmt_addr(rip));
            out["cr3"] = json!(fmt_addr(cr3));
            if let Some(symbol) = self.format_symbol(VirtAddr(rip)) {
                out["symbol"] = json!(symbol);
            }
        }
        out["process"] = self
            .session
            .target
            .current_process_info
            .as_ref()
            .map(|p| json!({ "pid": p.pid, "name": p.name }))
            .unwrap_or(Value::Null);
        Ok(out)
    }

    fn eval_address(&mut self, expr: String) -> Result<VirtAddr> {
        self.ensure_register_cache()?;
        Expr::eval(&expr, &self.session.target)
    }

    fn ensure_register_cache(&mut self) -> Result<()> {
        if self.session.target.registers.is_some() || self.session.backend.is_running() {
            return Ok(());
        }
        if self
            .session
            .backend
            .capabilities()
            .iter()
            .any(|entry| entry.capability == DebugCapability::ReadRegisters && entry.supported)
        {
            self.current_regs()?;
        }
        Ok(())
    }

    fn format_symbol(&self, address: VirtAddr) -> Option<String> {
        self.session.target.closest_symbol_current_context(address)
    }
}

fn write_json(value: Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")?;
    stdout.flush()?;
    Ok(())
}

fn required(value: Option<String>, field: &str) -> Result<String> {
    value.ok_or_else(|| Error::InvalidExpression(format!("missing {field}")))
}

fn fmt_addr(value: u64) -> String {
    format!("0x{value:016x}")
}

fn module_matches(module: &ModuleInfo, filter: Option<&str>) -> bool {
    filter.is_none_or(|f| {
        module.short_name.to_lowercase().contains(f) || module.name.to_lowercase().contains(f)
    })
}

fn decode_byte_pattern(pattern: &str) -> Result<Vec<u8>> {
    let pattern = pattern.trim();
    if pattern.starts_with("\\x") || pattern.starts_with("\\X") {
        let mut bytes = Vec::new();
        let mut rest = pattern;
        while let Some(stripped) = rest
            .strip_prefix("\\x")
            .or_else(|| rest.strip_prefix("\\X"))
        {
            if stripped.len() < 2 {
                return Err(Error::InvalidExpression(format!(
                    "invalid byte pattern: {pattern}"
                )));
            }
            let byte = u8::from_str_radix(&stripped[..2], 16)?;
            bytes.push(byte);
            rest = &stripped[2..];
        }
        if rest.is_empty() {
            return Ok(bytes);
        }
    }

    if pattern.len().is_multiple_of(2) && pattern.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(hex::decode(pattern)?);
    }

    Err(Error::InvalidExpression(format!(
        "invalid byte pattern: {pattern}"
    )))
}

fn instruction_target(instruction: &Instruction) -> Option<u64> {
    if instruction.is_ip_rel_memory_operand() {
        Some(instruction.ip_rel_memory_address())
    } else if instruction.is_call_near() || instruction.is_jmp_near() || instruction.is_jcc_near() {
        Some(instruction.near_branch_target())
    } else {
        None
    }
}

fn driver_matches(driver: &DriverObjectInfo, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| {
        driver.name.to_lowercase().contains(filter)
            || format!("{:#x}", driver.object.0).starts_with(filter)
            || format!("{:#x}", driver.driver_start.0).starts_with(filter)
    })
}

fn driver_json(driver: DriverObjectInfo) -> Value {
    json!({
        "name": driver.name,
        "object": fmt_addr(driver.object.0),
        "driver_start": fmt_addr(driver.driver_start.0),
        "driver_size": driver.driver_size,
        "device_object": fmt_addr(driver.device_object.0),
        "driver_unload": fmt_addr(driver.driver_unload.0),
    })
}

fn gdt_entry_json(entry: GdtEntry) -> Value {
    json!({
        "index": entry.index,
        "selector": entry.selector,
        "base": fmt_addr(entry.base),
        "limit": entry.effective_limit,
        "type": gdt_type_label(&entry),
        "type_raw": entry.ty,
        "system": entry.system,
        "dpl": entry.dpl,
        "present": entry.present,
        "long_mode": entry.long_mode,
        "default_big": entry.default_big,
        "granularity": entry.granularity,
        "avl": entry.avl,
        "raw": format!("0x{:032x}", entry.raw),
    })
}

fn pool_header_json(header: PoolHeader) -> Value {
    json!({
        "header": fmt_addr(header.header.0),
        "body": fmt_addr(header.body.0),
        "size": header.size,
        "previous_size": header.previous_size,
        "pool_type": header.pool_type,
        "tag": tag_string(header.tag),
        "tag_raw": format!("0x{:08x}", header.tag),
        "state": pool_block_state(&header),
        "synthetic_free": header.synthetic_free,
    })
}

fn big_pool_json(entry: BigPoolEntry) -> Value {
    json!({
        "va": fmt_addr(entry.va.0),
        "entry": fmt_addr(entry.entry.0),
        "index": entry.index,
        "nonpaged": entry.nonpaged,
        "size": entry.size,
        "tag": tag_string(entry.tag),
        "tag_raw": format!("0x{:08x}", entry.tag),
        "pattern": entry.pattern,
        "pool_flags": entry.pool_flags,
        "slush_size": entry.slush_size,
    })
}

fn thread_json(thread: &ThreadInfo, active_vcpu: Option<&str>) -> Value {
    json!({
        "active_vcpu": active_vcpu,
        "ethread": fmt_addr(thread.ethread.0),
        "kthread": fmt_addr(thread.kthread.0),
        "tid": thread.tid,
        "pid": thread.pid,
        "process": thread.process_name,
        "eprocess": thread.eprocess.map(|address| fmt_addr(address.0)),
        "state": thread.state.map(|state| json!({
            "value": state,
            "name": kthread_state_name(state),
        })),
        "wait_reason": thread.wait_reason.map(|reason| json!({
            "value": reason,
            "name": wait_reason_name(reason),
        })),
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "wait_irql": thread.wait_irql,
        "kernel_stack_resident": thread.kernel_stack_resident,
        "start_address": thread.start_address.map(|address| fmt_addr(address.0)),
        "win32_start_address": thread.win32_start_address.map(|address| fmt_addr(address.0)),
        "teb": thread.teb.map(|address| fmt_addr(address.0)),
        "kernel_stack": thread.kernel_stack.map(|address| fmt_addr(address.0)),
        "stack_base": thread.stack_base.map(|address| fmt_addr(address.0)),
        "stack_limit": thread.stack_limit.map(|address| fmt_addr(address.0)),
        "trap_frame": thread.trap_frame.map(|address| fmt_addr(address.0)),
        "pending_irps": thread.pending_irps.as_ref().map(|irps| {
            irps.iter().map(|address| fmt_addr(address.0)).collect::<Vec<_>>()
        }),
    })
}

fn windows_thread_matches(thread: &ThreadInfo, filter: &str) -> bool {
    let filter_lower = filter.to_ascii_lowercase();
    thread
        .process_name
        .as_deref()
        .is_some_and(|name| name.to_ascii_lowercase().contains(&filter_lower))
        || thread
            .pid
            .is_some_and(|pid| pid.to_string() == filter || format!("{pid:#x}") == filter_lower)
        || thread
            .tid
            .is_some_and(|tid| tid.to_string() == filter || format!("{tid:#x}") == filter_lower)
        || format!("{:#x}", thread.ethread.0) == filter_lower
        || format!("{:x}", thread.ethread.0) == filter_lower.trim_start_matches("0x")
}

fn backend_processor_index(thread_id: &str) -> Option<u16> {
    processor_index_from_backend_thread_id(thread_id).or_else(|| {
        let raw = thread_id.trim_start_matches("0x");
        u16::from_str_radix(raw, 16)
            .ok()
            .and_then(|one_based| one_based.checked_sub(1))
    })
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

fn memory_region_json(region: MemoryRegionInfo) -> Value {
    json!({
        "start": fmt_addr(region.start.0),
        "end": fmt_addr(region.end.0),
        "size": region.size(),
        "protection": vad_protection_label(region.protection),
        "protection_value": region.protection,
        "type": vad_type_label(&region),
        "vad_type": region.vad_type,
        "private": region.private_memory,
        "commit_charge": region.commit_charge,
        "details": region.details,
    })
}

fn module_symbol_report_json(report: ModuleSymbolLoadReport) -> Value {
    json!({
        "total": report.total,
        "loaded": report.loaded,
        "no_pdb": report.no_pdb,
        "skipped": report.skipped,
        "failed": report.failed,
    })
}

fn script_load_report_json(report: &embed::LoadReport) -> Value {
    json!({
        "loaded": report.loaded,
        "failed": report.failed.iter().map(|(path, error)| json!({
            "path": path.display().to_string(),
            "error": error,
        })).collect::<Vec<_>>(),
    })
}

fn completion_strategy_name(strategy: crate::repl::CompletionStrategy) -> &'static str {
    match strategy {
        crate::repl::CompletionStrategy::None => "none",
        crate::repl::CompletionStrategy::Symbol => "symbol",
        crate::repl::CompletionStrategy::Type => "type",
        crate::repl::CompletionStrategy::Process => "process",
        crate::repl::CompletionStrategy::Thread => "thread",
        crate::repl::CompletionStrategy::Vcpu => "vcpu",
        crate::repl::CompletionStrategy::Breakpoint => "breakpoint",
        crate::repl::CompletionStrategy::Driver => "driver",
    }
}

#[cfg(test)]
mod tests {
    use super::{backend_processor_index, region_matches_filter};
    use crate::target::MemoryRegionInfo;
    use crate::types::VirtAddr;

    #[test]
    fn backend_processor_index_accepts_kd_and_gdb_ids() {
        assert_eq!(backend_processor_index("p1.1"), Some(0));
        assert_eq!(backend_processor_index("p1.10"), Some(15));
        assert_eq!(backend_processor_index("1"), Some(0));
        assert_eq!(backend_processor_index("2"), Some(1));
        assert_eq!(backend_processor_index("0"), None);
    }

    #[test]
    fn vmmap_filter_matches_containing_address_and_metadata() {
        let region = MemoryRegionInfo {
            start: VirtAddr(0x1000),
            end: VirtAddr(0x3000),
            protection: Some(6),
            vad_type: Some(3),
            private_memory: Some(false),
            commit_charge: Some(2),
            details: Some("example.dll".to_string()),
        };
        assert!(region_matches_filter(&region, None, Some(VirtAddr(0x2000))));
        assert!(region_matches_filter(&region, Some("example"), None));
        assert!(region_matches_filter(&region, Some("x/rw"), None));
        assert!(!region_matches_filter(&region, Some("missing"), None));
    }
}
