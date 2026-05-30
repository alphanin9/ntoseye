use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::backend::MemoryOps;
use crate::dbg_backend::DebugBackend;
use crate::debugger::{AttachReport, DebuggerContext, DriverObjectInfo};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::{Breakpoint, BreakpointKind};
use crate::session::{DebuggerSession, StopOutcome};
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
use crate::script::{LoadReport, ScriptHost, ScriptOutput};
use crate::symbols::{ParsedType, TypeInfo};
use crate::types::VirtAddr;
use crate::unwind::{FrameSource, build_stacktrace};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, MemorySizeOptions, NasmFormatter,
};

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
}

struct AgentSession<'a> {
    debugger: &'a mut DebuggerContext,
    client: &'a mut dyn DebugBackend,
    session: DebuggerSession,
    script_host: ScriptHost,
}

pub fn start_agent_stdio(
    debugger: &mut DebuggerContext,
    client: &mut dyn DebugBackend,
) -> Result<()> {
    let register_map = client.register_map().clone();
    let current_thread = client
        .get_stopped_thread_id()
        .unwrap_or_else(|_| "1".to_string());
    let mut script_host = ScriptHost::new();
    let script_report = script_host.load_all(&agent_builtin_names(), Some(debugger));
    let mut session = AgentSession {
        debugger,
        client,
        session: DebuggerSession::new(register_map, current_thread),
        script_host,
    };

    write_json(json!({
        "ok": true,
        "event": "ready",
        "result": session.status(),
        "scripts": script_load_report_json(script_report),
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

    Ok(())
}

impl AgentSession<'_> {
    fn handle(&mut self, request: AgentRequest) -> Result<Value> {
        match request.command.as_str() {
            "status" => Ok(self.status()),
            "eval" => {
                let expr = required(request.expr, "expr")?;
                let address = self.eval_address(expr)?;
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
            "load-symbols" | "symbols.load" => self.load_symbols(request),
            "attach" => self.attach(request.pid),
            "detach" => {
                self.debugger.detach();
                Ok(self.status())
            }
            "thread" | "thread.set" => self.set_thread(required(request.thread, "thread")?),
            "threads" => self.threads(),
            "breakpoint.set" | "bp.set" => self.set_breakpoint(request),
            "breakpoint.clear" | "bp.clear" => self.clear_breakpoint(request.breakpoint),
            "breakpoint.disable" | "bp.disable" => self.disable_breakpoint(request.breakpoint),
            "breakpoint.enable" | "bp.enable" => self.enable_breakpoint(request.breakpoint),
            "breakpoint.list" | "bp.list" => self.list_breakpoints(),
            "continue" | "go" => self.continue_execution(request.timeout_ms),
            "interrupt" | "break" => self.interrupt(),
            "step" | "si" => self.step(),
            "qcmd" => {
                let command = required(request.expr, "expr")?;
                self.client
                    .monitor_command(&command)
                    .map(|output| json!({ "output": output }))
            }
            "qlog" => self.qlog(request),
            "scripts" | "script.list" => Ok(json!({
                "commands": self.script_host.command_names().into_iter().map(|(name, help, strategies)| json!({
                    "name": name,
                    "help": help,
                    "strategies": strategies.into_iter().map(completion_strategy_name).collect::<Vec<_>>(),
                })).collect::<Vec<_>>()
            })),
            "script.reload" => {
                self.script_host.reset();
                let report = self
                    .script_host
                    .load_all(&agent_builtin_names(), Some(self.debugger));
                Ok(script_load_report_json(report))
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
        if !self.script_host.has(name) {
            return Err(Error::InvalidExpression(format!(
                "no such script command: {name}"
            )));
        }
        let output = self
            .script_host
            .dispatch(
                name,
                args,
                self.debugger,
                self.client,
                &self.session.register_map,
                ScriptOutput::Capture,
            )
            .map_err(|e| Error::InvalidExpression(e.to_string()))?;
        Ok(json!({ "command": name, "output": output }))
    }

    fn status(&self) -> Value {
        let process = self
            .debugger
            .current_process_info
            .as_ref()
            .map(|p| json!({ "pid": p.pid, "name": p.name, "dtb": fmt_addr(p.dtb) }));

        json!({
            "running": self.client.is_running(),
            "current_thread": self.session.current_thread,
            "current_dtb": fmt_addr(self.debugger.current_dtb()),
            "current_process": process,
        })
    }

    fn registers(&mut self) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        let regs = self.session.refresh_register_cache(self.client, self.debugger)?;
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
        self.debugger
            .get_current_process()
            .memory(&self.debugger.kvm)
            .read_bytes(address, &mut bytes)?;
        Ok(json!({
            "address": fmt_addr(address.0),
            "data": hex::encode(bytes),
        }))
    }

    fn write_memory(&mut self, request: AgentRequest) -> Result<Value> {
        let address = self.eval_address(required(request.address, "address")?)?;
        let data = hex::decode(required(request.data, "data")?)?;
        self.debugger
            .get_current_process()
            .memory(&self.debugger.kvm)
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
        self.debugger
            .get_current_process()
            .memory(&self.debugger.kvm)
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

        self.debugger
            .get_current_process()
            .memory(&self.debugger.kvm)
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
        self.debugger
            .get_current_process()
            .memory(&self.debugger.kvm)
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
        let type_info = self
            .debugger
            .symbols
            .find_type_across_modules(self.debugger.current_dtb(), &lookup)
            .or_else(|| {
                self.debugger
                    .symbols
                    .find_type_across_modules(self.debugger.current_dtb(), &type_name)
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
        let mem = self
            .debugger
            .get_current_process()
            .memory(&self.debugger.kvm);
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
        let traversal = self.debugger.pte_traverse(address)?;
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

    fn current_regs(&mut self) -> Result<Vec<u8>> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        self.session.refresh_register_cache(self.client, self.debugger)
    }

    fn qemu_register_descriptors(&mut self) -> Result<String> {
        self.client.monitor_command("info registers").map_err(|e| {
            if matches!(e, Error::NotSupported) {
                Error::NotSupported
            } else {
                e
            }
        })
    }

    fn idt(&mut self, max_entries: Option<usize>) -> Result<Value> {
        let regs = self.current_regs()?;
        let monitor_output = self.qemu_register_descriptors()?;
        let idtr = parse_idtr_from_qemu_registers(&monitor_output).ok_or_else(|| {
            Error::InvalidExpression("QEMU monitor output did not contain IDT".into())
        })?;
        let entries =
            read_idt_entries(self.debugger, &self.session.register_map, &regs, idtr, max_entries)?;
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
        let entries =
            read_gdt_entries(self.debugger, &self.session.register_map, &regs, gdtr, max_entries)?;
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
        let (entry, stacks) =
            read_tss_stack_bases(self.debugger, &self.session.register_map, &regs, gdtr, selector)?;
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
        let layout = pool_layout(self.debugger)?;
        let region = classify_pool_region(self.debugger, target).map(|(name, start, end)| {
            json!({
                "name": name,
                "start": fmt_addr(start.0),
                "end": fmt_addr(end.0),
            })
        });
        let (blocks, target_index, page) =
            locate_pool_block_in_page(self.debugger, &layout, target);
        let big_pool = find_big_pool(self.debugger, &layout, target).map(big_pool_json);
        Ok(json!({
            "target": fmt_addr(target.0),
            "page": fmt_addr(page.0),
            "region": region,
            "target_index": target_index,
            "blocks": blocks.into_iter().map(pool_header_json).collect::<Vec<_>>(),
            "big_pool": big_pool,
            "segment_heap_hint": if target_index.is_none() { segment_heap_hint(self.debugger) } else { None },
            "near_symbol": if target_index.is_none() { annotate_near_symbol(self.debugger, target) } else { None },
        }))
    }

    fn stack_trace(&mut self, limit: Option<usize>) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }
        let regs = self.session.refresh_register_cache(self.client, self.debugger)?;
        let limit = limit.unwrap_or(64);
        let trace = build_stacktrace(self.debugger, &self.session.register_map, &regs, limit);
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
                "trap_frame": frame.trap_frame.map(fmt_addr),
            })).collect::<Vec<_>>()
        }))
    }

    fn drivers(&self, filter: Option<String>) -> Result<Value> {
        let filter = filter.map(|s| s.to_lowercase());
        Ok(json!({
            "drivers": self.debugger.enumerate_driver_objects()?
                .into_iter()
                .filter(|driver| driver_matches(driver, filter.as_deref()))
                .map(driver_json)
                .collect::<Vec<_>>()
        }))
    }

    fn processes(&self, filter: Option<String>) -> Result<Value> {
        let filter = filter.map(|s| s.to_lowercase());
        let rows: Vec<_> = self
            .debugger
            .guest
            .enumerate_processes(&self.debugger.kvm, &self.debugger.symbols)?
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
        let modules = if let Some(process_info) = &self.debugger.current_process_info {
            self.debugger.guest.get_process_modules(
                &self.debugger.kvm,
                &self.debugger.symbols,
                process_info,
            )?
        } else {
            self.debugger
                .guest
                .get_kernel_modules(&self.debugger.kvm, &self.debugger.symbols)?
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

    fn load_symbols(&mut self, request: AgentRequest) -> Result<Value> {
        let path = required(request.path.or(request.expr), "path")?;
        let report = load_symbols_from_directory(
            self.debugger,
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
        } = self.debugger.attach(pid)?;
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

    fn threads(&mut self) -> Result<Value> {
        Ok(json!({ "threads": self.client.get_thread_list()? }))
    }

    fn set_thread(&mut self, thread: String) -> Result<Value> {
        self.client.set_current_thread(&thread)?;
        self.session.current_thread = thread;
        Ok(self.status())
    }

    fn set_breakpoint(&mut self, request: AgentRequest) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        let address = self.eval_address(required(request.address, "address")?)?;
        let kind = match request.kind.as_deref().unwrap_or("software") {
            "software" | "bp" => BreakpointKind::Software,
            "hardware" | "hbp" => BreakpointKind::Hardware,
            other => {
                return Err(Error::InvalidExpression(format!(
                    "unknown breakpoint kind: {other}"
                )));
            }
        };
        let symbol = self
            .debugger
            .symbols
            .find_closest_symbol_for_address(self.debugger.current_dtb(), address)
            .map(|(module, sym, offset)| {
                if offset == 0 {
                    format!("{module}!{sym}")
                } else {
                    format!("{module}!{sym}+0x{offset:x}")
                }
            });

        let id = match kind {
            BreakpointKind::Software => {
                self.session.breakpoints
                    .add(self.client, self.debugger, address, symbol.clone())?
            }
            BreakpointKind::Hardware => self.session.breakpoints.add_hardware(
                self.client,
                self.debugger,
                address,
                symbol.clone(),
            )?,
        };

        Ok(json!({
            "id": id,
            "kind": kind.label(),
            "address": fmt_addr(address.0),
            "symbol": symbol,
        }))
    }

    fn clear_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.breakpoints.remove(self.client, self.debugger, id)?;
        Ok(json!({ "cleared": id }))
    }

    fn disable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.breakpoints.disable(self.client, self.debugger, id)?;
        Ok(json!({ "disabled": id }))
    }

    fn enable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.session.breakpoints.enable(self.client, self.debugger, id)?;
        Ok(json!({ "enabled": id }))
    }

    fn list_breakpoints(&self) -> Result<Value> {
        Ok(json!({
            "breakpoints": self.session.breakpoints.list().into_iter().map(|bp| json!({
                "id": bp.id,
                "enabled": bp.enabled,
                "kind": bp.kind.label(),
                "address": fmt_addr(bp.address.0),
                "symbol": bp.symbol,
                "scope": bp.scope.label(),
            })).collect::<Vec<_>>()
        }))
    }

    fn continue_execution(&mut self, timeout_ms: Option<u64>) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        // Step over a breakpoint at the current RIP and refresh the transport's
        // breakpoint view, matching the REPL's resume path.
        self.session.prepare_resume(self.client, self.debugger)?;
        self.client.continue_execution()?;
        self.debugger.registers = None;

        let Some(timeout_ms) = timeout_ms else {
            return Ok(json!({ "running": true }));
        };

        // Poll for a stop within the timeout budget, silently stepping over
        // wrong-process int3 hits and resuming until a real stop or the
        // deadline.
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(event) = self.client.try_wait_for_stop(remaining)? else {
                return Ok(json!({ "running": true, "stopped": false }));
            };

            let summary = event.summary.clone();
            match self.session.process_stop(self.client, self.debugger, &event)? {
                StopOutcome::Resumed(_) => {
                    if Instant::now() >= deadline {
                        return Ok(json!({ "running": true, "stopped": false }));
                    }
                }
                StopOutcome::TargetExited => return self.stop_json(summary, true, None),
                StopOutcome::Stopped => return self.stop_json(summary, false, None),
                StopOutcome::Breakpoint(bp) => return self.stop_json(summary, false, Some(&bp)),
            }
        }
    }

    fn interrupt(&mut self) -> Result<Value> {
        self.client.interrupt()?;
        if let Ok(thread) = self.client.get_stopped_thread_id() {
            self.session.current_thread = thread;
        }
        Ok(self.status())
    }

    fn step(&mut self) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        // Shared step-over/single-step path (handles sitting on a breakpoint).
        let result = self.session.step(self.client, self.debugger)?;
        self.stop_json(result.event.summary, result.event.target_exited, None)
    }

    fn qlog(&mut self, request: AgentRequest) -> Result<Value> {
        let items = request
            .expr
            .or(request.filter)
            .unwrap_or_else(|| "int,cpu_reset,guest_errors".to_string());
        if let Some(path) = request.path {
            let _ = self.client.monitor_command(&format!("logfile {path}"))?;
        }
        let output = self.client.monitor_command(&format!("log {items}"))?;
        Ok(json!({
            "items": items,
            "output": output,
        }))
    }

    /// Serialize a stop into the agent's JSON shape. The session has already
    /// updated the current thread and refreshed the register cache; this reads
    /// the current thread's registers for RIP/CR3/symbol context.
    fn stop_json(
        &mut self,
        summary: Option<String>,
        target_exited: bool,
        breakpoint: Option<&Breakpoint>,
    ) -> Result<Value> {
        let mut out = json!({
            "running": false,
            "stopped": true,
            "thread": self.session.current_thread,
            "summary": summary,
            "target_exited": target_exited,
        });

        if let Some(bp) = breakpoint {
            out["breakpoint"] = json!({
                "id": bp.id,
                "symbol": bp.symbol,
                "address": fmt_addr(bp.address.0),
            });
        }

        if !target_exited
            && let Ok(regs) = self.client.read_registers()
        {
            let rip = self.session.register_map.read_u64("rip", &regs).unwrap_or(0);
            let cr3 = self.session.register_map.read_u64("cr3", &regs).unwrap_or(0);
            self.debugger.registers = Some(self.session.register_map.to_hashmap(&regs));
            out["rip"] = json!(fmt_addr(rip));
            out["cr3"] = json!(fmt_addr(cr3));
            if let Some((module, symbol, offset)) = self
                .debugger
                .symbols
                .find_closest_symbol_for_address(self.debugger.current_dtb(), VirtAddr(rip))
            {
                out["symbol"] = json!(if offset == 0 {
                    format!("{module}!{symbol}")
                } else {
                    format!("{module}!{symbol}+0x{offset:x}")
                });
            }
        }

        Ok(out)
    }

    fn eval_address(&mut self, expr: String) -> Result<VirtAddr> {
        self.ensure_register_cache()?;
        Expr::eval(&expr, self.debugger)
    }

    fn ensure_register_cache(&mut self) -> Result<()> {
        if self.debugger.registers.is_some() || self.client.is_running() {
            return Ok(());
        }
        self.session
            .refresh_register_cache(self.client, self.debugger)?;
        Ok(())
    }

    fn format_symbol(&self, address: VirtAddr) -> Option<String> {
        self.debugger
            .symbols
            .find_closest_symbol_for_address(self.debugger.current_dtb(), address)
            .map(|(module, symbol, offset)| {
                if offset == 0 {
                    format!("{module}!{symbol}")
                } else {
                    format!("{module}!{symbol}+0x{offset:x}")
                }
            })
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

fn module_symbol_report_json(report: ModuleSymbolLoadReport) -> Value {
    json!({
        "total": report.total,
        "loaded": report.loaded,
        "no_pdb": report.no_pdb,
        "skipped": report.skipped,
        "failed": report.failed,
    })
}

fn script_load_report_json(report: LoadReport) -> Value {
    json!({
        "loaded": report.loaded,
        "failed": report.failed.into_iter().map(|(path, error)| json!({
            "path": path.display().to_string(),
            "error": error,
        })).collect::<Vec<_>>(),
    })
}

fn agent_builtin_names() -> HashSet<String> {
    [
        "status",
        "eval",
        "registers",
        "read-memory",
        "write-memory",
        "memory.read",
        "memory.write",
        "memory.search",
        "memory.fill",
        "disasm",
        "dt",
        "trap-frame",
        "tf",
        "pte",
        "idt",
        "gdt",
        "tss",
        "pool",
        "k",
        "drivers",
        "ps",
        "lm",
        "load-symbols",
        "attach",
        "detach",
        "threads",
        "thread.set",
        "bp.set",
        "bp.clear",
        "bp.disable",
        "bp.enable",
        "bp.list",
        "continue",
        "interrupt",
        "step",
        "qcmd",
        "qlog",
        "scripts",
        "script.list",
        "script.reload",
        "script.run",
        "script.exec",
        "quit",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn completion_strategy_name(strategy: crate::repl::CompletionStrategy) -> &'static str {
    match strategy {
        crate::repl::CompletionStrategy::None => "none",
        crate::repl::CompletionStrategy::Symbol => "symbol",
        crate::repl::CompletionStrategy::Type => "type",
        crate::repl::CompletionStrategy::Process => "process",
        crate::repl::CompletionStrategy::Thread => "thread",
        crate::repl::CompletionStrategy::Breakpoint => "breakpoint",
        crate::repl::CompletionStrategy::Driver => "driver",
    }
}
