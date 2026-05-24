use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::backend::MemoryOps;
use crate::dbg_backend::{DebugBackend, StopEvent};
use crate::debugger::{AttachReport, DebuggerContext, DriverObjectInfo};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::{BreakpointKind, BreakpointManager, RegisterMap};
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::memory::AddressSpace;
use crate::script::{LoadReport, ScriptHost};
use crate::symbols::{ModuleSymbolDiscovery, ParsedType, SymbolStore, TypeInfo};
use crate::types::{Dtb, VirtAddr};
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
    register_map: RegisterMap,
    current_thread: String,
    breakpoints: BreakpointManager,
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
        register_map,
        current_thread,
        breakpoints: BreakpointManager::new(),
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
            "quit" => Ok(json!({ "bye": true })),
            other => Err(Error::InvalidExpression(format!(
                "unknown agent command: {other}"
            ))),
        }
    }

    fn status(&self) -> Value {
        let process = self
            .debugger
            .current_process_info
            .as_ref()
            .map(|p| json!({ "pid": p.pid, "name": p.name, "dtb": fmt_addr(p.dtb) }));

        json!({
            "running": self.client.is_running(),
            "current_thread": self.current_thread,
            "current_dtb": fmt_addr(self.debugger.current_dtb()),
            "current_process": process,
        })
    }

    fn registers(&mut self) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        self.client.set_current_thread(&self.current_thread)?;
        let regs = self.client.read_registers()?;
        let map = self.register_map.to_hashmap(&regs);
        self.debugger.registers = Some(map.clone());
        Ok(json!({
            "thread": self.current_thread,
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
        self.client.set_current_thread(&self.current_thread)?;
        let regs = self.client.read_registers()?;
        self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
        Ok(regs)
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
            read_idt_entries(self.debugger, &self.register_map, &regs, idtr, max_entries)?;
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
            read_gdt_entries(self.debugger, &self.register_map, &regs, gdtr, max_entries)?;
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
            read_tss_stack_bases(self.debugger, &self.register_map, &regs, gdtr, selector)?;
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
        self.client.set_current_thread(&self.current_thread)?;
        let regs = self.client.read_registers()?;
        self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
        let limit = limit.unwrap_or(64);
        let trace = build_stacktrace(self.debugger, &self.register_map, &regs, limit);
        Ok(json!({
            "thread": self.current_thread,
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
        self.current_thread = thread;
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
                self.breakpoints
                    .add(self.client, self.debugger, address, symbol.clone())?
            }
            BreakpointKind::Hardware => self.breakpoints.add_hardware(
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
        self.breakpoints.remove(self.client, self.debugger, id)?;
        Ok(json!({ "cleared": id }))
    }

    fn disable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.breakpoints.disable(self.client, self.debugger, id)?;
        Ok(json!({ "disabled": id }))
    }

    fn enable_breakpoint(&mut self, id: Option<u32>) -> Result<Value> {
        let id = id.ok_or_else(|| Error::InvalidExpression("missing breakpoint".into()))?;
        self.breakpoints.enable(self.client, self.debugger, id)?;
        Ok(json!({ "enabled": id }))
    }

    fn list_breakpoints(&self) -> Result<Value> {
        Ok(json!({
            "breakpoints": self.breakpoints.list().into_iter().map(|bp| json!({
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

        self.breakpoints
            .refresh_enabled(self.client, self.debugger)?;
        self.client.continue_execution()?;
        self.debugger.registers = None;

        if let Some(timeout_ms) = timeout_ms {
            match self
                .client
                .try_wait_for_stop(Duration::from_millis(timeout_ms))?
            {
                Some(event) => self.stopped(event),
                None => Ok(json!({ "running": true, "stopped": false })),
            }
        } else {
            Ok(json!({ "running": true }))
        }
    }

    fn interrupt(&mut self) -> Result<Value> {
        self.client.interrupt()?;
        if let Ok(thread) = self.client.get_stopped_thread_id() {
            self.current_thread = thread;
        }
        Ok(self.status())
    }

    fn step(&mut self) -> Result<Value> {
        if self.client.is_running() {
            return Err(Error::InvalidExpression("VM is running".into()));
        }

        self.client.set_current_thread(&self.current_thread)?;
        self.client.step()?;
        let event = self.client.wait_for_stop()?;
        self.stopped(event)
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

    fn stopped(&mut self, event: StopEvent) -> Result<Value> {
        if let Some(thread) = event
            .thread_id
            .or_else(|| self.client.get_stopped_thread_id().ok())
        {
            self.current_thread = thread;
            let _ = self.client.set_current_thread(&self.current_thread);
        }

        let mut out = json!({
            "running": false,
            "stopped": true,
            "thread": self.current_thread,
            "summary": event.summary,
            "target_exited": event.target_exited,
        });

        if !event.target_exited
            && let Ok(regs) = self.client.read_registers()
        {
            let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
            let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
            self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
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
        self.client.set_current_thread(&self.current_thread)?;
        let regs = self.client.read_registers()?;
        self.debugger.registers = Some(self.register_map.to_hashmap(&regs));
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
        return Some(Idtr {
            base: VirtAddr(values.next()?),
            limit: values.next()? as u16,
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
        return Some(Gdtr {
            base: VirtAddr(values.next()?),
            limit: values.next()? as u16,
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
        return Some(
            value_text
                .split_whitespace()
                .next()
                .and_then(parse_hex_u64)? as u16,
        );
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

fn read_idt_entries(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    idtr: Idtr,
    max_entries: Option<usize>,
) -> Result<Vec<IdtEntry>> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let idt_size = idtr.limit as usize + 1;
    let entry_count = max_entries.map_or(idt_size / 16, |count| count.min(idt_size / 16));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }
    let mut data = vec![0u8; entry_count * 16];
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(idtr.base, &mut data)?;
    Ok(data
        .chunks_exact(16)
        .enumerate()
        .map(|(vector, bytes)| parse_idt_entry(vector, bytes))
        .collect())
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

fn read_gdt_entries(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    max_entries: Option<usize>,
) -> Result<Vec<GdtEntry>> {
    const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    let cr3 = register_map.read_u64("cr3", regs)? & CR3_PAGE_MASK;
    let gdt_size = gdtr.limit as usize + 1;
    let entry_count = max_entries.map_or(gdt_size / 8, |count| count.min(gdt_size / 8));
    if entry_count == 0 {
        return Err(Error::InvalidRange);
    }
    let read_len = gdt_size.min(entry_count * 8 + 8);
    let mut data = vec![0u8; read_len];
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(gdtr.base, &mut data)?;
    let mut entries = Vec::new();
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
        entries.push(parse_gdt_entry(index, &bytes));
    }
    Ok(entries)
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

fn parse_selector_arg(arg: &str) -> Option<u16> {
    let stripped = arg.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(stripped, 16)
        .or_else(|_| arg.parse::<u16>())
        .ok()
}

fn read_gdt_entry(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<GdtEntry> {
    let index = (selector >> 3) as usize;
    read_gdt_entries(debugger, register_map, regs, gdtr, Some(index + 1))?
        .into_iter()
        .find(|entry| entry.index == index)
        .ok_or(Error::InvalidRange)
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

fn read_tss_stack_bases(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    gdtr: Gdtr,
    selector: u16,
) -> Result<(GdtEntry, TssStackBases)> {
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
    AddressSpace::new(&debugger.kvm, cr3).read_bytes(VirtAddr(entry.base), &mut data)?;
    let stacks = parse_tss_stack_bases(&data)?;
    Ok((entry, stacks))
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
        (
            read_pool_field(&layout.pool_header, &mem, header, "PreviousSize")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "BlockSize")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "PoolType")? as u8,
            read_pool_field(&layout.pool_header, &mem, header, "PoolTag")? as u32,
        )
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
        (
            read_pool_field(ti, &mem, entry, "Va")?,
            read_pool_field(ti, &mem, entry, "NumberOfBytes")?,
            read_pool_field(ti, &mem, entry, "Key")? as u32,
            read_pool_field(ti, &mem, entry, "Pattern")? as u8,
            if layout.big_pool_has_pool_type {
                read_pool_field(ti, &mem, entry, "PoolType").unwrap_or(0) as u16 & 0xfff
            } else {
                0
            },
            if layout.big_pool_has_slush {
                read_pool_field(ti, &mem, entry, "SlushSize").unwrap_or(0) as u16 & 0xfff
            } else {
                0
            },
        )
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

fn segment_heap_hint(debugger: &DebuggerContext) -> Option<&'static str> {
    debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "RtlpHpHeapGlobals")?;
    Some("kernel has RtlpHpHeapGlobals; address may be segment heap instead of _POOL_HEADER")
}

fn annotate_near_symbol(debugger: &DebuggerContext, addr: VirtAddr) -> Option<String> {
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.current_dtb(), addr)?;
    (offset <= 0x1000).then(|| format!("{}!{}+0x{:x}", module, name, offset))
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
    if !dir.is_dir() {
        return Err(Error::InvalidExpression(format!(
            "not a directory: {}",
            dir.display()
        )));
    }
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
