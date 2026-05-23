use std::collections::{HashMap, HashSet};

use pelite::pe64::{
    Pe, PeView,
    image::{
        IMAGE_SCN_MEM_EXECUTE, UNW_FLAG_CHAININFO, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL,
        UWOP_PUSH_MACHFRAME, UWOP_PUSH_NONVOL, UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR,
        UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_SET_FPREG,
    },
};

use crate::{
    backend::MemoryOps,
    debugger::DebuggerContext,
    gdb::RegisterMap,
    guest::{ModuleInfo, ProcessInfo, read_pe_image},
    host::KvmHandle,
    memory::AddressSpace,
    types::{Dtb, VirtAddr},
};

const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const STACK_SCAN_BYTES: usize = 0x1000;
const UNWIND_REG_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

#[derive(Debug, Clone)]
pub struct ThreadTraceContext {
    pub description: String,
    pub active_dtb: Dtb,
    pub kernel_dtb: Dtb,
    pub process_dtb: Option<Dtb>,
    pub kernel_modules: Vec<ModuleInfo>,
    pub process_modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSource {
    Current,
    Unwind,
    Scan,
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub sp: u64,
    pub ip: u64,
    pub symbol: String,
    pub source: FrameSource,
    pub trap_frame: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct StackTrace {
    pub frames: Vec<StackFrame>,
    pub truncated: usize,
}

#[derive(Clone, Debug)]
struct RegisterContext {
    rip: u64,
    rsp: u64,
    regs: [Option<u64>; 16],
    last_trap_frame: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct TrapFrameLayout {
    rip_offset: u64,
    error_code_offset: Option<u64>,
}

impl TrapFrameLayout {
    fn base_from_machine_frame(&self, machine_frame: u64, has_error_code: bool) -> Option<u64> {
        let offset = if has_error_code {
            self.error_code_offset
                .unwrap_or(self.rip_offset.saturating_sub(8))
        } else {
            self.rip_offset
        };
        machine_frame.checked_sub(offset)
    }
}

#[derive(Debug, Clone)]
struct CachedModule {
    info: ModuleInfo,
    image: Vec<u8>,
    executable_ranges: Vec<(u32, u32)>,
}

#[derive(Debug, Clone)]
struct OwnedModule {
    info: ModuleInfo,
    dtb: Dtb,
}

#[derive(Debug, Clone, Copy)]
struct UnwindCodeSlot {
    code_offset: u8,
    unwind_op: u8,
    op_info: u8,
    raw_op_info: u8,
}

#[derive(Debug, Clone)]
struct ParsedUnwindInfo {
    size_of_prolog: u8,
    frame_register: u8,
    frame_offset: u8,
    codes: Vec<UnwindCodeSlot>,
    chain_info: bool,
}

struct StackTracer<'a> {
    trace: &'a ThreadTraceContext,
    kvm: &'a KvmHandle,
    memory: AddressSpace<'a, KvmHandle>,
    modules: HashMap<(Dtb, u64), CachedModule>,
    trap_frame_layout: Option<TrapFrameLayout>,
}

pub fn resolve_thread_trace_context(debugger: &DebuggerContext, cr3: u64) -> ThreadTraceContext {
    let cr3_masked = cr3 & CR3_PAGE_MASK;
    let kernel_dtb = debugger.guest.ntoskrnl.dtb();
    let kernel_dtb_masked = kernel_dtb & CR3_PAGE_MASK;

    if cr3_masked == kernel_dtb_masked {
        return ThreadTraceContext {
            description: "kernel".to_string(),
            active_dtb: kernel_dtb,
            kernel_dtb,
            process_dtb: None,
            kernel_modules: debugger
                .guest
                .get_kernel_modules(&debugger.kvm, &debugger.symbols)
                .unwrap_or_default(),
            process_modules: Vec::new(),
        };
    }

    if let Some(proc_info) = find_process_by_cr3(debugger, cr3_masked) {
        let process_modules = debugger
            .guest
            .get_process_modules(&debugger.kvm, &debugger.symbols, &proc_info)
            .unwrap_or_default();
        return ThreadTraceContext {
            description: format!("{} ({})", proc_info.name, proc_info.pid),
            active_dtb: cr3_masked,
            kernel_dtb,
            process_dtb: Some(proc_info.dtb),
            kernel_modules: debugger
                .guest
                .get_kernel_modules(&debugger.kvm, &debugger.symbols)
                .unwrap_or_default(),
            process_modules,
        };
    }

    ThreadTraceContext {
        description: "unknown".to_string(),
        active_dtb: cr3_masked,
        kernel_dtb,
        process_dtb: None,
        kernel_modules: debugger
            .guest
            .get_kernel_modules(&debugger.kvm, &debugger.symbols)
            .unwrap_or_default(),
        process_modules: Vec::new(),
    }
}

pub fn format_symbol(debugger: &DebuggerContext, trace: &ThreadTraceContext, addr: u64) -> String {
    let try_format = |dtb| {
        debugger
            .symbols
            .find_closest_symbol_for_address(dtb, VirtAddr(addr))
            .map(|(module, symbol, offset)| {
                if offset == 0 {
                    format!("{}!{}", module, symbol)
                } else {
                    format!("{}!{}+{:#x}", module, symbol, offset)
                }
            })
    };

    if let Some(module) = trace.module_for_address(addr) {
        return try_format(module.dtb).unwrap_or_else(|| {
            // TODO lazily load module symbols on stop so user return addresses resolve past module+offset.
            let offset = addr.saturating_sub(module.info.base_address.0);
            format!("{}+{:#x}", module.info.short_name, offset)
        });
    }

    if let Some(process_dtb) = trace.process_dtb
        && let Some(symbol) = try_format(process_dtb)
    {
        return symbol;
    }

    if let Some(symbol) = try_format(trace.kernel_dtb) {
        return symbol;
    }

    format!("{:#x}", addr)
}

pub fn preferred_code_dtb(trace: &ThreadTraceContext, addr: u64) -> Dtb {
    trace
        .module_for_address(addr)
        .map(|module| module.dtb)
        .unwrap_or(trace.active_dtb)
}

pub fn build_stacktrace(
    debugger: &DebuggerContext,
    register_map: &RegisterMap,
    regs: &[u8],
    limit: usize,
) -> StackTrace {
    let limit = limit.max(1);
    let rip = register_map.read_u64("rip", regs).unwrap_or(0);
    let rsp = register_map.read_u64("rsp", regs).unwrap_or(0);
    let cr3 = register_map.read_u64("cr3", regs).unwrap_or(0);

    let trace = resolve_thread_trace_context(debugger, cr3);
    let mut stacktrace = StackTrace::default();
    record_stack_frame(
        &mut stacktrace,
        limit,
        StackFrame {
            sp: rsp,
            ip: rip,
            symbol: format_symbol(debugger, &trace, rip),
            source: FrameSource::Current,
            trap_frame: None,
        },
    );

    let mut tracer = StackTracer::new(debugger, &trace);
    let mut context = RegisterContext::from_registers(register_map, regs);
    let mut seen = HashSet::from([rip]);

    loop {
        let previous_rip = context.rip;
        let previous_rsp = context.rsp;

        if !tracer.unwind_once(&mut context) {
            break;
        }

        if let Some(trap_frame) = context.take_last_trap_frame()
            && let Some(frame) = stacktrace.frames.last_mut()
            && frame.ip == previous_rip
        {
            frame.trap_frame = Some(trap_frame);
        }

        if context.rip == 0 || context.rip == previous_rip || context.rsp <= previous_rsp {
            break;
        }

        seen.insert(context.rip);
        record_stack_frame(
            &mut stacktrace,
            limit,
            StackFrame {
                sp: context.rsp,
                ip: context.rip,
                symbol: format_symbol(debugger, &trace, context.rip),
                source: FrameSource::Unwind,
                trap_frame: None,
            },
        );
    }

    for (sp, ip) in tracer.scan_stack(context.rsp, &seen) {
        record_stack_frame(
            &mut stacktrace,
            limit,
            StackFrame {
                sp,
                ip,
                symbol: format_symbol(debugger, &trace, ip),
                source: FrameSource::Scan,
                trap_frame: None,
            },
        );
    }

    stacktrace
}

fn record_stack_frame(stacktrace: &mut StackTrace, limit: usize, frame: StackFrame) {
    if stacktrace.frames.len() < limit {
        stacktrace.frames.push(frame);
    } else {
        stacktrace.truncated += 1;
    }
}

fn find_process_by_cr3(debugger: &DebuggerContext, cr3_masked: u64) -> Option<ProcessInfo> {
    debugger
        .guest
        .enumerate_processes(&debugger.kvm, &debugger.symbols)
        .ok()?
        .into_iter()
        .find(|proc| (proc.dtb & CR3_PAGE_MASK) == cr3_masked)
}

impl RegisterContext {
    fn from_registers(register_map: &RegisterMap, regs: &[u8]) -> Self {
        let mut register_values = [None; 16];
        for (index, name) in UNWIND_REG_NAMES.iter().enumerate() {
            register_values[index] = register_map.read_u64(*name, regs).ok();
        }

        Self {
            rip: register_map.read_u64("rip", regs).unwrap_or(0),
            rsp: register_map.read_u64("rsp", regs).unwrap_or(0),
            regs: register_values,
            last_trap_frame: None,
        }
    }

    fn get(&self, register: u8) -> Option<u64> {
        match register {
            4 => Some(self.rsp),
            _ => self.regs.get(register as usize).copied().flatten(),
        }
    }

    fn set(&mut self, register: u8, value: u64) {
        if register == 4 {
            self.rsp = value;
        }

        if let Some(slot) = self.regs.get_mut(register as usize) {
            *slot = Some(value);
        }
    }

    fn take_last_trap_frame(&mut self) -> Option<u64> {
        self.last_trap_frame.take()
    }
}

impl ThreadTraceContext {
    fn module_for_address(&self, address: u64) -> Option<OwnedModule> {
        self.kernel_modules
            .iter()
            .find(|module| module.contains_address(VirtAddr(address)))
            .cloned()
            .map(|info| OwnedModule {
                info,
                dtb: self.kernel_dtb,
            })
            .or_else(|| {
                self.process_modules
                    .iter()
                    .find(|module| module.contains_address(VirtAddr(address)))
                    .cloned()
                    .map(|info| OwnedModule {
                        info,
                        dtb: self.process_dtb.unwrap_or(self.active_dtb),
                    })
            })
    }
}

impl<'a> StackTracer<'a> {
    fn new(debugger: &'a DebuggerContext, trace: &'a ThreadTraceContext) -> Self {
        let trap_frame_layout = debugger
            .symbols
            .find_type_across_modules(trace.kernel_dtb, "_KTRAP_FRAME")
            .and_then(|ty| {
                let rip_offset = u64::from(ty.fields.get("Rip")?.offset);
                let error_code_offset = ty
                    .fields
                    .get("ErrorCode")
                    .map(|field| u64::from(field.offset));
                Some(TrapFrameLayout {
                    rip_offset,
                    error_code_offset,
                })
            });

        Self {
            trace,
            kvm: &debugger.kvm,
            memory: AddressSpace::new(&debugger.kvm, trace.active_dtb),
            modules: HashMap::new(),
            trap_frame_layout,
        }
    }

    fn unwind_once(&mut self, context: &mut RegisterContext) -> bool {
        let Some(module) = self.module_containing(context.rip) else {
            return self.unwind_leaf(context);
        };

        let Ok(view) = PeView::from_bytes(&module.image) else {
            return false;
        };

        let Ok(exception) = view.exception() else {
            return self.unwind_leaf(context);
        };

        let rva = (context.rip - module.info.base_address.0) as u32;
        let Some(function) = exception.lookup_function_entry(rva) else {
            return self.unwind_leaf(context);
        };

        let runtime_function = function.image();
        let rip_offset = rva.saturating_sub(runtime_function.BeginAddress);
        let Some(unwind_info) = parse_unwind_info(&module.image, runtime_function.UnwindData)
        else {
            return false;
        };

        if unwind_info.chain_info {
            // TODO support chained unwind entries instead of falling back to a stack scan here.
            return false;
        }

        let original_context = context.clone();
        let in_prolog = rip_offset < unwind_info.size_of_prolog as u32;
        let mut index = 0usize;

        while index < unwind_info.codes.len() {
            let slot = unwind_info.codes[index];
            let slots_used = unwind_slot_count(slot.unwind_op, slot.op_info);
            if slots_used == 0 || index + slots_used > unwind_info.codes.len() {
                return false;
            }

            let executed = !in_prolog || u32::from(slot.code_offset) <= rip_offset;
            if executed
                && self
                    .apply_unwind_code(context, &original_context, &unwind_info, index)
                    .is_none()
            {
                return false;
            }
            if context.last_trap_frame.is_some() {
                return true;
            }

            index += slots_used;
        }

        let Ok(return_address) = self.memory.read::<u64>(VirtAddr(context.rsp)) else {
            return false;
        };
        context.rip = return_address;
        context.rsp = context.rsp.saturating_add(8);
        true
    }

    fn unwind_leaf(&self, context: &mut RegisterContext) -> bool {
        let Ok(return_address) = self.memory.read::<u64>(VirtAddr(context.rsp)) else {
            return false;
        };

        context.rip = return_address;
        context.rsp = context.rsp.saturating_add(8);
        true
    }

    fn apply_unwind_code(
        &self,
        context: &mut RegisterContext,
        original_context: &RegisterContext,
        unwind_info: &ParsedUnwindInfo,
        index: usize,
    ) -> Option<()> {
        let slot = unwind_info.codes[index];
        match slot.unwind_op {
            UWOP_PUSH_NONVOL => {
                let saved = self.memory.read::<u64>(VirtAddr(context.rsp)).ok()?;
                context.set(slot.op_info, saved);
                context.rsp = context.rsp.saturating_add(8);
            }
            UWOP_ALLOC_SMALL => {
                context.rsp = context
                    .rsp
                    .saturating_add(((u64::from(slot.op_info) + 1) * 8).max(8));
            }
            UWOP_ALLOC_LARGE => {
                let allocation = if slot.op_info == 0 {
                    u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 8
                } else if slot.op_info == 1 {
                    u64::from(slot_u16(&unwind_info.codes, index + 1)?)
                        | (u64::from(slot_u16(&unwind_info.codes, index + 2)?) << 16)
                } else {
                    return None;
                };
                context.rsp = context.rsp.saturating_add(allocation);
            }
            UWOP_SET_FPREG => {}
            UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => {
                let offset = if slot.unwind_op == UWOP_SAVE_NONVOL {
                    u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 8
                } else {
                    u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 16
                };
                if slot.unwind_op == UWOP_SAVE_NONVOL {
                    let base = frame_base(original_context, unwind_info)?;
                    let saved = self.memory.read::<u64>(VirtAddr(base + offset)).ok()?;
                    context.set(slot.op_info, saved);
                }
            }
            UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => {
                let offset = u64::from(slot_u16(&unwind_info.codes, index + 1)?)
                    | (u64::from(slot_u16(&unwind_info.codes, index + 2)?) << 16);
                let scaled = if slot.unwind_op == UWOP_SAVE_NONVOL_FAR {
                    offset
                } else {
                    offset * 16
                };
                if slot.unwind_op == UWOP_SAVE_NONVOL_FAR {
                    let base = frame_base(original_context, unwind_info)?;
                    let saved = self.memory.read::<u64>(VirtAddr(base + scaled)).ok()?;
                    context.set(slot.op_info, saved);
                }
            }
            UWOP_PUSH_MACHFRAME => {
                let has_error_code = slot.op_info != 0;
                let machine_frame = context.rsp;
                let rip_slot = machine_frame.saturating_add(if has_error_code { 8 } else { 0 });
                let saved_rip = self.memory.read::<u64>(VirtAddr(rip_slot)).ok()?;
                let saved_rsp = self
                    .memory
                    .read::<u64>(VirtAddr(rip_slot.saturating_add(24)))
                    .ok()?;

                context.rip = saved_rip;
                context.rsp = saved_rsp;
                context.last_trap_frame = self
                    .trap_frame_layout
                    .and_then(|layout| {
                        layout.base_from_machine_frame(machine_frame, has_error_code)
                    })
                    .or(Some(machine_frame));
            }
            _ => return None,
        }

        Some(())
    }

    fn scan_stack(&mut self, start_rsp: u64, seen: &HashSet<u64>) -> Vec<(u64, u64)> {
        let mut frames = Vec::new();
        let mut failures = 0usize;

        for slot in 0..(STACK_SCAN_BYTES / 8) {
            if failures >= 32 {
                break;
            }

            let sp = start_rsp.saturating_add((slot * 8) as u64);
            let potential_ip = match self.memory.read::<u64>(VirtAddr(sp)) {
                Ok(addr) => {
                    failures = 0;
                    addr
                }
                Err(_) => {
                    failures += 1;
                    continue;
                }
            };

            if seen.contains(&potential_ip) || !self.is_executable_address(potential_ip) {
                continue;
            }

            frames.push((sp, potential_ip));
        }

        frames
    }

    fn is_executable_address(&mut self, address: u64) -> bool {
        let Some(module) = self.module_containing(address) else {
            return false;
        };

        let rva = (address - module.info.base_address.0) as u32;
        module
            .executable_ranges
            .iter()
            .any(|(start, end)| rva >= *start && rva < *end)
    }

    fn module_containing(&mut self, address: u64) -> Option<&CachedModule> {
        let module = self.trace.module_for_address(address)?;

        self.ensure_module_loaded(&module)?;
        self.modules.get(&(module.dtb, module.info.base_address.0))
    }

    fn ensure_module_loaded(&mut self, module: &OwnedModule) -> Option<()> {
        let key = (module.dtb, module.info.base_address.0);
        if self.modules.contains_key(&key) {
            return Some(());
        }

        let image_memory = AddressSpace::new(self.kvm, module.dtb);
        let image = read_pe_image(module.info.base_address, &image_memory).ok()?;
        let view = PeView::from_bytes(&image).ok()?;
        let executable_ranges = view
            .section_headers()
            .iter()
            .filter_map(|section| {
                if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                    return None;
                }

                let size = section.VirtualSize.max(section.SizeOfRawData);
                if size == 0 {
                    return None;
                }

                Some((
                    section.VirtualAddress,
                    section.VirtualAddress.saturating_add(size),
                ))
            })
            .collect();

        self.modules.insert(
            key,
            CachedModule {
                info: module.info.clone(),
                image,
                executable_ranges,
            },
        );

        Some(())
    }
}

fn parse_unwind_info(image: &[u8], unwind_rva: u32) -> Option<ParsedUnwindInfo> {
    let offset = unwind_rva as usize;
    let header = image.get(offset..offset + 4)?;
    let version_flags = header[0];
    let count_of_codes = header[2] as usize;
    let frame_register_offset = header[3];

    let codes_offset = offset + 4;
    let codes_end = codes_offset.checked_add(count_of_codes.checked_mul(2)?)?;
    let codes_bytes = image.get(codes_offset..codes_end)?;

    let aligned_code_count = (count_of_codes + 1) & !1;
    let tail_offset = offset + 4 + aligned_code_count * 2;
    let chain_info = (version_flags >> 3) & UNW_FLAG_CHAININFO != 0;
    if chain_info && image.get(tail_offset..tail_offset + 12).is_none() {
        return None;
    }

    let mut codes = Vec::with_capacity(count_of_codes);
    for raw in codes_bytes.chunks_exact(2) {
        codes.push(UnwindCodeSlot {
            code_offset: raw[0],
            unwind_op: raw[1] & 0x0f,
            op_info: raw[1] >> 4,
            raw_op_info: raw[1],
        });
    }

    Some(ParsedUnwindInfo {
        size_of_prolog: header[1],
        frame_register: frame_register_offset & 0x0f,
        frame_offset: frame_register_offset >> 4,
        codes,
        chain_info,
    })
}

fn frame_base(context: &RegisterContext, unwind_info: &ParsedUnwindInfo) -> Option<u64> {
    if unwind_info.frame_register == 0 {
        return Some(context.rsp);
    }

    let frame_register = context.get(unwind_info.frame_register)?;
    frame_register.checked_sub(u64::from(unwind_info.frame_offset) * 16)
}

fn unwind_slot_count(unwind_op: u8, op_info: u8) -> usize {
    match unwind_op {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
        UWOP_ALLOC_LARGE => {
            if op_info == 0 {
                2
            } else {
                3
            }
        }
        UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
        _ => 0,
    }
}

fn slot_u16(codes: &[UnwindCodeSlot], index: usize) -> Option<u16> {
    let slot = codes.get(index)?;
    Some(u16::from_le_bytes([slot.code_offset, slot.raw_op_info]))
}

#[cfg(test)]
mod tests {
    use super::{
        FrameSource, ParsedUnwindInfo, RegisterContext, StackFrame, StackTrace, TrapFrameLayout,
        UnwindCodeSlot, frame_base, record_stack_frame, slot_u16, unwind_slot_count,
    };

    #[test]
    fn slot_count_matches_opcode_encoding() {
        assert_eq!(unwind_slot_count(0, 0), 1);
        assert_eq!(unwind_slot_count(1, 0), 2);
        assert_eq!(unwind_slot_count(1, 1), 3);
        assert_eq!(unwind_slot_count(4, 0), 2);
        assert_eq!(unwind_slot_count(5, 0), 3);
    }

    #[test]
    fn slot_u16_reads_little_endian_slot_data() {
        let codes = vec![
            UnwindCodeSlot {
                code_offset: 0x34,
                unwind_op: 0,
                op_info: 0,
                raw_op_info: 0x12,
            },
            UnwindCodeSlot {
                code_offset: 0x78,
                unwind_op: 0,
                op_info: 0,
                raw_op_info: 0x56,
            },
        ];

        assert_eq!(slot_u16(&codes, 0), Some(0x1234));
        assert_eq!(slot_u16(&codes, 1), Some(0x5678));
    }

    #[test]
    fn frame_base_uses_frame_register_when_present() {
        let mut regs = [None; 16];
        regs[5] = Some(0x2000);
        let context = RegisterContext {
            rip: 0,
            rsp: 0x1800,
            regs,
            last_trap_frame: None,
        };
        let unwind = ParsedUnwindInfo {
            size_of_prolog: 0,
            frame_register: 5,
            frame_offset: 2,
            codes: Vec::new(),
            chain_info: false,
        };

        assert_eq!(frame_base(&context, &unwind), Some(0x1fe0));
    }

    #[test]
    fn trap_frame_layout_maps_machine_frame_to_ktrap_frame_base() {
        let layout = TrapFrameLayout {
            rip_offset: 0x238,
            error_code_offset: Some(0x230),
        };

        assert_eq!(
            layout.base_from_machine_frame(0xffff_8000_0000_1238, false),
            Some(0xffff_8000_0000_1000)
        );
        assert_eq!(
            layout.base_from_machine_frame(0xffff_8000_0000_1230, true),
            Some(0xffff_8000_0000_1000)
        );
    }

    #[test]
    fn record_stack_frame_counts_truncated_frames() {
        let mut stacktrace = StackTrace::default();

        for ip in [0x1000, 0x2000, 0x3000] {
            record_stack_frame(
                &mut stacktrace,
                2,
                StackFrame {
                    sp: 0,
                    ip,
                    symbol: String::new(),
                    source: FrameSource::Current,
                    trap_frame: None,
                },
            );
        }

        assert_eq!(stacktrace.frames.len(), 2);
        assert_eq!(stacktrace.truncated, 1);
    }
}
